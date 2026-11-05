package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/keyfile"
	"fga/internal/mcpbridge"
	"fga/internal/mcpwire"
)

// mcpBridge runs the local MCP bridge (R2 stretch M3, MCP-005): an MCP
// server on stdin and stdout for the application that started this
// process, forwarding to the fga MCP role at -mcp-url ($FGA_MCP_URL) with
// the user's MCP token ($FGA_MCP_TOKEN), for an agent the delegation it
// acts under ($FGA_MCP_DELEGATION), and opening client-mode packages
// with the keys in -dir ($FGA_KEY_DIR), checking signers with the keys
// role ($FGA_KEYS_URL, $FGA_KEYS_TOKEN) as fga get does. Stdout carries
// only MCP; diagnostics go to stderr. Configure it as the application's
// MCP server command; the application is then the one it serves.
func mcpBridge(args []string) error {
	fs := flag.NewFlagSet("mcp-bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", os.Getenv("FGA_KEY_DIR"), "key directory")
	upstream := fs.String("mcp-url", os.Getenv("FGA_MCP_URL"), "the fga MCP endpoint, such as https://mcp.example/mcp")
	passphraseFile := fs.String("passphrase-file", "", "file holding the key passphrase (default $FGA_KEY_PASSPHRASE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token := os.Getenv("FGA_MCP_TOKEN")
	if *dir == "" || *upstream == "" {
		return errors.New("mcp-bridge needs -dir or $FGA_KEY_DIR, -mcp-url or $FGA_MCP_URL, and $FGA_MCP_TOKEN or a sign-in key")
	}
	passphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_KEY_PASSPHRASE", *passphraseFile) }
	// Without $FGA_MCP_TOKEN, the account (an MCP account, with keys of its
	// own) signs its tokens with its sign-in key (signin.go).
	var tokens tokenSource = fixedToken(token)
	if token == "" {
		signer, err := loadSigner(*dir, "fga-mcp-bridge", passphrase)
		if err != nil {
			return err
		}
		if signer == nil {
			return errors.New("mcp-bridge needs $FGA_MCP_TOKEN or a sign-in key in its key directory")
		}
		tokens = signer
	}
	// An agent acting for a user names its delegation; the MCP role binds
	// the session to it, and the decision role checks that it names this
	// token's identity as its actor.
	dlg := os.Getenv("FGA_MCP_DELEGATION")
	if dlg != "" && !mcpwire.ValidDelegation(dlg) {
		return errors.New("$FGA_MCP_DELEGATION is not a delegation ID")
	}
	c, err := loadClient(*dir, passphrase)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	b, err := mcpbridge.New(ctx, mcpbridge.Deps{UpstreamURL: *upstream, HTTP: &http.Client{Transport: bearer{tokens: tokens, delegation: dlg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Key: c.Recipient, Trust: c.Trust, SignerStatus: c.SignerStatus, Logger: log})
	if err != nil {
		return err
	}
	defer b.Close()
	log.Info("fga mcp-bridge serving on stdio", "upstream", *upstream, "recipient", c.Recipient.Fingerprint().String())
	return b.Serve(ctx, &mcp.StdioTransport{})
}

// mcpAudience is the MCP role's token audience.
const mcpAudience = "fga-mcp"

// tokenSource returns a token for an audience.
type tokenSource interface {
	Token(audience string) (string, error)
}

// fixedToken is $FGA_MCP_TOKEN.
type fixedToken string

func (t fixedToken) Token(string) (string, error) { return string(t), nil }

// bearer is a transport that presents the MCP token and, for an agent,
// its delegation.
type bearer struct {
	tokens     tokenSource
	delegation string
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.tokens.Token(mcpAudience)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	if b.delegation != "" {
		r.Header.Set(mcpwire.DelegationHeader, b.delegation)
	}
	return http.DefaultTransport.RoundTrip(r)
}
