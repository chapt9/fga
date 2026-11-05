package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fga/internal/authn"
	"fga/internal/cryptowire"
	"fga/internal/keyfile"
)

// Sign-in keys (docs/design/sign-in-keys.md): the account signs its own
// short access tokens with a key an administrator registered for it.
//
//	fga sign-in-key new [-dir D] [-protect] [-passphrase-file F]
//	                    write D/signin.key and print its public key and
//	                    fingerprint, for the administrator to register
//
//	fga sign-in-key token -aud AUDIENCE [-dir D] [-passphrase-file F]
//	                    print a fresh token for AUDIENCE (fga-storage,
//	                    fga-keys, fga-mcp, …), for a tool such as curl
//
// The client commands and the MCP bridge then sign their tokens with
// D/signin.key when $FGA_TOKEN (and, for the bridge, $FGA_MCP_TOKEN) is
// unset, as $FGA_PRINCIPAL of $FGA_TENANT.

const signInFile = "signin.key"

func signInKeyNew(args []string) error {
	fs := flag.NewFlagSet("sign-in-key new", flag.ContinueOnError)
	dir := fs.String("dir", os.Getenv("FGA_KEY_DIR"), "key directory")
	protect := fs.Bool("protect", false, "protect the key with a passphrase")
	passphraseFile := fs.String("passphrase-file", "", "file holding the passphrase (default $FGA_KEY_PASSPHRASE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("sign-in-key new needs -dir or $FGA_KEY_DIR")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(*dir, signInFile)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists; a sign-in key is replaced by registering a new one and removing the old", path)
	}
	var passphrase []byte
	if *protect {
		p, err := keyfile.Passphrase("FGA_KEY_PASSPHRASE", *passphraseFile)
		if err != nil {
			return err
		}
		passphrase = p
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writePrivate(path, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), passphrase); err != nil {
		return err
	}
	fmt.Printf("sign-in key %s %s\n", cryptowire.SignInKeyFingerprint(pub), base64.StdEncoding.EncodeToString(pub))
	fmt.Println("Give the fingerprint and the public key to an administrator, who checks the fingerprint with you and registers it.")
	return nil
}

// keySigner signs an account's tokens with its sign-in key, one per
// audience, reused until a minute before it expires.
type keySigner struct {
	priv                    ed25519.PrivateKey
	fingerprint             string
	tenant, subject, client string
	now                     func() time.Time

	mu     sync.Mutex
	cached map[string]signedToken
}

type signedToken struct {
	token   string
	expires time.Time
}

// Token signs, or reuses, a token for audience.
func (s *keySigner) Token(audience string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if t, ok := s.cached[audience]; ok && now.Add(time.Minute).Before(t.expires) {
		return t.token, nil
	}
	tok, err := authn.SignInToken(s.priv, s.fingerprint, s.tenant, s.subject, s.client, audience, now, authn.SignInMaxLifetime)
	if err != nil {
		return "", err
	}
	s.cached[audience] = signedToken{token: tok, expires: now.Add(authn.SignInMaxLifetime)}
	return tok, nil
}

// loadSigner reads dir's sign-in key for $FGA_PRINCIPAL of $FGA_TENANT;
// it is nil when dir holds none.
func loadSigner(dir, client string, passphrase func() ([]byte, error)) (*keySigner, error) {
	path := filepath.Join(dir, signInFile)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	tenant, subject := os.Getenv("FGA_TENANT"), os.Getenv("FGA_PRINCIPAL")
	if tenant == "" || subject == "" {
		return nil, fmt.Errorf("%s signs tokens for $FGA_PRINCIPAL of $FGA_TENANT; set both", path)
	}
	return loadSignerFor(dir, tenant, subject, client, passphrase)
}

// loadSignerFor reads dir's sign-in key for subject of tenant; it is nil
// when dir holds none.
func loadSignerFor(dir, tenant, subject, client string, passphrase func() ([]byte, error)) (*keySigner, error) {
	path := filepath.Join(dir, signInFile)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	raw, err := keyfile.Read(path, passphrase)
	if err != nil {
		return nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s does not hold a base64 Ed25519 private key", path)
	}
	return newKeySigner(ed25519.PrivateKey(priv), tenant, subject, client), nil
}

// newKeySigner signs tokens with key for subject of tenant.
func newKeySigner(key ed25519.PrivateKey, tenant, subject, client string) *keySigner {
	return &keySigner{priv: key, fingerprint: cryptowire.SignInKeyFingerprint(key.Public().(ed25519.PublicKey)).String(),
		tenant: tenant, subject: subject, client: client, now: time.Now, cached: map[string]signedToken{}}
}

func signInKeyToken(args []string) error {
	fs := flag.NewFlagSet("sign-in-key token", flag.ContinueOnError)
	dir := fs.String("dir", os.Getenv("FGA_KEY_DIR"), "key directory")
	audience := fs.String("aud", "", "the token's audience")
	passphraseFile := fs.String("passphrase-file", "", "file holding the passphrase (default $FGA_KEY_PASSPHRASE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *audience == "" {
		return errors.New("sign-in-key token needs -dir or $FGA_KEY_DIR, and -aud")
	}
	passphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_KEY_PASSPHRASE", *passphraseFile) }
	var tokens interface{ Token(string) (string, error) }
	if boxMode(*dir) {
		// In box mode the sign-in key is in the person's box (box.go).
		c, err := boxClient(*dir, passphrase)
		if err != nil {
			return err
		}
		if c.Tokens == nil {
			return errors.New("unset $FGA_TOKEN and $FGA_KEYS_TOKEN to sign with the box's sign-in key")
		}
		tokens = c.Tokens
	} else {
		signer, err := loadSigner(*dir, "fga", passphrase)
		if err != nil {
			return err
		}
		if signer == nil {
			return fmt.Errorf("%s holds no %s", *dir, signInFile)
		}
		tokens = signer
	}
	tok, err := tokens.Token(*audience)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
