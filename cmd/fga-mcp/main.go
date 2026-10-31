// Command fga-mcp runs the MCP role (R2, MCP-001 to MCP-008): an MCP
// server over the streamable HTTP transport whose resources and tools read
// through the storage role's native API, for the user whose MCP token each
// request carries. It has no database, blob store, key material or policy
// evaluator, and links none of that code (MCP-002, MCP-008,
// allowed-imports.txt); the storage role decides and filters every read.
//
//	fga-mcp -config mcp.json
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fga/internal/authn"
	"fga/internal/mcpsvc"
	"fga/internal/strictjson"
)

// Config is the MCP role's configuration (MOD-003). It names no database,
// blob store or key (MCP-008).
type Config struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Listen  string `json:"listen"`
	// TLS is the certificate MCP clients connect to. Users authenticate
	// by bearer token, so no client certificate is asked for.
	TLS *ServerTLS `json:"tls,omitempty"`
	// TokenIssuer verifies the users' MCP tokens, for Audience (fga-mcp).
	TokenIssuer TokenIssuer `json:"token_issuer"`
	Audience    string      `json:"audience"`
	// StorageAudience is the storage role's decision audience
	// (fga-storage): the decisions this role asks for are addressed to it.
	StorageAudience string `json:"storage_audience"`
	// Decision and Storage are the roles it calls, each with the client
	// certificate that is this role's workload identity (TB2, TB3).
	Decision Peer `json:"decision"`
	Storage  Peer `json:"storage"`
	// Tools, if set, is the tools role, whose registered tools this role
	// lists and calls for the user as "tool.<id>"; ToolsAudience is its
	// decision audience (fga-tools).
	Tools         *Peer  `json:"tools,omitempty"`
	ToolsAudience string `json:"tools_audience,omitempty"`
	// Buckets are the buckets resources/list goes through.
	Buckets []string `json:"buckets,omitempty"`
	// Limits replaces mcpsvc.DefaultLimits field by field; zero keeps the
	// default.
	MaxBytes      int64 `json:"max_bytes,omitempty"`
	MaxUnits      int   `json:"max_units,omitempty"`
	UserRequests  int   `json:"user_requests,omitempty"`
	TotalRequests int   `json:"total_requests,omitempty"`
	UserSessions  int   `json:"user_sessions,omitempty"`
	TotalSessions int   `json:"total_sessions,omitempty"`
	// SessionTimeout closes idle MCP sessions (Go duration; default 30m).
	SessionTimeout string `json:"session_timeout,omitempty"`
	// PublicURL is the MCP endpoint as clients reach it; with it the role
	// serves its protected resource metadata (RFC 9728) naming
	// AuthorizationServers, the issuers of the MCP tokens. Production
	// needs both.
	PublicURL            string   `json:"public_url,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// AllowedOrigins are the browser origins served; a request with
	// another Origin is refused (DNS rebinding).
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
}

// ServerTLS is the server certificate.
type ServerTLS struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// TokenIssuer is the issuer of the users' tokens and its keys by key ID
// (base64 Ed25519).
type TokenIssuer struct {
	Issuer string            `json:"issuer"`
	Keys   map[string]string `json:"keys"`
}

// Peer is a role this role calls.
type Peer struct {
	URL      string `json:"url"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	CAFile   string `json:"ca_file,omitempty"`
}

// Validate reports every configuration problem.
func (c Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		fail("version must be 1")
	}
	switch c.Profile {
	case "production":
		if c.TLS == nil {
			fail("production requires tls")
		}
		if c.TokenIssuer.Issuer == "fga-dev" {
			fail("the development token issuer is not allowed in production")
		}
		if !strings.HasPrefix(c.PublicURL, "https://") || len(c.AuthorizationServers) == 0 {
			fail("production serves its protected resource metadata: public_url (https) and authorization_servers")
		}
		peers := map[string]Peer{"decision": c.Decision, "storage": c.Storage}
		if c.Tools != nil {
			peers["tools"] = *c.Tools
		}
		for name, p := range peers {
			if !strings.HasPrefix(p.URL, "https://") || p.CertFile == "" || p.KeyFile == "" {
				fail("production calls the %s role over mutual TLS", name)
			}
		}
	case "development":
		if c.TLS == nil && !loopback(c.Listen) {
			fail("development without tls listens on a loopback address only")
		}
	default:
		fail(`profile must be "production" or "development"`)
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		fail("tls needs cert_file and key_file")
	}
	if c.Listen == "" || c.Audience == "" || c.StorageAudience == "" || c.Decision.URL == "" || c.Storage.URL == "" {
		fail("listen, audience, storage_audience, decision.url and storage.url are required")
	}
	if c.PublicURL != "" {
		if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			fail("public_url must be an absolute URL without query or fragment")
		}
	}
	for _, o := range c.AllowedOrigins {
		if u, err := url.Parse(o); err != nil || u.Host == "" || u.Path != "" || u.String() != o {
			fail("allowed_origins holds origins, such as https://app.example: %q is not one", o)
		}
	}
	if c.Tools != nil && (c.Tools.URL == "" || c.ToolsAudience == "") {
		fail("tools needs a url and tools_audience")
	}
	if c.TokenIssuer.Issuer == "" || len(c.TokenIssuer.Keys) == 0 {
		fail("token_issuer is required")
	}
	if c.MaxBytes < 0 || c.MaxUnits < 0 || c.UserRequests < 0 || c.TotalRequests < 0 || c.UserSessions < 0 || c.TotalSessions < 0 {
		fail("limits are positive when given")
	} else if err := c.limits().Validate(); err != nil {
		fail("limits: %v", err)
	}
	if c.SessionTimeout != "" {
		if d, err := time.ParseDuration(c.SessionTimeout); err != nil || d <= 0 {
			fail("session_timeout must be a positive duration")
		}
	}
	return errors.Join(errs...)
}

// limits returns mcpsvc.DefaultLimits with the configured values.
func (c Config) limits() mcpsvc.Limits {
	l := mcpsvc.DefaultLimits
	for _, f := range []struct {
		dst *int
		v   int
	}{{&l.MaxUnits, c.MaxUnits}, {&l.UserRequests, c.UserRequests}, {&l.TotalRequests, c.TotalRequests},
		{&l.UserSessions, c.UserSessions}, {&l.TotalSessions, c.TotalSessions}} {
		if f.v > 0 {
			*f.dst = f.v
		}
	}
	if c.MaxBytes > 0 {
		l.MaxBytes = c.MaxBytes
	}
	return l
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// client returns the HTTP client that calls p, with this role's client
// certificate when one is configured.
func (p Peer) client() (*http.Client, error) {
	tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 16, IdleConnTimeout: 60 * time.Second}
	if p.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		if p.CAFile != "" {
			pem, err := os.ReadFile(p.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("ca_file holds no certificates")
			}
			cfg.RootCAs = pool
		}
		tr.TLSClientConfig = cfg
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// tokens returns the verifier of the users' tokens.
func (c Config) tokens() (*authn.Verifier, error) {
	keys := map[string]ed25519.PublicKey{}
	for id, b64 := range c.TokenIssuer.Keys {
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("token issuer key %q is not a base64 Ed25519 public key", id)
		}
		keys[id] = k
	}
	return authn.NewVerifier(c.TokenIssuer.Issuer, keys, time.Now), nil
}

func main() {
	path := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("fga-mcp stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := strictjson.Decode(raw, &cfg); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	tokens, err := cfg.tokens()
	if err != nil {
		return err
	}
	decisionHTTP, err := cfg.Decision.client()
	if err != nil {
		return err
	}
	storageHTTP, err := cfg.Storage.client()
	if err != nil {
		return err
	}
	var tools mcpsvc.Peer
	if cfg.Tools != nil {
		toolsHTTP, err := cfg.Tools.client()
		if err != nil {
			return err
		}
		tools = mcpsvc.Peer{URL: cfg.Tools.URL, HTTP: toolsHTTP}
	}
	var timeout time.Duration
	if cfg.SessionTimeout != "" {
		timeout, _ = time.ParseDuration(cfg.SessionTimeout)
	}
	svc, err := mcpsvc.New(mcpsvc.Deps{Tokens: tokens, Audience: cfg.Audience, StorageAudience: cfg.StorageAudience,
		Decision: mcpsvc.Peer{URL: cfg.Decision.URL, HTTP: decisionHTTP}, Storage: mcpsvc.Peer{URL: cfg.Storage.URL, HTTP: storageHTTP},
		Tools: tools, ToolsAudience: cfg.ToolsAudience, Buckets: cfg.Buckets, Limits: cfg.limits(), SessionTimeout: timeout,
		PublicURL: cfg.PublicURL, AuthorizationServers: cfg.AuthorizationServers, AllowedOrigins: cfg.AllowedOrigins,
		Logger: slog.Default()})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: cfg.Listen, Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			errc <- server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errc <- server.ListenAndServe()
		}
	}()
	slog.Info("fga-mcp listening", "addr", cfg.Listen, "profile", cfg.Profile)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
