// Package roleconfig holds the configuration pieces and server setup that
// the storage and keys roles share (specification 2.5, MOD-002, MOD-003,
// TRU-001, TRU-002). Configuration is typed, versioned and strictly
// parsed; production requires mutual TLS, and the development profile
// without TLS listens on loopback only with one named local adapter.
package roleconfig

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"fga/internal/admission"
	"fga/internal/authn"
	"fga/internal/decisionsvc"
	"fga/internal/signing"
	"fga/internal/strictjson"
)

// Profiles.
const (
	Production  = "production"
	Development = "development"
	// DevIssuer is the development token issuer, refused in production.
	DevIssuer = "fga-dev"
)

// Common is the configuration every storage-side role has.
type Common struct {
	Version     int    `json:"version"`
	Profile     string `json:"profile"`
	Listen      string `json:"listen"`
	TLS         *TLS   `json:"tls,omitempty"`
	DevAdapter  string `json:"dev_adapter_id,omitempty"`
	DatabaseURL string `json:"database_url"`
	// TokenIssuer verifies users' access tokens (TB1).
	TokenIssuer TokenIssuer `json:"token_issuer"`
	// Decision is the decision role and DecisionKeys its signing keys by
	// key ID (base64 Ed25519).
	Decision     Peer              `json:"decision"`
	DecisionKeys map[string]string `json:"decision_keys"`
	// Admission bounds per-tenant and total work (AVL-006); absent means
	// admission.DefaultLimits.
	Admission *admission.Limits `json:"admission,omitempty"`
}

// Limiter returns the admission limiter of the configuration.
func (c Common) Limiter() *admission.Limiter {
	if c.Admission == nil {
		return admission.New(admission.DefaultLimits)
	}
	return admission.New(*c.Admission)
}

// TLS names the server certificate and the CA of workload client
// certificates.
type TLS struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

// Peer is another role this role calls, with the client certificate that
// identifies this role to it.
type Peer struct {
	URL      string `json:"url"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	CAFile   string `json:"ca_file,omitempty"`
}

// TokenIssuer is one access-token issuer and its keys.
type TokenIssuer struct {
	Issuer string            `json:"issuer"`
	Keys   map[string]string `json:"keys"`
}

// Load reads a configuration file into cfg strictly.
func Load(path string, cfg any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := strictjson.Decode(raw, cfg); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	return nil
}

// Validate reports every problem of the common part.
func (c Common) Validate() []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		fail("version must be 1")
	}
	switch c.Profile {
	case Production:
		if c.TLS == nil || c.DevAdapter != "" {
			fail("production requires tls and no dev_adapter_id")
		}
		if c.TokenIssuer.Issuer == DevIssuer {
			fail("the development token issuer is not allowed in production")
		}
		if !strings.HasPrefix(c.Decision.URL, "https://") || c.Decision.CertFile == "" {
			fail("production calls the decision role over mutual TLS")
		}
	case Development:
		if c.TLS == nil && (c.DevAdapter == "" || !Loopback(c.Listen)) {
			fail("development without tls needs dev_adapter_id and a loopback listen address")
		}
	default:
		fail("profile must be %q or %q", Production, Development)
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "") {
		fail("tls needs cert_file, key_file and client_ca_file")
	}
	if c.Listen == "" || c.DatabaseURL == "" || c.Decision.URL == "" {
		fail("listen, database_url and decision.url are required")
	}
	if c.TokenIssuer.Issuer == "" || len(c.TokenIssuer.Keys) == 0 || len(c.DecisionKeys) == 0 {
		fail("token_issuer and decision_keys are required")
	}
	if c.Admission != nil {
		if err := c.Admission.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Loopback reports whether addr is a loopback host:port.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// PublicKey decodes a base64 Ed25519 public key.
func PublicKey(b64 string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64 Ed25519 public key")
	}
	return key, nil
}

// PrivateKeyFile reads a base64 Ed25519 private key file.
func PrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s does not hold a base64 Ed25519 private key", path)
	}
	return key, nil
}

// Tokens returns the access-token verifier.
func (c Common) Tokens() (*authn.Verifier, error) {
	keys := map[string]ed25519.PublicKey{}
	for id, b64 := range c.TokenIssuer.Keys {
		k, err := PublicKey(b64)
		if err != nil {
			return nil, fmt.Errorf("token issuer key %q: %w", id, err)
		}
		keys[id] = k
	}
	return authn.NewVerifier(c.TokenIssuer.Issuer, keys, time.Now), nil
}

// Verifier returns a decision verifier for audience. Single-use
// consumption happens in the authority fence, never here.
func (c Common) Verifier(audience string) (*signing.Verifier, error) {
	keys := map[string]signing.Key{}
	for id, b64 := range c.DecisionKeys {
		k, err := PublicKey(b64)
		if err != nil {
			return nil, fmt.Errorf("decision key %q: %w", id, err)
		}
		keys[id] = signing.Key{Public: k, NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}
	}
	return signing.NewVerifier(audience, func() map[string]signing.Key { return keys }, signing.NewMemoryConsumption(), time.Now), nil
}

// Client returns the HTTP client for calling p: mutual TLS when a client
// certificate is configured.
func (p Peer) Client() (*http.Client, error) {
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

// Server returns the role's HTTP server and how it identifies a calling
// workload: the verified client certificate with TLS, otherwise the
// configured development adapter.
func (c Common) Server(handler http.Handler) (*http.Server, decisionsvc.AdapterOf, error) {
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	if c.TLS == nil {
		dev := c.DevAdapter
		return server, func(*http.Request) (string, error) { return dev, nil }, nil
	}
	pem, err := os.ReadFile(c.TLS.ClientCAFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("client_ca_file holds no certificates")
	}
	// Users authenticate by bearer token, workloads by certificate, so a
	// client certificate is verified when presented and required by the
	// internal routes through AdapterOf.
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	return server, decisionsvc.AdapterFromClientCert, nil
}

// Serve runs server until ctx ends, then shuts it down.
func (c Common) Serve(ctx context.Context, server *http.Server) error {
	errc := make(chan error, 1)
	go func() {
		if c.TLS != nil {
			errc <- server.ListenAndServeTLS(c.TLS.CertFile, c.TLS.KeyFile)
		} else {
			errc <- server.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
