package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"fga/internal/admission"
	"fga/internal/strictjson"
)

// Config is the typed, versioned configuration of the decision role
// (MOD-003). Unknown fields are rejected.
type Config struct {
	Version        int               `json:"version"`
	Profile        string            `json:"profile"`
	Listen         string            `json:"listen"`
	TLS            *TLSConfig        `json:"tls,omitempty"`
	DevAdapterID   string            `json:"dev_adapter_id,omitempty"`
	DatabaseURL    string            `json:"database_url"`
	BundleDir      string            `json:"bundle_dir"`
	PublisherKeys  map[string]string `json:"publisher_keys"`
	SigningKeyFile string            `json:"signing_key_file"`
	SigningKeyID   string            `json:"signing_key_id"`
	Audiences      []string          `json:"audiences"`
	DecisionMaxAge string            `json:"decision_max_age"`
	OutboxCapacity int               `json:"outbox_capacity"`
	// TokenIssuer verifies first-hop user tokens (TRU-003). Without it only
	// delegated requests can be decided.
	TokenIssuer *TokenIssuerConfig `json:"token_issuer,omitempty"`
	// AdapterAudiences maps each adapter to the token audiences of the users
	// it serves; PublicAudience is the audience of the public facade.
	AdapterAudiences map[string][]string `json:"adapter_audiences,omitempty"`
	PublicAudience   string              `json:"public_audience,omitempty"`
	// Gateways maps each gateway adapter (the MCP role) to the audiences
	// its decisions for MCP tool calls may be addressed to; the role it
	// calls presents such a decision as the user's evidence (TB3).
	Gateways map[string][]string `json:"gateways,omitempty"`
	// Admission bounds concurrent requests per calling workload and in
	// total (AVL-006); absent means defaultAdmission.
	Admission *AdmissionConfig `json:"admission,omitempty"`
}

// AdmissionConfig bounds the decision role's concurrent requests.
type AdmissionConfig struct {
	AdapterRequests int `json:"adapter_requests"`
	TotalRequests   int `json:"total_requests"`
}

// defaultAdmission are the initial bounds (D-10 open; not measured): one
// workload can hold at most a quarter of the role.
var defaultAdmission = AdmissionConfig{AdapterRequests: 128, TotalRequests: 512}

// limits returns the configured bounds as admission limits, keyed by
// workload.
func (c Config) limits() admission.Limits {
	a := defaultAdmission
	if c.Admission != nil {
		a = *c.Admission
	}
	return admission.Limits{TenantRequests: a.AdapterRequests, TenantStreams: 1, TotalRequests: a.TotalRequests}
}

// TokenIssuerConfig names one token issuer and its Ed25519 verification
// keys by key ID (base64). D-04 is open: the only qualified use is the
// development issuer, which production refuses.
type TokenIssuerConfig struct {
	Issuer string            `json:"issuer"`
	Keys   map[string]string `json:"keys"`
}

// devIssuer is the development token issuer of first-hop-authentication.md.
const devIssuer = "fga-dev"

// TLSConfig names the server certificate and the CA that issues adapter
// workload certificates. Client certificates are required (DEC-007).
type TLSConfig struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

const (
	profileProduction  = "production"
	profileDevelopment = "development"
	maxDecisionAge     = 5 * time.Minute
)

// loadConfig reads and validates a configuration file.
func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := strictjson.Decode(raw, &c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, c.Validate()
}

// Validate rejects missing values and combinations that would weaken the
// role. Production requires mutual TLS; development without TLS may listen
// on a loopback address only and must name the single local adapter.
func (c Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		fail("version must be 1")
	}
	switch c.Profile {
	case profileProduction:
		if c.TLS == nil {
			fail("production requires tls with a client CA")
		}
		if c.DevAdapterID != "" {
			fail("dev_adapter_id is not allowed in production")
		}
	case profileDevelopment:
		if c.TLS == nil && (c.DevAdapterID == "" || !loopback(c.Listen)) {
			fail("development without tls needs dev_adapter_id and a loopback listen address")
		}
		if c.TLS != nil && c.DevAdapterID != "" {
			fail("dev_adapter_id is only for development without tls")
		}
	default:
		fail("profile must be %q or %q", profileProduction, profileDevelopment)
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "") {
		fail("tls needs cert_file, key_file and client_ca_file")
	}
	if c.Listen == "" {
		fail("listen is required")
	}
	for name, v := range map[string]string{"database_url": c.DatabaseURL, "bundle_dir": c.BundleDir,
		"signing_key_file": c.SigningKeyFile, "signing_key_id": c.SigningKeyID} {
		if v == "" {
			fail("%s is required", name)
		}
	}
	if len(c.PublisherKeys) == 0 {
		fail("publisher_keys is required")
	}
	if len(c.Audiences) == 0 {
		fail("audiences is required")
	}
	if age, err := time.ParseDuration(c.DecisionMaxAge); err != nil || age <= 0 || age > maxDecisionAge {
		fail("decision_max_age must be a duration in (0, %s]", maxDecisionAge)
	}
	if c.OutboxCapacity <= 0 {
		fail("outbox_capacity must be positive")
	}
	if ti := c.TokenIssuer; ti != nil {
		if ti.Issuer == "" || len(ti.Keys) == 0 {
			fail("token_issuer needs issuer and keys")
		}
		if ti.Issuer == devIssuer && c.Profile == profileProduction {
			fail("the development token issuer is not allowed in production")
		}
	}
	for gw, audiences := range c.Gateways {
		if len(c.AdapterAudiences[gw]) == 0 {
			fail("gateway %s needs adapter_audiences for its users' tokens", gw)
		}
		for _, a := range audiences {
			if !slices.Contains(c.Audiences, a) {
				fail("gateway %s may address only audiences the role signs for, not %s", gw, a)
			}
		}
	}
	if a := c.Admission; a != nil && (a.AdapterRequests <= 0 || a.TotalRequests < a.AdapterRequests) {
		fail("admission needs adapter_requests above 0 and total_requests at least as large")
	}
	if (len(c.AdapterAudiences) > 0 || c.PublicAudience != "") && c.TokenIssuer == nil {
		fail("adapter_audiences and public_audience need a token_issuer")
	}
	return errors.Join(errs...)
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
