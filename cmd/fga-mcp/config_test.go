package main

import (
	"strings"
	"testing"

	"fga/internal/mcpsvc"
)

func validDev() Config {
	return Config{Version: 1, Profile: "development", Listen: "127.0.0.1:17446", Audience: "fga-mcp", StorageAudience: "fga-storage",
		TokenIssuer: TokenIssuer{Issuer: "fga-dev", Keys: map[string]string{"tok-1": "k"}},
		Decision:    Peer{URL: "http://127.0.0.1:17443"}, Storage: Peer{URL: "http://127.0.0.1:17445"}}
}

// TestValidate covers MOD-003 for the MCP role: production needs TLS, a
// real token issuer and mutual TLS to the roles it calls (the tools role
// too, when configured, with its audience); development
// without TLS listens on loopback only; limits are positive, a total at
// least its per-user limit, and absent ones keep their defaults.
func TestValidate(t *testing.T) {
	if err := validDev().Validate(); err != nil {
		t.Fatalf("valid development config rejected: %v", err)
	}
	if l := validDev().limits(); l != mcpsvc.DefaultLimits {
		t.Fatalf("default limits %+v", l)
	}
	mtls := func(url string) Peer { return Peer{URL: url, CertFile: "c", KeyFile: "k"} }
	prod := func(c *Config) {
		c.Profile, c.TLS, c.Listen = "production", &ServerTLS{CertFile: "c", KeyFile: "k"}, "0.0.0.0:443"
		c.TokenIssuer.Issuer = "idp"
		c.Decision, c.Storage = mtls("https://decision"), mtls("https://storage")
	}
	for _, tt := range []struct {
		name, want string
		edit       func(*Config)
	}{
		{"production without TLS", "requires tls", func(c *Config) { prod(c); c.TLS = nil }},
		{"production with the development issuer", "development token issuer", func(c *Config) { prod(c); c.TokenIssuer.Issuer = "fga-dev" }},
		{"production calling storage over plain HTTP", "storage role over mutual TLS", func(c *Config) { prod(c); c.Storage = Peer{URL: "http://storage"} }},
		{"production calling decision without a certificate", "decision role over mutual TLS",
			func(c *Config) { prod(c); c.Decision = Peer{URL: "https://decision"} }},
		{"development without TLS off loopback", "loopback", func(c *Config) { c.Listen = "0.0.0.0:17446" }},
		{"no storage audience", "storage_audience", func(c *Config) { c.StorageAudience = "" }},
		{"a negative limit", "positive", func(c *Config) { c.UserSessions = -1 }},
		{"a total below its per-user limit", "limits", func(c *Config) { c.UserRequests, c.TotalRequests = 10, 5 }},
		{"a bad session timeout", "session_timeout", func(c *Config) { c.SessionTimeout = "forever" }},
		{"the tools role without its audience", "tools_audience", func(c *Config) { c.Tools = &Peer{URL: "http://127.0.0.1:17448"} }},
		{"production calling tools over plain HTTP", "tools role over mutual TLS",
			func(c *Config) { prod(c); c.Tools, c.ToolsAudience = &Peer{URL: "http://tools"}, "fga-tools" }},
	} {
		c := validDev()
		tt.edit(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
	c := validDev()
	prod(&c)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
	c.UserRequests = 3
	if l := c.limits(); l.UserRequests != 3 || l.TotalRequests != mcpsvc.DefaultLimits.TotalRequests {
		t.Fatalf("limits %+v", l)
	}
}
