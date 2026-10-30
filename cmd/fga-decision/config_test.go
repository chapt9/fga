package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validDev() Config {
	return Config{Version: 1, Profile: profileDevelopment, Listen: "127.0.0.1:7443", DevAdapterID: "local-dev",
		DatabaseURL: "postgres://localhost/fga", BundleDir: "bundle", PublisherKeys: map[string]string{"p": "k"},
		SigningKeyFile: "dec.key", SigningKeyID: "dec-1", Audiences: []string{"storage"}, DecisionMaxAge: "30s", OutboxCapacity: 100}
}

func TestValidate(t *testing.T) {
	if err := validDev().Validate(); err != nil {
		t.Fatalf("valid development config rejected: %v", err)
	}
	tls := &TLSConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}
	tests := []struct {
		name    string
		edit    func(*Config)
		wantErr string
	}{
		{"production without TLS", func(c *Config) { c.Profile, c.DevAdapterID = profileProduction, "" }, "requires tls"},
		{"production with a development adapter", func(c *Config) { c.Profile, c.TLS = profileProduction, tls }, "not allowed in production"},
		{"development without TLS off loopback", func(c *Config) { c.Listen = "0.0.0.0:7443" }, "loopback"},
		{"TLS without a client CA", func(c *Config) { c.TLS, c.DevAdapterID = &TLSConfig{CertFile: "c", KeyFile: "k"}, "" }, "client_ca_file"},
		{"unknown profile", func(c *Config) { c.Profile = "test" }, "profile must be"},
		{"decision age too long", func(c *Config) { c.DecisionMaxAge = "1h" }, "decision_max_age"},
		{"no audiences", func(c *Config) { c.Audiences = nil }, "audiences"},
		{"no database", func(c *Config) { c.DatabaseURL = "" }, "database_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validDev()
			tt.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
	prod := validDev()
	prod.Profile, prod.DevAdapterID, prod.TLS, prod.Listen = profileProduction, "", tls, "0.0.0.0:7443"
	if err := prod.Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decision.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"profile":"development","debug_listener":":6060"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadConfig = %v, want an unknown-field error", err)
	}
}
