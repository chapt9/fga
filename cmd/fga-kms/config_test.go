package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fga/internal/kek"
)

// TestConfig covers D-13's production rules for the key management role:
// mutual TLS, a ring sealed under a passphrase, and that passphrase from a
// file; development without TLS stays on loopback with one client.
func TestConfig(t *testing.T) {
	dir := t.TempDir()
	plain, sealed := filepath.Join(dir, "plain"), filepath.Join(dir, "sealed")
	if err := kek.WriteRing(plain, kek.NewRing(), nil); err != nil {
		t.Fatal(err)
	}
	if err := kek.WriteRing(sealed, kek.NewRing(), []byte("a passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pass"), []byte("a passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	prod := func() Config {
		return Config{Version: 1, Profile: "production", Listen: ":8449", Clients: []string{"keys-1"}, KEKFile: sealed,
			KEKPassphraseFile: filepath.Join(dir, "pass"), TLS: &TLSConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}}
	}
	if err := prod().Validate(); err != nil {
		t.Fatalf("production: %v", err)
	}
	for name, c := range map[string]struct {
		edit func(*Config)
		want string
	}{
		"without tls":              {func(c *Config) { c.TLS = nil }, "requires tls"},
		"a plain ring":             {func(c *Config) { c.KEKFile = plain }, "passphrase-protected ring"},
		"a passphrase not in file": {func(c *Config) { c.KEKPassphraseFile = "" }, "kek_passphrase_file"},
		"no clients":               {func(c *Config) { c.Clients = nil }, "clients"},
	} {
		cfg := prod()
		c.edit(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dev := Config{Version: 1, Profile: "development", Listen: "127.0.0.1:18449", Clients: []string{"keys-1"}, DevClient: "keys-1", KEKFile: plain}
	if err := dev.Validate(); err != nil {
		t.Fatalf("development: %v", err)
	}
	dev.Listen = ":18449"
	if err := dev.Validate(); err == nil {
		t.Fatal("development without tls on every address")
	}
}
