package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/audit"
	"fga/internal/authn"
	"fga/internal/catalog"
	"fga/internal/pgtest"
	"fga/internal/roleconfig"
)

func validServeConfig() ServeConfig {
	pub, _, _ := ed25519.GenerateKey(nil)
	key := base64.StdEncoding.EncodeToString(pub)
	return ServeConfig{Version: 1, Profile: "development", Listen: "127.0.0.1:18450", Consoles: []string{"console-dev"}, DevConsole: "console-dev",
		DatabaseURL: "postgres://localhost/fga", JournalDir: "journal", Audience: "fga-admin", Admins: map[string][]string{"t-acme": {"root"}},
		TokenIssuer: authn.IssuerConfig{Issuer: "fga-dev", Keys: map[string]string{"tok-1": key}}, BundleDir: "bundle",
		PublisherKeys: map[string]string{"publisher-1": key}}
}

// TestServeConfig covers the admin API's configuration: production needs
// TLS and no development console, development without TLS listens on
// loopback only, and administrators come from the file.
func TestServeConfig(t *testing.T) {
	if err := validServeConfig().Validate(); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
	for name, change := range map[string]func(*ServeConfig){
		"production without tls": func(c *ServeConfig) { c.Profile = "production" },
		"production with a dev console": func(c *ServeConfig) {
			c.Profile, c.TLS = "production", &roleconfig.TLS{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}
		},
		"no tls off loopback":                     func(c *ServeConfig) { c.Listen = "0.0.0.0:18450" },
		"a dev console not listed":                func(c *ServeConfig) { c.Consoles = []string{"other"} },
		"no consoles":                             func(c *ServeConfig) { c.Consoles = nil },
		"no administrators":                       func(c *ServeConfig) { c.Admins = nil },
		"a tenant without administrator":          func(c *ServeConfig) { c.Admins = map[string][]string{"t-acme": {}} },
		"no journal":                              func(c *ServeConfig) { c.JournalDir = "" },
		"no audience":                             func(c *ServeConfig) { c.Audience = "" },
		"no bundle":                               func(c *ServeConfig) { c.BundleDir = "" },
		"a bad publisher key":                     func(c *ServeConfig) { c.PublisherKeys = map[string]string{"p": "not base64"} },
		"no token issuer":                         func(c *ServeConfig) { c.TokenIssuer = authn.IssuerConfig{} },
		"tls without a client CA":                 func(c *ServeConfig) { c.TLS = &roleconfig.TLS{CertFile: "c", KeyFile: "k"} },
		"a negative tenant share":                 func(c *ServeConfig) { c.OutboxTenantCapacity = -1 },
		"a tenant share above the outbox":         func(c *ServeConfig) { c.OutboxCapacity, c.OutboxTenantCapacity = 10, 11 },
		"a tenant share above the default outbox": func(c *ServeConfig) { c.OutboxTenantCapacity = 100_001 },
	} {
		c := validServeConfig()
		change(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestAdminOutboxTenantShare covers audit F6: outbox_tenant_capacity bounds
// each tenant's undelivered administration events, as in every other
// role, so one tenant's changes cannot fill the outbox for the others.
func TestAdminOutboxTenantShare(t *testing.T) {
	pool := pgtest.Pool(t, catalog.Migrate)
	cfg := validServeConfig()
	cfg.OutboxCapacity, cfg.OutboxTenantCapacity = 10, 1
	ops := adminops.Ops{Store: cfg.store(pool), Now: time.Now}
	who := adminops.Who{Actor: "root", Via: "cli"}
	ctx := context.Background()
	if err := ops.PutIdentity(ctx, who, "t-acme", "lena", []string{"member"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := ops.PutIdentity(ctx, who, "t-acme", "carl", []string{"member"}, nil); !errors.Is(err, audit.ErrFull) {
		t.Fatalf("t-acme beyond its share: %v", err)
	}
	if err := ops.PutIdentity(ctx, who, "t-other", "erin", []string{"member"}, nil); err != nil {
		t.Fatalf("t-other within its share: %v", err)
	}
}
