package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/adminapi"
	"fga/internal/adminops"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/roleconfig"
)

// ServeConfig configures fga-admin serve, the admin API
// (docs/design/admin-api.md). It runs where the security journal is.
type ServeConfig struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Listen  string `json:"listen"`
	// TLS is the server certificate and the CA of consoles' client
	// certificates.
	TLS *roleconfig.TLS `json:"tls,omitempty"`
	// Consoles are the client identities (certificate URI SAN, else common
	// name) that may call. Without TLS, in development on a loopback
	// address, every caller is DevConsole, which must be listed.
	Consoles    []string `json:"consoles"`
	DevConsole  string   `json:"dev_console_id,omitempty"`
	DatabaseURL string   `json:"database_url"`
	JournalDir  string   `json:"journal_dir"`
	// TokenIssuer verifies administrators' tokens, for Audience.
	TokenIssuer roleconfig.TokenIssuer `json:"token_issuer"`
	Audience    string                 `json:"audience"`
	// Admins lists the administrators' token subjects per tenant. Only
	// this file names administrators (ADM-002).
	Admins map[string][]string `json:"admins"`
	// BundleDir is the signed policy bundle shown to administrators, and
	// PublisherKeys the trusted publishers' public keys (base64 Ed25519).
	BundleDir      string            `json:"bundle_dir"`
	PublisherKeys  map[string]string `json:"publisher_keys"`
	OutboxCapacity int               `json:"outbox_capacity,omitempty"`
	// OutboxTenantCapacity, if set, bounds each tenant's undelivered audit
	// events below the outbox capacity, as in every other role, so one
	// tenant's administration cannot fill the outbox for every other
	// (AUD-002, audit F6).
	OutboxTenantCapacity int `json:"outbox_tenant_capacity,omitempty"`
}

// outboxCapacity is outbox_capacity, 100,000 events when not given.
func (c ServeConfig) outboxCapacity() int {
	if c.OutboxCapacity == 0 {
		return 100_000
	}
	return c.OutboxCapacity
}

// store is the catalog the admin API changes, with the outbox bounds.
func (c ServeConfig) store(pool *pgxpool.Pool) *catalog.Store {
	return catalog.New(pool, c.outboxCapacity()).LimitTenants(c.OutboxTenantCapacity)
}

// Validate reports every configuration problem.
func (c ServeConfig) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		fail("version must be 1")
	}
	switch c.Profile {
	case roleconfig.Production:
		if c.TLS == nil || c.DevConsole != "" {
			fail("production requires tls and no dev_console_id")
		}
	case roleconfig.Development:
		if c.TLS == nil && (c.DevConsole == "" || !roleconfig.Loopback(c.Listen)) {
			fail("development without tls needs dev_console_id and a loopback listen address")
		}
	default:
		fail("profile must be %q or %q", roleconfig.Production, roleconfig.Development)
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "") {
		fail("tls needs cert_file, key_file and client_ca_file")
	}
	if len(c.Consoles) == 0 {
		fail("consoles lists the client identities that may call")
	}
	if c.DevConsole != "" && !slices.Contains(c.Consoles, c.DevConsole) {
		fail("dev_console_id must be one of consoles")
	}
	if c.Listen == "" || c.DatabaseURL == "" || c.JournalDir == "" || c.Audience == "" {
		fail("listen, database_url, journal_dir and audience are required")
	}
	if len(c.Admins) == 0 {
		fail("admins names at least one administrator")
	}
	for tenant, subjects := range c.Admins {
		if tenant == "" || len(subjects) == 0 || slices.Contains(subjects, "") {
			fail("admins maps a tenant to administrators' token subjects")
		}
	}
	if c.BundleDir == "" || len(c.PublisherKeys) == 0 {
		fail("bundle_dir and publisher_keys are required")
	}
	for id, b64 := range c.PublisherKeys {
		if _, err := roleconfig.PublicKey(b64); err != nil {
			fail("publisher key %q: %v", id, err)
		}
	}
	if err := c.TokenIssuer.Validate(c.Profile == roleconfig.Production); err != nil {
		fail("%v", err)
	}
	if c.OutboxCapacity < 0 {
		fail("outbox_capacity is positive when given")
	}
	if c.OutboxTenantCapacity < 0 || c.OutboxTenantCapacity > c.outboxCapacity() {
		fail("outbox_tenant_capacity must be in [0, outbox_capacity]")
	}
	return errors.Join(errs...)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "", "path to the admin API configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var cfg ServeConfig
	if err := roleconfig.Load(*path, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	publishers := map[string]ed25519.PublicKey{}
	for id, b64 := range cfg.PublisherKeys {
		publishers[id], _ = roleconfig.PublicKey(b64) // validated
	}
	tokens, err := cfg.TokenIssuer.Verifier(time.Now)
	if err != nil {
		return err
	}
	// The journal must exist: it is created once by journal init, never
	// implicitly.
	j, err := journal.Open(cfg.JournalDir, time.Now)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := catalog.Migrate(ctx, pool); err != nil {
		return err
	}
	common := roleconfig.Common{Profile: cfg.Profile, Listen: cfg.Listen, TLS: cfg.TLS, DevAdapter: cfg.DevConsole}
	server, consoleOf, err := common.Server(nil)
	if err != nil {
		return err
	}
	server.Handler = adminapi.Handler(adminapi.Config{
		Ops:    adminops.Ops{Store: cfg.store(pool), Journal: func() (*journal.Journal, error) { return j, nil }, Now: time.Now},
		Tokens: tokens, Audience: cfg.Audience, Admins: cfg.Admins, Consoles: cfg.Consoles, ConsoleOf: consoleOf,
		Policy: func() (adminapi.Policy, error) { return adminapi.LoadPolicy(cfg.BundleDir, publishers) },
		Logger: slog.Default(),
	})
	slog.Info("fga-admin serving the admin API", "addr", cfg.Listen, "profile", cfg.Profile)
	return common.Serve(ctx, server)
}
