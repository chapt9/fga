// Command fga-decision runs the decision role: the only policy authority.
// It has its own entrypoint so that its import graph stays on the allowlist
// in allowed-imports.txt (MOD-004).
//
//	fga-decision -config decision.json
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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/approval"
	"fga/internal/authn"
	"fga/internal/catalog"
	"fga/internal/decision"
	"fga/internal/decisionsvc"
	"fga/internal/gate"
	"fga/internal/guard"
	"fga/internal/registry"
	"fga/internal/release"
	"fga/internal/signing"
)

func main() {
	path := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("fga-decision stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string) error {
	cfg, err := loadConfig(path)
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
	store := catalog.New(pool, cfg.OutboxCapacity)

	svc, err := wire(ctx, cfg, store)
	if err != nil {
		return err
	}
	server, adapterOf, err := httpServer(cfg)
	if err != nil {
		return err
	}
	// A panic in a request is answered 500 and logged; the role goes on
	// serving (internal/guard).
	server.Handler = guard.Handler(nil, svc.Handler(adapterOf))

	errc := make(chan error, 1)
	go func() {
		slog.Info("fga-decision listening", "addr", cfg.Listen, "profile", cfg.Profile)
		if cfg.TLS != nil {
			errc <- server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
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

// wire builds the decision service over the catalog and activates the
// configured bundle. Startup fails if the bundle does not activate.
func wire(ctx context.Context, cfg Config, store *catalog.Store) (*decisionsvc.Service, error) {
	publishers := map[string]ed25519.PublicKey{}
	for id, b64 := range cfg.PublisherKeys {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("publisher key %q is not a base64 Ed25519 public key", id)
		}
		publishers[id] = key
	}
	types := registry.CoreTypes()
	releases := release.NewManager(publishers, release.CoreEnvironment(), store, time.Now)
	bundle, _, err := release.LoadBundle(cfg.BundleDir)
	if err != nil {
		return nil, err
	}
	if err := releases.Activate(ctx, bundle); err != nil {
		return nil, err
	}
	// Enforcing roles read the active label order from the catalog to tell
	// a raise from a lowering; decisions bind its generation (D-06).
	if err := store.SetLabelOrder(ctx, bundle.Info.LabelGeneration, bundle.Info.LabelOrder); err != nil {
		return nil, err
	}

	resolver := registry.NewResolver(store.Resources(), types)
	g, err := gate.New(gate.Deps{Identities: store.Identities(), Delegations: store.Delegations(), Capabilities: store,
		Resources: resolver, Epochs: store, Recipients: store, Now: time.Now})
	if err != nil {
		return nil, err
	}
	decider, err := decision.NewDecider(g, releases, time.Now)
	if err != nil {
		return nil, err
	}
	signer, err := loadSigner(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := tokenVerifier(cfg)
	if err != nil {
		return nil, err
	}
	maxAge, _ := time.ParseDuration(cfg.DecisionMaxAge) // validated by Config.Validate
	// The role checks its own decisions when a gateway's decision comes
	// back as a user's evidence (TB3).
	self := signing.NewVerifier("", func() map[string]signing.Key {
		return map[string]signing.Key{cfg.SigningKeyID: {Public: signer.Public(), NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}}
	}, nil, time.Now)
	return decisionsvc.New(decisionsvc.Deps{Decider: decider, Gate: g, Releases: releases, Resolver: resolver, Types: types,
		Authn: tokens, AdapterAudiences: cfg.AdapterAudiences, PublicAudience: cfg.PublicAudience, Gateways: cfg.Gateways, SelfVerifier: self,
		Operations: registry.CoreOperations(types), Authority: store, Approvals: approval.New(store.Pool(), time.Now),
		Signer: signer, Outbox: store, Audiences: cfg.Audiences, MaxAge: maxAge, Limits: decisionsvc.DefaultLimits, Now: time.Now})
}

// tokenVerifier returns the configured first-hop token verifier, or nil.
func tokenVerifier(cfg Config) (decisionsvc.TokenVerifier, error) {
	if cfg.TokenIssuer == nil {
		return nil, nil
	}
	keys := map[string]ed25519.PublicKey{}
	for id, b64 := range cfg.TokenIssuer.Keys {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("token issuer key %q is not a base64 Ed25519 public key", id)
		}
		keys[id] = key
	}
	return authn.NewVerifier(cfg.TokenIssuer.Issuer, keys, time.Now), nil
}

func loadSigner(cfg Config) (*signing.Signer, error) {
	raw, err := os.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing_key_file must hold a base64 Ed25519 private key")
	}
	return signing.NewSigner(cfg.SigningKeyID, key)
}

// httpServer returns the server and how it identifies the calling adapter:
// the verified client certificate with TLS, otherwise the single configured
// development adapter on a loopback address.
func httpServer(cfg Config) (*http.Server, decisionsvc.AdapterOf, error) {
	server := &http.Server{Addr: cfg.Listen, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	if cfg.TLS == nil {
		dev := cfg.DevAdapterID
		return server, func(*http.Request) (string, error) { return dev, nil }, nil
	}
	caPEM, err := os.ReadFile(cfg.TLS.ClientCAFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("client_ca_file holds no certificates")
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	return server, decisionsvc.AdapterFromClientCert, nil
}
