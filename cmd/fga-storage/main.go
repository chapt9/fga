// Command fga-storage runs the storage role: the native object API over
// the content service (specification 2.5, CNT-001, CNT-009). It holds
// ciphertext, descriptors and catalog state only; it links no client
// decryption or key-unwrap code (MOD-004, allowed-imports.txt).
//
//	fga-storage -config storage.json
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/fence"
	"fga/internal/journal"
	"fga/internal/nativeapi"
	"fga/internal/roleconfig"
	"fga/internal/rpc"
)

// Config is the storage role's configuration (MOD-003).
type Config struct {
	roleconfig.Common
	BlobDir string `json:"blob_dir"`
	// Keys is the keys role's internal delivery endpoint (TB3).
	Keys roleconfig.Peer `json:"keys"`
	// TokenKeyFile holds the 32-byte base64 key that seals listing
	// continuation tokens.
	TokenKeyFile       string `json:"token_key_file"`
	MaxCiphertextBytes int64  `json:"max_ciphertext_bytes,omitempty"`
	OutboxCapacity     int    `json:"outbox_capacity"`
	// JournalDir is the security journal, shared with the keys role: the
	// storage role journals removed share grants (AVL-008).
	JournalDir string `json:"journal_dir"`
}

// Validate reports every configuration problem.
func (c Config) Validate() error {
	errs := c.Common.Validate()
	if c.BlobDir == "" || c.Keys.URL == "" || c.TokenKeyFile == "" || c.OutboxCapacity <= 0 || c.JournalDir == "" {
		errs = append(errs, errors.New("blob_dir, keys.url, token_key_file, outbox_capacity and journal_dir are required"))
	}
	if c.Profile == roleconfig.Production && (!strings.HasPrefix(c.Keys.URL, "https://") || c.Keys.CertFile == "") {
		errs = append(errs, errors.New("production calls the keys role over mutual TLS"))
	}
	return errors.Join(errs...)
}

func main() {
	path := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("fga-storage stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string) error {
	var cfg Config
	if err := roleconfig.Load(path, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
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
	blobs, err := blob.Open(cfg.BlobDir)
	if err != nil {
		return err
	}
	defer blobs.Close()
	tokens, err := cfg.Tokens()
	if err != nil {
		return err
	}
	verifier, err := cfg.Verifier(content.Audience)
	if err != nil {
		return err
	}
	decisionHTTP, err := cfg.Decision.Client()
	if err != nil {
		return err
	}
	keysHTTP, err := cfg.Keys.Client()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(cfg.TokenKeyFile)
	if err != nil {
		return err
	}
	tokenKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(tokenKey) != 32 {
		return fmt.Errorf("%s must hold a base64 32-byte key", cfg.TokenKeyFile)
	}
	limits := content.DefaultLimits
	if cfg.MaxCiphertextBytes > 0 {
		limits.MaxCiphertext = cfg.MaxCiphertextBytes
	}
	j, err := journal.Open(cfg.JournalDir, time.Now)
	if err != nil {
		return err
	}
	svc, err := content.New(content.Deps{Catalog: store, Blobs: blobs, Fence: fence.New(pool, time.Second, time.Now),
		Decider: rpc.DecisionClient{BaseURL: cfg.Decision.URL, HTTP: decisionHTTP}, Verifier: verifier,
		Keys: rpc.KeysClient{BaseURL: cfg.Keys.URL, HTTP: keysHTTP}, DataKeys: rpc.KeysClient{BaseURL: cfg.Keys.URL, HTTP: keysHTTP},
		Journal: j, TokenKey: tokenKey, Limits: limits, Now: time.Now})
	if err != nil {
		return err
	}
	ready := func() bool {
		pctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return pool.Ping(pctx) == nil
	}
	server, _, err := cfg.Server(nativeapi.Storage(svc, tokens, ready, cfg.Limiter()))
	if err != nil {
		return err
	}
	slog.Info("fga-storage listening", "addr", cfg.Listen, "profile", cfg.Profile)
	return cfg.Serve(ctx, server)
}
