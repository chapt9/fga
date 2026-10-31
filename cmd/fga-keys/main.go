// Command fga-keys runs the keys role: the recipient-key registry and the
// store of opaque recipient envelopes (specification 2.5, KEY-002,
// RCP-002, TRU-005). It cannot open an envelope: it links no HPKE or
// payload-decryption code (MOD-004, allowed-imports.txt).
//
//	fga-keys -config keys.json
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/journal"
	"fga/internal/keysapi"
	"fga/internal/roleconfig"
	"fga/internal/rpc"
)

// Config is the keys role's configuration (MOD-003).
type Config struct {
	roleconfig.Common
	JournalDir string `json:"journal_dir"`
	// ReceiptKeyFile holds the base64 Ed25519 key that signs delivery
	// receipts; it is used for nothing else (RCP-001).
	ReceiptKeyFile string `json:"receipt_key_file"`
	ReceiptKeyID   string `json:"receipt_key_id"`
	// StorageAdapter is the workload allowed to call internal delivery.
	StorageAdapter string `json:"storage_adapter"`
	OutboxCapacity int    `json:"outbox_capacity"`
}

// Validate reports every configuration problem.
func (c Config) Validate() error {
	errs := c.Common.Validate()
	if c.JournalDir == "" || c.ReceiptKeyFile == "" || c.ReceiptKeyID == "" || c.StorageAdapter == "" || c.OutboxCapacity <= 0 {
		errs = append(errs, errors.New("journal_dir, receipt_key_file, receipt_key_id, storage_adapter and outbox_capacity are required"))
	}
	return errors.Join(errs...)
}

func main() {
	path := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("fga-keys stopped", "error", err)
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
	tokens, err := cfg.Tokens()
	if err != nil {
		return err
	}
	verifier, err := cfg.Verifier(enforce.KeysAudience)
	if err != nil {
		return err
	}
	decisionHTTP, err := cfg.Decision.Client()
	if err != nil {
		return err
	}
	receiptKey, err := roleconfig.PrivateKeyFile(cfg.ReceiptKeyFile)
	if err != nil {
		return err
	}
	j, err := journal.Open(cfg.JournalDir, time.Now)
	if err != nil {
		return err
	}
	svc, err := envelope.New(envelope.Deps{Catalog: catalog.New(pool, cfg.OutboxCapacity), Fence: fence.New(pool, time.Second, time.Now),
		Decider: rpc.DecisionClient{BaseURL: cfg.Decision.URL, HTTP: decisionHTTP}, Verifier: verifier,
		ReceiptKeyID: cfg.ReceiptKeyID, ReceiptKey: receiptKey, Journal: j, Now: time.Now})
	if err != nil {
		return err
	}
	ready := func() bool {
		pctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return pool.Ping(pctx) == nil
	}
	server, adapterOf, err := cfg.Server(nil)
	if err != nil {
		return err
	}
	server.Handler = keysapi.Keys(svc, tokens, adapterOf, cfg.StorageAdapter, ready)
	slog.Info("fga-keys listening", "addr", cfg.Listen, "profile", cfg.Profile)
	return cfg.Serve(ctx, server)
}
