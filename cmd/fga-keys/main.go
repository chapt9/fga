// Command fga-keys runs the keys role: the recipient-key registry and the
// store of opaque recipient envelopes (specification 2.6, KEY-002,
// RCP-002, TRU-005), and in server mode the tenants' key-encryption keys,
// which seal and release data keys under signed decisions (SSE-002,
// SSE-003). It cannot open an envelope and never decrypts a payload: it
// links no HPKE or payload-decryption code (MOD-004, allowed-imports.txt).
//
//	fga-keys -config keys.json
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/datakeys"
	"fga/internal/datakeysapi"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/journal"
	"fga/internal/kek"
	"fga/internal/keyfile"
	"fga/internal/keysapi"
	"fga/internal/kms"
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
	// OutboxTenantCapacity, if set, bounds each tenant's undelivered audit
	// events below outbox_capacity, so one tenant cannot fill the outbox
	// for every other (AUD-002).
	OutboxTenantCapacity int `json:"outbox_tenant_capacity,omitempty"`
	// KMS is the fga-kms role that holds the server-mode key-encryption
	// keys and seals and opens data keys for this role (D-13). KEKFile is
	// the development alternative: the ring read by this role itself,
	// protected with $FGA_KEK_PASSPHRASE or KEKPassphraseFile, which
	// production refuses (SSE-002). Without either, server mode is
	// unavailable.
	KMS               *roleconfig.Peer `json:"kms,omitempty"`
	KEKFile           string           `json:"kek_file,omitempty"`
	KEKPassphraseFile string           `json:"kek_passphrase_file,omitempty"`
}

// Validate reports every configuration problem.
func (c Config) Validate() error {
	errs := c.Common.Validate()
	if c.JournalDir == "" || c.ReceiptKeyFile == "" || c.ReceiptKeyID == "" || c.StorageAdapter == "" || c.OutboxCapacity <= 0 {
		errs = append(errs, errors.New("journal_dir, receipt_key_file, receipt_key_id, storage_adapter and outbox_capacity are required"))
	}
	if c.OutboxTenantCapacity < 0 || c.OutboxTenantCapacity > c.OutboxCapacity {
		errs = append(errs, errors.New("outbox_tenant_capacity must be in [0, outbox_capacity]"))
	}
	switch {
	case c.KEKFile != "" && c.KMS != nil:
		errs = append(errs, errors.New("kek_file and kms exclude each other"))
	case c.KEKFile != "" && c.Profile == "production":
		errs = append(errs, errors.New("kek_file is development key custody; production uses the fga-kms role (kms, D-13)"))
	case c.KMS != nil && (c.KMS.URL == "" || c.Profile == "production" && (!strings.HasPrefix(c.KMS.URL, "https://") || c.KMS.CertFile == "")):
		errs = append(errs, errors.New("kms needs a url; production calls the fga-kms role over mutual TLS"))
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
	tokens, err := cfg.Tokens(catalog.New(pool, cfg.OutboxCapacity).SignInKeyLookup(roleconfig.SignInLookupTimeout))
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
	svc, err := envelope.New(envelope.Deps{Catalog: catalog.New(pool, cfg.OutboxCapacity).LimitTenants(cfg.OutboxTenantCapacity), Fence: fence.New(pool, time.Second, time.Now),
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
	var more []func(*http.ServeMux)
	if cfg.KEKFile != "" || cfg.KMS != nil {
		var keks datakeys.Sealer
		if cfg.KMS != nil {
			client, err := cfg.KMS.Client()
			if err != nil {
				return err
			}
			keks = kms.Client{URL: cfg.KMS.URL, HTTP: client}
		} else if keks, err = kek.Load(cfg.KEKFile, func() ([]byte, error) { return keyfile.Passphrase("FGA_KEK_PASSPHRASE", cfg.KEKPassphraseFile) }); err != nil {
			return err
		}
		dk, err := datakeys.New(datakeys.Deps{Catalog: catalog.New(pool, cfg.OutboxCapacity).LimitTenants(cfg.OutboxTenantCapacity), Fence: fence.New(pool, time.Second, time.Now),
			Verifier: verifier, KEKs: keks, Now: time.Now})
		if err != nil {
			return err
		}
		more = append(more, datakeysapi.Register(dk, adapterOf, cfg.StorageAdapter))
	}
	server.Handler = keysapi.Keys(svc, tokens, adapterOf, cfg.StorageAdapter, ready, cfg.Limiter(), more...)
	slog.Info("fga-keys listening", "addr", cfg.Listen, "profile", cfg.Profile)
	return cfg.Serve(ctx, server)
}
