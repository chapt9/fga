// Command fga-tools runs the tools role (R2, optional feature executor,
// docs/design/executor.md): it carries out calls of registered, reviewed
// tools on external destinations for authorized users, under decisions of
// the decision role, with approvals and budget reservations, and records
// every invocation durably (AGT-001 to AGT-006, INV-001 to INV-009). It
// links no payload, key-encryption, client decryption or MCP code
// (MOD-004, allowed-imports.txt).
//
//	fga-tools -config tools.json                       serve
//	fga-tools -config tools.json tool add -tenant T -file tool.json
//	fga-tools -config tools.json tool review -tenant T -id ID
//	fga-tools -config tools.json destination add -tenant T -id D -url URL -cidrs 10.0.0.0/8 [-credential-file F] [-reconcile-path P] [-approved]
//	fga-tools -config tools.json budget set -tenant T -id B -currency EUR -limit MINOR
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/executor"
	"fga/internal/fence"
	"fga/internal/guard"
	"fga/internal/httpapi"
	"fga/internal/invocation"
	"fga/internal/registry"
	"fga/internal/reservation"
	"fga/internal/roleconfig"
	"fga/internal/rpc"
	"fga/internal/strictjson"
	"fga/internal/tools"
	"fga/internal/tools/connector"
	"fga/internal/toolstore"
)

// Config is the tools role's configuration (MOD-003).
type Config struct {
	roleconfig.Common
	OutboxCapacity int `json:"outbox_capacity"`
	// OutboxTenantCapacity, if set, bounds each tenant's undelivered audit
	// events below outbox_capacity, so one tenant cannot fill the outbox
	// for every other (AUD-002).
	OutboxTenantCapacity int `json:"outbox_tenant_capacity,omitempty"`
	// Worker names this replica as a lease owner; it defaults to the host
	// name. Lease bounds a dispatch before another worker may reconcile
	// it, and ConnectorTimeout one destination call (Go durations).
	Worker           string `json:"worker,omitempty"`
	Lease            string `json:"lease,omitempty"`
	ConnectorTimeout string `json:"connector_timeout,omitempty"`
	// ReconcileEvery is how often open outcomes are reconciled (default
	// 30s).
	ReconcileEvery string `json:"reconcile_every,omitempty"`
	// MCPAdapters are the MCP role's workload identities: their calls carry
	// the user's MCP decision instead of a token (TB3).
	MCPAdapters []string `json:"mcp_adapters,omitempty"`
}

// Validate reports every configuration problem.
func (c Config) Validate() error {
	errs := c.Common.Validate()
	if c.OutboxCapacity <= 0 {
		errs = append(errs, errors.New("outbox_capacity is required"))
	}
	if c.OutboxTenantCapacity < 0 || c.OutboxTenantCapacity > c.OutboxCapacity {
		errs = append(errs, errors.New("outbox_tenant_capacity must be in [0, outbox_capacity]"))
	}
	for name, v := range map[string]string{"lease": c.Lease, "connector_timeout": c.ConnectorTimeout, "reconcile_every": c.ReconcileEvery} {
		if v != "" {
			if d, err := time.ParseDuration(v); err != nil || d <= 0 {
				errs = append(errs, fmt.Errorf("%s must be a positive duration", name))
			}
		}
	}
	// A worker sends only within its lease; a lease that cannot hold one
	// whole destination call would cut every slow call short.
	if duration(c.Lease, time.Minute) < duration(c.ConnectorTimeout, 30*time.Second)+10*time.Second {
		errs = append(errs, errors.New("lease must exceed connector_timeout by at least 10s"))
	}
	return errors.Join(errs...)
}

func duration(v string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return def
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("fga-tools stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("fga-tools", flag.ContinueOnError)
	path := global.String("config", "", "path to the configuration file")
	if err := global.Parse(args); err != nil {
		return err
	}
	var cfg Config
	if err := roleconfig.Load(*path, &cfg); err != nil {
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
	if err := toolstore.Migrate(ctx, pool); err != nil {
		return err
	}
	store := catalog.New(pool, cfg.OutboxCapacity).LimitTenants(cfg.OutboxTenantCapacity)
	if rest := global.Args(); len(rest) > 0 {
		return admin(ctx, pool, store, toolstore.New(pool), rest)
	}
	return serve(ctx, cfg, pool, store)
}

func serve(ctx context.Context, cfg Config, pool *pgxpool.Pool, store *catalog.Store) error {
	tokens, err := cfg.Tokens(store.SignInKeyLookup(roleconfig.SignInLookupTimeout))
	if err != nil {
		return err
	}
	verifier, err := cfg.Verifier(executor.Audience)
	if err != nil {
		return err
	}
	decisionHTTP, err := cfg.Decision.Client()
	if err != nil {
		return err
	}
	worker := cfg.Worker
	if worker == "" {
		worker, _ = os.Hostname()
	}
	svc, err := executor.New(executor.Deps{Catalog: store, Tools: toolstore.New(pool), Invocations: invocation.New(pool, time.Now),
		Reservations: reservation.New(pool), Decider: rpc.DecisionClient{BaseURL: cfg.Decision.URL, HTTP: decisionHTTP}, Verifier: verifier,
		Fence: fence.New(pool, time.Second, time.Now), Connector: connector.New(duration(cfg.ConnectorTimeout, 30*time.Second)),
		Worker: worker, Lease: duration(cfg.Lease, time.Minute), Now: time.Now})
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
	var gw *httpapi.Gateway
	if len(cfg.MCPAdapters) > 0 {
		gw = &httpapi.Gateway{AdapterOf: adapterOf, Adapters: map[string]bool{}, Operation: registry.OpMCPInvoke, Verifier: verifier}
		for _, a := range cfg.MCPAdapters {
			gw.Adapters[a] = true
		}
	}
	server.Handler = executor.Handler(svc, tokens, ready, cfg.Limiter(), gw)
	// Open outcomes are reconciled in the background; a panic in a pass is
	// contained and the next pass runs (INV-003, INV-006).
	every := duration(cfg.ReconcileEvery, 30*time.Second)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				func() {
					defer guard.Recover(nil, "reconcile", nil)
					if n, err := svc.Reconcile(ctx, 100); err != nil {
						slog.Error("fga-tools: reconcile", "error", err)
					} else if n > 0 {
						slog.Info("fga-tools: reconciled", "invocations", n)
					}
				}()
			}
		}
	}()
	slog.Info("fga-tools listening", "addr", cfg.Listen, "profile", cfg.Profile, "worker", worker)
	return cfg.Serve(ctx, server)
}

// admin registers tools, destinations and budgets: the out-of-band
// administration of the tool registry (AGT-001). Only a reviewed tool's
// operation is recorded for the decision role.
func admin(ctx context.Context, pool *pgxpool.Pool, store *catalog.Store, ts *toolstore.Store, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: tool add|tool review|destination add|budget set [flags]")
	}
	cmd := args[0] + " " + args[1]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant")
	file := fs.String("file", "", "tool add: the tool record (JSON)")
	id := fs.String("id", "", "tool, destination or budget ID")
	baseURL := fs.String("url", "", "destination add: base URL")
	cidrs := fs.String("cidrs", "", "destination add: allowed address ranges, comma-separated")
	credential := fs.String("credential-file", "", "destination add: file holding the destination's credential")
	reconcile := fs.String("reconcile-path", "", "destination add: path that reports an idempotency key's outcome, with {key}")
	approved := fs.Bool("approved", false, "destination add: mark the destination approved (policy sees resource.attributes.approved)")
	currency := fs.String("currency", "", "budget set: currency")
	limit := fs.Int64("limit", 0, "budget set: limit in minor units")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New(cmd + ": -tenant is required")
	}
	switch cmd {
	case "tool add":
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var t tools.Tool
		if err := strictjson.Decode(raw, &t); err != nil {
			return fmt.Errorf("%s: %w", *file, err)
		}
		if err := t.Validate(registry.CoreTypes()); err != nil {
			return err
		}
		if err := ts.PutTool(ctx, *tenant, t, false); err != nil {
			return err
		}
		fmt.Printf("tool %s version %d stored, schema digest %s; it is unusable until reviewed\n", t.ID, t.Version, t.SchemaDigest())
		return nil
	case "tool review":
		t, err := executor.ReviewTool(ctx, pool, *tenant, *id)
		if err != nil {
			return err
		}
		fmt.Printf("tool %s version %d reviewed and registered (%s)\n", t.ID, t.Version, t.SchemaDigest())
		return nil
	case "destination add":
		d := tools.Destination{ID: *id, BaseURL: *baseURL, CredentialFile: *credential, ReconcilePath: *reconcile}
		for _, c := range strings.Split(*cidrs, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return fmt.Errorf("destination add: -cidrs: %w", err)
			}
			d.AllowedCIDRs = append(d.AllowedCIDRs, p)
		}
		if *id == "" || *baseURL == "" {
			return errors.New("destination add: -id and -url are required")
		}
		if err := executor.RegisterDestination(ctx, pool, *tenant, d, map[string]any{"approved": *approved}); err != nil {
			return err
		}
		fmt.Printf("destination %s registered\n", *id)
		return nil
	case "budget set":
		if *id == "" || *currency == "" || *limit < 0 {
			return errors.New("budget set: -id, -currency and a limit of at least 0 are required")
		}
		if err := ts.PutBudget(ctx, *tenant, *id, tools.Money{Currency: *currency, Minor: *limit}); err != nil {
			return err
		}
		fmt.Printf("budget %s: %d %s\n", *id, *limit, *currency)
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}
