package catalog

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/audit"
	"fga/internal/decision"
	"fga/internal/delegation"
	"fga/internal/gate"
	"fga/internal/identity"
	"fga/internal/pgtest"
	"fga/internal/policy"
	"fga/internal/registry"
)

var now = time.Unix(1_800_000_000, 0).UTC()

// testStore migrates a fresh schema in the database named by
// FGA_TEST_DATABASE_URL and loads a small fixture. Tests skip without it.
func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Pool(t, Migrate)
	ctx := context.Background()
	for _, stmt := range []string{
		`INSERT INTO identities VALUES ('t-acme','user-42',88,false,'{reviewer}','{"project_ids":["p1"]}'),
		                               ('t-acme','agent-7',12,false,'{agent}','{}'),
		                               ('t-other','user-42',1,false,'{admin}','{}')`,
		`INSERT INTO delegations VALUES ('t-acme','dlg-5','agent-7','user-42','tools-gw-1',
		   '[{"resource_type":"document.text_unit","actions":["read"]}]', '2027-01-15 09:00:00+00', NULL, 3, false)`,
		`INSERT INTO resources VALUES ('t-acme','u-1','document.text_unit','acme',7,17,2,'{"state":"LIVE"}')`,
		`INSERT INTO aliases VALUES ('t-acme','mcp','doc://reports/q3#personnel','u-1')`,
		`INSERT INTO capabilities VALUES ('t-acme','agent-7','document.text_unit','read')`,
		`INSERT INTO tenant_epochs VALUES ('t-acme', 5)`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	return New(pool, 3), pool
}

func TestIdentitiesAreTenantScoped(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	i, err := s.Identities().Get(ctx, "t-acme", "user-42")
	if err != nil || i.Revision != 88 || len(i.Roles) != 1 || i.Roles[0] != "reviewer" {
		t.Fatalf("identity = %+v, %v", i, err)
	}
	other, _ := s.Identities().Get(ctx, "t-other", "user-42")
	if other.Roles[0] != "admin" {
		t.Errorf("t-other's user-42 has roles %v; the two tenants' identities must not mix", other.Roles)
	}
	if _, err := s.Identities().Get(ctx, "t-acme", "nobody"); !errors.Is(err, identity.ErrUnknown) {
		t.Errorf("unknown identity: %v, want %v", err, identity.ErrUnknown)
	}
}

// TestCrossTenantReferenceIsRejected covers DAT-001: a delegation cannot name
// an actor from another tenant, because references include the tenant.
func TestCrossTenantReferenceIsRejected(t *testing.T) {
	_, pool := testStore(t)
	_, err := pool.Exec(context.Background(), `INSERT INTO delegations VALUES ('t-other','dlg-x','agent-7','user-42','gw',
	   '[]', '2027-01-15 08:00:00+00', NULL, 1, false)`)
	if err == nil {
		t.Fatal("a delegation referencing another tenant's actor was stored")
	}
}

func TestDelegationsAndResources(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	chain, err := delegation.Resolve(ctx, s.Delegations(), "t-acme", "dlg-5", now)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.Covers("document.text_unit", "read") || chain.Covers("document.text_unit", "use-in-model") {
		t.Errorf("grants were not read back exactly: %+v", chain.Leaf().Grants)
	}
	r := registry.NewResolver(s.Resources(), registry.R1Types())
	res, err := r.Resolve(ctx, "t-acme", registry.Alias{Namespace: "mcp", Name: "doc://reports/q3#personnel"})
	if err != nil || res.ID != "u-1" || res.Generation != 17 || res.Attributes["state"] != "LIVE" {
		t.Fatalf("resource = %+v, %v", res, err)
	}
	if _, err := r.Resolve(ctx, "t-other", registry.Alias{Namespace: "mcp", Name: "doc://reports/q3#personnel"}); !errors.Is(err, registry.ErrUnknownAlias) {
		t.Errorf("another tenant resolved the alias: %v", err)
	}
	if epoch, _ := s.RequiredEpoch(ctx, "t-acme"); epoch != 5 {
		t.Errorf("required epoch = %d, want 5", epoch)
	}
	if epoch, _ := s.RequiredEpoch(ctx, "t-none"); epoch != 0 {
		t.Errorf("required epoch of a tenant without a row = %d, want 0", epoch)
	}
}

// TestGateOverCatalog wires the gate to PostgreSQL: the principal and its
// roles come from the database.
func TestGateOverCatalog(t *testing.T) {
	s, _ := testStore(t)
	g, err := gate.New(gate.Deps{Recipients: gate.MemoryRecipients{}, Identities: s.Identities(), Delegations: s.Delegations(), Capabilities: s,
		Resources: registry.NewResolver(s.Resources(), registry.R1Types()), Epochs: s, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	b := decision.Batch{
		Envelope: decision.Envelope{Tenant: "t-acme", Adapter: "tools-gw-1", Actor: decision.Ref{ID: "agent-7", Revision: 12},
			Subject: decision.Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5"},
		Checks: []decision.Check{{ID: "c1", Action: "read", Resource: policy.Resource{Kind: "document.text_unit", ID: "u-1"}}},
	}
	adm, err := g.Admit(context.Background(), b)
	if p := adm.Principal; err != nil || p.ID != "user-42" || p.Roles[0] != "reviewer" {
		t.Fatalf("Admit = %+v, %v", adm, err)
	}
}

// TestConsumeOnceAcrossConnections covers V-121 with a shared database: of
// many concurrent consumers on separate connections, exactly one wins.
func TestConsumeOnceAcrossConnections(t *testing.T) {
	s, _ := testStore(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first, err := s.Consume(context.Background(), "d-1", now.Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			if first {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d consumers won, want 1", wins.Load())
	}
}

func TestOutbox(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	ev := func(id string) audit.Event {
		return audit.Event{ID: id, Kind: audit.KindDecision, Tenant: "t-acme", Actor: "agent-7", Outcome: "ALLOW", At: now,
			Checks: []audit.Check{{ID: "c1", Action: "read", ResourceType: "document.text_unit", ResourceID: "u-1", Effect: "ALLOW"}}}
	}
	for _, id := range []string{"e1", "e2", "e3", "e1"} { // the repeated e1 is a retry
		if err := s.Append(ctx, ev(id)); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
	}
	if err := s.Append(ctx, ev("e4")); !errors.Is(err, audit.ErrFull) {
		t.Fatalf("Append beyond capacity = %v, want %v", err, audit.ErrFull)
	}
	pending, err := s.Pending(ctx, 10)
	if err != nil || len(pending) != 3 || pending[0].ID != "e1" || pending[2].ID != "e3" || pending[0].Checks[0].ResourceID != "u-1" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	for range 2 {
		if err := s.MarkDelivered(ctx, []string{"e1", "unknown"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Append(ctx, ev("e4")); err != nil {
		t.Fatalf("Append after delivery: %v", err)
	}
	pending, _ = s.Pending(ctx, 10)
	if len(pending) != 3 || pending[0].ID != "e2" {
		t.Fatalf("pending after delivery = %+v", pending)
	}
}

func TestCapabilities(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if ok, err := s.Allows(ctx, "t-acme", "agent-7", "document.text_unit", "read"); !ok || err != nil {
		t.Errorf("registered capability = %v, %v", ok, err)
	}
	if ok, _ := s.Allows(ctx, "t-acme", "agent-7", "document.text_unit", "export-key"); ok {
		t.Error("unregistered capability allowed")
	}
}

// TestCoreMigrationsHaveNoExecutorTables: the executor's tables are created
// only by roles that enable the executor (feature executor).
func TestCoreMigrationsHaveNoExecutorTables(t *testing.T) {
	_, pool := testStore(t)
	for _, table := range []string{"tools", "invocations", "reservations", "budgets", "agent_keys", "destinations"} {
		var exists bool
		if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Errorf("core migrations created executor table %s", table)
		}
	}
}
