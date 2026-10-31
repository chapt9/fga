package invocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/approval"
	"fga/internal/pgtest"
	"fga/internal/reservation"
	"fga/internal/tools"
	"fga/internal/toolstore"
)

var start = time.Unix(1_800_000_000, 0).UTC()

type fixture struct {
	s     *Store
	pool  *pgxpool.Pool
	clock *time.Time
	inv   Invocation
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool := pgtest.Pool(t, toolstore.Migrate)
	pgtest.Invocations(t, pool) // identities, tool and budget only
	now := start
	f := &fixture{pool: pool, clock: &now}
	f.s = New(pool, func() time.Time { return *f.clock })
	inv, err := f.s.Create(context.Background(), Invocation{Tenant: "t-acme", IdempotencyKey: "idem-1", OperationDigest: "sha256:op",
		Tool: "expense.submit", ToolVersion: 1, Arguments: []byte(`{"vendor":"Rail Co"}`), Actor: "agent-7", Subject: "user-42", Delegation: "dlg-5"})
	if err != nil {
		t.Fatal(err)
	}
	f.inv = inv
	return f
}

func (f *fixture) reserve(t *testing.T, minor int64) {
	t.Helper()
	if _, err := reservation.New(f.pool).Reserve(context.Background(), "t-acme", "team-travel", f.inv.ID, tools.Money{Currency: "EUR", Minor: minor}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.MarkReserved(context.Background(), "t-acme", f.inv.ID); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) budget(t *testing.T) (reserved, spent int64) {
	t.Helper()
	_ = f.pool.QueryRow(context.Background(), `SELECT reserved_minor, spent_minor FROM budgets`).Scan(&reserved, &spent)
	return reserved, spent
}

// dispatch acquires the lease and moves the invocation to DISPATCHING.
func (f *fixture) dispatch(t *testing.T) int64 {
	t.Helper()
	inv, err := f.s.Acquire(context.Background(), "t-acme", f.inv.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.BeginDispatch(context.Background(), "t-acme", f.inv.ID, inv.FencingToken, ""); err != nil {
		t.Fatal(err)
	}
	return inv.FencingToken
}

func TestCreateIsIdempotentPerOperation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	again, err := f.s.Create(ctx, Invocation{Tenant: "t-acme", IdempotencyKey: "idem-1", OperationDigest: "sha256:op",
		Tool: "expense.submit", ToolVersion: 1, Arguments: []byte(`{}`), Actor: "agent-7", Subject: "user-42"})
	if err != nil || again.ID != f.inv.ID {
		t.Fatalf("retry = %+v, %v; want the first invocation", again, err)
	}
	for name, inv := range map[string]Invocation{
		"a changed operation (INV-004)": {OperationDigest: "sha256:changed", Actor: "agent-7", Subject: "user-42"},
		// The key never shows one principal's invocation to another.
		"another actor":   {OperationDigest: "sha256:op", Actor: "agent-8", Subject: "user-42"},
		"another subject": {OperationDigest: "sha256:op", Actor: "agent-7", Subject: "user-43"},
	} {
		inv.Tenant, inv.IdempotencyKey, inv.Tool, inv.ToolVersion, inv.Arguments = "t-acme", "idem-1", "expense.submit", 1, []byte(`{}`)
		if _, err := f.s.Create(ctx, inv); !errors.Is(err, ErrIdempotencyConflict) {
			t.Errorf("same key, %s: %v, want %v", name, err, ErrIdempotencyConflict)
		}
	}
}

// TestLeaseAndFencing covers INV-002: one owner at a time, and a worker
// whose lease was taken over cannot act.
func TestLeaseAndFencing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-b", time.Minute); !errors.Is(err, ErrLeased) {
		t.Fatalf("second worker while the lease is live: %v", err)
	}
	*f.clock = start.Add(2 * time.Minute)
	b, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-b", time.Minute)
	if err != nil || b.FencingToken <= a.FencingToken {
		t.Fatalf("takeover = %+v, %v", b, err)
	}
	if err := f.s.BeginDispatch(ctx, "t-acme", f.inv.ID, a.FencingToken, ""); !errors.Is(err, ErrFenced) {
		t.Fatalf("the replaced worker dispatching: %v, want %v", err, ErrFenced)
	}
	if err := f.s.BeginDispatch(ctx, "t-acme", f.inv.ID, b.FencingToken, ""); err != nil {
		t.Fatal(err)
	}
}

// TestDispatchConsumesTheApproval covers APR-003 and V-040: the approval is
// consumed with the move to DISPATCHING, so it cannot serve a second dispatch.
func TestDispatchConsumesTheApproval(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	approvals := approval.New(f.pool, func() time.Time { return *f.clock })
	a, _ := approvals.Request(ctx, approval.Approval{Tenant: "t-acme", Operation: f.inv.ID, OperationDigest: "sha256:op",
		RequestedBy: "user-42", Actor: "agent-7", ExpiresAt: start.Add(time.Hour)})
	_ = approvals.Decide(ctx, "t-acme", a.ID, "finance-1", true)

	inv, _ := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-a", time.Minute)
	if err := f.s.BeginDispatch(ctx, "t-acme", f.inv.ID, inv.FencingToken, a.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := approvals.Get(ctx, "t-acme", a.ID); got.State != approval.StateConsumed {
		t.Fatalf("approval state = %s, want CONSUMED", got.State)
	}

	// Another invocation of the same operation cannot reuse it.
	other, _ := f.s.Create(ctx, Invocation{Tenant: "t-acme", IdempotencyKey: "idem-2", OperationDigest: "sha256:op",
		Tool: "expense.submit", ToolVersion: 1, Arguments: []byte(`{}`), Actor: "agent-7", Subject: "user-42"})
	lease, _ := f.s.Acquire(ctx, "t-acme", other.ID, "worker-a", time.Minute)
	if err := f.s.BeginDispatch(ctx, "t-acme", other.ID, lease.FencingToken, a.ID); !errors.Is(err, approval.ErrNotUsable) {
		t.Fatalf("reusing a consumed approval: %v", err)
	}
	if got, _ := f.s.Get(ctx, "t-acme", other.ID); got.State != StatePrepared {
		t.Errorf("failed dispatch left state %s, want PREPARED", got.State)
	}
}

// TestOutcomesSettleTheReservation covers INV-007 and V-042.
func TestOutcomesSettleTheReservation(t *testing.T) {
	for _, tc := range []struct {
		outcome         State
		reserved, spent int64
	}{
		{StateSucceeded, 0, 500},
		{StateFailed, 0, 0},
		{StateUnknown, 500, 0}, // V-042: kept until resolution
	} {
		f := setup(t)
		f.reserve(t, 500)
		token := f.dispatch(t)
		if err := f.s.Complete(context.Background(), "t-acme", f.inv.ID, token, tc.outcome, "r-1"); err != nil {
			t.Fatal(err)
		}
		if reserved, spent := f.budget(t); reserved != tc.reserved || spent != tc.spent {
			t.Errorf("%s: budget reserved %d spent %d, want %d and %d", tc.outcome, reserved, spent, tc.reserved, tc.spent)
		}
	}
}

// TestNoRedispatch covers INV-003 and V-043: a worker that finds a stalled
// DISPATCHING invocation gets the lease but cannot dispatch again, and a
// finished invocation cannot be acquired at all.
func TestNoRedispatch(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.dispatch(t)
	*f.clock = start.Add(2 * time.Minute)
	stalled, _ := f.s.Stalled(ctx, 10)
	if len(stalled) != 1 || stalled[0].ID != f.inv.ID {
		t.Fatalf("stalled = %+v", stalled)
	}
	takeover, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-b", time.Minute)
	if err != nil || takeover.State != StateDispatching {
		t.Fatalf("takeover = %+v, %v", takeover, err)
	}
	if err := f.s.BeginDispatch(ctx, "t-acme", f.inv.ID, takeover.FencingToken, ""); !errors.Is(err, ErrState) {
		t.Fatalf("redispatch after takeover: %v, want %v", err, ErrState)
	}
	if err := f.s.Complete(ctx, "t-acme", f.inv.ID, takeover.FencingToken, StateUnknown, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-c", time.Minute); !errors.Is(err, ErrState) {
		t.Fatalf("acquiring an UNKNOWN invocation: %v, want %v", err, ErrState)
	}
}

// TestResolution covers INV-006, INV-009 and V-044 to V-046.
func TestResolution(t *testing.T) {
	ctx := context.Background()
	unknown := func(t *testing.T) *fixture {
		f := setup(t)
		f.reserve(t, 500)
		token := f.dispatch(t)
		_ = f.s.Complete(ctx, "t-acme", f.inv.ID, token, StateUnknown, "")
		return f
	}

	f := unknown(t)
	if err := f.s.Resolve(ctx, "t-acme", f.inv.ID, "user-42", StateFailed, "vendor says no charge"); !errors.Is(err, ErrSelfResolution) {
		t.Fatalf("requester resolving (V-045): %v", err)
	}
	if err := f.s.Resolve(ctx, "t-acme", f.inv.ID, "finance-1", StateFailed, ""); !errors.Is(err, ErrEvidence) {
		t.Fatalf("resolution without evidence: %v", err)
	}
	if err := f.s.Resolve(ctx, "t-acme", f.inv.ID, "finance-1", StateFailed, "vendor statement 2027-01-15 shows no charge"); err != nil {
		t.Fatal(err)
	}
	if reserved, spent := f.budget(t); reserved != 0 || spent != 0 {
		t.Errorf("verified failure (V-044): reserved %d spent %d, want both 0", reserved, spent)
	}

	f = unknown(t)
	if err := f.s.Resolve(ctx, "t-acme", f.inv.ID, "finance-1", StateAbandoned, "vendor unreachable"); err != nil {
		t.Fatal(err)
	}
	if reserved, spent := f.budget(t); reserved != 0 || spent != 500 {
		t.Errorf("abandoned (V-046): reserved %d spent %d, want 0 and 500 (charge kept)", reserved, spent)
	}
	if _, err := f.s.Acquire(ctx, "t-acme", f.inv.ID, "worker-a", time.Minute); !errors.Is(err, ErrState) {
		t.Errorf("abandoned invocation acquired for redispatch: %v", err)
	}
	if err := f.s.WriteOff(ctx, "t-acme", f.inv.ID, "agent-7", "accept"); !errors.Is(err, ErrSelfResolution) {
		t.Errorf("acting agent writing off: %v", err)
	}
	if err := f.s.WriteOff(ctx, "t-acme", f.inv.ID, "finance-1", "accepted risk, ticket FIN-12"); err != nil {
		t.Fatal(err)
	}
	if _, spent := f.budget(t); spent != 0 {
		t.Errorf("after write-off spent %d, want 0", spent)
	}
	got, _ := f.s.Get(ctx, "t-acme", f.inv.ID)
	if got.State != StateAbandoned || got.Resolution == nil || got.Resolution.WriteOff == "" {
		t.Errorf("after write-off: %+v", got)
	}
}
