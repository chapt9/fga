package approval

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/opplan"
	"fga/internal/pgtest"
)

var now = time.Unix(1_800_000_000, 0).UTC()

func setup(t *testing.T) (*Store, *pgxpool.Pool, Approval) {
	t.Helper()
	pool := pgtest.Pool(t, catalog.Migrate)
	s := New(pool, func() time.Time { return now })
	a, err := s.Request(context.Background(), Approval{Tenant: "t-acme", Operation: "op-1", OperationDigest: "sha256:op-1",
		Summary: opplan.Summary{Operation: "storage.object.delete-version", OperationDigest: "sha256:op-1", Action: "delete-version",
			Targets: []opplan.Target{{Role: "object", Type: "storage.object", ID: "o-1", Version: "v-1"}}},
		RequestedBy: "user-42", Actor: "agent-7", ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return s, pool, a
}

func TestDecide(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		approver string
		clock    time.Time
		want     error
	}{
		"requester cannot approve":    {"user-42", now, ErrSelfApproval},
		"acting agent cannot approve": {"agent-7", now, ErrSelfApproval},
		"expired":                     {"finance-1", now.Add(2 * time.Hour), ErrExpired},
		"an independent approver may": {"finance-1", now, nil},
	} {
		s, _, a := setup(t)
		s.now = func() time.Time { return tc.clock }
		if err := s.Decide(ctx, "t-acme", a.ID, tc.approver, true); !errors.Is(err, tc.want) {
			t.Errorf("%s: Decide = %v, want %v", name, err, tc.want)
		}
	}

	s, _, a := setup(t)
	if err := s.Decide(ctx, "t-acme", a.ID, "finance-1", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(ctx, "t-acme", a.ID, "finance-1", true); !errors.Is(err, ErrNotPending) {
		t.Errorf("deciding twice: %v, want %v", err, ErrNotPending)
	}
	if ok, _ := s.Usable(ctx, "t-acme", a.ID, a.OperationDigest); ok {
		t.Error("a rejected approval is usable")
	}
}

// TestApprovalIsBoundToTheOperation covers V-030: an approval for one
// digest does not cover a changed operation.
func TestApprovalIsBoundToTheOperation(t *testing.T) {
	s, _, a := setup(t)
	ctx := context.Background()
	_ = s.Decide(ctx, "t-acme", a.ID, "finance-1", true)
	if ok, _ := s.Usable(ctx, "t-acme", a.ID, a.OperationDigest); !ok {
		t.Fatal("approved approval is not usable for its own operation")
	}
	if ok, _ := s.Usable(ctx, "t-acme", a.ID, "sha256:changed-amount"); ok {
		t.Fatal("approval is usable for a changed operation")
	}
}

// TestConsumedOnce covers V-040: of concurrent dispatch transactions, one
// consumes the approval.
func TestConsumedOnce(t *testing.T) {
	s, pool, a := setup(t)
	ctx := context.Background()
	_ = s.Decide(ctx, "t-acme", a.ID, "finance-1", true)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if err := ConsumeTx(ctx, tx, "t-acme", a.ID, a.OperationDigest, now); err == nil && tx.Commit(ctx) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d transactions consumed the approval, want 1", wins.Load())
	}
	if got, _ := s.Get(ctx, "t-acme", a.ID); got.State != StateConsumed {
		t.Errorf("state = %s, want %s", got.State, StateConsumed)
	}
}

// TestNoToolDependency covers MOD-004 and the decoupling of approvals from
// tool execution: the approval package links no executor package.
func TestNoToolDependency(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, executor := range []string{"fga/internal/tools", "fga/internal/toolstore", "fga/internal/invocation", "fga/internal/reservation"} {
			if dep == executor || strings.HasPrefix(dep, executor+"/") {
				t.Errorf("approval imports %s", dep)
			}
		}
	}
}
