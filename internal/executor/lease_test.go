package executor_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"fga/internal/executor"
	"fga/internal/executortest"
	"fga/internal/invocation"
	"fga/internal/r1test"
	"fga/internal/tools"
	"fga/internal/toolstore"
)

// TestFenceRefusalReleasesLease is the regression test of audit finding
// F-EXE-2: a dispatch the fence refused kept the worker's lease, so a
// retry was refused as leased until the lease ran out. The lease is now
// given back with the refusal, and the retry dispatches once the
// refusal's cause is gone.
func TestFenceRefusalReleasesLease(t *testing.T) {
	f := deploy(t, plainInvoke, nil, http.StatusOK, 10_000)
	alice := f.Caller(t, "alice", "member")
	elsewhere := &executortest.Destination{Status: http.StatusOK}
	srv := httptest.NewServer(elsewhere)
	t.Cleanup(srv.Close)
	moved := false
	f.Svc = f.Service(t, afterDecider{r1test.Decider{Service: f.St.Decisions, Adapter: r1test.ToolsAdapter}, func() {
		if moved {
			return
		}
		moved = true
		// The transport changes apart from its resource, so the fence
		// refuses the dispatch (review v4 F03).
		if err := toolstore.New(f.St.Pool).PutDestination(ctx, r1test.Tenant, tools.Destination{ID: "bank", BaseURL: srv.URL,
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}); err != nil {
			t.Error(err)
		}
	}})
	if _, err := f.Svc.Invoke(ctx, alice, payment("l-1", 100)); !errors.Is(err, executor.ErrConflict) {
		t.Fatalf("a dispatch over a changed transport: %v", err)
	}
	if n := f.St.Count(`SELECT count(*) FROM invocations WHERE idempotency_key = 'l-1' AND state = 'PREPARED' AND lease_expires_at IS NULL`); n != 1 {
		t.Fatal("the refused dispatch kept its lease")
	}
	// Registered as its resource records it, the destination takes the
	// retried call at once.
	if err := executor.RegisterDestination(ctx, f.St.Pool, r1test.Tenant, tools.Destination{ID: "bank", BaseURL: srv.URL,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}, map[string]any{"approved": true}); err != nil {
		t.Fatal(err)
	}
	res, err := f.Svc.Invoke(ctx, alice, payment("l-1", 100))
	if err != nil || res.State != string(invocation.StateSucceeded) || elsewhere.Count() != 1 || f.Dest.Count() != 0 {
		t.Fatalf("the retry after the refusal: %+v %v, %d and %d calls", res, err, elsewhere.Count(), f.Dest.Count())
	}
}
