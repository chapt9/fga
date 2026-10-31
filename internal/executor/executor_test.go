package executor_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/decisionsvc"
	"fga/internal/delegation"
	"fga/internal/enforce"
	"fga/internal/executor"
	"fga/internal/executortest"
	"fga/internal/invocation"
	"fga/internal/r1test"
	"fga/internal/release"
	"fga/internal/signing"
	"fga/internal/tools"
	"fga/internal/toolstore"
)

var ctx = context.Background()

type fixture = executortest.Fixture

const plainInvoke = executortest.PlainInvoke

var pay = executortest.Pay

// deploy installs the tools role's fixture: pay to bank answering status,
// a budget of limit cents, members invoking by invokeRule.
func deploy(t *testing.T, invokeRule string, mapping *release.ObligationMapping, status int, limit int64) *fixture {
	t.Helper()
	return executortest.Deploy(t, executortest.Options{InvokeRule: invokeRule, Mapping: mapping, Status: status, Limit: limit})
}

var payment = executortest.Payment

// TestInvoke covers AGT-003 end to end: a member's call of a registered,
// reviewed tool is decided for the tool's operation, dispatched once to
// the registered destination with the destination's own credential and
// the invocation as idempotency key, and recorded SUCCEEDED; a retry with
// the same key returns it without a second dispatch, the same key with
// other arguments or for another actor is a conflict (INV-004); an
// unknown, unreviewed or other-version tool, an argument outside the
// schema, and a user without the rights answer alike (default deny,
// V-120: nothing registers a tool here).
func TestInvoke(t *testing.T) {
	f := deploy(t, plainInvoke, nil, http.StatusCreated, 100_000)
	alice := f.Caller(t, "alice", "member")
	res, err := f.Svc.Invoke(ctx, alice, payment("k-1", 1200))
	if err != nil || res.State != string(invocation.StateSucceeded) || res.Receipt == "" {
		t.Fatalf("invoke: %+v %v", res, err)
	}
	if f.Dest.Count() != 1 || f.Dest.Calls[0].Key != res.Invocation || f.Dest.Calls[0].Auth != "Bearer bank-secret" ||
		!strings.Contains(string(f.Dest.Calls[0].Body), `"minor":1200`) {
		t.Fatalf("the destination got %+v", f.Dest.Calls)
	}
	again, err := f.Svc.Invoke(ctx, alice, payment("k-1", 1200))
	if err != nil || again.Invocation != res.Invocation || f.Dest.Count() != 1 {
		t.Fatalf("a retry: %+v %v, %d calls", again, err, f.Dest.Count())
	}
	if _, err := f.Svc.Invoke(ctx, alice, payment("k-1", 1300)); !errors.Is(err, executor.ErrConflict) {
		t.Fatalf("the key with other arguments: %v", err)
	}
	bob := f.Caller(t, "bob", "member")
	if _, err := f.Svc.Invoke(ctx, bob, payment("k-1", 1200)); !errors.Is(err, executor.ErrConflict) {
		t.Fatalf("another actor with the key: %v", err)
	}
	if got, err := f.Svc.Get(ctx, bob, res.Invocation); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("another member reads the invocation: %+v %v", got, err)
	}
	if got, err := f.Svc.Get(ctx, alice, res.Invocation); err != nil || got.State != res.State {
		t.Fatalf("the actor reads it: %+v %v", got, err)
	}

	for name, r := range map[string]executor.Request{
		"an unknown tool":   {Tool: "wire", Version: 1, IdempotencyKey: "x1", Args: json.RawMessage(`{}`)},
		"another version":   {Tool: "pay", Version: 2, IdempotencyKey: "x2", Args: payment("x2", 1).Args},
		"an extra argument": {Tool: "pay", Version: 1, IdempotencyKey: "x3", Args: json.RawMessage(`{"amount":{"currency":"EUR","minor":1},"account":"acct-1","to":"x"}`)},
	} {
		if _, err := f.Svc.Invoke(ctx, alice, r); err == nil {
			t.Errorf("%s was dispatched", name)
		}
	}
	guest := f.Caller(t, "guest", "guest")
	if _, err := f.Svc.Invoke(ctx, guest, payment("shared", 100)); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("a user without the rights: %v", err)
	}
	// A refused call leaves nothing behind, and takes no key from another
	// (review v4 F07).
	if res, err := f.Svc.Invoke(ctx, alice, payment("shared", 100)); err != nil || res.State != string(invocation.StateSucceeded) {
		t.Fatalf("alice after the guest used her key: %+v %v", res, err)
	}
	if n := f.St.Count(`SELECT count(*) FROM invocations WHERE actor = 'guest'`); n != 0 {
		t.Fatalf("a refused call left %d invocations", n)
	}
	// A record changed after review is not usable (AGT-001).
	changed := pay
	changed.Description = "pay anything"
	if err := toolstore.New(f.St.Pool).PutTool(ctx, r1test.Tenant, changed, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Svc.Invoke(ctx, alice, payment("k-2", 100)); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("an unreviewed record: %v", err)
	}
	if f.Dest.Count() != 2 {
		t.Fatalf("%d dispatches", f.Dest.Count())
	}
}

// TestInvokeApproval covers APR-001 to APR-005 and AGT-004 for tools: a
// payment above a limit the policy reads from the plan's arguments
// (request.operation) waits for a lead's approval of exactly that plan;
// with it, the call is dispatched once and the approval consumed with the
// dispatch; other arguments are another plan the approval does not cover.
func TestInvokeApproval(t *testing.T) {
	rule := `{"id":"members-invoke-small","effect":"allow","actions":["invoke"],"roles":["member"],
	  "when":"resource.attributes.kind == \"executor\" && request.operation.amount_minor <= 5000"},
	  {"id":"members-invoke-large","effect":"allow","actions":["invoke"],"roles":["member"],"requires":["approval"],
	  "when":"resource.attributes.kind == \"executor\" && request.operation.amount_minor > 5000"}`
	f := deploy(t, rule, nil, http.StatusOK, 100_000)
	alice := f.Caller(t, "alice", "member")
	f.Caller(t, "lena", "lead")
	if res, err := f.Svc.Invoke(ctx, alice, payment("small", 4000)); err != nil || res.State != string(invocation.StateSucceeded) {
		t.Fatalf("a small payment: %+v %v", res, err)
	}
	_, err := f.Svc.Invoke(ctx, alice, payment("large", 9000))
	var need *enforce.ApprovalRequired
	if !errors.As(err, &need) || f.Dest.Count() != 1 {
		t.Fatalf("a large payment: %v", err)
	}
	// The lead decides in the approval inbox, which the storage role serves.
	if _, err := f.St.Content.DecideApproval(ctx, f.St.Caller("lena"), need.ID, true); err != nil {
		t.Fatal(err)
	}
	approved := alice
	approved.Approval = need.ID
	if _, err := f.Svc.Invoke(ctx, approved, payment("large-other", 9500)); !errors.Is(err, enforce.ErrApprovalNotUsable) {
		t.Fatalf("other arguments under the approval: %v", err)
	}
	res, err := f.Svc.Invoke(ctx, approved, payment("large", 9000))
	if err != nil || res.State != string(invocation.StateSucceeded) || f.Dest.Count() != 2 {
		t.Fatalf("with the approval: %+v %v", res, err)
	}
	if n := f.St.Count(`SELECT count(*) FROM approvals WHERE id = $1 AND state = 'CONSUMED'`, need.ID); n != 1 {
		t.Fatal("the approval was not consumed with the dispatch")
	}
	// A consumed approval serves no second dispatch of the same plan (V-040).
	if _, err := f.Svc.Invoke(ctx, approved, payment("large-again", 9000)); err == nil || f.Dest.Count() != 2 {
		t.Fatalf("a consumed approval was used again: %v, %d dispatches", err, f.Dest.Count())
	}
}

// TestInvokeReservation covers APR-004, INV-002 and INV-007: with a
// release that maps the reservation prerequisite to an obligation, the
// decision obliges the tools role to reserve the payment on the tool's
// budget in the dispatch's own transaction; a success charges it, a
// refusal releases it, an unknown outcome keeps it held, and a payment the
// budget cannot cover is refused before anything is sent.
func TestInvokeReservation(t *testing.T) {
	rule := `{"id":"members-invoke-reserved","effect":"allow","actions":["invoke"],"roles":["member"],"requires":["reservation"],
	  "when":"resource.attributes.kind == \"executor\""}`
	mapping := &release.ObligationMapping{Version: signing.ObligationsV1, Prerequisites: map[string]string{"reservation": signing.Reservation}}
	budget := func(f *fixture) (reserved, spent int64) {
		_ = f.St.Pool.QueryRow(ctx, `SELECT reserved_minor, spent_minor FROM budgets WHERE id = 'ops'`).Scan(&reserved, &spent)
		return
	}
	t.Run("charged on success, refused beyond the budget", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusOK, 10_000)
		alice := f.Caller(t, "alice", "member")
		if res, err := f.Svc.Invoke(ctx, alice, payment("r-1", 6000)); err != nil || res.State != string(invocation.StateSucceeded) {
			t.Fatalf("a reserved payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 0 || s != 6000 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
		if _, err := f.Svc.Invoke(ctx, alice, payment("r-2", 5000)); !errors.Is(err, executor.ErrBudget) || f.Dest.Count() != 1 {
			t.Fatalf("beyond the budget: %v, %d calls", err, f.Dest.Count())
		}
	})
	t.Run("released on refusal", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusUnprocessableEntity, 10_000)
		alice := f.Caller(t, "alice", "member")
		if res, err := f.Svc.Invoke(ctx, alice, payment("r-3", 6000)); err != nil || res.State != string(invocation.StateFailed) {
			t.Fatalf("a refused payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 0 || s != 0 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
	})
	t.Run("held while unknown", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusBadGateway, 10_000)
		alice := f.Caller(t, "alice", "member")
		if res, err := f.Svc.Invoke(ctx, alice, payment("r-4", 6000)); err != nil || res.State != string(invocation.StateUnknown) {
			t.Fatalf("an unanswered payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 6000 || s != 0 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
	})
	t.Run("not applied without the mapping", func(t *testing.T) {
		f := deploy(t, rule, nil, http.StatusOK, 10_000)
		alice := f.Caller(t, "alice", "member")
		if _, err := f.Svc.Invoke(ctx, alice, payment("r-5", 100)); err == nil || f.Dest.Count() != 0 {
			t.Fatalf("a reservation nobody can make: %v", err)
		}
	})
}

// TestResolution covers INV-006 and INV-009: an UNKNOWN invocation is
// closed only by a principal with resolve on the tool who is not its
// actor, with evidence; ABANDONED keeps the charge, which only a write-off
// by another principal releases. An agent acting for a principal is that
// principal here too.
func TestResolution(t *testing.T) {
	rule := `{"id":"members-invoke-reserved","effect":"allow","actions":["invoke"],"roles":["member"],"requires":["reservation"],
	  "when":"resource.attributes.kind == \"executor\""}`
	mapping := &release.ObligationMapping{Version: signing.ObligationsV1, Prerequisites: map[string]string{"reservation": signing.Reservation}}
	f := deploy(t, rule, mapping, http.StatusBadGateway, 10_000)
	alice, lena, mark := f.Caller(t, "alice", "member"), f.Caller(t, "lena", "lead"), f.Caller(t, "mark", "lead")
	res, err := f.Svc.Invoke(ctx, alice, payment("u-1", 2000))
	if err != nil || res.State != string(invocation.StateUnknown) {
		t.Fatalf("invoke: %+v %v", res, err)
	}
	if _, err := f.Svc.Resolve(ctx, alice, res.Invocation, invocation.StateFailed, "the bank says no"); err == nil {
		t.Fatal("the actor resolved its own call")
	}
	if _, err := f.Svc.Resolve(ctx, lena, res.Invocation, invocation.StateFailed, ""); !errors.Is(err, executor.ErrInvalid) {
		t.Fatalf("a resolution without evidence: %v", err)
	}
	if got, err := f.Svc.Get(ctx, lena, res.Invocation); err != nil || got.State != string(invocation.StateUnknown) {
		t.Fatalf("a resolver reads it: %+v %v", got, err)
	}
	got, err := f.Svc.Resolve(ctx, lena, res.Invocation, invocation.StateAbandoned, "the bank cannot tell; ticket 42")
	if err != nil || got.State != string(invocation.StateAbandoned) {
		t.Fatalf("abandon: %+v %v", got, err)
	}
	if n := f.St.Count(`SELECT count(*) FROM reservations WHERE state = 'COMMITTED'`); n != 1 {
		t.Fatal("an abandoned call's charge was not kept")
	}
	if _, err := f.Svc.Invoke(ctx, alice, payment("u-1", 2000)); err != nil || f.Dest.Count() != 1 {
		t.Fatalf("an abandoned call was dispatched again: %v, %d calls", err, f.Dest.Count())
	}
	if _, err := f.Svc.WriteOff(ctx, mark, res.Invocation, "accepted risk, ticket 42"); err != nil {
		t.Fatalf("write-off: %v", err)
	}
	if n := f.St.Count(`SELECT count(*) FROM reservations WHERE state = 'WRITTEN_OFF'`); n != 1 {
		t.Fatal("the write-off released nothing")
	}

	// An agent acting for a lead under a delegation resolves another's
	// call, but never the lead's own, whichever agent it is.
	lara := f.Caller(t, "lara", "member", "lead")
	f.Caller(t, "agent-9", "agent")
	if err := f.St.Catalog.PutDelegation(ctx, delegation.Delegation{ID: "dlg-9", Tenant: r1test.Tenant, Actor: "agent-9", Subject: "lara",
		Audience: r1test.ToolsAdapter, Grants: []delegation.Grant{{ResourceType: "agent.tool", Actions: []string{"resolve"}}},
		ExpiresAt: f.St.Clock.Add(time.Hour)}, *f.St.Clock); err != nil {
		t.Fatal(err)
	}
	agent := enforce.Caller{Tenant: r1test.Tenant, Principal: "agent-9", Subject: "lara", Delegation: "dlg-9"}
	own, err := f.Svc.Invoke(ctx, lara, payment("u-2", 1000))
	if err != nil || own.State != string(invocation.StateUnknown) {
		t.Fatalf("lara's call: %+v %v", own, err)
	}
	if _, err := f.Svc.Resolve(ctx, agent, own.Invocation, invocation.StateFailed, "the bank says no"); !errors.Is(err, executor.ErrInvalid) {
		t.Fatalf("lara's agent resolved lara's call: %v", err)
	}
	other, err := f.Svc.Invoke(ctx, alice, payment("u-3", 1000))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.Svc.Resolve(ctx, agent, other.Invocation, invocation.StateFailed, "the bank says no; ticket 43"); err != nil ||
		got.State != string(invocation.StateFailed) {
		t.Fatalf("lara's agent resolves alice's call: %+v %v", got, err)
	}
}

// TestReconcile covers INV-003, INV-006 and INV-008: a pass asks the
// destination, by the idempotency key, for the outcome of a dispatch whose
// worker stopped and of an UNKNOWN call, records what it reports (a key it
// never received failed), and never sends again; without a way to ask, the
// call stays UNKNOWN, with its charge held, and is escalated once when
// held beyond its tool's maximum hold age.
func TestReconcile(t *testing.T) {
	o := executortest.Options{InvokeRule: `{"id":"members-invoke-reserved","effect":"allow","actions":["invoke"],"roles":["member"],
	  "requires":["reservation"],"when":"resource.attributes.kind == \"executor\""}`,
		Mapping: &release.ObligationMapping{Version: signing.ObligationsV1, Prerequisites: map[string]string{"reservation": signing.Reservation}},
		Status:  http.StatusBadGateway, Limit: 10_000}
	unknown := func(t *testing.T, f *fixture, key string) string {
		t.Helper()
		res, err := f.Svc.Invoke(ctx, f.Caller(t, "alice", "member"), payment(key, 2000))
		if err != nil || res.State != string(invocation.StateUnknown) {
			t.Fatalf("invoke: %+v %v", res, err)
		}
		return res.Invocation
	}
	// stall makes id a dispatch whose worker stopped before recording it.
	stall := func(t *testing.T, f *fixture, id string) {
		t.Helper()
		if _, err := f.St.Pool.Exec(ctx, `UPDATE invocations SET state = 'DISPATCHING', lease_owner = 'w0', lease_expires_at = $2
			WHERE id = $1`, id, f.St.Clock.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	reconcile := func(t *testing.T, f *fixture, want int) {
		t.Helper()
		if n, err := f.Svc.Reconcile(ctx, 10); err != nil || n != want {
			t.Fatalf("reconcile: %d %v, want %d", n, err, want)
		}
	}
	state := func(t *testing.T, f *fixture, id string) invocation.Invocation {
		t.Helper()
		inv, err := f.Inv.Get(ctx, r1test.Tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return inv
	}

	t.Run("asked of the destination dispatched to", func(t *testing.T) {
		o := o
		o.Reconcilable = true
		f := executortest.Deploy(t, o)
		reported, stalled := unknown(t, f, "c-1"), unknown(t, f, "c-2")
		f.Dest.Report(reported, "succeeded")
		stall(t, f, stalled)
		// The destination is registered anew elsewhere: the open calls are
		// still asked of the one they were sent to (review v4 F01).
		other := &executortest.Destination{Status: http.StatusOK}
		srv := httptest.NewServer(other)
		t.Cleanup(srv.Close)
		if err := executor.RegisterDestination(ctx, f.St.Pool, r1test.Tenant, tools.Destination{ID: "bank", BaseURL: srv.URL,
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, ReconcilePath: "/payments/{key}"},
			map[string]any{"approved": true}); err != nil {
			t.Fatal(err)
		}
		reconcile(t, f, 2)
		if inv := state(t, f, reported); inv.State != invocation.StateSucceeded || inv.Resolution == nil || inv.Resolution.By != executor.Reconciler {
			t.Fatalf("a reported success: %+v", inv)
		}
		// Never received, but the worker could still send until its
		// deadline: not yet a failure (F02).
		if inv := state(t, f, stalled); inv.State != invocation.StateUnknown {
			t.Fatalf("a stalled dispatch within its send window: %+v", inv)
		}
		*f.St.Clock = f.St.Clock.Add(3 * time.Minute)
		reconcile(t, f, 1)
		if inv := state(t, f, stalled); inv.State != invocation.StateFailed {
			t.Fatalf("a stalled dispatch never received after its window: %+v", inv)
		}
		if n := f.St.Count(`SELECT count(*) FROM reservations WHERE state = 'COMMITTED'`); n != 1 ||
			f.St.Count(`SELECT count(*) FROM reservations WHERE state = 'RELEASED'`) != 1 {
			t.Fatal("the reservations were not settled by the reported outcomes")
		}
		if f.St.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'outcome' IN ('RESOLVED_SUCCEEDED', 'RECONCILED_UNKNOWN', 'RESOLVED_FAILED')`) != 3 {
			t.Fatal("a reconciliation step has no audit event")
		}
		reconcile(t, f, 0)
		if f.Dest.Count() != 2 || len(other.Asked) != 0 {
			t.Fatalf("%d dispatches; the new destination asked %v", f.Dest.Count(), other.Asked)
		}
	})
	t.Run("every open call is reached", func(t *testing.T) {
		o := o
		o.Reconcilable = true
		f := executortest.Deploy(t, o)
		var keys []string
		for _, k := range []string{"e-1", "e-2", "e-3"} {
			keys = append(keys, unknown(t, f, k))
			*f.St.Clock = f.St.Clock.Add(time.Second)
		}
		for range 2 {
			if _, err := f.Svc.Reconcile(ctx, 2); err != nil {
				t.Fatal(err)
			}
		}
		for _, k := range keys {
			if !slices.Contains(f.Dest.Asked, k) {
				t.Fatalf("%s was never asked about in two passes of two (F06): %v", k, f.Dest.Asked)
			}
		}
	})
	t.Run("not askable: held, escalated once", func(t *testing.T) {
		f := executortest.Deploy(t, o)
		id := unknown(t, f, "c-3")
		stall(t, f, id)
		reconcile(t, f, 1)
		if inv := state(t, f, id); inv.State != invocation.StateUnknown {
			t.Fatalf("a stalled dispatch nobody can ask about: %+v", inv)
		}
		reconcile(t, f, 0)
		*f.St.Clock = f.St.Clock.Add(2 * time.Hour)
		reconcile(t, f, 1)
		reconcile(t, f, 0)
		if f.St.Count(`SELECT count(*) FROM invocations WHERE escalated_at IS NOT NULL`) != 1 ||
			f.St.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'ESCALATED'`) != 1 {
			t.Fatal("the held call was not escalated once")
		}
		if n := f.St.Count(`SELECT count(*) FROM reservations WHERE state = 'HELD'`); n != 1 || f.Dest.Count() != 1 {
			t.Fatalf("the charge was not held, or the call was sent again (%d)", f.Dest.Count())
		}
	})
}

// TestDispatchFence covers DAT-007 and INV-002 for tools: a revocation
// that commits between the decision and the dispatch leaves the call
// undispatched, its invocation PREPARED.
func TestDispatchFence(t *testing.T) {
	f := deploy(t, plainInvoke, nil, http.StatusOK, 10_000)
	alice := f.Caller(t, "alice", "member")
	revoked := false
	f.Svc = f.Service(t, afterDecider{r1test.Decider{Service: f.St.Decisions, Adapter: r1test.ToolsAdapter}, func() {
		if !revoked {
			revoked = true
			if err := f.St.Catalog.DisableIdentity(ctx, r1test.Tenant, "alice"); err != nil {
				t.Error(err)
			}
		}
	}})
	if _, err := f.Svc.Invoke(ctx, alice, payment("f-1", 100)); err == nil || f.Dest.Count() != 0 {
		t.Fatalf("a call after its actor was disabled: %v, %d calls", err, f.Dest.Count())
	}
}

// afterDecider runs after once a decision is made, before the caller
// dispatches.
type afterDecider struct {
	r1test.Decider
	after func()
}

func (a afterDecider) Decide(ctx context.Context, req decisionsvc.Request) (decisionsvc.Response, error) {
	resp, err := a.Decider.Decide(ctx, req)
	a.after()
	return resp, err
}

// TestDispatchBinding covers review v4 F02 and F03: a dispatch uses the
// destination's transport only as the resource its decision saw records
// it, and a worker sends nothing it cannot finish within its lease.
func TestDispatchBinding(t *testing.T) {
	t.Run("a transport changed apart from its resource", func(t *testing.T) {
		f := deploy(t, plainInvoke, nil, http.StatusOK, 10_000)
		alice := f.Caller(t, "alice", "member")
		elsewhere := &executortest.Destination{Status: http.StatusOK}
		srv := httptest.NewServer(elsewhere)
		t.Cleanup(srv.Close)
		f.Svc = f.Service(t, afterDecider{r1test.Decider{Service: f.St.Decisions, Adapter: r1test.ToolsAdapter}, func() {
			if err := toolstore.New(f.St.Pool).PutDestination(ctx, r1test.Tenant, tools.Destination{ID: "bank", BaseURL: srv.URL,
				AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}); err != nil {
				t.Error(err)
			}
		}})
		if _, err := f.Svc.Invoke(ctx, alice, payment("b-1", 100)); !errors.Is(err, executor.ErrConflict) || f.Dest.Count()+elsewhere.Count() != 0 {
			t.Fatalf("a call over a transport its decision did not see: %v, %d and %d calls", err, f.Dest.Count(), elsewhere.Count())
		}
	})
	t.Run("no time left in the lease", func(t *testing.T) {
		f := deploy(t, plainInvoke, nil, http.StatusOK, 10_000)
		alice := f.Caller(t, "alice", "member")
		svc := f.Service(t, r1test.Decider{Service: f.St.Decisions, Adapter: r1test.ToolsAdapter}, func(d *executor.Deps) { d.Lease = time.Second })
		if res, err := svc.Invoke(ctx, alice, payment("b-2", 100)); err != nil || res.State != string(invocation.StateFailed) || f.Dest.Count() != 0 {
			t.Fatalf("a call the worker could not finish in its lease: %+v %v, %d calls", res, err, f.Dest.Count())
		}
	})
}

// TestOutcomeAudited covers review v4 F08: an outcome is recorded with its
// audit event or not at all; one that could not be is recorded later by
// reconciliation, with its event.
func TestOutcomeAudited(t *testing.T) {
	f := executortest.Deploy(t, executortest.Options{Reconcilable: true})
	alice := f.Caller(t, "alice", "member")
	f.Dest.OnCall = func() {
		if _, err := f.St.Pool.Exec(ctx, `INSERT INTO audit_outbox (id, tenant, kind, event)
			SELECT 'fill-' || g, 'x', 'x', '{}' FROM generate_series(1, 10000) g`); err != nil {
			t.Error(err)
		}
	}
	res, err := f.Svc.Invoke(ctx, alice, payment("a-1", 100))
	if err != nil || res.State != string(invocation.StateDispatching) {
		t.Fatalf("an outcome whose event could not be recorded: %+v %v", res, err)
	}
	f.Dest.OnCall = nil
	f.Dest.Report(res.Invocation, "succeeded")
	if _, err := f.St.Pool.Exec(ctx, `DELETE FROM audit_outbox WHERE id LIKE 'fill-%'`); err != nil {
		t.Fatal(err)
	}
	*f.St.Clock = f.St.Clock.Add(2 * time.Minute)
	if n, err := f.Svc.Reconcile(ctx, 10); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if inv, _ := f.Inv.Get(ctx, r1test.Tenant, res.Invocation); inv.State != invocation.StateSucceeded ||
		f.St.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'RECONCILED_SUCCEEDED'`) != 1 {
		t.Fatalf("the reconciled outcome and its event: %+v", inv)
	}
}

// TestAudience pins the tools role's audience to the test stack's.
func TestAudience(t *testing.T) {
	if executor.Audience != r1test.ToolsAudience {
		t.Fatalf("%s, want %s", executor.Audience, r1test.ToolsAudience)
	}
}
