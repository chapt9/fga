package executor_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/executor"
	"fga/internal/fence"
	"fga/internal/invocation"
	"fga/internal/r1test"
	"fga/internal/release"
	"fga/internal/reservation"
	"fga/internal/signing"
	"fga/internal/tools"
	"fga/internal/tools/connector"
	"fga/internal/toolstore"
)

var ctx = context.Background()

// destination is a fake external service: it records calls and answers
// with status.
type destination struct {
	mu     sync.Mutex
	calls  []call
	status int
}

type call struct {
	key, auth string
	body      []byte
}

func (d *destination) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, call{key: r.Header.Get("Idempotency-Key"), auth: r.Header.Get("Authorization"), body: b})
	w.WriteHeader(d.status)
	_, _ = io.WriteString(w, `{"payment":"p-1"}`)
}

func (d *destination) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

// pay is the test tool: a payment of amount to a business record account,
// charged to the budget ops.
var pay = tools.Tool{ID: "pay", Version: 1, Description: "pay an invoice", Destination: "bank",
	Endpoint: tools.Endpoint{Method: "POST", Path: "/payments"}, MaxHoldAge: "1h", Budget: "ops", AmountArgument: "amount",
	Arguments: []tools.ArgSpec{
		{Name: "amount", Type: tools.ArgMoney, Required: true},
		{Name: "account", Type: tools.ArgResource, Required: true, Namespace: "account", ResourceType: "business.record", Action: "update"},
	}}

// Policies of the fixture: members invoke executor tools and send to
// approved destinations; leads approve, resolve and write off; members
// update the business records of their projects.
func policies(invokeRule string) map[string]string {
	p := maps.Clone(r1test.Policies)
	p["tools.json"] = `{"format":"fga.policy/v1","set":"business","resource":"agent.tool","scope":"","rules":[
	  {"id":"members-use-mcp","effect":"allow","actions":["discover","invoke"],"roles":["member"],"when":"resource.attributes.kind == \"mcp\""},
	  ` + invokeRule + `,
	  {"id":"leads-settle","effect":"allow","actions":["approve","resolve","write-off"],"roles":["lead"],"when":"resource.attributes.kind == \"executor\""}]}`
	p["destinations.json"] = `{"format":"fga.policy/v1","set":"business","resource":"network.destination","scope":"","rules":[
	  {"id":"members-send-approved","effect":"allow","actions":["send"],"roles":["member"],"when":"resource.attributes.approved == true"}]}`
	p["records.json"] = `{"format":"fga.policy/v1","set":"business","resource":"business.record","scope":"","rules":[
	  {"id":"members-update-records","effect":"allow","actions":["update"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`
	return p
}

const plainInvoke = `{"id":"members-invoke","effect":"allow","actions":["invoke"],"roles":["member"],"when":"resource.attributes.kind == \"executor\""}`

type fixture struct {
	st   *r1test.Stack
	svc  *executor.Service
	dest *destination
	inv  *invocation.Store
}

// deploy registers pay, its destination bank (answering status), a budget
// ops of limit cents, and account acct-1 of project p1, and returns the
// tools role over the stack.
func deploy(t *testing.T, invokeRule string, mapping *release.ObligationMapping, status int, limit int64) *fixture {
	t.Helper()
	st := r1test.NewWith(t, r1test.Options{Policies: policies(invokeRule), ObligationMapping: mapping})
	if err := toolstore.Migrate(ctx, st.Pool); err != nil {
		t.Fatal(err)
	}
	dest := &destination{status: status}
	srv := httptest.NewServer(dest)
	t.Cleanup(srv.Close)
	cred := filepath.Join(t.TempDir(), "bank.token")
	if err := os.WriteFile(cred, []byte("bank-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := toolstore.New(st.Pool)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(ts.PutTool(ctx, r1test.Tenant, pay, true))
	must(ts.PutDestination(ctx, r1test.Tenant, tools.Destination{ID: "bank", BaseURL: srv.URL,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, CredentialFile: cred}))
	must(ts.PutBudget(ctx, r1test.Tenant, "ops", tools.Money{Currency: "EUR", Minor: limit}))
	must(st.Catalog.RegisterTool(ctx, r1test.Tenant, "pay", pay.Operation(), map[string]any{"name": "pay", "kind": "executor", "destination": "bank"}))
	must(st.Catalog.RegisterDestination(ctx, r1test.Tenant, "bank", map[string]any{"approved": true}))
	_, err := st.Pool.Exec(ctx, `INSERT INTO resources VALUES ($1, 'record:acct-1', 'business.record', '', 1, 1, 1, '{"project":"p1"}')`, r1test.Tenant)
	must(err)
	_, err = st.Pool.Exec(ctx, `INSERT INTO aliases VALUES ($1, 'account', 'acct-1', 'record:acct-1')`, r1test.Tenant)
	must(err)
	now := func() time.Time { return *st.Clock }
	inv := invocation.New(st.Pool, now)
	svc, err := executor.New(executor.Deps{Catalog: st.Catalog, Tools: ts, Invocations: inv, Reservations: reservation.New(st.Pool),
		Decider: r1test.Decider{Service: st.Decisions, Adapter: r1test.ToolsAdapter}, Verifier: st.Verifier(executor.Audience),
		Fence: fence.New(st.Pool, time.Second, now), Connector: connector.New(5 * time.Second), Worker: "w1", Lease: time.Minute, Now: now})
	must(err)
	return &fixture{st: st, svc: svc, dest: dest, inv: inv}
}

func (f *fixture) caller(t *testing.T, id string, roles ...string) enforce.Caller {
	t.Helper()
	f.st.User(id, roles, "p1")
	return f.st.CallerFor(id, executor.Audience)
}

func payment(key string, minor int64) executor.Request {
	return executor.Request{Tool: "pay", Version: 1, IdempotencyKey: key,
		Args: json.RawMessage(`{"amount":{"currency":"EUR","minor":` + itoa(minor) + `},"account":"acct-1"}`)}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

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
	alice := f.caller(t, "alice", "member")
	res, err := f.svc.Invoke(ctx, alice, payment("k-1", 1200))
	if err != nil || res.State != string(invocation.StateSucceeded) || res.Receipt == "" {
		t.Fatalf("invoke: %+v %v", res, err)
	}
	if f.dest.count() != 1 || f.dest.calls[0].key != res.Invocation || f.dest.calls[0].auth != "Bearer bank-secret" ||
		!strings.Contains(string(f.dest.calls[0].body), `"minor":1200`) {
		t.Fatalf("the destination got %+v", f.dest.calls)
	}
	again, err := f.svc.Invoke(ctx, alice, payment("k-1", 1200))
	if err != nil || again.Invocation != res.Invocation || f.dest.count() != 1 {
		t.Fatalf("a retry: %+v %v, %d calls", again, err, f.dest.count())
	}
	if _, err := f.svc.Invoke(ctx, alice, payment("k-1", 1300)); !errors.Is(err, executor.ErrConflict) {
		t.Fatalf("the key with other arguments: %v", err)
	}
	bob := f.caller(t, "bob", "member")
	if _, err := f.svc.Invoke(ctx, bob, payment("k-1", 1200)); !errors.Is(err, executor.ErrConflict) {
		t.Fatalf("another actor with the key: %v", err)
	}
	if got, err := f.svc.Get(ctx, bob, res.Invocation); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("another member reads the invocation: %+v %v", got, err)
	}
	if got, err := f.svc.Get(ctx, alice, res.Invocation); err != nil || got.State != res.State {
		t.Fatalf("the actor reads it: %+v %v", got, err)
	}

	for name, r := range map[string]executor.Request{
		"an unknown tool":   {Tool: "wire", Version: 1, IdempotencyKey: "x1", Args: json.RawMessage(`{}`)},
		"another version":   {Tool: "pay", Version: 2, IdempotencyKey: "x2", Args: payment("x2", 1).Args},
		"an extra argument": {Tool: "pay", Version: 1, IdempotencyKey: "x3", Args: json.RawMessage(`{"amount":{"currency":"EUR","minor":1},"account":"acct-1","to":"x"}`)},
	} {
		if _, err := f.svc.Invoke(ctx, alice, r); err == nil {
			t.Errorf("%s was dispatched", name)
		}
	}
	guest := f.caller(t, "guest", "guest")
	if _, err := f.svc.Invoke(ctx, guest, payment("g-1", 100)); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("a user without the rights: %v", err)
	}
	// A record changed after review is not usable (AGT-001).
	changed := pay
	changed.Description = "pay anything"
	if err := toolstore.New(f.st.Pool).PutTool(ctx, r1test.Tenant, changed, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Invoke(ctx, alice, payment("k-2", 100)); !errors.Is(err, executor.ErrNotFound) {
		t.Fatalf("an unreviewed record: %v", err)
	}
	if f.dest.count() != 1 {
		t.Fatalf("%d dispatches", f.dest.count())
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
	alice := f.caller(t, "alice", "member")
	f.caller(t, "lena", "lead")
	if res, err := f.svc.Invoke(ctx, alice, payment("small", 4000)); err != nil || res.State != string(invocation.StateSucceeded) {
		t.Fatalf("a small payment: %+v %v", res, err)
	}
	_, err := f.svc.Invoke(ctx, alice, payment("large", 9000))
	var need *enforce.ApprovalRequired
	if !errors.As(err, &need) || f.dest.count() != 1 {
		t.Fatalf("a large payment: %v", err)
	}
	// The lead decides in the approval inbox, which the storage role serves.
	if _, err := f.st.Content.DecideApproval(ctx, f.st.Caller("lena"), need.ID, true); err != nil {
		t.Fatal(err)
	}
	approved := alice
	approved.Approval = need.ID
	if _, err := f.svc.Invoke(ctx, approved, payment("large-other", 9500)); !errors.Is(err, enforce.ErrApprovalNotUsable) {
		t.Fatalf("other arguments under the approval: %v", err)
	}
	res, err := f.svc.Invoke(ctx, approved, payment("large", 9000))
	if err != nil || res.State != string(invocation.StateSucceeded) || f.dest.count() != 2 {
		t.Fatalf("with the approval: %+v %v", res, err)
	}
	if n := f.st.Count(`SELECT count(*) FROM approvals WHERE id = $1 AND state = 'CONSUMED'`, need.ID); n != 1 {
		t.Fatal("the approval was not consumed with the dispatch")
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
		_ = f.st.Pool.QueryRow(ctx, `SELECT reserved_minor, spent_minor FROM budgets WHERE id = 'ops'`).Scan(&reserved, &spent)
		return
	}
	t.Run("charged on success, refused beyond the budget", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusOK, 10_000)
		alice := f.caller(t, "alice", "member")
		if res, err := f.svc.Invoke(ctx, alice, payment("r-1", 6000)); err != nil || res.State != string(invocation.StateSucceeded) {
			t.Fatalf("a reserved payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 0 || s != 6000 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
		if _, err := f.svc.Invoke(ctx, alice, payment("r-2", 5000)); !errors.Is(err, executor.ErrBudget) || f.dest.count() != 1 {
			t.Fatalf("beyond the budget: %v, %d calls", err, f.dest.count())
		}
	})
	t.Run("released on refusal", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusUnprocessableEntity, 10_000)
		alice := f.caller(t, "alice", "member")
		if res, err := f.svc.Invoke(ctx, alice, payment("r-3", 6000)); err != nil || res.State != string(invocation.StateFailed) {
			t.Fatalf("a refused payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 0 || s != 0 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
	})
	t.Run("held while unknown", func(t *testing.T) {
		f := deploy(t, rule, mapping, http.StatusBadGateway, 10_000)
		alice := f.caller(t, "alice", "member")
		if res, err := f.svc.Invoke(ctx, alice, payment("r-4", 6000)); err != nil || res.State != string(invocation.StateUnknown) {
			t.Fatalf("an unanswered payment: %+v %v", res, err)
		}
		if r, s := budget(f); r != 6000 || s != 0 {
			t.Fatalf("budget reserved %d spent %d", r, s)
		}
	})
	t.Run("not applied without the mapping", func(t *testing.T) {
		f := deploy(t, rule, nil, http.StatusOK, 10_000)
		alice := f.caller(t, "alice", "member")
		if _, err := f.svc.Invoke(ctx, alice, payment("r-5", 100)); err == nil || f.dest.count() != 0 {
			t.Fatalf("a reservation nobody can make: %v", err)
		}
	})
}

// TestResolution covers INV-006 and INV-009: an UNKNOWN invocation is
// closed only by a principal with resolve on the tool who is not its
// actor, with evidence; ABANDONED keeps the charge, which only a write-off
// by another principal releases.
func TestResolution(t *testing.T) {
	rule := `{"id":"members-invoke-reserved","effect":"allow","actions":["invoke"],"roles":["member"],"requires":["reservation"],
	  "when":"resource.attributes.kind == \"executor\""}`
	mapping := &release.ObligationMapping{Version: signing.ObligationsV1, Prerequisites: map[string]string{"reservation": signing.Reservation}}
	f := deploy(t, rule, mapping, http.StatusBadGateway, 10_000)
	alice, lena, mark := f.caller(t, "alice", "member"), f.caller(t, "lena", "lead"), f.caller(t, "mark", "lead")
	res, err := f.svc.Invoke(ctx, alice, payment("u-1", 2000))
	if err != nil || res.State != string(invocation.StateUnknown) {
		t.Fatalf("invoke: %+v %v", res, err)
	}
	if _, err := f.svc.Resolve(ctx, alice, res.Invocation, invocation.StateFailed, "the bank says no"); err == nil {
		t.Fatal("the actor resolved its own call")
	}
	if _, err := f.svc.Resolve(ctx, lena, res.Invocation, invocation.StateFailed, ""); !errors.Is(err, executor.ErrInvalid) {
		t.Fatalf("a resolution without evidence: %v", err)
	}
	if got, err := f.svc.Get(ctx, lena, res.Invocation); err != nil || got.State != string(invocation.StateUnknown) {
		t.Fatalf("a resolver reads it: %+v %v", got, err)
	}
	got, err := f.svc.Resolve(ctx, lena, res.Invocation, invocation.StateAbandoned, "the bank cannot tell; ticket 42")
	if err != nil || got.State != string(invocation.StateAbandoned) {
		t.Fatalf("abandon: %+v %v", got, err)
	}
	if n := f.st.Count(`SELECT count(*) FROM reservations WHERE state = 'COMMITTED'`); n != 1 {
		t.Fatal("an abandoned call's charge was not kept")
	}
	if _, err := f.svc.Invoke(ctx, alice, payment("u-1", 2000)); err != nil || f.dest.count() != 1 {
		t.Fatalf("an abandoned call was dispatched again: %v, %d calls", err, f.dest.count())
	}
	if _, err := f.svc.WriteOff(ctx, mark, res.Invocation, "accepted risk, ticket 42"); err != nil {
		t.Fatalf("write-off: %v", err)
	}
	if n := f.st.Count(`SELECT count(*) FROM reservations WHERE state = 'WRITTEN_OFF'`); n != 1 {
		t.Fatal("the write-off released nothing")
	}
}

// TestDispatchFence covers DAT-007 and INV-002 for tools: a revocation
// that commits between the decision and the dispatch leaves the call
// undispatched, its invocation PREPARED.
func TestDispatchFence(t *testing.T) {
	f := deploy(t, plainInvoke, nil, http.StatusOK, 10_000)
	alice := f.caller(t, "alice", "member")
	revoked := false
	f.svc = mustSvcWithHook(t, f, func() {
		if !revoked {
			revoked = true
			if err := f.st.Catalog.DisableIdentity(ctx, r1test.Tenant, "alice"); err != nil {
				t.Error(err)
			}
		}
	})
	if _, err := f.svc.Invoke(ctx, alice, payment("f-1", 100)); err == nil || f.dest.count() != 0 {
		t.Fatalf("a call after its actor was disabled: %v, %d calls", err, f.dest.count())
	}
}

// mustSvcWithHook rebuilds f's service with a decider that runs after
// before returning each decision.
func mustSvcWithHook(t *testing.T, f *fixture, after func()) *executor.Service {
	t.Helper()
	now := func() time.Time { return *f.st.Clock }
	svc, err := executor.New(executor.Deps{Catalog: f.st.Catalog, Tools: toolstore.New(f.st.Pool), Invocations: f.inv,
		Reservations: reservation.New(f.st.Pool), Decider: afterDecider{r1test.Decider{Service: f.st.Decisions, Adapter: r1test.ToolsAdapter}, after},
		Verifier: f.st.Verifier(executor.Audience), Fence: fence.New(f.st.Pool, time.Second, now), Connector: connector.New(5 * time.Second),
		Worker: "w1", Lease: time.Minute, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return svc
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

// TestAudience pins the tools role's audience to the test stack's.
func TestAudience(t *testing.T) {
	if executor.Audience != r1test.ToolsAudience {
		t.Fatalf("%s, want %s", executor.Audience, r1test.ToolsAudience)
	}
}
