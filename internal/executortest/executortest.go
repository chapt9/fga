// Package executortest installs the tools role's test fixture on an r1test
// stack: the tool pay, its destination bank (a recording fake), a budget
// and a business record, with the policies that govern them. The tools
// role's own tests and the MCP role's use it. Test code only; no role
// links it.
package executortest

import (
	"context"
	"encoding/json"
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

	"fga/internal/enforce"
	"fga/internal/executor"
	"fga/internal/fence"
	"fga/internal/invocation"
	"fga/internal/r1test"
	"fga/internal/release"
	"fga/internal/reservation"
	"fga/internal/tools"
	"fga/internal/tools/connector"
	"fga/internal/toolstore"
)

// Destination is a fake external service: it records calls and answers
// them with Status, running OnCall first if set. With a reconcile path
// registered, GET /payments/{key} reports Outcomes[key] ("succeeded" or
// "failed"), or 404 for a key it never received; Asked records the keys
// asked about.
type Destination struct {
	mu       sync.Mutex
	Calls    []Call
	Asked    []string
	Status   int
	Outcomes map[string]string
	OnCall   func()
}

// Call is one recorded call.
type Call struct {
	Key, Auth string
	Body      []byte
}

func (d *Destination) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Method == http.MethodGet {
		key := strings.TrimPrefix(r.URL.Path, "/payments/")
		d.Asked = append(d.Asked, key)
		outcome, ok := d.Outcomes[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"status":"`+outcome+`"}`)
		return
	}
	if d.OnCall != nil {
		d.OnCall()
	}
	b, _ := io.ReadAll(r.Body)
	d.Calls = append(d.Calls, Call{Key: r.Header.Get("Idempotency-Key"), Auth: r.Header.Get("Authorization"), Body: b})
	w.WriteHeader(d.Status)
	_, _ = io.WriteString(w, `{"payment":"p-1"}`)
}

// Count returns the number of calls received.
func (d *Destination) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.Calls)
}

// Report sets the outcome the destination reports for key.
func (d *Destination) Report(key, outcome string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Outcomes == nil {
		d.Outcomes = map[string]string{}
	}
	d.Outcomes[key] = outcome
}

// Pay is the test tool: a payment of amount to a business record account,
// charged to the budget ops.
var Pay = tools.Tool{ID: "pay", Version: 1, Description: "pay an invoice", Destination: "bank",
	Endpoint: tools.Endpoint{Method: "POST", Path: "/payments"}, MaxHoldAge: "1h", Budget: "ops", AmountArgument: "amount",
	Arguments: []tools.ArgSpec{
		{Name: "amount", Type: tools.ArgMoney, Required: true},
		{Name: "account", Type: tools.ArgResource, Required: true, Namespace: "account", ResourceType: "business.record", Action: "update"},
	}}

// PlainInvoke lets members invoke executor tools.
const PlainInvoke = `{"id":"members-invoke","effect":"allow","actions":["invoke"],"roles":["member"],"when":"resource.attributes.kind == \"executor\""}`

// Policies are the fixture's: members and viewers use the MCP tools;
// members discover executor tools, invoke them by invokeRule, and send to
// approved destinations; leads approve, resolve and write off; members
// update the business records of their projects.
func Policies(invokeRule string) map[string]string {
	p := maps.Clone(r1test.Policies)
	p["tools.json"] = `{"format":"fga.policy/v1","set":"business","resource":"agent.tool","scope":"","rules":[
	  {"id":"members-use-mcp","effect":"allow","actions":["discover","invoke"],"roles":["member","viewer"],"when":"resource.attributes.kind == \"mcp\""},
	  {"id":"members-discover","effect":"allow","actions":["discover"],"roles":["member"],"when":"resource.attributes.kind == \"executor\""},
	  ` + invokeRule + `,
	  {"id":"leads-settle","effect":"allow","actions":["approve","resolve","write-off"],"roles":["lead"],"when":"resource.attributes.kind == \"executor\""}]}`
	p["destinations.json"] = `{"format":"fga.policy/v1","set":"business","resource":"network.destination","scope":"","rules":[
	  {"id":"members-send-approved","effect":"allow","actions":["send"],"roles":["member"],"when":"resource.attributes.approved == true"}]}`
	p["records.json"] = `{"format":"fga.policy/v1","set":"business","resource":"business.record","scope":"","rules":[
	  {"id":"members-update-records","effect":"allow","actions":["update"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`
	return p
}

// Options shape the fixture. Zero values take the defaults.
type Options struct {
	// InvokeRule is the members' invoke rule (PlainInvoke).
	InvokeRule string
	// Mapping is the release's obligation mapping (none).
	Mapping *release.ObligationMapping
	// Status is the destination's answer (200), Limit the budget in cents
	// (100,000).
	Status int
	Limit  int64
	// Reconcilable registers the destination's reconcile path.
	Reconcilable bool
}

func (o Options) defaults() Options {
	if o.InvokeRule == "" {
		o.InvokeRule = PlainInvoke
	}
	if o.Status == 0 {
		o.Status = http.StatusOK
	}
	if o.Limit == 0 {
		o.Limit = 100_000
	}
	return o
}

// Stack returns the stack options the fixture needs.
func (o Options) Stack() r1test.Options {
	o = o.defaults()
	return r1test.Options{Policies: Policies(o.InvokeRule), ObligationMapping: o.Mapping}
}

// Fixture is the installed fixture.
type Fixture struct {
	St   *r1test.Stack
	Svc  *executor.Service
	Dest *Destination
	Inv  *invocation.Store
}

var ctx = context.Background()

// Deploy installs the fixture on a new stack.
func Deploy(t *testing.T, o Options) *Fixture {
	t.Helper()
	return Install(t, r1test.NewWith(t, o.Stack()), o)
}

// Install registers pay, its destination bank (answering o.Status), the
// budget ops of o.Limit cents and the account acct-1 of project p1 on st,
// which was made with o.Stack(), and returns the tools role over it.
func Install(t *testing.T, st *r1test.Stack, o Options) *Fixture {
	t.Helper()
	o = o.defaults()
	if err := toolstore.Migrate(ctx, st.Pool); err != nil {
		t.Fatal(err)
	}
	dest := &Destination{Status: o.Status}
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
	d := tools.Destination{ID: "bank", BaseURL: srv.URL, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, CredentialFile: cred}
	if o.Reconcilable {
		d.ReconcilePath = "/payments/{key}"
	}
	must(ts.PutTool(ctx, r1test.Tenant, Pay, true))
	must(executor.RegisterDestination(ctx, st.Pool, r1test.Tenant, d, map[string]any{"approved": true}))
	must(ts.PutBudget(ctx, r1test.Tenant, "ops", tools.Money{Currency: "EUR", Minor: o.Limit}))
	must(st.Catalog.RegisterTool(ctx, r1test.Tenant, "pay", Pay.Operation(), map[string]any{"name": "pay", "kind": "executor", "destination": "bank"}))
	_, err := st.Pool.Exec(ctx, `INSERT INTO resources VALUES ($1, 'record:acct-1', 'business.record', '', 1, 1, 1, '{"project":"p1"}')`, r1test.Tenant)
	must(err)
	_, err = st.Pool.Exec(ctx, `INSERT INTO aliases VALUES ($1, 'account', 'acct-1', 'record:acct-1')`, r1test.Tenant)
	must(err)
	f := &Fixture{St: st, Dest: dest, Inv: invocation.New(st.Pool, func() time.Time { return *st.Clock })}
	f.Svc = f.Service(t, r1test.Decider{Service: st.Decisions, Adapter: r1test.ToolsAdapter})
	return f
}

// Service builds the tools role over the fixture with decider, after edit
// if set.
func (f *Fixture) Service(t *testing.T, decider enforce.Decider, edit ...func(*executor.Deps)) *executor.Service {
	t.Helper()
	now := func() time.Time { return *f.St.Clock }
	d := executor.Deps{Catalog: f.St.Catalog, Tools: toolstore.New(f.St.Pool), Invocations: f.Inv,
		Reservations: reservation.New(f.St.Pool), Decider: decider, Verifier: f.St.Verifier(executor.Audience),
		Fence: fence.New(f.St.Pool, time.Second, now), Connector: connector.New(5 * time.Second), Worker: "w1", Lease: time.Minute, Now: now}
	for _, e := range edit {
		e(&d)
	}
	svc, err := executor.New(d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// Caller registers id with roles in project p1 and returns it as a caller
// of the tools role.
func (f *Fixture) Caller(t *testing.T, id string, roles ...string) enforce.Caller {
	t.Helper()
	f.St.User(id, roles, "p1")
	return f.St.CallerFor(id, executor.Audience)
}

// Payment is a call of pay for minor cents to acct-1 under key.
func Payment(key string, minor int64) executor.Request {
	return executor.Request{Tool: "pay", Version: 1, IdempotencyKey: key, Args: json.RawMessage(PaymentArgs(minor))}
}

// PaymentArgs are pay's arguments for minor cents to acct-1.
func PaymentArgs(minor int64) string {
	b, _ := json.Marshal(minor)
	return `{"amount":{"currency":"EUR","minor":` + string(b) + `},"account":"acct-1"}`
}
