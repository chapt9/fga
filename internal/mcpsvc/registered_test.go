package mcpsvc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/executor"
	"fga/internal/executortest"
	"fga/internal/mcpsvc"
	"fga/internal/mcptest"
	"fga/internal/r1test"
)

// TestMCPRegisteredTools covers AGT-002 and AGT-003 through the MCP role
// (R2 executor E2): a member's tools/list shows the tools role's
// registered tool, with its argument schema, and a call of it is decided
// for the member, carried out once by the tools role with the member as
// actor, and an approval the policy requires is asked for and then used;
// a user who may use MCP but not the tool sees and calls nothing, and a
// call outside the tool's schema or of another version is refused.
func TestMCPRegisteredTools(t *testing.T) {
	o := executortest.Options{InvokeRule: `{"id":"members-invoke-small","effect":"allow","actions":["invoke"],"roles":["member"],
	  "when":"resource.attributes.kind == \"executor\" && request.operation.amount_minor <= 5000"},
	  {"id":"members-invoke-large","effect":"allow","actions":["invoke"],"roles":["member"],"requires":["approval"],
	  "when":"resource.attributes.kind == \"executor\" && request.operation.amount_minor > 5000"}`}
	var f *executortest.Fixture
	d := mcptest.DeployWith(t, mcptest.Options{Limits: mcpsvc.DefaultLimits, Stack: o.Stack(), Tools: func(st *r1test.Stack) *executor.Service {
		f = executortest.Install(t, st, o)
		return f.Svc
	}})
	if err := d.St.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	f.Caller(t, "alice", "member")
	f.Caller(t, "vera", "viewer")
	f.Caller(t, "lena", "lead")
	alice, vera := connect(t, d, "alice", ""), connect(t, d, "vera", "")

	res, err := alice.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(res.Tools, func(tool *mcp.Tool) bool { return tool.Name == mcpsvc.RegisteredPrefix+"pay" })
	if i < 0 {
		t.Fatalf("alice's tools: %v", toolNames(t, alice))
	}
	if schema, _ := res.Tools[i].InputSchema.(map[string]any); !strings.Contains(jsonOf(t, schema), `"const":1`) ||
		!strings.Contains(jsonOf(t, schema), `"account"`) {
		t.Fatalf("pay's input schema: %v", res.Tools[i].InputSchema)
	}
	if slices.Contains(toolNames(t, vera), mcpsvc.RegisteredPrefix+"pay") {
		t.Fatal("vera discovers pay")
	}

	args := func(key string, minor int64) map[string]any {
		return map[string]any{"version": 1, "idempotency_key": key, "arguments": jsonValue(t, executortest.PaymentArgs(minor))}
	}
	var out struct {
		Invocation string `json:"invocation_id"`
		State      string `json:"state"`
		Approval   string `json:"approval_id"`
	}
	if _, err := call(alice, "tool.pay", args("small", 4000), &out); err != nil || out.State != "SUCCEEDED" || f.Dest.Count() != 1 ||
		f.Dest.Calls[0].Key != out.Invocation {
		t.Fatalf("a small payment: %+v %v", out, err)
	}
	if inv, err := f.Inv.Get(ctx, r1test.Tenant, out.Invocation); err != nil || inv.Actor != "alice" {
		t.Fatalf("the invocation's actor: %+v %v", inv, err)
	}
	out.State = ""
	text, err := call(alice, "tool.pay", args("large", 9000), &out)
	if err != nil || out.Approval == "" || !strings.Contains(text, "approval required") || f.Dest.Count() != 1 {
		t.Fatalf("a large payment: %q %+v %v", text, out, err)
	}
	if _, err := d.St.Content.DecideApproval(ctx, d.St.Caller("lena"), out.Approval, true); err != nil {
		t.Fatal(err)
	}
	approved := args("large", 9000)
	approved["approval"] = out.Approval
	if _, err := call(alice, "tool.pay", approved, &out); err != nil || out.State != "SUCCEEDED" || f.Dest.Count() != 2 {
		t.Fatalf("with the approval: %+v %v", out, err)
	}

	for name, a := range map[string]map[string]any{
		"an argument outside the schema": {"version": 1, "idempotency_key": "x1", "arguments": jsonValue(t, `{"amount":{"currency":"EUR","minor":1},"account":"acct-1","to":"x"}`)},
		"another version":                {"version": 2, "idempotency_key": "x2", "arguments": jsonValue(t, executortest.PaymentArgs(1))},
		"a field the call does not have": {"version": 1, "idempotency_key": "x3", "arguments": jsonValue(t, executortest.PaymentArgs(1)), "actor": "bob"},
	} {
		if _, err := call(alice, "tool.pay", a, nil); err == nil {
			t.Errorf("%s was carried out", name)
		}
	}
	if _, err := call(vera, "tool.pay", args("v-1", 100), nil); err == nil {
		t.Fatal("vera called pay")
	}
	if _, err := call(alice, "tool.wire", args("w-1", 100), nil); err == nil {
		t.Fatal("an unregistered tool was called")
	}
	if f.Dest.Count() != 2 {
		t.Fatalf("%d dispatches", f.Dest.Count())
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jsonValue(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestMCPRegisteredToolsUnreadable covers review v4 F14: an answer of the
// tools role that cannot be read, or lacks what it must say, is an error
// for the MCP client, never a result.
func TestMCPRegisteredToolsUnreadable(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"truncated":              {http.StatusOK, `{"invocation_id":"i-1","st`},
		"no state":               {http.StatusOK, `{"invocation_id":"i-1"}`},
		"approval without an ID": {http.StatusAccepted, `{"status":"APPROVAL_REQUIRED"}`},
	}
	var current string
	tools := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := answers[current]
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	t.Cleanup(tools.Close)
	d := mcptest.DeployWith(t, mcptest.Options{Limits: mcpsvc.DefaultLimits, Edit: func(deps *mcpsvc.Deps) {
		deps.Tools, deps.ToolsAudience = mcpsvc.Peer{URL: tools.URL, HTTP: http.DefaultClient}, executor.Audience
	}})
	serverDocument(t, d)
	alice := connect(t, d, "alice", "")
	for name := range answers {
		current = name
		if text, err := call(alice, "tool.pay", map[string]any{"version": 1, "idempotency_key": "k", "arguments": map[string]any{}}, nil); err == nil {
			t.Errorf("%s: a result %q", name, text)
		}
	}
}
