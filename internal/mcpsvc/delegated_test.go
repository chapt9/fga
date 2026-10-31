package mcpsvc_test

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/delegation"
	"fga/internal/executor"
	"fga/internal/executortest"
	"fga/internal/mcpsvc"
	"fga/internal/mcptest"
	"fga/internal/mcpwire"
	"fga/internal/r1test"
)

// TestMCPDelegatedAgent covers DLG-001 to DLG-005, MCP-006 and MCP-007 for
// an agent acting for a user through the MCP role: the agent names only
// its delegation; it reads what the user may read and the delegation
// grants, and calls a registered tool, which the tools role records with
// the agent as actor and the user as subject. A delegation that does not
// grant reading, one naming another agent, none at all, a session reused
// under another delegation, and a revoked delegation all refuse.
func TestMCPDelegatedAgent(t *testing.T) {
	o := executortest.Options{}
	var f *executortest.Fixture
	d := mcptest.DeployWith(t, mcptest.Options{Limits: mcpsvc.DefaultLimits, Stack: o.Stack(), Tools: func(st *r1test.Stack) *executor.Service {
		f = executortest.Install(t, st, o)
		return f.Svc
	}})
	serverDocument(t, d)
	f.Caller(t, "agent-7", "agent")
	f.Caller(t, "agent-8", "agent")
	everything := []delegation.Grant{}
	for typ := range r1test.UserActions {
		everything = append(everything, delegation.Grant{ResourceType: typ, Actions: []string{delegation.AllActions}})
	}
	tools := []delegation.Grant{{ResourceType: "agent.tool", Actions: []string{"discover", "invoke"}},
		{ResourceType: "network.destination", Actions: []string{"send"}}, {ResourceType: "business.record", Actions: []string{"update"}}}
	for id, grants := range map[string][]delegation.Grant{"dlg-all": everything, "dlg-tools": tools} {
		if err := d.St.Catalog.PutDelegation(ctx, delegation.Delegation{ID: delegation.ID(id), Tenant: r1test.Tenant, Actor: "agent-7",
			Subject: "alice", Audience: r1test.MCPAdapter, Grants: grants, ExpiresAt: d.St.Clock.Add(time.Hour)}, *d.St.Clock); err != nil {
			t.Fatal(err)
		}
	}
	// narrow is a session (MCP-007); the others speak the sessionless
	// protocol, naming the delegation on every request.
	session := func(agent, dlg, protocol string) *mcp.ClientSession {
		t.Helper()
		s, err := d.ConnectWith(t, mcptest.Conn{User: agent, Delegation: dlg, Protocol: protocol})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	readNotes := func(s *mcp.ClientSession) (string, error) {
		return call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil)
	}

	all := session("agent-7", "dlg-all", "")
	if text, err := readNotes(all); err != nil || !strings.Contains(text, "First paragraph.") {
		t.Fatalf("the agent for alice reads her document: %q %v", text, err)
	}

	narrow := session("agent-7", "dlg-tools", mcptest.Stateful)
	if _, err := readNotes(narrow); err == nil {
		t.Fatal("a delegation without read access read the document")
	}
	if !slices.Contains(toolNames(t, narrow), mcpsvc.RegisteredPrefix+"pay") {
		t.Fatal("the agent does not see the registered tool")
	}
	var out struct {
		Invocation string `json:"invocation_id"`
		State      string `json:"state"`
	}
	if _, err := call(narrow, "tool.pay", map[string]any{"version": 1, "idempotency_key": "a-1",
		"arguments": jsonValue(t, executortest.PaymentArgs(1200))}, &out); err != nil || out.State != "SUCCEEDED" {
		t.Fatalf("the agent calls pay for alice: %+v %v", out, err)
	}
	if inv, err := f.Inv.Get(ctx, r1test.Tenant, out.Invocation); err != nil || inv.Actor != "agent-7" || inv.Subject != "alice" ||
		inv.Delegation != "dlg-tools" {
		t.Fatalf("the invocation's identities: %+v %v", inv, err)
	}
	if got, err := f.Svc.Get(ctx, d.St.CallerFor("alice", executor.Audience), out.Invocation); err != nil || got.State != "SUCCEEDED" {
		t.Fatalf("alice sees what her agent did: %+v %v", got, err)
	}

	for name, s := range map[string]*mcp.ClientSession{
		"another agent under alice's delegation": session("agent-8", "dlg-all", ""),
		"the agent without a delegation":         session("agent-7", "", ""),
	} {
		if _, err := readNotes(s); err == nil {
			t.Errorf("%s read the document", name)
		}
	}

	// The session is bound to its delegation (MCP-007).
	post := func(dlg string) int {
		req, _ := http.NewRequest(http.MethodPost, d.MCP.URL+"/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Session-Id", narrow.ID())
		req.Header.Set("Mcp-Protocol-Version", narrow.InitializeResult().ProtocolVersion)
		req.Header.Set("Authorization", "Bearer "+d.Token(t, "agent-7"))
		req.Header.Set(mcpwire.DelegationHeader, dlg)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("dlg-tools"); code != http.StatusOK {
		t.Fatalf("the agent in its session: %d", code)
	}
	if code := post("dlg-all"); code != http.StatusForbidden {
		t.Fatalf("the session under another delegation: %d", code)
	}

	// Revocation ends the delegation for every session (DLG-005).
	if err := d.St.Catalog.RevokeDelegation(ctx, r1test.Tenant, "dlg-all"); err != nil {
		t.Fatal(err)
	}
	if _, err := readNotes(all); err == nil {
		t.Fatal("a revoked delegation still reads")
	}
}
