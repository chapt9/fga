package mcpsvc

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/httpapi"
	"fga/internal/registry"
	"fga/internal/strictjson"
)

// TestSharedNames pins the names the role copies from the registry and
// the storage role, which it does not link.
func TestSharedNames(t *testing.T) {
	for _, p := range [][2]string{{opInvoke, registry.OpMCPInvoke}, {opDiscover, registry.OpMCPDiscover},
		{toolNamespace, registry.MCPToolNamespace}, {roleTool, registry.RoleTool}, {decisionHeader, httpapi.DecisionHeader}} {
		if p[0] != p[1] {
			t.Errorf("%q, want %q", p[0], p[1])
		}
	}
	if maxSelect != content.MaxSelect {
		t.Errorf("maxSelect %d, want %d", maxSelect, content.MaxSelect)
	}
	if !slices.Equal(Tools, registry.MCPTools) {
		t.Errorf("tools %v, want %v", Tools, registry.MCPTools)
	}
}

// TestWireFormat pins the role's copy of the DecideBatch format: the
// decision role decodes a request strictly, and the role reads the
// outcome, the per-check effects and the signed decision of a response.
func TestWireFormat(t *testing.T) {
	b, err := json.Marshal(decisionRequest{RequestID: "r", Tenant: "t", Operation: opInvoke, OperationID: "o", Audience: "fga-storage",
		Actor: actorRef{ID: "alice"}, Evidence: "token",
		Checks: []toolCheck{{ID: "tool-0", Role: roleTool, Action: "invoke", Resource: toolAlias{Namespace: toolNamespace, Name: ToolSearch}}}})
	if err != nil {
		t.Fatal(err)
	}
	var req decisionsvc.Request
	if err := strictjson.Decode(b, &req); err != nil {
		t.Fatal(err)
	}
	want := decisionsvc.Request{RequestID: "r", Tenant: "t", Operation: opInvoke, OperationID: "o", Audience: "fga-storage",
		Actor: decisionsvc.Ref{ID: "alice"}, Evidence: "token",
		Checks: []decisionsvc.Check{{ID: "tool-0", Role: roleTool, Action: "invoke", Resource: decisionsvc.Alias{Namespace: toolNamespace, Name: ToolSearch}}}}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("decoded %+v", req)
	}

	b, err = json.Marshal(decisionsvc.Response{DecisionID: "d", Outcome: "ALLOW", Results: []decisionsvc.Result{{CheckID: "tool-0", Effect: "ALLOW"}},
		Signed: &decisionsvc.SignedDecision{Payload: "cA==", JWS: "j"}})
	if err != nil {
		t.Fatal(err)
	}
	var resp decisionResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outcome != "ALLOW" || len(resp.Results) != 1 || resp.Results[0].CheckID != "tool-0" || resp.Results[0].Effect != "ALLOW" ||
		resp.Signed == nil || resp.Signed.Payload != "cA==" || resp.Signed.JWS != "j" {
		t.Fatalf("read %+v", resp)
	}
}

// TestResourceURIs covers the fga:// form: keys with any characters round
// trip, and anything but a bucket, a key and at most one version and one
// unit is refused.
func TestResourceURIs(t *testing.T) {
	for _, key := range []string{"plan.txt", "q3/notes.md", "a b/c?d#e%f&g=h", "ünïcode/ключ"} {
		got, ok := parseURI(resourceURI("vault", key))
		if !ok || got != (target{bucket: "vault", key: key}) {
			t.Errorf("%q: %+v %v", key, got, ok)
		}
	}
	if got, ok := parseURI("fga://vault/q3/notes.md?version=v1&unit=u2"); !ok || got != (target{"vault", "q3/notes.md", "v1", "u2"}) {
		t.Errorf("with version and unit: %+v %v", got, ok)
	}
	for _, bad := range []string{"", "file:///etc/passwd", "fga:vault/x", "fga:///x", "fga://vault", "fga://vault/", "fga://u@vault/x",
		"fga://vault/x#f", "fga://vault/x?other=1", "fga://vault/x?version=", "fga://vault/x?unit=a&unit=b", "fga://vault/x?%zz"} {
		if got, ok := parseURI(bad); ok {
			t.Errorf("%q parsed as %+v", bad, got)
		}
	}
}
