package engine

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fga/internal/policy"
	"fga/internal/policy/format"
)

type testSchema map[string][]string

func (s testSchema) HasResourceType(t string) bool { _, ok := s[t]; return ok }
func (s testSchema) HasAction(t, a string) bool    { return slices.Contains(s[t], a) }

var schema = testSchema{"document.text_unit": {"read", "use-in-model", "export-key", "stat"}}

// bundle is the policy set used by the vectors below.
var bundle = []string{
	`{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[
	  {"id":"reviewers-read-own-projects","effect":"allow","actions":["read"],"roles":["reviewer"],
	   "when":"resource.attributes.project_id in principal.attributes.project_ids"},
	  {"id":"banned-user","effect":"deny","actions":["read"],"roles":["*"],"when":"principal.id == 'user-banned'"},
	  {"id":"contractors-never-read","effect":"deny","actions":["read"],"roles":["contractor"]},
	  {"id":"reviewers-use-in-model","effect":"allow","actions":["use-in-model"],"roles":["reviewer"]},
	  {"id":"restricted-not-in-model","effect":"deny","actions":["use-in-model"],"roles":["*"],
	   "when":"resource.attributes.classification == 'restricted'"},
	  {"id":"auditors-export","effect":"allow","actions":["export-key"],"roles":["auditor"]},
	  {"id":"auditors-no-export","effect":"deny","actions":["export-key"],"roles":["auditor"]},
	  {"id":"load-test","effect":"allow","actions":["stat"],"roles":["load-tester"],
	   "when":"principal.attributes.items.all(x, x > 0)"}]}`,
	`{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"acme","rules":[
	  {"id":"acme-analysts-read","effect":"allow","actions":["read"],"roles":["analyst","contractor"]}]}`,
	`{"format":"fga.policy/v1","set":"ceiling","resource":"document.text_unit","scope":"","rules":[
	  {"id":"only-live-units","effect":"deny","actions":["read","use-in-model"],"roles":["*"],
	   "when":"resource.attributes.state != 'LIVE'"}]}`,
}

func compileBundle(t *testing.T, docs []string) *Engine {
	t.Helper()
	var parsed []format.Document
	for _, d := range docs {
		doc, err := format.Parse([]byte(d))
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, doc)
	}
	e, err := Compile("sha256:test", parsed, schema, DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func request(set policy.Set, id string, roles []string, scope string, unit map[string]any, action string) policy.Request {
	return policy.Request{
		SnapshotDigest: "sha256:test",
		Set:            set,
		Principal:      policy.Principal{ID: id, Roles: roles, Attributes: map[string]any{"project_ids": []string{"p1"}}},
		Resource:       policy.Resource{Kind: "document.text_unit", ID: "u-1", Scope: scope, Attributes: unit},
		Actions:        []string{action},
		Now:            time.Unix(1_800_000_000, 0),
	}
}

func TestEvaluateVectors(t *testing.T) {
	e := compileBundle(t, bundle)
	live := map[string]any{"project_id": "p1", "state": "LIVE", "classification": "internal"}
	draft := map[string]any{"project_id": "p1", "state": "DRAFT", "classification": "internal"}
	noClassification := map[string]any{"project_id": "p1", "state": "LIVE"}
	noState := map[string]any{"project_id": "p1"}
	R, C := policy.SetBusiness, policy.SetCeiling

	tests := []struct {
		name        string
		req         policy.Request
		wantEffect  policy.Effect
		wantErrored bool
	}{
		{"V-001 reviewer reads a unit of their project", request(R, "user-42", []string{"reviewer"}, "", live, "read"), policy.EffectAllow, false},
		{"V-003 no rule grants the action", request(R, "user-42", []string{"reviewer"}, "", live, "stat"), policy.EffectDeny, false},
		{"V-004 deny overrides allow in one role", request(R, "user-7", []string{"auditor"}, "", live, "export-key"), policy.EffectDeny, false},
		{"V-005 deny overrides allow across roles", request(R, "user-8", []string{"reviewer", "contractor"}, "", live, "read"), policy.EffectDeny, false},
		{"V-008 per-principal deny condition", request(R, "user-banned", []string{"reviewer"}, "", live, "read"), policy.EffectDeny, false},
		{"V-012 erroring deny condition denies", request(R, "user-42", []string{"reviewer"}, "", noClassification, "use-in-model"), policy.EffectDeny, true},
		{"POL-014 child scope adds an allow", request(R, "user-9", []string{"analyst"}, "acme.eu", live, "read"), policy.EffectAllow, false},
		{"POL-014 the allow does not apply outside its scope", request(R, "user-9", []string{"analyst"}, "", live, "read"), policy.EffectDeny, false},
		{"POL-014 child scope cannot lift a root deny", request(R, "user-10", []string{"contractor"}, "acme", live, "read"), policy.EffectDeny, false},
		{"ceiling has no objection to a LIVE unit", request(C, "user-42", []string{"reviewer"}, "", live, "read"), policy.EffectAllow, false},
		{"V-006 ceiling objects to a DRAFT unit", request(C, "user-42", []string{"reviewer"}, "", draft, "read"), policy.EffectDeny, false},
		{"V-018 ceiling condition error objects", request(C, "user-42", []string{"reviewer"}, "", noState, "read"), policy.EffectDeny, true},
		{"ceiling without rules for the action has no objection", request(C, "user-7", []string{"auditor"}, "", draft, "export-key"), policy.EffectAllow, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := e.Evaluate(context.Background(), tt.req)
			if err != nil {
				t.Fatal(err)
			}
			got := res.Actions[tt.req.Actions[0]]
			if got.Effect != tt.wantEffect || got.Errored != tt.wantErrored {
				t.Fatalf("got %v (errored %v), want %v (errored %v)", got.Effect, got.Errored, tt.wantEffect, tt.wantErrored)
			}
		})
	}
}

// TestEvaluateCannotDecide covers requests the engine must refuse rather
// than answer: an exhausted cost limit (V-016), a cancelled request, another
// bundle's snapshot and an unknown policy set.
func TestEvaluateCannotDecide(t *testing.T) {
	e := compileBundle(t, bundle)
	items := make([]int, 100_000)
	for i := range items {
		items[i] = 1
	}
	costly := request(policy.SetBusiness, "user-11", []string{"load-tester"}, "", map[string]any{}, "stat")
	costly.Principal.Attributes = map[string]any{"items": items}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	otherSnapshot := request(policy.SetBusiness, "user-42", []string{"reviewer"}, "", nil, "read")
	otherSnapshot.SnapshotDigest = "sha256:other"
	unknownSet := request(policy.Set(9), "user-42", []string{"reviewer"}, "", nil, "read")

	for name, tc := range map[string]struct {
		ctx context.Context
		req policy.Request
	}{
		"cost limit (V-016)": {context.Background(), costly},
		"cancelled request":  {cancelled, request(policy.SetBusiness, "user-42", []string{"reviewer"}, "", nil, "read")},
		"another snapshot":   {context.Background(), otherSnapshot},
		"unknown policy set": {context.Background(), unknownSet},
	} {
		if _, err := e.Evaluate(tc.ctx, tc.req); err == nil {
			t.Errorf("%s: Evaluate succeeded, want an error", name)
		}
	}
}

func TestCompileRejectsBadConditions(t *testing.T) {
	for name, when := range map[string]string{
		"not boolean":      "principal.id",
		"syntax error":     "principal.id ==",
		"unknown variable": "subject.id == 'x'",
	} {
		doc := strings.Replace(bundle[1], `"roles":["analyst","contractor"]}`, `"roles":["analyst"],"when":"`+when+`"}`, 1)
		parsed, err := format.Parse([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Compile("sha256:test", []format.Document{parsed}, schema, DefaultOptions); err == nil {
			t.Errorf("%s: Compile succeeded, want an error", name)
		}
	}
}

// TestEvaluateConcurrently runs under the race detector to back the claim
// that a compiled engine is safe for concurrent use.
func TestEvaluateConcurrently(t *testing.T) {
	e := compileBundle(t, bundle)
	live := map[string]any{"project_id": "p1", "state": "LIVE"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := e.Evaluate(context.Background(), request(policy.SetBusiness, "user-42", []string{"reviewer"}, "", live, "read"))
				if err != nil || res.Actions["read"].Effect != policy.EffectAllow {
					t.Errorf("concurrent evaluation = %v, %v", res, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestRequiresAreTheUnionOfMatchingAllows covers APR-007: prerequisites from
// every matching allow rule are combined, and a deny leaves none.
func TestRequiresAreTheUnionOfMatchingAllows(t *testing.T) {
	e := compileBundle(t, []string{`{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[
	  {"id":"read-with-approval","effect":"allow","actions":["read"],"roles":["reviewer"],"requires":["approval"]},
	  {"id":"read-large-with-budget","effect":"allow","actions":["read"],"roles":["reviewer"],"requires":["reservation"],
	   "when":"resource.attributes.size > 100"},
	  {"id":"no-contractors","effect":"deny","actions":["read"],"roles":["contractor"]}]}`})
	for name, tc := range map[string]struct {
		roles []string
		size  int
		want  []string
	}{
		"one matching allow":   {[]string{"reviewer"}, 10, []string{"approval"}},
		"two matching allows":  {[]string{"reviewer"}, 500, []string{"approval", "reservation"}},
		"deny leaves no allow": {[]string{"reviewer", "contractor"}, 500, nil},
	} {
		res, err := e.Evaluate(context.Background(), request(policy.SetBusiness, "user-42", tc.roles, "", map[string]any{"size": tc.size}, "read"))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Actions["read"].Requires; !slices.Equal(got, tc.want) {
			t.Errorf("%s: requires = %v, want %v", name, got, tc.want)
		}
	}
}

// TestExpressionLibraryMatchesModule keeps the environment identity of
// release manifests (REL-001) in step with the pinned cel-go version.
func TestExpressionLibraryMatchesModule(t *testing.T) {
	mod, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mod), "\n\t"+ExpressionLibrary+"\n") {
		t.Fatalf("go.mod does not require %q", ExpressionLibrary)
	}
}
