package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixture is a fixture file of schema fga.fixture/v1.
type Fixture struct {
	Schema       string          `json:"schema"`
	CaseID       string          `json:"case_id"`
	Kind         string          `json:"kind"`
	InitialState json.RawMessage `json:"initial_state"`
	Inputs       []map[string]any
	Schedule     []struct {
		Step    string `json:"step"`
		Request string `json:"request"`
	} `json:"schedule"`
	Assertions []struct {
		Path      string `json:"path"`
		Equals    any    `json:"equals"`
		NotEquals any    `json:"not_equals"`
		AtMost    string `json:"at_most"`
	} `json:"assertions"`
	digest string
}

func load(t *testing.T, caseID string) *Fixture {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "spec", "vectors", "fixtures", strings.ToLower(caseID)+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f Fixture
	if err := json.Unmarshal(raw, &f); err != nil || f.Schema != "fga.fixture/v1" || f.CaseID != caseID {
		t.Fatalf("fixture %s: %v", caseID, err)
	}
	sum := sha256.Sum256(raw)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	return &f
}

// input returns the named input of the fixture.
func (f *Fixture) input(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, in := range f.Inputs {
		if in["id"] == id {
			return in
		}
	}
	t.Fatalf("%s: no input %q", f.CaseID, id)
	return nil
}

// check evaluates the fixture's assertions against observed values by
// path and logs the run line.
func (f *Fixture) check(t *testing.T, observed map[string]any) {
	t.Helper()
	failed := false
	norm := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for _, a := range f.Assertions {
		got, ok := observed[a.Path]
		switch {
		case !ok:
			t.Errorf("%s: no observation for %s", f.CaseID, a.Path)
			failed = true
		case a.Equals != nil && norm(got) != norm(a.Equals):
			t.Errorf("%s: %s = %s, want %s", f.CaseID, a.Path, norm(got), norm(a.Equals))
			failed = true
		case a.NotEquals != nil && norm(got) == norm(a.NotEquals):
			t.Errorf("%s: %s = %s, want anything else", f.CaseID, a.Path, norm(got))
			failed = true
		case a.AtMost != "":
			limit, err1 := time.Parse(time.RFC3339, a.AtMost)
			gotT, ok := got.(time.Time)
			if err1 != nil || !ok || gotT.After(limit) {
				t.Errorf("%s: %s = %v, want at most %s", f.CaseID, a.Path, got, a.AtMost)
				failed = true
			}
		}
	}
	result := "PASS"
	if failed {
		result = "FAIL"
	}
	t.Logf("CASE %s fixture %s %s", f.CaseID, f.digest, result)
}

// unbound reports a case this implementation cannot express.
func (f *Fixture) unbound(t *testing.T, reason string) {
	t.Helper()
	t.Logf("CASE %s fixture %s UNBOUND: %s", f.CaseID, f.digest, reason)
	t.Skipf("UNBOUND: %s", reason)
}

func mustTime(t *testing.T, s any) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s.(string))
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
