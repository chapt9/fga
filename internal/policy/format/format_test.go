package format

import (
	"slices"
	"strings"
	"testing"
)

type testSchema map[string][]string

func (s testSchema) HasResourceType(t string) bool { _, ok := s[t]; return ok }
func (s testSchema) HasAction(t, a string) bool    { return slices.Contains(s[t], a) }

var schema = testSchema{"document.text_unit": {"read", "use-in-model"}}

const validDoc = `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"acme",
 "rules":[{"id":"r1","effect":"allow","actions":["read"],"roles":["reviewer"],"when":"true"}]}`

func TestParseRejectsAmbiguousInput(t *testing.T) {
	tests := []struct{ name, doc, wantErr string }{
		{"unknown field (V-010)", strings.Replace(validDoc, `"scope":"acme"`, `"scope":"acme","lenient":true`, 1), "unknown field"},
		{"duplicate field", strings.Replace(validDoc, `"scope":"acme"`, `"scope":"acme","scope":""`, 1), "duplicate field"},
		{"trailing data", validDoc + ` {}`, "trailing data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
	if _, err := Parse([]byte(validDoc)); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
}

func TestValidateBundle(t *testing.T) {
	valid, err := Parse([]byte(validDoc))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle([]Document{valid}, schema); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}

	tests := []struct {
		name    string
		edit    func(*Document)
		wantErr string
	}{
		{"unsupported format (V-014)", func(d *Document) { d.Format = "fga.policy/v2" }, "unsupported format"},
		{"unknown policy set", func(d *Document) { d.Set = "tenant" }, "unknown policy set"},
		{"unknown resource type", func(d *Document) { d.Resource = "storage.object" }, "unknown resource type"},
		{"unregistered action (V-011)", func(d *Document) { d.Rules[0].Actions = []string{"export"} }, "not registered"},
		{"allow rule in the ceiling set (V-017)", func(d *Document) { d.Set = SetCeiling }, "only deny rules"},
		{"invalid scope", func(d *Document) { d.Scope = "Acme..eu" }, "invalid scope"},
		{"no rules", func(d *Document) { d.Rules = nil }, "no rules"},
		{"unknown effect", func(d *Document) { d.Rules[0].Effect = "permit" }, "unknown effect"},
		{"no roles", func(d *Document) { d.Rules[0].Roles = nil }, "no roles"},
		{"oversized condition", func(d *Document) { d.Rules[0].When = strings.Repeat("x", MaxConditionBytes+1) }, "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := Parse([]byte(validDoc))
			tt.edit(&d)
			if err := ValidateBundle([]Document{d}, schema); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("duplicate rule id and document", func(t *testing.T) {
		err := ValidateBundle([]Document{valid, valid}, schema)
		if err == nil || !strings.Contains(err.Error(), "duplicate rule id") || !strings.Contains(err.Error(), "same set") {
			t.Fatalf("error = %v, want duplicate rule id and duplicate document", err)
		}
	})
}

func TestScopeChain(t *testing.T) {
	for scope, want := range map[string][]string{
		"":        {""},
		"acme":    {"acme", ""},
		"acme.eu": {"acme.eu", "acme", ""},
	} {
		if got := ScopeChain(scope); !slices.Equal(got, want) {
			t.Errorf("ScopeChain(%q) = %q, want %q", scope, got, want)
		}
	}
}

func TestValidatePrerequisites(t *testing.T) {
	for name, tc := range map[string]struct {
		edit    func(*Document)
		wantErr string
	}{
		"unknown prerequisite":        {func(d *Document) { d.Rules[0].Requires = []string{"blessing"} }, "unknown prerequisite"},
		"prerequisite on a deny rule": {func(d *Document) { d.Rules[0].Effect, d.Rules[0].Requires = EffectDeny, []string{RequireApproval} }, "only business allow"},
	} {
		d, _ := Parse([]byte(validDoc))
		tc.edit(&d)
		if err := ValidateBundle([]Document{d}, schema); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %v, want containing %q", name, err, tc.wantErr)
		}
	}
	d, _ := Parse([]byte(validDoc))
	d.Rules[0].Requires = []string{RequireApproval, RequireReservation}
	if err := ValidateBundle([]Document{d}, schema); err != nil {
		t.Errorf("an allow rule requiring approval and a reservation was rejected: %v", err)
	}
}
