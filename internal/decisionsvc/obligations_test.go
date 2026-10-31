package decisionsvc

import (
	"encoding/json"
	"slices"
	"testing"

	"fga/internal/decision"
	"fga/internal/release"
	"fga/internal/signing"
)

// TestApplyObligations covers POL-011 and APR-007 at the decision role:
// without a mapping, outputs stay data and a reservation stays unmet; a
// mapped reservation prerequisite becomes an obligation (an approval never
// does); mapped projections merge to the fields they all name, and an
// unmapped output or a denied decision yields none.
func TestApplyObligations(t *testing.T) {
	mapping := &release.ObligationMapping{Version: signing.ObligationsV1, Outputs: map[string]string{"projection": signing.MetadataProjection},
		Prerequisites: map[string]string{"reservation": signing.Reservation}}
	allowed := func(outputs ...map[string]any) decision.CheckResult {
		return decision.CheckResult{Effect: decision.CheckAllow, Outputs: outputs}
	}
	fields := func(o signing.Obligation) []string {
		var p struct {
			Fields []string `json:"fields"`
		}
		_ = json.Unmarshal(o.Parameters, &p)
		return p.Fields
	}
	for name, tc := range map[string]struct {
		m        *release.ObligationMapping
		d        decision.Decision
		outcome  decision.Outcome
		types    []string
		projects []string
	}{
		"no mapping": {nil, decision.Decision{Outcome: decision.OutcomeNeedsReservation, Requires: []string{"reservation"},
			Results: []decision.CheckResult{allowed(map[string]any{"projection": []any{"id"}})}}, decision.OutcomeNeedsReservation, nil, nil},
		"reservation mapped": {mapping, decision.Decision{Outcome: decision.OutcomeNeedsReservation, Requires: []string{"reservation"},
			Results: []decision.CheckResult{allowed()}}, decision.OutcomeAllow, []string{signing.Reservation}, nil},
		"approval never mapped": {mapping, decision.Decision{Outcome: decision.OutcomeNeedsApproval, Requires: []string{"approval", "reservation"},
			Results: []decision.CheckResult{allowed()}}, decision.OutcomeNeedsApproval, nil, nil},
		"projections intersect": {mapping, decision.Decision{Outcome: decision.OutcomeAllow, Results: []decision.CheckResult{
			allowed(map[string]any{"projection": []any{"id", "size", "etag"}}, map[string]any{"note": "data"}),
			allowed(map[string]any{"projection": []any{"etag", "id", "owner"}}),
			allowed()}}, decision.OutcomeAllow, []string{signing.MetadataProjection}, []string{"etag", "id"}},
		"unmapped output": {mapping, decision.Decision{Outcome: decision.OutcomeAllow,
			Results: []decision.CheckResult{allowed(map[string]any{"note": "data"})}}, decision.OutcomeAllow, nil, nil},
		"denied": {mapping, decision.Decision{Outcome: decision.OutcomeDeny,
			Results: []decision.CheckResult{{Effect: decision.CheckDeny}}}, decision.OutcomeDeny, nil, nil},
	} {
		d := tc.d
		version, obligations := applyObligations(tc.m, &d)
		var types []string
		for _, o := range obligations {
			types = append(types, o.Type)
			if o.ParametersDigest != signing.ParametersDigest(o.Parameters) {
				t.Errorf("%s: %s parameters do not match their digest", name, o.Type)
			}
			if o.Type == signing.MetadataProjection && !slices.Equal(fields(o), tc.projects) {
				t.Errorf("%s: projection %v, want %v", name, fields(o), tc.projects)
			}
		}
		wantVersion := signing.ObligationsV1
		if tc.m == nil {
			wantVersion = signing.NoObligations
		}
		if d.Outcome != tc.outcome || version != wantVersion || !slices.Equal(types, tc.types) {
			t.Errorf("%s: %s %s %v, want %s %s %v", name, d.Outcome, version, types, tc.outcome, wantVersion, tc.types)
		}
	}
}
