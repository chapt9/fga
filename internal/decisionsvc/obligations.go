package decisionsvc

import (
	"encoding/json"
	"slices"

	"fga/internal/decision"
	"fga/internal/policy"
	"fga/internal/release"
	"fga/internal/signing"
)

// applyObligations applies a release's obligation mapping to a decision
// (POL-011, APR-007). A reservation prerequisite that the mapping maps
// becomes a reservation obligation, so a decision that otherwise waits for
// a reservation is signed for the enforcing role to meet it; an approval is
// never mapped. The mapped outputs of every allowed check become
// obligations, merged restrictively: several metadata projections allow
// only the fields they all name. It returns the mapping version and the
// obligations, sorted by type, and adjusts d's outcome.
func applyObligations(m *release.ObligationMapping, d *decision.Decision) (string, []signing.Obligation) {
	if m == nil {
		return signing.NoObligations, nil
	}
	var out []signing.Obligation
	if d.Outcome == decision.OutcomeNeedsReservation && m.Prerequisites[policy.RequireReservation] == signing.Reservation &&
		!slices.Contains(d.Requires, policy.RequireApproval) {
		d.Outcome, d.Reason = decision.OutcomeAllow, ""
		out = append(out, obligation(signing.Reservation, map[string]any{}))
	}
	if d.Outcome != decision.OutcomeAllow {
		return m.Version, nil
	}
	var fields []string
	projected := false
	for _, r := range d.Results {
		for _, o := range r.Outputs {
			for name, v := range o {
				if m.Outputs[name] != signing.MetadataProjection {
					continue
				}
				list := stringList(v)
				if !projected {
					fields, projected = list, true
				} else {
					fields = slices.DeleteFunc(fields, func(f string) bool { return !slices.Contains(list, f) })
				}
			}
		}
	}
	if projected {
		slices.Sort(fields)
		out = append(out, obligation(signing.MetadataProjection, map[string]any{"fields": slices.Compact(fields)}))
	}
	slices.SortFunc(out, func(a, b signing.Obligation) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		return 0
	})
	return m.Version, out
}

// obligation is a version-1 obligation of type t with params.
func obligation(t string, params map[string]any) signing.Obligation {
	raw, _ := json.Marshal(params) // maps of strings and string lists always marshal
	return signing.Obligation{Type: t, Version: 1, Parameters: raw, ParametersDigest: signing.ParametersDigest(raw),
		ReferencedRevisions: []signing.Ref{}}
}

// stringList is a validated list output's strings.
func stringList(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
