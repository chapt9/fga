// Package labels holds the label order arithmetic shared by the decision
// role and the enforcing roles (D-06, FLW-004, LAB-001 to LAB-004).
package labels

import (
	"maps"
	"slices"

	"fga/internal/policy"
)

// Rank returns label's position in order, from 0, and whether label is in
// the order. A label outside the order, or no label, counts as the highest
// level (D-06), so its rank is the last position.
func Rank(order []string, label string) (int, bool) {
	if i := slices.Index(order, label); i >= 0 {
		return i, true
	}
	return len(order) - 1, false
}

// Valid reports whether order is a usable label order: at least one label,
// none empty, none repeated.
func Valid(order []string) bool {
	seen := map[string]bool{}
	for _, l := range order {
		if l == "" || seen[l] {
			return false
		}
		seen[l] = true
	}
	return len(order) > 0
}

// Attributes computed from the signed label order before evaluation
// (D-06, FLW-004), by the decision role and by a release's sentinel
// checks. Stored attributes of the same names are dropped, so a policy only
// ever sees computed ranks.
const (
	AttrLabelRank     = "label_rank"
	AttrNewLabelRank  = "new_label_rank"
	AttrFloorRank     = "floor_rank"
	AttrClearanceRank = "clearance_rank"
)

// Ranked returns copies of principal and resource with the label ranks
// added: the resource's label, proposed new label and floor (a missing or
// unknown label ranks highest), and the principal's clearance when it is in
// the order. A principal without a known clearance has no clearance_rank,
// so a condition on it errors and denies (POL-005).
func Ranked(order []string, p policy.Principal, r policy.Resource) (policy.Principal, policy.Resource) {
	pa := maps.Clone(p.Attributes)
	ra := maps.Clone(r.Attributes)
	delete(pa, AttrClearanceRank)
	for _, k := range []string{AttrLabelRank, AttrNewLabelRank, AttrFloorRank} {
		delete(ra, k)
	}
	if len(order) > 0 {
		if ra == nil {
			ra = map[string]any{}
		}
		label, _ := ra["label"].(string)
		rank, _ := Rank(order, label)
		ra[AttrLabelRank] = int64(rank)
		for attr, rankAttr := range map[string]string{"new_label": AttrNewLabelRank, "floor": AttrFloorRank} {
			if v, ok := ra[attr].(string); ok {
				rank, _ := Rank(order, v)
				ra[rankAttr] = int64(rank)
			}
		}
		if c, ok := pa["clearance"].(string); ok {
			if rank, known := Rank(order, c); known {
				pa[AttrClearanceRank] = int64(rank)
			}
		}
	}
	p.Attributes, r.Attributes = pa, ra
	return p, r
}
