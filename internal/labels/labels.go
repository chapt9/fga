// Package labels holds the label order arithmetic shared by the decision
// role and the enforcing roles (D-06, FLW-004, LAB-001 to LAB-004).
package labels

import "slices"

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
