package labels

import (
	"testing"

	"fga/internal/policy"
)

// TestLabelRanks covers D-06: ranks come from the batch's label order,
// stored rank attributes are dropped, a missing or unknown label ranks
// highest, and an unknown clearance gives no clearance rank.
func TestLabelRanks(t *testing.T) {
	order := []string{"public", "internal", "confidential", "restricted"}
	p := policy.Principal{ID: "u", Attributes: map[string]any{"clearance": "confidential", "clearance_rank": int64(9)}}
	r := policy.Resource{Kind: "storage.object", Attributes: map[string]any{"label": "internal", "new_label": "secret", "floor": "public", "label_rank": int64(0)}}
	gp, gr := Ranked(order, p, r)
	want := map[string]any{"label_rank": int64(1), "new_label_rank": int64(3), "floor_rank": int64(0)}
	for k, v := range want {
		if gr.Attributes[k] != v {
			t.Errorf("resource %s = %v, want %v", k, gr.Attributes[k], v)
		}
	}
	if gp.Attributes["clearance_rank"] != int64(2) {
		t.Errorf("clearance_rank = %v", gp.Attributes["clearance_rank"])
	}
	if r.Attributes["label_rank"] != int64(0) || p.Attributes["clearance_rank"] != int64(9) {
		t.Error("ranked changed its inputs")
	}
	gp, gr = Ranked(order, policy.Principal{Attributes: map[string]any{"clearance": "top", "clearance_rank": int64(3)}}, policy.Resource{})
	if _, ok := gp.Attributes["clearance_rank"]; ok || gr.Attributes["label_rank"] != int64(3) {
		t.Errorf("unknown clearance or missing label: %v, %v", gp.Attributes, gr.Attributes)
	}
	gp, gr = Ranked(nil, p, r)
	if _, ok := gp.Attributes["clearance_rank"]; ok {
		t.Error("a stored clearance_rank survived without an order")
	}
	if _, ok := gr.Attributes["label_rank"]; ok {
		t.Error("a stored label_rank survived without an order")
	}
}
