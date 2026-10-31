package fence

import (
	"testing"
	"time"
)

// TestMerge covers the combination of several decisions of one operation
// (DEC-009 batches): shared facts must agree, the earliest expiry and the
// lowest epoch apply, and only one approval may be bound.
func TestMerge(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	a := Binding{DecisionID: "d1", Tenant: "t", Incarnation: 1, PolicyEpoch: 3, ValidUntil: now.Add(time.Minute), SingleUse: true,
		Identities: []Ref{{ID: "alice", Revision: 2}}, Resources: []Resource{{Type: "storage.object", ID: "o", Generation: 4, MetadataRevision: 1}}}
	b := Binding{DecisionID: "d2", Tenant: "t", Incarnation: 1, PolicyEpoch: 2, ValidUntil: now.Add(30 * time.Second), SingleUse: true,
		Identities: []Ref{{ID: "alice", Revision: 2}, {ID: "bob", Revision: 7}}, Keys: []Ref{{ID: "fp", Revision: 1}},
		Resources: []Resource{{Type: "storage.object", ID: "o", Generation: 4, MetadataRevision: 1}, {Type: "document.text_unit", ID: "u", Generation: 1, MetadataRevision: 1}}}
	m, err := Merge([]Binding{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if !m.ValidUntil.Equal(b.ValidUntil) || m.PolicyEpoch != 2 || len(m.Identities) != 2 || len(m.Keys) != 1 || len(m.Resources) != 2 {
		t.Fatalf("merged = %+v", m)
	}
	for name, edit := range map[string]func(*Binding){
		"identity at another revision": func(x *Binding) { x.Identities = []Ref{{ID: "alice", Revision: 3}} },
		"resource in another state": func(x *Binding) {
			x.Resources = []Resource{{Type: "storage.object", ID: "o", Generation: 5, MetadataRevision: 1}}
		},
		"another tenant":      func(x *Binding) { x.Tenant = "u" },
		"another incarnation": func(x *Binding) { x.Incarnation = 2 },
	} {
		c := b
		edit(&c)
		if _, err := Merge([]Binding{a, c}); err == nil {
			t.Errorf("%s: merged", name)
		}
	}
	a.Approval, b.Approval = &Ref{ID: "ap1", Revision: 2}, &Ref{ID: "ap2", Revision: 2}
	if _, err := Merge([]Binding{a, b}); err == nil {
		t.Error("two approvals merged")
	}
}
