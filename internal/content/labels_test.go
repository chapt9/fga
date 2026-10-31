package content_test

import (
	"errors"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
	"fga/internal/registry"
)

// objectLabel reads an object's stored label and metadata revision.
func objectLabel(t *testing.T, st *r1test.Stack, key string) (string, uint64) {
	t.Helper()
	var label string
	var meta uint64
	err := st.Pool.QueryRow(ctx, `SELECT r.attributes->>'label', r.metadata_revision FROM objects o
	                               JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text WHERE o.key = $1`, key).Scan(&label, &meta)
	if err != nil {
		t.Fatal(err)
	}
	return label, meta
}

func withApproval(c content.Caller, id string) content.Caller {
	c.Approval = id
	return c
}

// TestLabelChanges covers LAB-002 to LAB-005: raising needs label,
// lowering needs relabel (here with an approval), a label outside the
// order or below the bucket floor is refused, and a change advances the
// metadata revision.
func TestLabelChanges(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	out, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "confidential")
	if err != nil || out.Previous != "internal" || out.MetadataRevision != 2 {
		t.Fatalf("raise = %+v, %v", out, err)
	}
	if label, meta := objectLabel(t, st, "doc"); label != "confidential" || meta != 2 {
		t.Fatalf("stored label %s at revision %d", label, meta)
	}
	for _, label := range []string{"public", "secret", ""} {
		if _, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", label); !errors.Is(err, content.ErrInvalid) {
			t.Errorf("label %q: %v, want invalid", label, err)
		}
	}
	if _, err := st.Content.SetLabel(ctx, bob.Caller, "reports", "doc", "restricted"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a non-owner raised the label: %v", err)
	}
	// Lowering is relabel, which the fixture policy allows only with an
	// approval.
	_, err = st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "internal")
	var need *content.ApprovalRequired
	if !errors.As(err, &need) {
		t.Fatalf("lowering without approval: %v", err)
	}
	if label, _ := objectLabel(t, st, "doc"); label != "confidential" {
		t.Fatalf("label changed before approval: %s", label)
	}
	_, err = st.Content.SetLabel(ctx, withApproval(alice.Caller, need.ID), "reports", "doc", "internal")
	var again *content.ApprovalRequired
	if !errors.As(err, &again) || again.ID != need.ID {
		t.Fatalf("retry while pending: %v", err)
	}
	lena := st.User("lena", []string{"member", "lead"}, "p1")
	views, _, err := st.Content.PendingApprovals(ctx, lena, "", 10)
	if err != nil || len(views) != 1 || views[0].ID != need.ID || views[0].Plan.Action != "relabel" ||
		views[0].Plan.Changes["label"] != "internal" || views[0].RequestedBy != "alice" {
		t.Fatalf("approver's list = %+v, %v", views, err)
	}
	if views, _, err := st.Content.PendingApprovals(ctx, bob.Caller, "", 10); err != nil || len(views) != 0 {
		t.Fatalf("a member without approve sees %+v, %v", views, err)
	}
	if _, err := st.Content.DecideApproval(ctx, bob.Caller, need.ID, true); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member without approve decided: %v", err)
	}
	if v, err := st.Content.DecideApproval(ctx, lena, need.ID, true); err != nil || v.State != "APPROVED" {
		t.Fatalf("approve = %+v, %v", v, err)
	}
	out, err = st.Content.SetLabel(ctx, withApproval(alice.Caller, need.ID), "reports", "doc", "internal")
	if err != nil || out.Label != "internal" || out.MetadataRevision != 3 {
		t.Fatalf("approved lowering = %+v, %v", out, err)
	}
	var state string
	_ = st.Pool.QueryRow(ctx, `SELECT state FROM approvals WHERE id = $1`, need.ID).Scan(&state)
	if state != "CONSUMED" {
		t.Fatalf("approval state = %s, want CONSUMED", state)
	}
	if _, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "restricted"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.SetLabel(ctx, withApproval(alice.Caller, need.ID), "reports", "doc", "internal"); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("a consumed approval was used again: %v", err)
	}
	var events int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'RELABELED'
	                           AND event->'targets' @> '[{"type":"platform.approval"}]'`).Scan(&events)
	if events != 1 {
		t.Fatalf("relabel audit events naming the approval = %d, want 1", events)
	}
}

// TestApprovalBinding covers APR-001 and APR-002: an approval covers only
// the operation and resource state it was requested for, is decided only
// by someone other than the requester, and an approval for one requester
// does not serve another.
func TestApprovalBinding(t *testing.T) {
	policies := map[string]string{}
	for name, doc := range r1test.Policies {
		policies[name] = doc
	}
	// Deleting needs an approval; leads may delete too (to test another
	// requester using the approval).
	policies["objects.json"] = strings.Replace(policies["objects.json"], `"new-version","delete","delete-version"`, `"new-version","delete-version"`, 1)
	policies["objects.json"] = strings.Replace(policies["objects.json"], `"rules":[`, `"rules":[
	  {"id":"delete-with-approval","effect":"allow","actions":["delete"],"roles":["member"],"requires":["approval"],
	   "when":"resource.attributes.project in principal.attributes.projects"},`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member", "lead"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("one")); err != nil {
		t.Fatal(err)
	}
	_, err := st.Content.DeleteKey(ctx, alice.Caller, "reports", "doc")
	var need *content.ApprovalRequired
	if !errors.As(err, &need) {
		t.Fatalf("delete without approval: %v", err)
	}
	if _, err := st.Content.DecideApproval(ctx, alice.Caller, need.ID, true); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("the requester approved its own request: %v", err)
	}
	lena := st.User("lena", []string{"member", "lead"}, "p1")
	if _, err := st.Content.DecideApproval(ctx, lena, need.ID, true); err != nil {
		t.Fatal(err)
	}
	// Another requester cannot use it.
	if _, err := st.Content.DeleteKey(ctx, withApproval(lena, need.ID), "reports", "doc"); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("another requester used the approval: %v", err)
	}
	// A change to the object after the request invalidates it.
	if _, err := alice.Put("reports", "doc", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.DeleteKey(ctx, withApproval(alice.Caller, need.ID), "reports", "doc"); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("approval used after the object changed: %v", err)
	}
	// A fresh request, approved, deletes once.
	_, err = st.Content.DeleteKey(ctx, alice.Caller, "reports", "doc")
	if !errors.As(err, &need) {
		t.Fatalf("second request: %v", err)
	}
	if _, err := st.Content.DecideApproval(ctx, lena, need.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.DeleteKey(ctx, withApproval(alice.Caller, need.ID), "reports", "doc"); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("a rejected approval was used: %v", err)
	}
	_, err = st.Content.DeleteKey(ctx, alice.Caller, "reports", "doc")
	if !errors.As(err, &need) {
		t.Fatalf("third request: %v", err)
	}
	if _, err := st.Content.DecideApproval(ctx, lena, need.ID, true); err != nil {
		t.Fatal(err)
	}
	if out, err := st.Content.DeleteKey(ctx, withApproval(alice.Caller, need.ID), "reports", "doc"); err != nil || out.State != "DELETE_MARKER" {
		t.Fatalf("approved delete = %+v, %v", out, err)
	}
}

// TestLabeledUpload covers LAB-002 at publication: an explicit label must
// be in the order and not below the floor, and publishing it needs label
// on the planned object; an existing key keeps its label.
func TestLabeledUpload(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", Label: "confidential"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(u); err != nil {
		t.Fatal(err)
	}
	if label, meta := objectLabel(t, st, "doc"); label != "confidential" || meta != 1 {
		t.Fatalf("label %s at revision %d", label, meta)
	}
	if _, err := st.Content.Begin(ctx, alice.Caller, content.BeginRequest{Bucket: "reports", Key: "low", IdempotencyKey: "k1", Label: "public"}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("label below the floor: %v", err)
	}
	if _, err := st.Content.Begin(ctx, alice.Caller, content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "k2", Label: "restricted"}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("relabel through upload: %v", err)
	}
}

// TestClearanceRanks covers D-06's computed ranks: a policy may bound the
// labels a principal sets by its clearance, and a stored clearance_rank
// attribute is ignored.
func TestClearanceRanks(t *testing.T) {
	policies := map[string]string{}
	for name, doc := range r1test.Policies {
		policies[name] = doc
	}
	policies["objects.json"] = strings.Replace(policies["objects.json"], `"share","label","export"]`, `"share","export"]`, 1)
	if strings.Contains(policies["objects.json"], `"share","label"`) {
		t.Fatal("the owner's unconditional label right is still in the policy")
	}
	policies["objects.json"] = strings.Replace(policies["objects.json"], `"rules":[`, `"rules":[
	  {"id":"label-within-clearance","effect":"allow","actions":["label"],"roles":["*"],
	   "when":"resource.attributes.owner == principal.id && resource.attributes.new_label_rank <= principal.attributes.clearance_rank"},`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	set := func(attrs map[string]any, label string) error {
		attrs["projects"] = []string{"p1"}
		if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "alice", []string{"member"}, attrs, nil); err != nil {
			t.Fatal(err)
		}
		_, err := st.Content.SetLabel(ctx, st.Caller("alice"), "reports", "doc", label)
		return err
	}
	if err := set(map[string]any{"clearance": "confidential"}, "confidential"); err != nil {
		t.Fatalf("label within clearance: %v", err)
	}
	if err := set(map[string]any{"clearance": "confidential"}, "restricted"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("label above clearance: %v", err)
	}
	if err := set(map[string]any{"clearance_rank": 3}, "restricted"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a stored clearance_rank counted: %v", err)
	}
}

// TestUnitAndDerivedLabels covers LAB-004 for document units and derived
// outputs: raising is label, lowering is relabel (with an approval in the
// fixture), never below the bucket floor; a derived output can be lowered
// below its lineage maximum only through relabel; text entries are not
// labelled alone.
func TestUnitAndDerivedLabels(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	lena := st.User("lena", []string{"member", "lead"}, "p1")
	up, err := alice.PrepareDocument("reports", "q3.md", []string{"a", "b"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	unit := up.Intent.Units[0].Unit
	resourceLabel := func(id string) string {
		var l string
		_ = st.Pool.QueryRow(ctx, `SELECT attributes->>'label' FROM resources WHERE id = $1`, id).Scan(&l)
		return l
	}
	if out, err := st.Content.SetUnitLabel(ctx, alice.Caller, "reports", "q3.md", "", unit, "confidential"); err != nil || out.MetadataRevision != 2 {
		t.Fatalf("raise a unit = %+v, %v", out, err)
	}
	if _, err := st.Content.SetUnitLabel(ctx, bob.Caller, "reports", "q3.md", "", unit, "restricted"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member labelled alice's unit: %v", err)
	}
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "reports", "q3.md", "", unit, "public"); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a unit below the floor: %v", err)
	}
	lower := func(set func(content.Caller) (content.LabelOutcome, error)) {
		t.Helper()
		_, err := set(alice.Caller)
		var need *content.ApprovalRequired
		if !errors.As(err, &need) {
			t.Fatalf("lowering without approval: %v", err)
		}
		if _, err := st.Content.DecideApproval(ctx, lena, need.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := set(withApproval(alice.Caller, need.ID)); err != nil {
			t.Fatalf("approved lowering: %v", err)
		}
	}
	// The derived output's lineage maximum is the unit's confidential.
	p, err := alice.PutDerived("reports", "summary", []byte("s"), unitSources(up), "")
	if err != nil {
		t.Fatal(err)
	}
	if l := resourceLabel(p.Object); l != "confidential" {
		t.Fatalf("derived label %s", l)
	}
	lower(func(c content.Caller) (content.LabelOutcome, error) {
		return st.Content.SetDerivedLabel(ctx, c, "reports", "summary", "internal")
	})
	if l := resourceLabel(p.Object); l != "internal" {
		t.Fatalf("derived label after relabel %s", l)
	}
	lower(func(c content.Caller) (content.LabelOutcome, error) {
		return st.Content.SetUnitLabel(ctx, c, "reports", "q3.md", "", unit, "internal")
	})
	if l := resourceLabel(unit); l != "internal" {
		t.Fatalf("unit label after relabel %s", l)
	}
	col, err := alice.PrepareCollection("reports", "chat", []string{"hi"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(col); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "reports", "chat", "", col.Intent.Units[0].Unit, "confidential"); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("labelling a text entry: %v", err)
	}
}

// TestConcurrentRaiseKeepsRelabel is the regression test of review v3
// finding F01: a change was classified as a raise (label) from the label
// read before its decision, and a raise committed in between let it lower
// the label without relabel or its approval. The commit now requires the
// label it was classified against.
func TestConcurrentRaiseKeepsRelabel(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	raised := false
	st.BeforeDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpLabel && !raised {
			raised = true
			if _, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "restricted"); err != nil {
				t.Errorf("the concurrent raise: %v", err)
			}
		}
	}
	if _, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "confidential"); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("a raise classified before a concurrent raise to restricted: %v", err)
	}
	st.BeforeDecide = nil
	if label, _ := objectLabel(t, st, "doc"); label != "restricted" {
		t.Fatalf("the label is %s, want restricted", label)
	}
	// A fresh request to the same label is a lowering and needs approval.
	_, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "doc", "confidential")
	var need *content.ApprovalRequired
	if !errors.As(err, &need) {
		t.Fatalf("a fresh lowering: %v", err)
	}
}
