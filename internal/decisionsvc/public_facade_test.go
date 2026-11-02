package decisionsvc_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decision"
	"fga/internal/decisionsvc"
	"fga/internal/opplan"
	"fga/internal/r1test"
	"fga/internal/registry"
)

var ctx = context.Background()

// TestPublicFacadeOpensNoApproval is the regression test of audit finding
// F-DEC-1: the public facade evaluated a caller's plan and, when the
// policy required an approval, opened a pending approval for it, so any
// token holder could fill the approvers' inboxes from the facade. It now
// answers without opening one; the same request through the storage
// role's adapter still opens it.
func TestPublicFacadeOpensNoApproval(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	p, err := alice.Put("reports", "doc", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Catalog.GetIdentity(ctx, r1test.Tenant, "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Lowering the label needs an approval (owner-lowers-with-approval).
	details, _ := json.Marshal(map[string]string{"bucket": "reports", "key": "doc"})
	plan := opplan.Summary{Operation: registry.OpRelabel, Action: "relabel",
		Targets: []opplan.Target{{Role: registry.RoleObject, Type: "storage.object", ID: p.Object}},
		Changes: map[string]string{"label": "public", "previous_label": "internal"}, Details: details}
	request := func(audience string) decisionsvc.Request {
		tok, err := st.Issuer.Issue("alice", r1test.Tenant, audience, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return decisionsvc.Request{RequestID: cryptowire.NewUUID().String(), Tenant: r1test.Tenant, Operation: registry.OpRelabel,
			OperationID: cryptowire.NewUUID().String(), OperationDigest: opplan.Digest(plan), Audience: content.Audience, SingleUse: true,
			Actor: decisionsvc.Ref{ID: "alice", Revision: id.Revision}, Evidence: tok, Plan: &plan,
			Checks: []decisionsvc.Check{{ID: registry.RoleObject, Role: registry.RoleObject, Action: "relabel",
				Resource: decisionsvc.Alias{Namespace: registry.ChangeLabel, Name: p.Object + "|public"}}}}
	}
	public := request(r1test.PublicAudience)
	if pub := st.Decisions.DecidePublic(ctx, public.Evidence, public); pub.Outcome != decision.OutcomeDeny.String() || pub.Reason != decisionsvc.PublicDenied {
		t.Fatalf("the facade's answer: %+v", pub)
	}
	if n := st.Count(`SELECT count(*) FROM approvals`); n != 0 {
		t.Fatalf("the public facade opened %d approvals", n)
	}
	resp := st.Decisions.Decide(ctx, r1test.StorageAdapter, request(content.Audience))
	if resp.Outcome != decision.OutcomeNeedsApproval.String() || resp.ApprovalID == "" {
		t.Fatalf("the storage role's request: %+v", resp)
	}
	if n := st.Count(`SELECT count(*) FROM approvals WHERE id = $1 AND state = 'PENDING'`, resp.ApprovalID); n != 1 {
		t.Fatalf("the storage role's request opened %d approvals", n)
	}
}
