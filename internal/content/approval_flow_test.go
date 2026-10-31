package content_test

import (
	"errors"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

// approveNext has lena approve the approval err names and returns its ID.
func approveNext(t *testing.T, st *r1test.Stack, lena content.Caller, err error) string {
	t.Helper()
	var need *content.ApprovalRequired
	if !errors.As(err, &need) {
		t.Fatalf("want an approval, got %v", err)
	}
	if _, err := st.Content.DecideApproval(ctx, lena, need.ID, true); err != nil {
		t.Fatal(err)
	}
	return need.ID
}

// TestPublicationApprovals covers APR-001 to APR-003 for publication:
// with create-object subject to an approval, preparing an upload (begin,
// staging) needs only the right, and the commit of an object, a document
// and a derived output needs an approval, consumed there.
func TestPublicationApprovals(t *testing.T) {
	policies := edited(map[string][2]string{"buckets.json": {
		`{"id":"members-use-bucket","effect":"allow","actions":["create-object","list"],"roles":["member"],`,
		`{"id":"members-list-bucket","effect":"allow","actions":["list"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"members-create-with-approval","effect":"allow","actions":["create-object"],"roles":["member"],"requires":["approval"],`}})
	if !strings.Contains(policies["buckets.json"], "members-create-with-approval") {
		t.Fatal("policy edit did not apply")
	}
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.User("lena", []string{"member", "lead"}, "p1")
	commit := func(id string, f func() error) error {
		alice.Caller.Approval = id
		defer func() { alice.Caller.Approval = "" }()
		return f()
	}

	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "k1"}, []byte("x"), alice)
	if err != nil {
		t.Fatalf("preparing an upload needs no approval: %v", err)
	}
	_, err = alice.Finalize(u)
	id := approveNext(t, st, lena, err)
	if err := commit(id, func() error { _, err := alice.Finalize(u); return err }); err != nil {
		t.Fatalf("approved object publication: %v", err)
	}

	up, err := alice.PrepareDocument("reports", "q3.md", []string{"a"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	_, err = alice.FinalizeDocument(up)
	id = approveNext(t, st, lena, err)
	if err := commit(id, func() error { _, err := alice.FinalizeDocument(up); return err }); err != nil {
		t.Fatalf("approved document publication: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM approvals WHERE state = 'CONSUMED'`); n != 2 {
		t.Fatalf("consumed approvals = %d", n)
	}

	src := []cryptowire.LineageSource{{Type: cryptowire.SourceUnit, ID: up.Intent.Units[0].Unit, Version: up.Intent.Units[0].UnitVersion}}
	_, err = alice.PutDerived("reports", "summary", []byte("s"), src, "")
	id = approveNext(t, st, lena, err)
	if err := commit(id, func() error { _, err := alice.PutDerived("reports", "summary2", []byte("s"), src, ""); return err }); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("an approval for one derived output used for another: %v", err)
	}
}

// TestShareApproval covers APR-001 for the keys role: with share subject
// to an approval, a share answers with a pending approval and succeeds
// once an approver approved it.
func TestShareApproval(t *testing.T) {
	policies := edited(map[string][2]string{"objects.json": {
		`"new-version","delete","delete-version","share","label","export"]`,
		`"new-version","delete","delete-version","label","export"]`}})
	policies["objects.json"] = strings.Replace(policies["objects.json"], `"rules":[`, `"rules":[
	  {"id":"owner-shares-with-approval","effect":"allow","actions":["share"],"roles":["*"],"requires":["approval"],
	   "when":"resource.attributes.owner == principal.id"},`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	lena := st.User("lena", []string{"member", "lead"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "k1"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	_, err = alice.Finalize(u) // initial envelopes are shares too
	alice.Caller.Approval = approveNext(t, st, lena, err)
	p, err := alice.Finalize(u)
	alice.Caller.Approval = ""
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := st.Content.ReadPackage(ctx, alice.Caller, "reports", "doc", "", alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		alice.Recipient, alice.Trust, crypto.Recipient{Fingerprint: bob.Recipient.Fingerprint(), KeyVersion: bob.KeyVersion}, 1, alice.Signer, *st.Clock)
	if err != nil {
		t.Fatal(err)
	}
	keys := st.KeysCaller("alice")
	in := content.EnvelopeIn{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature}
	_, err = st.Envelopes.Publish(ctx, keys, "reports", "doc", p.Version, in)
	keys.Approval = approveNext(t, st, lena, err)
	if _, err := st.Envelopes.Publish(ctx, keys, "reports", "doc", p.Version, in); err != nil {
		t.Fatalf("approved share: %v", err)
	}
}
