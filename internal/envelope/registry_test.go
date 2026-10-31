package envelope_test

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

// TestEnrollment covers RCP-002: a key becomes ACTIVE only with a correct,
// unexpired, unused possession proof from its own principal.
func TestEnrollment(t *testing.T) {
	st := r1test.New(t)
	ctx := context.Background()
	st.User("erin", []string{"member"}, "p1")
	st.User("mallory", []string{"member"}, "p1")
	erin, mallory := st.KeysCaller("erin"), st.KeysCaller("mallory")
	key, _ := crypto.NewRecipientKey()
	ch, err := st.Envelopes.EnrollRecipient(ctx, erin, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if ch.Fingerprint != key.Fingerprint().String() || ch.KeyVersion != 1 {
		t.Fatalf("challenge = %+v", ch)
	}
	if rec, _ := st.Envelopes.Recipient(ctx, erin, ch.Fingerprint); rec.Status != "PENDING" {
		t.Fatalf("status before proof = %s", rec.Status)
	}
	other, _ := crypto.NewRecipientKey()
	wrong, _ := other.Prove(ch.EphemeralPublic, ch.Nonce, ch.ID, r1test.Tenant, "erin")
	if _, err := st.Envelopes.ActivateRecipient(ctx, erin, ch.Fingerprint, ch.ID, wrong); !errors.Is(err, envelope.ErrInvalid) {
		t.Fatalf("proof from another key: %v", err)
	}
	proof, _ := key.Prove(ch.EphemeralPublic, ch.Nonce, ch.ID, r1test.Tenant, "erin")
	if _, err := st.Envelopes.ActivateRecipient(ctx, mallory, ch.Fingerprint, ch.ID, proof); !errors.Is(err, envelope.ErrNotFound) {
		t.Fatalf("another principal activates: %v", err)
	}
	rec, err := st.Envelopes.ActivateRecipient(ctx, erin, ch.Fingerprint, ch.ID, proof)
	if err != nil || rec.Status != "ACTIVE" {
		t.Fatalf("activate = %+v, %v", rec, err)
	}
	if _, err := st.Envelopes.ActivateRecipient(ctx, erin, ch.Fingerprint, ch.ID, proof); err == nil {
		t.Fatal("a challenge was used twice")
	}
	if _, err := st.Envelopes.EnrollRecipient(ctx, erin, key.PublicKey()); err == nil {
		t.Fatal("the same key was enrolled twice")
	}

	late, _ := crypto.NewRecipientKey()
	ch2, err := st.Envelopes.EnrollRecipient(ctx, erin, late.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	*st.Clock = st.Clock.Add(envelope.ChallengeLifetime + time.Second)
	erin = st.KeysCaller("erin")
	proof2, _ := late.Prove(ch2.EphemeralPublic, ch2.Nonce, ch2.ID, r1test.Tenant, "erin")
	if _, err := st.Envelopes.ActivateRecipient(ctx, erin, ch2.Fingerprint, ch2.ID, proof2); !errors.Is(err, envelope.ErrInvalid) {
		t.Fatalf("expired challenge: %v", err)
	}
	if _, err := st.Envelopes.EnrollRecipient(ctx, erin, make([]byte, 32)); !errors.Is(err, envelope.ErrInvalid) {
		t.Fatalf("low-order key: %v", err)
	}
}

// TestShareAndRetire covers KEY-012, KEY-016 and RetireEnvelope: a reader
// shares a version with an eligible recipient, who decrypts; an ineligible
// recipient is refused; a generation must be the next one; a retired
// envelope is no longer delivered.
func TestShareAndRetire(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	carol := st.Client("carol", []string{"member"}, "p2")
	alice.Pin(bob)
	alice.Pin(carol)
	bob.Pin(alice)
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Get("reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob before sharing: %v", err)
	}
	id, err := alice.Share("reports", "doc", "", bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bob.Get("reports", "doc", ""); err != nil || string(got) != "payroll" {
		t.Fatalf("bob after sharing: %q, %v", got, err)
	}
	if _, err := alice.Share("reports", "doc", "", bob, 1); !errors.Is(err, envelope.ErrConflict) {
		t.Fatalf("reusing generation 1: %v", err)
	}
	if _, err := alice.Share("reports", "doc", "", carol, 1); !errors.Is(err, envelope.ErrNotFound) {
		t.Fatalf("sharing with an ineligible recipient: %v", err)
	}
	if _, err := st.Envelopes.Retire(context.Background(), st.KeysCaller("bob"), id); !errors.Is(err, envelope.ErrNotFound) {
		t.Fatalf("a non-owner retires: %v", err)
	}
	if _, err := st.Envelopes.Retire(context.Background(), st.KeysCaller("alice"), id); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Get("reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("delivery after retirement: %v", err)
	}
}

// TestRevokeRecipient covers KEY-008 and KEY-010: after revocation no new
// delivery or sharing reaches the key.
func TestRevokeRecipient(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := st.Envelopes.RevokeRecipient(context.Background(), st.KeysCaller("alice"), alice.Recipient.Fingerprint().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Get("reports", "doc", ""); err == nil {
		t.Fatal("an envelope was delivered to a revoked key")
	}
	if _, err := alice.Put("reports", "doc2", []byte("x")); err == nil {
		t.Fatal("a new version was published for a revoked key")
	}
}

// TestLookupNeedsRule covers ruling 7 for the key directory: without a
// discover rule, recipient and signing-key lookups are refused, even for
// the key's own principal.
func TestLookupNeedsRule(t *testing.T) {
	policies := map[string]string{}
	for name, doc := range r1test.Policies {
		if name != "recipients.json" && name != "signing-keys.json" {
			policies[name] = doc
		}
	}
	policies["recipients.json"] = `{"format":"fga.policy/v1","set":"business","resource":"crypto.recipient","scope":"","rules":[
	  {"id":"own-key","effect":"allow","actions":["enroll","activate","receive-key","revoke"],"roles":["*"],"when":"resource.attributes.principal == principal.id"}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	ctx := context.Background()
	alice := st.Client("alice", []string{"member"}, "p1")
	c := st.KeysCaller("alice")
	if _, err := st.Envelopes.Recipient(ctx, c, alice.Recipient.Fingerprint().String()); !errors.Is(err, envelope.ErrNotFound) {
		t.Fatalf("recipient lookup without a rule: %v", err)
	}
	if _, err := st.Envelopes.SigningKey(ctx, c, alice.Signer.Fingerprint.String()); !errors.Is(err, envelope.ErrNotFound) {
		t.Fatalf("signing-key lookup without a rule: %v", err)
	}

	st = r1test.New(t)
	alice = st.Client("alice", []string{"member"}, "p1")
	st.User("bob", []string{"member"}, "p1")
	bob := st.KeysCaller("bob")
	if k, err := st.Envelopes.Recipient(ctx, bob, alice.Recipient.Fingerprint().String()); err != nil || k.Principal != "alice" {
		t.Fatalf("recipient lookup with a rule = %+v, %v", k, err)
	}
	if k, err := st.Envelopes.SigningKey(ctx, bob, alice.Signer.Fingerprint.String()); err != nil || k.Status != "ACTIVE" {
		t.Fatalf("signing-key lookup with a rule = %+v, %v", k, err)
	}
}

// TestKeyApprovals covers APR-001 to APR-003 for the keys role: under a
// policy that holds activating and revoking a recipient key and retiring
// an envelope for an approval, each answers with an approval of exactly
// that plan; once a lead approves it in the inbox, the repeated call
// carries it out and consumes the approval; the requester cannot approve
// its own.
func TestKeyApprovals(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["recipients.json"] = `{"format":"fga.policy/v1","set":"business","resource":"crypto.recipient","scope":"","rules":[
	  {"id":"own-key","effect":"allow","actions":["enroll","receive-key","discover"],"roles":["*"],"when":"resource.attributes.principal == principal.id"},
	  {"id":"own-key-approved","effect":"allow","actions":["activate","revoke"],"roles":["*"],"requires":["approval"],
	   "when":"resource.attributes.principal == principal.id"},
	  {"id":"leads-approve-keys","effect":"allow","actions":["approve"],"roles":["lead"]}]}`
	policies["envelopes.json"] = strings.Replace(policies["envelopes.json"],
		`{"id":"owner-retires","effect":"allow","actions":["retire"],"roles":["*"],"when":"resource.attributes.owner == principal.id"},`,
		`{"id":"owner-retires","effect":"allow","actions":["retire"],"roles":["*"],"requires":["approval"],"when":"resource.attributes.owner == principal.id"},
		 {"id":"leads-approve-envelopes","effect":"allow","actions":["approve"],"roles":["lead"]},`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	ctx := context.Background()
	st.User("lena", []string{"member", "lead"}, "p1")
	st.User("erin", []string{"member"}, "p1")
	erin := st.KeysCaller("erin")
	approve := func(id string) {
		t.Helper()
		if _, err := st.Content.DecideApproval(ctx, st.Caller("erin"), id, true); err == nil {
			t.Fatal("the requester approved its own")
		}
		if _, err := st.Content.DecideApproval(ctx, st.Caller("lena"), id, true); err != nil {
			t.Fatal(err)
		}
	}
	held := func(err error) string {
		t.Helper()
		var need *enforce.ApprovalRequired
		if !errors.As(err, &need) {
			t.Fatalf("not held for an approval: %v", err)
		}
		return need.ID
	}
	with := func(c enforce.Caller, id string) enforce.Caller { c.Approval = id; return c }

	key, _ := crypto.NewRecipientKey()
	ch, err := st.Envelopes.EnrollRecipient(ctx, erin, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := key.Prove(ch.EphemeralPublic, ch.Nonce, ch.ID, r1test.Tenant, "erin")
	_, err = st.Envelopes.ActivateRecipient(ctx, erin, ch.Fingerprint, ch.ID, proof)
	id := held(err)
	approve(id)
	if rec, err := st.Envelopes.ActivateRecipient(ctx, with(erin, id), ch.Fingerprint, ch.ID, proof); err != nil || rec.Status != "ACTIVE" {
		t.Fatalf("activation with the approval: %+v %v", rec, err)
	}
	err = st.Envelopes.RevokeRecipient(ctx, erin, ch.Fingerprint)
	id = held(err)
	approve(id)
	if err := st.Envelopes.RevokeRecipient(ctx, with(erin, id), ch.Fingerprint); err != nil {
		t.Fatalf("revocation with the approval: %v", err)
	}
	if err := st.Envelopes.RevokeRecipient(ctx, with(erin, id), ch.Fingerprint); err == nil {
		t.Fatal("a consumed approval served again")
	}

	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	envID, err := alice.Share("reports", "doc", "", bob, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Envelopes.Retire(ctx, st.KeysCaller("alice"), envID)
	id = held(err)
	if _, err := st.Content.DecideApproval(ctx, st.Caller("lena"), id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Envelopes.Retire(ctx, with(st.KeysCaller("alice"), id), envID); err != nil {
		t.Fatalf("retirement with the approval: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM approvals WHERE state = 'CONSUMED'`); n != 3 {
		t.Fatalf("%d approvals consumed, want 3", n)
	}
}
