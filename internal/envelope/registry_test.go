package envelope_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"fga/internal/content"
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
