package envelope_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/envelope"
	"fga/internal/r1test"
	"fga/internal/registry"
)

var ctx = context.Background()

func setup(t *testing.T) (*r1test.Stack, *r1test.Client, string) {
	t.Helper()
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	return st, alice, alice.Recipient.Fingerprint().String()
}

// TestDeliveryRules covers TRU-005 and KEY-002: the keys role delivers only
// against a decision for its own audience whose checks are exactly the
// GetRecipientEnvelope mapping, once, while the recipient key is active;
// the receipt is signed and bound to the envelope.
func TestDeliveryRules(t *testing.T) {
	st, alice, fp := setup(t)
	d, id, err := alice.DeliveryDecision("reports", "doc", fp, registry.OpGetEnvelope, content.KeysAudience)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Envelopes.Deliver(ctx, d, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cryptowire.Verify(cryptowire.TypeReceipt, got.ReceiptSignature, got.Receipt, func(kid string) (ed25519.PublicKey, error) {
		return st.ReceiptKey, nil
	}); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	r, err := cryptowire.ParseReceipt(got.Receipt)
	if err != nil || r.EnvelopeID != id || r.Recipient != fp || r.Audience != "alice" ||
		r.EnvelopeDigest != cryptowire.EnvelopeDigest(got.Context, got.Ciphertext).String() {
		t.Fatalf("receipt = %+v, %v", r, err)
	}
	if _, err := st.Envelopes.Deliver(ctx, d, id); !errors.Is(err, envelope.ErrDecision) {
		t.Fatalf("replayed delivery decision: %v", err)
	}

	storage, id, _ := alice.DeliveryDecision("reports", "doc", fp, registry.OpGetEnvelope, content.Audience)
	if _, err := st.Envelopes.Deliver(ctx, storage, id); !errors.Is(err, envelope.ErrDecision) {
		t.Fatalf("decision for the storage audience: %v", err)
	}
	subset, id, err := alice.DeliveryDecision("reports", "doc", fp, registry.OpRead, content.KeysAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Envelopes.Deliver(ctx, subset, id); !errors.Is(err, envelope.ErrDecision) {
		t.Fatalf("decision with only the read check: %v", err)
	}

	fresh, id, _ := alice.DeliveryDecision("reports", "doc", fp, registry.OpGetEnvelope, content.KeysAudience)
	if err := st.Catalog.RevokeRecipientKey(ctx, r1test.Tenant, fp); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Envelopes.Deliver(ctx, fresh, id); err == nil {
		t.Fatal("delivered to a key revoked after the decision")
	}
	var delivered int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE kind = 'key_release'`).Scan(&delivered)
	if delivered != 1 {
		t.Errorf("delivery audit events = %d, want 1", delivered)
	}
}

// TestDeliveryNeedsTheExactEnvelope: a decision for one envelope cannot
// release another.
func TestDeliveryNeedsTheExactEnvelope(t *testing.T) {
	st, alice, fp := setup(t)
	if _, err := alice.Put("reports", "other", []byte("x")); err != nil {
		t.Fatal(err)
	}
	d, _, err := alice.DeliveryDecision("reports", "doc", fp, registry.OpGetEnvelope, content.KeysAudience)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := alice.DeliveryDecision("reports", "other", fp, registry.OpGetEnvelope, content.KeysAudience)
	if _, err := st.Envelopes.Deliver(ctx, d, other); !errors.Is(err, envelope.ErrDecision) {
		t.Fatalf("decision for doc releasing other's envelope: %v", err)
	}
}
