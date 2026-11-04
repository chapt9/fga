package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"fga/internal/cryptowire"
)

// TestKeyCommitment is the regression test of the security review of 4
// November 2026, finding 5: the signed descriptor commits to the key
// package every envelope wraps, so an envelope that holds another key is
// refused before anything is decrypted, and one signed version decrypts to
// one plaintext for every recipient. A descriptor from before the
// commitment is opened without the check.
func TestKeyCommitment(t *testing.T) {
	f := newFixture(t)
	plaintext := []byte("one plaintext for everyone")
	ct, sealed := f.encrypt(t, plaintext, f.alice, f.bob)
	desc, err := cryptowire.ParseDescriptor(sealed.Descriptor)
	if err != nil || desc.KeyCommitment == "" {
		t.Fatalf("descriptor without a key commitment: %+v, %v", desc, err)
	}
	// Bob's envelope rewrapped around another key package for the same
	// version: his client refuses it.
	aad := cryptowire.PayloadAAD(f.params.Tenant, f.params.Object, f.params.CryptoVersion, cryptowire.Suite1, cryptowire.Format1)
	var sum cryptowire.Digest
	var n uint64
	other, err := seal(io.Discard, bytes.NewReader([]byte("another plaintext")), aad, &sum, &n)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := cryptowire.ParseEnvelopeContext(sealed.Envelopes[1].Context)
	if err != nil {
		t.Fatal(err)
	}
	swapped, err := wrap(ec, f.bob.PublicKey(), other, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	pkg := Package{Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature, Envelope: swapped}
	if err := Decrypt(&out, bytes.NewReader(ct), pkg, f.bob, f.trust); !errors.Is(err, ErrBinding) || out.Len() != 0 {
		t.Fatalf("an envelope with another key: %v, %d bytes released", err, out.Len())
	}
	if _, err := Reshare(pkg, f.bob, f.trust, Recipient{Fingerprint: f.alice.Fingerprint()}, 2, f.signer, now); !errors.Is(err, ErrBinding) {
		t.Fatalf("resharing an envelope with another key: %v", err)
	}
	pkg.Envelope = sealed.Envelopes[1]
	if err := Decrypt(&out, bytes.NewReader(ct), pkg, f.bob, f.trust); err != nil || !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("the honest envelope: %v", err)
	}
	// A descriptor from before the commitment.
	desc.KeyCommitment = ""
	legacy, err := desc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := f.signer.Sign(cryptowire.TypeDescriptor, legacy)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Decrypt(&out, bytes.NewReader(ct), Package{Descriptor: legacy, DescriptorSignature: sig, Envelope: sealed.Envelopes[1]}, f.bob, f.trust); err != nil ||
		!bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("a descriptor from before the commitment: %v", err)
	}
}
