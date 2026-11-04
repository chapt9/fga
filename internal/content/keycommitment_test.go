package content_test

import (
	"errors"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
)

// TestPublicationNeedsKeyCommitment is the regression test of the
// security review of 4 November 2026, finding 5: the client's descriptors
// commit to the key package every envelope wraps, and the storage role
// publishes no object, unit or original whose descriptor does not.
func TestPublicationNeedsKeyCommitment(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	d, err := cryptowire.ParseDescriptor(u.Sealed.Descriptor)
	if err != nil || d.KeyCommitment == "" {
		t.Fatalf("the client's descriptor commits to no key: %+v, %v", d, err)
	}
	d.KeyCommitment = ""
	if u.Sealed.Descriptor, err = d.Marshal(); err != nil {
		t.Fatal(err)
	}
	if u.Sealed.DescriptorSignature, err = alice.Signer.Sign(cryptowire.TypeDescriptor, u.Sealed.Descriptor); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(u); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("an object without a key commitment: %v", err)
	}
	up, err := alice.PrepareDocument("reports", "q3.md", []string{"a"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	ud, err := cryptowire.ParseUnitDescriptor(up.Sealed.Units[0].Descriptor)
	if err != nil || ud.KeyCommitment == "" {
		t.Fatalf("the client's unit descriptor commits to no key: %+v, %v", ud, err)
	}
	ud.KeyCommitment = ""
	if up.Sealed.Units[0].Descriptor, err = ud.Marshal(); err != nil {
		t.Fatal(err)
	}
	if up.Sealed.Units[0].DescriptorSignature, err = alice.Signer.Sign(cryptowire.TypeUnitDescriptor, up.Sealed.Units[0].Descriptor); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a unit without a key commitment: %v", err)
	}
}
