package content_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

func unitSources(up r1test.DocumentUpload) []cryptowire.LineageSource {
	out := make([]cryptowire.LineageSource, len(up.Intent.Units))
	for i, u := range up.Intent.Units {
		out[i] = cryptowire.LineageSource{Type: cryptowire.SourceUnit, ID: u.Unit, Version: u.UnitVersion}
	}
	return out
}

func readDerived(t *testing.T, st *r1test.Stack, c *r1test.Client, key string) (string, error) {
	t.Helper()
	fp := c.Recipient.Fingerprint().String()
	pkg, err := st.Content.DerivedPackage(ctx, c.Caller, "reports", key, "", fp)
	if err != nil {
		return "", err
	}
	s, err := st.Content.ReadDerivedCiphertext(ctx, c.Caller, "reports", key, "", fp)
	if err != nil {
		return "", err
	}
	ct, err := io.ReadAll(s)
	s.Close()
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	err = crypto.Decrypt(&out, bytes.NewReader(ct), crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		c.Recipient, c.Trust)
	return out.String(), err
}

// TestDerivedLabelAndLineage covers DRV-001 and DRV-007: the stored label
// is at least the lineage maximum, a lower proposal is ignored and a
// higher one applies; lineage must name live sources of the tenant.
func TestDerivedLabelAndLineage(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "restricted"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	p, err := alice.PutDerived("reports", "summary", []byte("summary"), unitSources(up), "public")
	if err != nil {
		t.Fatal(err)
	}
	var label string
	var depth, edges int
	_ = st.Pool.QueryRow(ctx, `SELECT r.attributes->>'label', d.depth, (SELECT count(*) FROM lineage WHERE derived_version = d.version)
	                            FROM derived_versions d JOIN resources r ON r.id = d.derived::text WHERE d.version = $1`, p.Version).Scan(&label, &depth, &edges)
	if label != "restricted" || depth != 1 || edges != 2 {
		t.Fatalf("derived label %q, depth %d, %d edges", label, depth, edges)
	}
	if got, err := readDerived(t, st, alice, "summary"); err != nil || got != "summary" {
		t.Fatalf("owner reads the derived output: %q, %v", got, err)
	}
	// A derived output of the derived output, with a higher proposal on an
	// internal-only lineage, takes the proposal.
	p2, err := alice.PutDerived("reports", "low", []byte("x"), unitSources(up)[:1], "confidential")
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Pool.QueryRow(ctx, `SELECT attributes->>'label' FROM resources WHERE id = $1`, p2.Object).Scan(&label)
	if label != "confidential" {
		t.Fatalf("raised proposal: label %q", label)
	}
	ghost := []cryptowire.LineageSource{{Type: cryptowire.SourceUnit, ID: cryptowire.NewUUID().String(), Version: cryptowire.NewUUID().String()}}
	if _, err := alice.PutDerived("reports", "ghost", []byte("x"), ghost, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("lineage naming an unknown source: %v", err)
	}
	if _, err := st.Content.ReadCiphertext(ctx, alice.Caller, "reports", "summary", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a derived output through the object route: %v", err)
	}
}

// TestDerivedDelivery covers DRV-002 and DRV-008: sharing a derived output
// needs the recipient's read on every source, or a declassify for that
// recipient; without either nothing is shared.
func TestDerivedDelivery(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	lena := st.Client("lena", []string{"member", "lead"}, "p1")
	alice.Pin(bob)
	alice.Pin(lena)
	bob.Pin(alice)
	lena.Pin(alice)
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "restricted"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	p, err := alice.PutDerived("reports", "summary", []byte("summary"), unitSources(up), "")
	if err != nil {
		t.Fatal(err)
	}
	share := func(to *r1test.Client) error {
		pkg, err := st.Content.DerivedPackage(ctx, alice.Caller, "reports", "summary", "", alice.Recipient.Fingerprint().String())
		if err != nil {
			return err
		}
		env, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
			Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
			alice.Recipient, alice.Trust, crypto.Recipient{Fingerprint: to.Recipient.Fingerprint(), KeyVersion: to.KeyVersion}, 1, alice.Signer, *st.Clock)
		if err != nil {
			return err
		}
		_, err = st.Content.ShareDerived(ctx, alice.Caller, "reports", "summary", p.Version,
			content.EnvelopeIn{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature})
		return err
	}
	// Bob may not read the restricted source and is not declassified to.
	if err := share(bob); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("share to a recipient without the lineage: %v", err)
	}
	// Lena cannot read the restricted unit either, but receives declassified
	// outputs.
	if err := share(lena); err != nil {
		t.Fatalf("share to a declassified recipient: %v", err)
	}
	if got, err := readDerived(t, st, lena, "summary"); err != nil || got != "summary" {
		t.Fatalf("declassified recipient reads: %q, %v", got, err)
	}
	if _, err := readDerived(t, st, bob, "summary"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob reads without lineage or declassify: %v", err)
	}
}

// TestDerivedLeaseFollowsLineage covers DRV-009: a change to a source of
// the transitive lineage ends an admitted derived stream with
// LINEAGE_AUTHORITY_CHANGED, while the output itself is unchanged.
func TestDerivedLeaseFollowsLineage(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	src, err := alice.Put("reports", "s", []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	d1, err := alice.PutDerived("reports", "d1", []byte("d1"), []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: src.Object, Version: src.Version}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PutDerived("reports", "d2", bytes.Repeat([]byte("d2"), 2<<20),
		[]cryptowire.LineageSource{{Type: cryptowire.SourceDerived, ID: d1.Object, Version: d1.Version}}, ""); err != nil {
		t.Fatal(err)
	}
	s, err := st.Content.ReadDerivedCiphertext(ctx, alice.Caller, "reports", "d2", "", alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	buf := make([]byte, 1024)
	if _, err := s.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.SetLabel(ctx, alice.Caller, "reports", "s", "restricted"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * r1test.LeaseCheckEvery)
	if _, err := io.ReadAll(s); !errors.Is(err, content.ErrLineageChanged) {
		t.Fatalf("stream after a source label change: %v, want %v", err, content.ErrLineageChanged)
	}
}
