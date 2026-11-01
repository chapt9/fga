package content_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/signing"
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
// TestDerivedPreconditions covers review v5 F05: If-None-Match holds for a
// derived output as for an object (PUB-007). A key created since begin, or
// an output that already exists, fails the precondition and publishes
// nothing; without it a new version is published.
func TestDerivedPreconditions(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	up, err := alice.PrepareDocument("reports", "src.md", []string{"u1"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	sources := unitSources(up)
	begin := func(idem string) content.Intent {
		t.Helper()
		in, err := alice.BeginDerived(content.BeginRequest{Bucket: "reports", Key: "out", IdempotencyKey: idem, IfNoneMatch: true})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	first, second := begin("d1"), begin("d2")
	if _, err := alice.FinishDerived(first, []byte("one"), sources); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinishDerived(second, []byte("two"), sources); !errors.Is(err, content.ErrPrecondition) {
		t.Errorf("a key created since begin: %v", err)
	}
	if _, err := alice.FinishDerived(begin("d3"), []byte("three"), sources); !errors.Is(err, content.ErrPrecondition) {
		t.Errorf("an existing output: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM derived_versions`); n != 1 {
		t.Fatalf("%d derived versions published, want 1", n)
	}
	if _, err := alice.PutDerived("reports", "out", []byte("four"), sources, ""); err != nil {
		t.Fatalf("a new version without If-None-Match: %v", err)
	}
}

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

// TestDeclassifiedLeaseFollowsLineage is the regression test of review v4
// F04: a stream admitted by declassification, without the reader's read on
// any source, still depends on every source (DRV-009): a source change
// ends it.
func TestDeclassifiedLeaseFollowsLineage(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.Client("lena", []string{"member", "lead"}, "p1")
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "restricted"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PutDerived("reports", "big", bytes.Repeat([]byte("s"), 4<<20), unitSources(up), ""); err != nil {
		t.Fatal(err)
	}
	s, err := st.Content.ReadDerivedCiphertext(ctx, lena.Caller, "reports", "big", "", lena.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatalf("lena by declassification: %v", err)
	}
	defer s.Close()
	if _, err := s.Read(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "reports", "src.md", "", up.Intent.Units[0].Unit, "confidential"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * r1test.LeaseCheckEvery)
	if _, err := io.ReadAll(s); !errors.Is(err, content.ErrLineageChanged) {
		t.Fatalf("a declassified stream after a source change: %v, want %v", err, content.ErrLineageChanged)
	}
}

// TestDerivedLeaseFollowsLineage covers DRV-009: a change to a source of
// the transitive lineage ends an admitted derived stream with
// LINEAGE_AUTHORITY_CHANGED, while the output itself is unchanged; a
// change to the output itself ends its stream as any lease does.
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

	// The output's own label rises during a stream of it (its lineage is
	// unchanged): a lease error, not a lineage change.
	own, err := st.Content.ReadDerivedCiphertext(ctx, alice.Caller, "reports", "d1", "", alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if _, err := st.Content.SetDerivedLabel(ctx, alice.Caller, "reports", "d1", "confidential"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * r1test.LeaseCheckEvery)
	if _, err := io.ReadAll(own); !errors.Is(err, content.ErrLease) || errors.Is(err, content.ErrLineageChanged) {
		t.Fatalf("stream after the output's own label change: %v, want %v", err, content.ErrLease)
	}
}

// TestDerivedVersions covers new versions of a derived output: each needs
// new-version on the output and carries its own lineage; delivery of a
// version follows that version's lineage; a version raises the label to
// its lineage maximum but never lowers it.
func TestDerivedVersions(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "restricted"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	src := unitSources(up)
	label := func(id string) string {
		var l string
		_ = st.Pool.QueryRow(ctx, `SELECT attributes->>'label' FROM resources WHERE id = $1`, id).Scan(&l)
		return l
	}
	v1, err := alice.PutDerived("reports", "summary", []byte("v1"), src[:1], "")
	if err != nil || label(v1.Object) != "internal" {
		t.Fatalf("v1 = %+v, %v, label %s", v1, err, label(v1.Object))
	}
	v2, err := alice.PutDerived("reports", "summary", []byte("v2"), src[1:], "")
	if err != nil || v2.Object != v1.Object || v2.Generation != 2 || label(v1.Object) != "restricted" {
		t.Fatalf("v2 = %+v, %v, label %s", v2, err, label(v1.Object))
	}
	v3, err := alice.PutDerived("reports", "summary", []byte("v3"), src[:1], "")
	if err != nil || label(v1.Object) != "restricted" {
		t.Fatalf("v3 lowered the label implicitly: %+v, %v, label %s", v3, err, label(v1.Object))
	}
	if n := st.Count(`SELECT count(*) FROM derived_versions WHERE derived::text = $1`, v1.Object); n != 3 {
		t.Fatalf("derived versions = %d", n)
	}
	for _, v := range []content.Published{v1, v3} {
		var lineage string
		_ = st.Pool.QueryRow(ctx, `SELECT source_id FROM lineage WHERE derived_version::text = $1`, v.Version).Scan(&lineage)
		if lineage != src[0].ID {
			t.Fatalf("version %s lineage %s", v.Version, lineage)
		}
	}
	if _, err := bob.PutDerived("reports", "summary", []byte("x"), src[:1], ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member without new-version added a version: %v", err)
	}
	if _, err := alice.Put("reports", "summary", []byte("x")); err == nil {
		t.Fatal("an object version was published over a derived key")
	}
}

// deliverFunc is a content.EnvelopeDelivery written as a function.
type deliverFunc func(ctx context.Context, d signing.Signed, id string, extra ...signing.Signed) (content.Delivered, error)

func (f deliverFunc) Deliver(ctx context.Context, d signing.Signed, id string, extra ...signing.Signed) (content.Delivered, error) {
	return f(ctx, d, id, extra...)
}

// TestDerivedDeliveryKeepsOneAuthority covers review v5 F03 for client
// mode: the keys role delivers a derived output's envelope only with a
// recipient path decided for the delivery's own authority. A storage role
// that is not honest (the storage role itself checks each decision against
// its request) presents alice's recipient-source decision changed to name
// bob as the subject, validly signed; the keys role refuses the delivery.
func TestDerivedDeliveryKeepsOneAuthority(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("reports", "p1", "public")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.Client("bob", []string{"member"}, "p1")
	bob, err := st.Catalog.GetIdentity(ctx, r1test.Tenant, "bob")
	if err != nil {
		t.Fatal(err)
	}
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "internal"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PutDerived("reports", "summary", []byte("summary"), unitSources(up), ""); err != nil {
		t.Fatal(err)
	}
	if got, err := readDerived(t, st, alice, "summary"); err != nil || got != "summary" {
		t.Fatalf("alice reads her output: %q, %v", got, err)
	}
	altered := 0
	st.Keys = deliverFunc(func(ctx context.Context, d signing.Signed, id string, extra ...signing.Signed) (content.Delivered, error) {
		for i, x := range extra {
			var rec signing.Record
			if err := json.Unmarshal(x.Payload, &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Operation != registry.OpDerivedRecipientSources {
				continue
			}
			rec.Subject = signing.Ref{ID: "bob", Revision: bob.Revision}
			if extra[i], err = st.DecisionSigner.Sign(rec); err != nil {
				t.Fatal(err)
			}
			altered++
		}
		return st.Envelopes.Deliver(ctx, d, id, extra...)
	})
	defer func() { st.Keys = st.Envelopes }()
	_, err = st.Content.DerivedPackage(ctx, alice.Caller, "reports", "summary", "", alice.Recipient.Fingerprint().String())
	if altered == 0 {
		t.Fatal("no recipient-source decision reached the keys role")
	}
	if err == nil {
		t.Fatal("the envelope was delivered with a recipient path for another subject")
	}
}
