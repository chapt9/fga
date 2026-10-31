package content_test

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

// disclosureFixture publishes a 20-unit document of alice's, five of whose
// units are restricted (every fourth from position 3), to alice only. Bob,
// a project member, may read the version's units below restricted.
func disclosureFixture(t *testing.T) (*r1test.Stack, *r1test.Client, *r1test.Client, content.DocumentPublished, []content.UnitIntent) {
	t.Helper()
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	specs := make([]content.DocumentUnitSpec, 20)
	for i := 3; i < 20; i += 4 {
		specs[i].Label = "restricted"
	}
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "q3.md", paragraphs(20), specs, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	p, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	return st, alice, bob, p, up.Intent.Units
}

func restricted(i int) bool { return i%4 == 3 }

// TestExplicitSelection covers DOC-007 and V-054: an explicit selection
// is all or nothing, with a generic denial.
func TestExplicitSelection(t *testing.T) {
	st, alice, bob, _, units := disclosureFixture(t)
	got, err := st.Content.SelectUnits(ctx, bob.Caller, "reports", "q3.md", "", []string{units[2].Unit, units[0].Unit})
	if err != nil || len(got) != 2 || got[0].Unit != units[2].Unit || got[1].Unit != units[0].Unit {
		t.Fatalf("permitted selection = %+v, %v", got, err)
	}
	mixed := []string{units[0].Unit, units[3].Unit}
	if _, err := st.Content.SelectUnits(ctx, bob.Caller, "reports", "q3.md", "", mixed); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("mixed selection: %v", err)
	}
	unknown := []string{units[0].Unit, "00000000-0000-4000-8000-000000000000"}
	if _, err := st.Content.SelectUnits(ctx, bob.Caller, "reports", "q3.md", "", unknown); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("selection with an unknown unit: %v", err)
	}
	if got, err := st.Content.SelectUnits(ctx, alice.Caller, "reports", "q3.md", "", mixed); err != nil || len(got) != 2 {
		t.Fatalf("owner's selection = %+v, %v", got, err)
	}
}

// TestAuthorizedSubset covers DOC-007, V-055 and V-070: the subset
// returns only permitted units in document order across pages, with no
// placeholders or totals, and its continuation is bound to the caller.
func TestAuthorizedSubset(t *testing.T) {
	st, alice, bob, _, units := disclosureFixture(t)
	var want []string
	for i, u := range units {
		if !restricted(i) {
			want = append(want, u.Unit)
		}
	}
	var got []string
	cont, pages := "", 0
	for {
		page, err := st.Content.ListUnits(ctx, bob.Caller, "reports", "q3.md", "", 6, cont)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, u := range page.Units {
			got = append(got, u.Unit)
		}
		if page.Continuation == "" {
			break
		}
		if _, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q3.md", "", 6, page.Continuation); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("another caller used the continuation: %v", err)
		}
		cont = page.Continuation
	}
	if len(got) != len(want) || pages != 3 {
		t.Fatalf("subset = %d units in %d pages, want %d in 3", len(got), pages, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("subset order differs at %d", i)
		}
	}
	all, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q3.md", "", 100, "")
	if err != nil || len(all.Units) != 20 || all.Continuation != "" {
		t.Fatalf("owner's subset = %d units, %q, %v", len(all.Units), all.Continuation, err)
	}
	if _, _, err := st.Content.Manifest(ctx, bob.Caller, "reports", "q3.md", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("manifest with hidden units: %v", err)
	}
	if m, _, err := st.Content.Manifest(ctx, alice.Caller, "reports", "q3.md", ""); err != nil || len(m) == 0 {
		t.Fatalf("owner's manifest: %v", err)
	}
}

// TestUnitPackage covers the unit package and ciphertext routes: the
// owner receives its envelope and the exact ciphertext and decrypts the
// unit; a reader without an envelope gets nothing; a restricted unit is
// not disclosed to a member at all.
func TestUnitPackage(t *testing.T) {
	st, alice, bob, p, units := disclosureFixture(t)
	u := units[5]
	pkg, err := st.Content.UnitPackage(ctx, alice.Caller, "reports", "q3.md", "", u.Unit, alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := st.Content.ReadUnitCiphertext(ctx, alice.Caller, "reports", "q3.md", p.DocumentVersion, u.Unit)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(stream)
	stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err = crypto.DecryptUnit(&out, bytes.NewReader(ct), crypto.UnitPackage{Descriptor: pkg.Unit.Descriptor, DescriptorSignature: pkg.Unit.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		alice.Recipient, alice.Trust)
	if err != nil || out.String() != paragraphs(20)[5] {
		t.Fatalf("decrypted %q, %v", out.String(), err)
	}
	if _, err := st.Content.UnitPackage(ctx, bob.Caller, "reports", "q3.md", "", u.Unit, bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("package without an envelope: %v", err)
	}
	if _, err := st.Content.ReadUnitCiphertext(ctx, bob.Caller, "reports", "q3.md", "", units[3].Unit); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("restricted unit ciphertext to a member: %v", err)
	}
	if _, err := st.Content.ReadCiphertext(ctx, alice.Caller, "reports", "q3.md", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a document through the object route: %v", err)
	}
}

// TestOriginalFile covers CNT-003 and V-053: the encrypted original is a
// separate ciphertext under its own key, disclosed only with raw-read on
// the version and read on every unit. A member who may raw-read but not
// read a restricted unit gets no original, while still reading the units
// it may; a unit's envelope never opens the original.
func TestOriginalFile(t *testing.T) {
	policies := map[string]string{}
	for name, doc := range r1test.Policies {
		policies[name] = doc
	}
	policies["documents.json"] = strings.Replace(policies["documents.json"], `"actions":["read-units","discover"],"roles":["member"]`,
		`"actions":["read-units","discover","raw-read"],"roles":["member"]`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	original := []byte("%PDF-1.7 the whole report, as uploaded")
	up, err := alice.PrepareDocumentWithOriginal("reports", "q3.pdf", paragraphs(3), original, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	p, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	read := func(c *r1test.Client) ([]byte, error) {
		pkg, err := st.Content.OriginalPackage(ctx, c.Caller, "reports", "q3.pdf", "", c.Recipient.Fingerprint().String())
		if err != nil {
			return nil, err
		}
		s, err := st.Content.ReadOriginal(ctx, c.Caller, "reports", "q3.pdf", "")
		if err != nil {
			return nil, err
		}
		ct, err := io.ReadAll(s)
		s.Close()
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		ctxv, err := crypto.DecryptOriginal(&out, bytes.NewReader(ct), crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
			Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
			c.Recipient, c.Trust)
		if err == nil && ctxv.DocumentVersion.String() != p.DocumentVersion {
			t.Errorf("the original's envelope names version %s", ctxv.DocumentVersion)
		}
		return out.Bytes(), err
	}
	for _, c := range []*r1test.Client{alice, bob} {
		if got, err := read(c); err != nil || !bytes.Equal(got, original) {
			t.Fatalf("%s reads the original: %q, %v", c.Caller.Principal, got, err)
		}
	}
	// A unit's envelope does not open the original.
	unit, err := st.Content.UnitPackage(ctx, alice.Caller, "reports", "q3.pdf", "", up.Intent.Units[0].Unit, alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := st.Content.OriginalPackage(ctx, alice.Caller, "reports", "q3.pdf", "", alice.Recipient.Fingerprint().String())
	s, _ := st.Content.ReadOriginal(ctx, alice.Caller, "reports", "q3.pdf", "")
	ct, _ := io.ReadAll(s)
	s.Close()
	if _, err := crypto.DecryptOriginal(io.Discard, bytes.NewReader(ct), crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: unit.Envelope.Context, Ciphertext: unit.Envelope.Ciphertext, Signature: unit.Envelope.Signature}},
		alice.Recipient, alice.Trust); err == nil {
		t.Fatal("a unit envelope opened the original")
	}

	// V-053: with one restricted unit, bob may read-units and raw-read but
	// not read every unit, so the whole-document path is denied.
	specs := []content.DocumentUnitSpec{{}, {Label: "restricted"}, {}}
	up2, err := alice.PrepareDocumentFull(ctx, "reports", "hr.md", paragraphs(3), specs, nil, []byte("the whole HR file"), alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.ReadOriginal(ctx, alice.Caller, "reports", "hr.md", ""); err != nil {
		t.Fatalf("the owner's whole-document path: %v", err)
	}
	if _, err := st.Content.ReadOriginal(ctx, bob.Caller, "reports", "hr.md", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("whole-document path with a denied unit: %v", err)
	}
	if _, err := st.Content.OriginalPackage(ctx, bob.Caller, "reports", "hr.md", "", bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("original package with a denied unit: %v", err)
	}
	if page, err := st.Content.ListUnits(ctx, bob.Caller, "reports", "hr.md", "", 10, ""); err != nil || len(page.Units) != 2 {
		t.Fatalf("bob's subset = %+v, %v", page, err)
	}
}

// TestQuarantinedUnitsStayGuarded is the regression test of review v3
// finding F05: the manifest and the original file were authorized against
// the version's LIVE units only, so with units quarantined after a restore
// a caller got the whole manifest (with every unit quarantined, without
// any decision) and the original's ciphertext without read on the
// quarantined units. Whole-document disclosures now check every unit the
// version lists.
func TestQuarantinedUnitsStayGuarded(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["documents.json"] = strings.Replace(policies["documents.json"],
		`{"id":"members-read-versions","effect":"allow","actions":["read-units","discover"]`,
		`{"id":"members-read-versions","effect":"allow","actions":["read-units","raw-read","discover"]`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	eve := st.Client("eve", []string{"member"}, "p2")
	alice.Pin(bob)
	up, err := alice.PrepareDocumentWithOriginal("reports", "doc", []string{"Public.", "Secret."}, []byte("Public. Secret."), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	secret := up.Intent.Units[1]
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "reports", "doc", "", secret.Unit, "restricted"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.ReadOriginal(ctx, bob.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob reads the original without read on the restricted unit: %v", err)
	}
	quarantine := func(versions ...string) {
		t.Helper()
		for _, v := range versions {
			if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET state = 'QUARANTINED' WHERE id::text = $1`, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	quarantine(secret.UnitVersion)
	if _, _, err := st.Content.Manifest(ctx, bob.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob's manifest with the restricted unit quarantined: %v", err)
	}
	if _, err := st.Content.ReadOriginal(ctx, bob.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob's original with the restricted unit quarantined: %v", err)
	}
	quarantine(up.Intent.Units[0].UnitVersion)
	if _, _, err := st.Content.Manifest(ctx, eve.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("another project's manifest with every unit quarantined: %v", err)
	}
	if _, _, err := st.Content.Manifest(ctx, alice.Caller, "reports", "doc", ""); err != nil {
		t.Fatalf("the owner's manifest: %v", err)
	}
}
