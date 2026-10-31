package content_test

import (
	"bytes"
	"errors"
	"io"
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
