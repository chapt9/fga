package content_test

import (
	"errors"
	"testing"

	"fga/internal/content"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

// TestTextCollection covers DOC-005: a text collection's units are
// text.entry resources; appending is a new version that reuses the
// earlier entries; members read entries with read on text.entry; a key
// keeps its kind, and entries are not reused into ordinary documents.
func TestTextCollection(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	up, err := alice.PrepareCollection("reports", "chat", []string{"hello", "how are you?"}, nil, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, st, `SELECT count(*) FROM resources WHERE type = 'text.entry'`); n != 2 {
		t.Fatalf("text entries = %d", n)
	}
	// Append: the next version keeps both entries and adds one.
	reuse := map[int]*crypto.SealedUnit{0: up.Units[0], 1: up.Units[1]}
	up2, err := alice.PrepareCollection("reports", "chat", []string{"hello", "how are you?", "fine, thanks"}, reuse, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := alice.FinalizeDocument(up2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Generation != 2 || v2.Units != 3 {
		t.Fatalf("appended version = %+v", v2)
	}
	page, err := st.Content.ListUnits(ctx, bob.Caller, "reports", "chat", "", 10, "")
	if err != nil || len(page.Units) != 3 {
		t.Fatalf("bob's entries = %+v, %v", page, err)
	}
	if got, err := readUnit(t, st, bob, v2.DocumentVersion, 2); err != nil || got != "fine, thanks" {
		t.Fatalf("bob reads the appended entry: %q, %v", got, err)
	}
	if got, err := readUnit(t, st, bob, v1.DocumentVersion, 1); err != nil || got != "how are you?" {
		t.Fatalf("bob reads an entry of the first version: %q, %v", got, err)
	}
	if _, err := st.Content.UnitPackage(ctx, bob.Caller, "reports", "chat", "", up2.Intent.Units[2].Unit, bob.Recipient.Fingerprint().String()); err != nil {
		t.Fatalf("entry package for bob: %v", err)
	}
	// A key keeps its kind; entries are not units.
	if _, err := alice.PrepareDocument("reports", "chat", []string{"x"}, nil, alice); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("an ordinary version of a collection: %v", err)
	}
	if _, err := alice.PrepareDocument("reports", "other.md", []string{"x"}, map[int]*crypto.SealedUnit{0: up.Units[0]}, alice); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("an entry reused into a document: %v", err)
	}
	if _, err := alice.PrepareDocumentSpecs(ctx, "reports", "chat2", []string{"x"}, []content.DocumentUnitSpec{{Label: "restricted"}}, nil, alice); err != nil {
		t.Fatal(err)
	}
	units := []string{up2.Intent.Units[0].Unit}
	if _, err := st.Content.ExportUnits(ctx, alice.Caller, "reports", "chat", "", units, bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("export of text entries: %v", err)
	}
}
