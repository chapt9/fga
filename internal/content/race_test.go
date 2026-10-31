package content_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
	"fga/internal/registry"
)

// TestOverwriteDuringReadKeepsHistoryRule is the regression test of review
// finding 2: whether the requested version is current was decided before
// the decision, so an overwrite in between let an old version be read
// with plain read, without read-history. The head the operation selected
// is now rechecked against the decision's binding.
func TestOverwriteDuringReadKeepsHistoryRule(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1") // read, stat; no read-history
	if _, err := alice.Put("reports", "doc", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	overwrite := func() {
		st.BeforeDecide = func(req decisionsvc.Request) {
			if req.Operation == registry.OpRead || req.Operation == registry.OpStat {
				st.BeforeDecide = nil
				if _, err := alice.Put("reports", "doc", []byte("v2")); err != nil {
					t.Error(err)
				}
			}
		}
	}
	overwrite()
	if s, err := st.Content.ReadCiphertext(ctx, bob.Caller, "reports", "doc", ""); err == nil {
		b, _ := io.ReadAll(s)
		s.Close()
		t.Fatalf("an overwritten version was read as current without read-history (%d bytes, current=%t)", len(b), s.Version.Current)
	} else if !errors.Is(err, content.ErrConflict) {
		t.Fatalf("read across an overwrite: %v, want a conflict", err)
	}
	overwrite()
	if _, err := st.Content.ReadPackage(ctx, bob.Caller, "reports", "doc", "", bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("package across an overwrite: %v, want a conflict", err)
	}
	overwrite()
	if _, err := st.Content.Stat(ctx, bob.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("stat across an overwrite: %v, want a conflict", err)
	}
	// Without a concurrent write, the current version reads normally.
	if _, err := st.Content.Stat(ctx, bob.Caller, "reports", "doc", ""); err != nil {
		t.Fatal(err)
	}
}

// TestOriginalDeliveryBindsUnits is the regression test of review finding
// 3: the original's envelope was released by a keys-role decision that
// did not bind the per-unit read checks, so a unit's label raised after
// the storage role's checks still let the envelope out. The unit checks
// now reach the keys role's delivery fence.
func TestOriginalDeliveryBindsUnits(t *testing.T) {
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
	up, err := alice.PrepareDocumentWithOriginal("reports", "q3.pdf", []string{"a", "b"}, []byte("original"), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	unit := up.Intent.Units[1].Unit
	st.BeforeDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpDocGetOriginalEnvelope {
			st.BeforeDecide = nil
			if _, err := st.Pool.Exec(ctx, `UPDATE resources SET attributes = attributes || '{"label":"restricted"}',
			                                metadata_revision = metadata_revision + 1 WHERE id = $1`, unit); err != nil {
				t.Error(err)
			}
		}
	}
	if _, err := st.Content.OriginalPackage(ctx, bob.Caller, "reports", "q3.pdf", "", bob.Recipient.Fingerprint().String()); err == nil {
		t.Fatal("the original's envelope was delivered after bob lost read on a unit")
	}
	if _, err := st.Content.OriginalPackage(ctx, bob.Caller, "reports", "q3.pdf", "", bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a fresh request after the change: %v", err)
	}
}
