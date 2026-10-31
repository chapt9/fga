package content_test

import (
	"errors"
	"io"
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
