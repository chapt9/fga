package content_test

import (
	"errors"
	"testing"

	"fga/internal/content"
	"fga/internal/r1test"
	"fga/internal/recovery"
	"fga/sdk/go/crypto"
)

// TestDocumentWithdrawal covers PUB-005 and DOC-002 for documents:
// withdrawing a version withdraws the units and original no live version
// still references, retires its envelopes and schedules reclamation;
// shared units stay LIVE (V-064); withdrawing the current version and
// deleting the key clear the head; only delete rights allow either.
func TestDocumentWithdrawal(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	up1, err := alice.PrepareDocumentWithOriginal("reports", "q3.md", []string{"a", "b"}, []byte("original v1"), alice)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := alice.FinalizeDocument(up1)
	if err != nil {
		t.Fatal(err)
	}
	up2, err := alice.PrepareDocument("reports", "q3.md", []string{"a", "c"}, map[int]*crypto.SealedUnit{0: up1.Units[0]}, alice)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := alice.FinalizeDocument(up2)
	if err != nil {
		t.Fatal(err)
	}
	state := func(unitVersion string) string {
		var s string
		_ = st.Pool.QueryRow(ctx, `SELECT state FROM object_versions WHERE id::text = $1`, unitVersion).Scan(&s)
		return s
	}
	if _, err := st.Content.WithdrawDocumentVersion(ctx, bob.Caller, "reports", "q3.md", v1.DocumentVersion); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member withdrew alice's version: %v", err)
	}
	out, err := st.Content.WithdrawDocumentVersion(ctx, alice.Caller, "reports", "q3.md", v1.DocumentVersion)
	if err != nil || out.State != "WITHDRAWN" {
		t.Fatalf("withdraw v1 = %+v, %v", out, err)
	}
	shared, only := up1.Intent.Units[0].UnitVersion, up1.Intent.Units[1].UnitVersion
	if state(shared) != "LIVE" || state(only) != "WITHDRAWN" || state(up1.Intent.Original.UnitVersion) != "WITHDRAWN" {
		t.Fatalf("after withdrawing v1: shared %s, only-v1 %s, original %s", state(shared), state(only), state(up1.Intent.Original.UnitVersion))
	}
	if n := count(t, st, `SELECT count(*) FROM envelopes WHERE document_version::text = $1 AND status = 'ACTIVE'`, v1.DocumentVersion); n != 0 {
		t.Fatalf("active envelopes of the withdrawn version = %d", n)
	}
	if _, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q3.md", v1.DocumentVersion, 10, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("units of a withdrawn version: %v", err)
	}
	if got, err := readUnit(t, st, alice, v2.DocumentVersion, 0); err != nil || got != "a" {
		t.Fatalf("the shared unit in v2: %q, %v", got, err)
	}
	rec, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, *st.Clock)
	if err != nil || rec.Retired != 2 {
		t.Fatalf("reclaim = %+v, %v; want the unit and original only v1 had", rec, err)
	}
	// Withdrawing the current version clears the head and withdraws its
	// now unreferenced units.
	if _, err := st.Content.WithdrawDocumentVersion(ctx, alice.Caller, "reports", "q3.md", v2.DocumentVersion); err != nil {
		t.Fatal(err)
	}
	if state(shared) != "WITHDRAWN" || state(up2.Intent.Units[1].UnitVersion) != "WITHDRAWN" {
		t.Fatal("units of the last live version were not withdrawn")
	}
	if _, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q3.md", "", 10, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("current units after withdrawing the current version: %v", err)
	}
	// Deleting a key clears its head; its version stays readable by ID.
	up3, err := alice.PrepareDocument("reports", "q4.md", []string{"x"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	v3, err := alice.FinalizeDocument(up3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.DeleteDocument(ctx, bob.Caller, "reports", "q4.md"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member deleted alice's document: %v", err)
	}
	if _, err := st.Content.DeleteDocument(ctx, alice.Caller, "reports", "q4.md"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q4.md", "", 10, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("current units of a deleted key: %v", err)
	}
	if page, err := st.Content.ListUnits(ctx, alice.Caller, "reports", "q4.md", v3.DocumentVersion, 10, ""); err != nil || len(page.Units) != 1 {
		t.Fatalf("a deleted key's version by ID: %+v, %v", page, err)
	}
}
