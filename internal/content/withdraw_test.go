package content_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	if n := st.Count(`SELECT count(*) FROM envelopes WHERE document_version::text = $1 AND status = 'ACTIVE'`, v1.DocumentVersion); n != 0 {
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

// TestWithdrawalLockOrder is the regression test of review v4 F11: a
// withdrawal takes a unit's resource before its version, as a publication
// that reuses the unit does, so the two wait for each other in one order
// and never deadlock.
func TestWithdrawalLockOrder(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	up, err := alice.PrepareDocument("reports", "q3.md", []string{"a"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	v, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	unitVersion := up.Intent.Units[0].UnitVersion
	var unitObject string
	if err := st.Pool.QueryRow(ctx, `SELECT object::text FROM object_versions WHERE id::text = $1`, unitVersion).Scan(&unitObject); err != nil {
		t.Fatal(err)
	}
	// A publication reusing the unit holds its resource in its fence...
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM resources WHERE id = $1 FOR SHARE`, unitObject); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Content.WithdrawDocumentVersion(ctx, alice.Caller, "reports", "q3.md", v.DocumentVersion)
		done <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var waiting int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the withdrawal never waited for the publication")
		}
	}
	// ...and then takes the unit's version, which the withdrawal must not
	// hold while it waits.
	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := tx.Exec(lockCtx, `SELECT 1 FROM object_versions WHERE id::text = $1 FOR SHARE`, unitVersion); err != nil {
		t.Fatalf("the publication's version lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the withdrawal after the publication: %v", err)
	}
}
