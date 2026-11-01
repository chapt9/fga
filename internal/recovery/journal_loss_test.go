package recovery_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/backupcrypt"
	"fga/internal/content"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

// TestLostJournalFailsClosed is the regression test of review finding 1:
// opening a missing journal silently created an empty one, and restore
// and reconcile then reopened admission without the revocation made
// after the backup. Recovery now refuses a journal it cannot show to be
// the deployment's, complete up to what the catalog recorded.
func TestLostJournalFailsClosed(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	// An older copy of the journal, from before the revocation.
	older := filepath.Join(t.TempDir(), "older")
	copyDir(t, st.JournalDir, older)
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("alice"), alice.Recipient.Fingerprint().String(), true); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return *st.Clock }

	// The journal is lost: it is not recreated implicitly.
	if err := os.RemoveAll(st.JournalDir); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Open(st.JournalDir, now); !errors.Is(err, journal.ErrMissing) {
		t.Fatalf("opening a lost journal: %v", err)
	}
	// A new journal is not this deployment's; an older copy lacks entries.
	fresh, err := journal.Init(st.JournalDir, now)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := journal.Open(older, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, j := range map[string]*journal.Journal{"new journal": fresh, "older copy": stale} {
		if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, j, dir, backupKey(t)); !errors.Is(err, recovery.ErrJournalContinuity) {
			t.Fatalf("restore with a %s: %v", name, err)
		}
	}
	var status string
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM recipient_keys`).Scan(&status)
	if status != "REVOKED" {
		t.Fatalf("a refused restore changed the catalog: key is %s", status)
	}
	// Only an explicit operator decision proceeds without the journal.
	if _, err := recovery.RestoreWith(ctx, st.Pool, st.Blobs, fresh, dir, backupKey(t), recovery.Options{AcceptJournalLoss: true}); err != nil {
		t.Fatalf("restore with accepted journal loss: %v", err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	des, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		b, err := os.ReadFile(filepath.Join(from, d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, d.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStagedUploadDoesNotSurviveRestore is the regression test of review
// finding 5: a backup kept upload intents but only published ciphertext,
// so after a restore onto an empty blob directory a staged upload could
// be finalized into a LIVE version whose ciphertext was missing. Restore
// now aborts uploads in flight, and finalize verifies the staged blob.
func TestStagedUploadDoesNotSurviveRestore(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "kept", []byte("published")); err != nil {
		t.Fatal(err)
	}
	staged, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "in-flight", IdempotencyKey: "k1"}, []byte("staged"), alice)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	// The blob directory is lost; restore brings back what the backup has.
	stored := filepath.Join(st.BlobDir, "blobs")
	if err := os.RemoveAll(stored); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stored, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(staged); err == nil {
		t.Fatal("a staged upload without its ciphertext was published after the restore")
	}
	var versions int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM object_versions v JOIN objects o ON o.id = v.object WHERE o.key = 'in-flight'`).Scan(&versions)
	if versions != 0 {
		t.Fatalf("versions of the in-flight key = %d", versions)
	}
	if got, err := alice.Get("reports", "kept", ""); err != nil || string(got) != "published" {
		t.Fatalf("published object after restore: %q, %v", got, err)
	}
}

// TestJournalHistoryContinuity is the regression test of review v2
// finding 1: continuity compared only the journal's identity and entry
// count, so an entry lost and then hidden by a later one passed, and a
// restore brought back the access it revoked. The journal is now a hash
// chain, and the catalog records the hash of the last entry it saw.
func TestJournalHistoryContinuity(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("alice"), alice.Recipient.Fingerprint().String(), true); err != nil {
		t.Fatal(err)
	}
	// Alice's entry is lost; bob's revocation brings the count back.
	files, err := filepath.Glob(filepath.Join(st.JournalDir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("journal entries %v, %v", files, err)
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("bob"), bob.Recipient.Fingerprint().String(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); !errors.Is(err, recovery.ErrJournalContinuity) {
		t.Fatalf("restore with a journal that lost an entry: %v", err)
	}
	var revoked int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM recipient_keys WHERE status = 'REVOKED'`).Scan(&revoked); err != nil || revoked != 2 {
		t.Fatalf("a refused restore changed the catalog: %d revoked keys, %v", revoked, err)
	}
}

// TestRestoreWithoutCatalogRecord is the regression test of review v3 F02
// (specification 2.6.2, AVL-008, V-179): restored without the catalog's
// own record of the journal, as onto an empty catalog, the backup's record
// was trusted, so a journal copy missing a revocation made after the
// backup passed, and reconcile gave the revoked access back. Reconcile now
// keeps admission closed until an operator states, audited, that the
// journal is complete (or accepts its loss).
func TestRestoreWithoutCatalogRecord(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(t.TempDir(), "older")
	copyDir(t, st.JournalDir, older)
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("alice"), alice.Recipient.Fingerprint().String(), true); err != nil {
		t.Fatal(err)
	}
	// The catalog's record of the journal is lost with it.
	if _, err := st.Pool.Exec(ctx, `DELETE FROM journal_state`); err != nil {
		t.Fatal(err)
	}
	stale, err := journal.Open(older, func() time.Time { return *st.Clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, stale, dir, backupKey(t)); err != nil {
		t.Fatalf("restore with only the backup's record: %v", err)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, stale); !errors.Is(err, recovery.ErrJournalUnproven) {
		t.Fatalf("reconcile without an operator statement: %v", err)
	}
	if _, err := alice.Get("reports", "doc", ""); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("a read while admission stays closed: %v", err)
	}
	if _, err := recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, stale, recovery.Options{JournalComplete: true}); err != nil {
		t.Fatalf("reconcile with the operator's statement: %v", err)
	}
	var n int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'JOURNAL_COMPLETENESS_STATED'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audited statements: %d, %v", n, err)
	}
}
