package recovery_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"fga/internal/content"
	"fga/internal/r1test"
	"fga/internal/recovery"
	"fga/internal/registry"
)

var ctx = context.Background()

// TestRestoreReconcilesRevocation covers V-144 and AVL-008: a revocation
// made after the backup survives the restore through the security
// journal, admission stays closed until reconcile, and a decision made
// before the restore is refused by its old incarnation.
func TestRestoreReconcilesRevocation(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	if got, err := alice.Get("reports", "doc", ""); err != nil || string(got) != "payroll" {
		t.Fatalf("baseline delivery: %q, %v", got, err)
	}
	stale, staleID, err := alice.DeliveryDecision("reports", "doc", alice.Recipient.Fingerprint().String(), registry.OpGetEnvelope, content.KeysAudience)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "backup")
	m, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Blobs) != 1 || m.Incarnation != 1 {
		t.Fatalf("manifest = %+v", m)
	}
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("alice"), alice.Recipient.Fingerprint().String()); err != nil {
		t.Fatal(err)
	}
	entries, _ := st.Journal.Entries()
	if len(entries) != 1 || entries[0].Kind != "recipient-revoked" {
		t.Fatalf("journal = %+v", entries)
	}

	inc, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir)
	if err != nil || inc != 2 {
		t.Fatalf("restore = %d, %v", inc, err)
	}
	var status string
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM recipient_keys`).Scan(&status)
	if status != "ACTIVE" {
		t.Fatalf("the backup's key status is %s; the test needs the pre-revocation state", status)
	}
	if _, err := alice.Get("reports", "doc", ""); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("read while admission is closed: %v", err)
	}

	rep, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal)
	if err != nil || rep.Replayed != 1 {
		t.Fatalf("reconcile = %+v, %v", rep, err)
	}
	_ = st.Pool.QueryRow(ctx, `SELECT status FROM recipient_keys`).Scan(&status)
	if status != "REVOKED" {
		t.Fatalf("key status after reconcile = %s", status)
	}
	if _, err := alice.Get("reports", "doc", ""); err == nil {
		t.Fatal("an envelope was delivered to a key revoked after the backup")
	}
	if _, err := st.Envelopes.Deliver(ctx, stale, staleID); err == nil {
		t.Fatal("a decision from before the restore was accepted")
	}
	var delivered int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE kind = 'key_release'`).Scan(&delivered)
	if delivered != 1 {
		t.Fatalf("deliveries recorded = %d, want the one before the backup", delivered)
	}
}

// TestReconcileQuarantines covers KEY-017 and PUB-006: a version whose
// ciphertext is missing after a restore is quarantined, not served.
func TestReconcileQuarantines(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(st.BlobDir, "blobs")); err != nil {
		t.Fatal(err)
	}
	rep, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal)
	if err != nil || rep.Quarantined != 1 {
		t.Fatalf("reconcile = %+v, %v", rep, err)
	}
	if _, err := st.Content.Stat(ctx, st.Caller("alice"), "reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("stat of a quarantined version: %v", err)
	}
}

// TestBackupIntegrity: a backup file changed after the backup is refused.
func TestBackupIntegrity(t *testing.T) {
	st := r1test.New(t)
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog", "identities.copy"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir); err == nil {
		t.Fatal("a tampered backup was restored")
	}
}
