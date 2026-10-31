package recovery_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/backupcrypt"
	"fga/internal/blob"
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
	m, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme)
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

	inc, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t))
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
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
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
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog", "identities.copy"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err == nil {
		t.Fatal("a tampered backup was restored")
	}
}

// TestBackupEncryption covers AVL-005: backup files are encrypted, an
// encrypted backup needs its key, another key cannot open it, and a plain
// backup is not mistaken for an encrypted one.
func TestBackupEncryption(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	ids, _ := os.ReadFile(filepath.Join(dir, "catalog", "identities.copy"))
	manifest, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if bytes.Contains(ids, []byte("alice")) || bytes.Contains(manifest, []byte("fga.backup/v1")) {
		t.Fatal("backup files hold plaintext")
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, nil); err == nil {
		t.Fatal("an encrypted backup was restored without its key")
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, otherKey(t)); err == nil {
		t.Fatal("an encrypted backup was restored with another key")
	}
	plain := filepath.Join(t.TempDir(), "plain")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, plain, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.ReadManifest(plain, backupKey(t)); err == nil {
		t.Fatal("a plain backup was read as an encrypted one")
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatalf("restore with the key: %v", err)
	}
}

var keys = map[string]*backupcrypt.Key{}

func loadKey(t *testing.T, name string) *backupcrypt.Key {
	t.Helper()
	if k, ok := keys[name]; ok {
		return k
	}
	raw, err := backupcrypt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	k, err := backupcrypt.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	keys[name] = k
	return k
}

func backupKey(t *testing.T) *backupcrypt.Key { return loadKey(t, "backup") }
func otherKey(t *testing.T) *backupcrypt.Key  { return loadKey(t, "other") }

// TestReclaim covers PUB-005 and PUB-006: a withdrawn version's blob is
// removed and the version marked RETIRED; an expired upload is aborted and
// its staged blob removed; live blobs stay.
func TestReclaim(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	v1, err := alice.Put("reports", "doc", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Put("reports", "doc", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.DeleteVersion(ctx, alice.Caller, "reports", "doc", v1.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "abandoned"}, []byte("x"), alice); err != nil {
		t.Fatal(err)
	}
	got, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, st.Clock.Add(2*time.Hour))
	if err != nil || got.Retired != 1 || got.Aborted != 1 {
		t.Fatalf("reclaim = %+v, %v", got, err)
	}
	var state string
	_ = st.Pool.QueryRow(ctx, `SELECT state FROM object_versions WHERE id::text = $1`, v1.Version).Scan(&state)
	if state != "RETIRED" {
		t.Fatalf("withdrawn version is %s", state)
	}
	if b, err := alice.Get("reports", "doc", ""); err != nil || string(b) != "two" {
		t.Fatalf("current version after reclaim: %q, %v", b, err)
	}
	if again, _ := recovery.Reclaim(ctx, st.Pool, st.Blobs, st.Clock.Add(2*time.Hour)); again.Retired+again.Aborted+again.KeysDestroyed != 0 {
		t.Fatalf("second run = %+v, want nothing", again)
	}
}

// TestRestoreKeepsGrantRemoval covers AVL-008 for share grants (SHR-002):
// a grant removed after the backup is restored with it but removed again
// by reconcile from the security journal, so a restore does not give
// access back.
func TestRestoreKeepsGrantRemoval(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.Client("bob", []string{"member"}, "p2")
	if _, err := alice.Put("reports", "doc", []byte("payroll")); err != nil {
		t.Fatal(err)
	}
	target := content.GrantTarget{Bucket: "reports", Key: "doc"}
	if _, err := st.Content.RecordGrant(ctx, alice.Caller, target, content.GrantRequest{Grantee: "bob", Actions: []string{"read"},
		ExpiresAt: st.Clock.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	removed, err := st.Content.RemoveGrant(ctx, alice.Caller, target, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	active := func() int {
		var n int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM share_grants WHERE removed_at IS NULL`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := active(); n != 1 {
		t.Fatalf("%d active grants after the restore; the test needs the backup's grant", n)
	}
	rep, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal)
	if err != nil || rep.Replayed != 1 {
		t.Fatalf("reconcile = %+v, %v", rep, err)
	}
	var by string
	if err := st.Pool.QueryRow(ctx, `SELECT removed_by FROM share_grants WHERE id::text = $1`, removed.Grant.ID).Scan(&by); err != nil || by != "recovery" {
		t.Fatalf("the grant after reconcile: removed by %q, %v", by, err)
	}
	if n := active(); n != 0 {
		t.Fatalf("%d active grants after reconcile", n)
	}
}

// TestBackupReportsMissingBlobs is the regression test of review v2
// finding 4: a blob that could not be read was skipped silently and the
// backup reported success without that content. A backup now fails when a
// LIVE or WITHDRAWN version's blob is unreadable, unless the operator
// accepts it, and then the manifest lists it as missing.
func TestBackupReportsMissingBlobs(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	p, err := alice.Put("reports", "doc", []byte("payroll"))
	if err != nil {
		t.Fatal(err)
	}
	var ref blob.Ref
	if err := st.Pool.QueryRow(ctx, `SELECT t.id, v.blob FROM object_versions v JOIN tenants t ON t.name = v.tenant WHERE v.id::text = $1`,
		p.Version).Scan(&ref.Tenant, &ref.Blob); err != nil {
		t.Fatal(err)
	}
	if err := st.Blobs.Remove(ref); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); !errors.Is(err, recovery.ErrIncomplete) {
		t.Fatalf("a backup missing a live blob: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the incomplete backup was left behind: %v", err)
	}
	m, err := recovery.BackupWith(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme, recovery.BackupOptions{AllowMissing: true})
	if err != nil || len(m.Blobs) != 0 || len(m.Missing) != 1 || m.Missing[0].Blob != ref.Blob.String() {
		t.Fatalf("a backup accepting the missing blob: %+v, %v", m, err)
	}
	if got, err := recovery.ReadManifest(dir, backupKey(t)); err != nil || len(got.Missing) != 1 {
		t.Fatalf("the manifest read back: %+v, %v", got, err)
	}
}
