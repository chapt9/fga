package recovery_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/backupcrypt"
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
	if err := st.Envelopes.RevokeRecipient(ctx, st.KeysCaller("alice"), alice.Recipient.Fingerprint().String()); err != nil {
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
