package blob

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"fga/internal/cryptowire"
)

func digestOf(b []byte) cryptowire.Digest { return cryptowire.Digest(sha256.Sum256(b)) }

func put(t *testing.T, s *Store, ref Ref, data []byte) (Receipt, error) {
	t.Helper()
	return s.Put(ref, bytes.NewReader(data), int64(len(data)), digestOf(data))
}

// TestFinalizeAndOpen covers BKD-001 and BKD-003: a receipt only after the
// exact length and digest, private permissions, and exact bytes back.
func TestFinalizeAndOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref := Ref{Tenant: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	data := []byte("ciphertext bytes")
	rec, err := put(t, s, ref, data)
	if err != nil || rec.Length != int64(len(data)) {
		t.Fatalf("Put = %+v, %v", rec, err)
	}
	r, err := s.Open(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("bytes differ")
	}
	info, _ := os.Stat(filepath.Join(dir, ref.name()))
	dirInfo, _ := os.Stat(filepath.Join(dir, ref.dir()))
	if info.Mode().Perm() != 0o600 || dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("modes %v and %v, want 0600 and 0700", info.Mode().Perm(), dirInfo.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, tmpDir)); len(entries) != 0 {
		t.Errorf("temporary files left: %d", len(entries))
	}
}

// TestIdentityAndContent covers BKD-001: the same identity and content is
// idempotent, other bytes for the same ID are rejected, and a length or
// digest mismatch produces no blob.
func TestIdentityAndContent(t *testing.T) {
	s, _ := Open(t.TempDir())
	ref := Ref{Tenant: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	data := []byte("version one")
	if _, err := put(t, s, ref, data); err != nil {
		t.Fatal(err)
	}
	if _, err := put(t, s, ref, data); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	if _, err := put(t, s, ref, []byte("version two")); !errors.Is(err, ErrConflict) {
		t.Fatalf("other bytes: %v, want %v", err, ErrConflict)
	}
	fresh := Ref{Tenant: ref.Tenant, Blob: cryptowire.NewUUID()}
	if _, err := s.Put(fresh, bytes.NewReader(data), int64(len(data)), digestOf([]byte("x"))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong digest: %v", err)
	}
	if _, err := s.Put(fresh, bytes.NewReader(data), int64(len(data))+1, digestOf(data)); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong length: %v", err)
	}
	if _, err := s.Open(Receipt{Ref: fresh, Length: int64(len(data)), SHA256: digestOf(data)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed blob exists: %v", err)
	}
	w, _ := s.Begin(fresh, 4)
	if _, err := w.Write([]byte("12345")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	w.Abort()
}

func TestVerifyAndRemove(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	ref := Ref{Tenant: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	rec, _ := put(t, s, ref, []byte("abcdef"))
	if err := s.Verify(rec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ref.name()), []byte("abcdeX"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(rec); !errors.Is(err, ErrMismatch) {
		t.Fatalf("corruption: %v", err)
	}
	if err := s.Remove(ref); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ref); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := s.Open(rec); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed blob opened: %v", err)
	}
}

// TestRepair covers review v4 F09: Repair replaces bytes that fail the
// receipt, keeps bytes that match it, and refuses source bytes that do not
// match, leaving the blob as it was.
func TestRepair(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	ref := Ref{Tenant: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	data := []byte("abcdef")
	rec, _ := put(t, s, ref, data)
	if _, err := s.Repair(ref, bytes.NewReader([]byte("abcdeX")), 6, digestOf(data)); !errors.Is(err, ErrMismatch) || s.Verify(rec) != nil {
		t.Fatalf("repair from wrong bytes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ref.name()), []byte("abcdeX"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ref, bytes.NewReader(data), 6, digestOf(data)); !errors.Is(err, ErrConflict) {
		t.Fatalf("Put over damaged bytes: %v", err)
	}
	if _, err := s.Repair(ref, bytes.NewReader(data), 6, digestOf(data)); err != nil || s.Verify(rec) != nil {
		t.Fatalf("repair of damaged bytes: %v", err)
	}
	if _, err := s.Repair(ref, bytes.NewReader(data), 6, digestOf(data)); err != nil || s.Verify(rec) != nil {
		t.Fatalf("repair of intact bytes: %v", err)
	}
}

// TestSymlinkCannotEscape covers BKD-003: a planted symlink in the store
// does not lead outside it.
func TestSymlinkCannotEscape(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	s, _ := Open(dir)
	ref := Ref{Tenant: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	if err := os.Symlink(outside, filepath.Join(dir, blobDir, ref.Tenant.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := put(t, s, ref, []byte("x")); err == nil {
		t.Fatal("a blob was written through a symlink out of the store")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("bytes reached the outside directory")
	}
}
