package kek

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/cryptowire"
)

func binding() Binding {
	return Binding{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), Version: cryptowire.NewUUID(),
		CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
}

// TestSealOpen covers SSE-001 and SSE-002: a data key opens only under
// its tenant, KEK version and exact identity, and resealing under a new
// version keeps the data key.
func TestSealOpen(t *testing.T) {
	r := NewRing()
	if _, err := r.Add("t-acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("t-other", time.Now()); err != nil {
		t.Fatal(err)
	}
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	b := binding()
	sealed, err := r.Seal("t-acme", 1, key, b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Open("t-acme", 1, sealed, b)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("open: %v", err)
	}
	moved := b
	moved.Version = cryptowire.NewUUID()
	if _, err := r.Open("t-acme", 1, sealed, moved); !errors.Is(err, ErrOpen) {
		t.Fatalf("a sealed key moved to another version opened: %v", err)
	}
	if _, err := r.Open("t-other", 1, sealed, b); !errors.Is(err, ErrOpen) {
		t.Fatalf("another tenant's KEK opened it: %v", err)
	}
	if _, err := r.Open("t-acme", 2, sealed, b); !errors.Is(err, ErrNoKey) {
		t.Fatalf("an absent version: %v", err)
	}
	if _, err := r.Add("t-acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	resealed, err := r.Reseal("t-acme", 1, 2, sealed, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open("t-acme", 1, resealed, b); !errors.Is(err, ErrOpen) {
		t.Fatalf("a key resealed under version 2 opened under version 1: %v", err)
	}
	if got, err := r.Open("t-acme", 2, resealed, b); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("resealed key: %v", err)
	}
	if _, err := r.Seal("t-acme", 2, key[:16], b); err == nil {
		t.Fatal("a short data key was sealed")
	}
}

// TestRingFile: a ring survives a protected round trip; a file opened as
// a File picks up a version added later without a restart.
func TestRingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keks")
	pass := func() ([]byte, error) { return []byte("ring passphrase"), nil }
	r := NewRing()
	if _, err := r.Add("t-acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := WriteRing(path, r, []byte("ring passphrase")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte("t-acme")) {
		t.Fatalf("the protected ring shows its contents: %v", err)
	}
	f, err := Load(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRing(path, func() ([]byte, error) { return []byte("wrong"), nil }); err == nil {
		t.Fatal("a wrong passphrase opened the ring")
	}
	key, _ := NewDataKey()
	b := binding()
	if _, err := f.Seal("t-acme", 2, key, b); !errors.Is(err, ErrNoKey) {
		t.Fatalf("version 2 before it exists: %v", err)
	}
	if _, err := r.Add("t-acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := WriteRing(path, r, []byte("ring passphrase")); err != nil {
		t.Fatal(err)
	}
	sealed, err := f.Seal("t-acme", 2, key, b)
	if err != nil {
		t.Fatalf("version 2 after a rotation: %v", err)
	}
	if got, err := r.Open("t-acme", 2, sealed, b); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("open: %v", err)
	}
}

// TestParse rejects malformed rings.
func TestParse(t *testing.T) {
	for _, bad := range []string{
		`{"format":"fga.kek-ring/v1"}`,
		`{"format":"other","tenants":{}}`,
		`{"format":"fga.kek-ring/v1","tenants":{"t":[{"version":2,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","created_at":"2026-10-31T00:00:00Z"}]}}`,
		`{"format":"fga.kek-ring/v1","tenants":{"t":[{"version":1,"key":"AAAA","created_at":"2026-10-31T00:00:00Z"}]}}`,
		`{"format":"fga.kek-ring/v1","tenants":{},"extra":1}`,
	} {
		if _, err := Parse([]byte(bad)); !errors.Is(err, ErrFormat) {
			t.Errorf("accepted %s: %v", bad, err)
		}
	}
}
