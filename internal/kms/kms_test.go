package kms_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fga/internal/cryptowire"
	"fga/internal/kek"
	"fga/internal/kms"
)

type workload string

func (w workload) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Workload", string(w))
	return http.DefaultTransport.RoundTrip(r)
}

// TestSealAndOpen covers D-13: the keys role seals and opens data keys
// through the key management role, which alone holds the KEKs; a key moved
// to another binding does not open, an unknown version is reported as
// such, and a workload that is not a client is refused.
func TestSealAndOpen(t *testing.T) {
	ring := kek.NewRing()
	if _, err := ring.Add("t-acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(kms.Handler(ring, func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Workload"), nil },
		map[string]bool{"keys-1": true}))
	defer srv.Close()
	keys := kms.Client{URL: srv.URL, HTTP: &http.Client{Transport: workload("keys-1")}}
	b := kek.Binding{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), Version: cryptowire.NewUUID(),
		CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	dk, _ := kek.NewDataKey()
	want := bytes.Clone(dk)
	sealed, err := keys.Seal("t-acme", 1, dk, b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, want) {
		t.Fatal("the sealed key holds the data key")
	}
	if got, err := keys.Open("t-acme", 1, sealed, b); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("open: %v", err)
	}
	if direct, err := ring.Open("t-acme", 1, sealed, b); err != nil || !bytes.Equal(direct, want) {
		t.Fatalf("the ring opens what the role sealed: %v", err)
	}
	other := b
	other.Blob = cryptowire.NewUUID()
	if _, err := keys.Open("t-acme", 1, sealed, other); !errors.Is(err, kek.ErrOpen) {
		t.Fatalf("another binding: %v, want %v", err, kek.ErrOpen)
	}
	if _, err := keys.Seal("t-acme", 2, want, b); !errors.Is(err, kek.ErrNoKey) {
		t.Fatalf("an unknown version: %v, want %v", err, kek.ErrNoKey)
	}
	stranger := kms.Client{URL: srv.URL, HTTP: &http.Client{Transport: workload("storage-1")}}
	if _, err := stranger.Open("t-acme", 1, sealed, b); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("another workload: %v", err)
	}
}
