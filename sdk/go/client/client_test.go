package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

type trust struct {
	recipients map[cryptowire.Digest][]byte
	signers    map[cryptowire.Digest]ed25519.PublicKey
}

func (t trust) Recipient(fp cryptowire.Digest) ([]byte, bool) {
	k, ok := t.recipients[fp]
	return k, ok
}
func (t trust) Signer(fp cryptowire.Digest) (ed25519.PublicKey, bool) {
	k, ok := t.signers[fp]
	return k, ok
}

// TestGetChecksRequestedVersion is the regression test of review finding
// 8: asked for version A, a faulty or hostile endpoint answered with a
// correctly signed package of version B, and Get decrypted B. Get now
// compares the signed identity with the one it asked for before any
// plaintext is released.
func TestGetChecksRequestedVersion(t *testing.T) {
	rk, _ := crypto.NewRecipientKey()
	sk, _ := crypto.NewSigningKey()
	tr := trust{recipients: map[cryptowire.Digest][]byte{rk.Fingerprint(): rk.PublicKey()},
		signers: map[cryptowire.Digest]ed25519.PublicKey{sk.Fingerprint: sk.Private.Public().(ed25519.PublicKey)}}
	p := crypto.Params{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), LogicalVersion: cryptowire.NewUUID(),
		CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID(), Attempt: cryptowire.NewUUID()}
	var ct bytes.Buffer
	sealed, err := crypto.Encrypt(&ct, bytes.NewReader([]byte("version B")), p, []crypto.Recipient{{Fingerprint: rk.Fingerprint(), KeyVersion: 1}},
		sk, tr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	versionB := p.LogicalVersion.String()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/buckets/b/object/package", func(w http.ResponseWriter, r *http.Request) {
		e := sealed.Envelopes[0]
		_ = json.NewEncoder(w).Encode(packageJSON{Version: VersionInfo{Version: versionB, CiphertextLength: int64(ct.Len())},
			Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature,
			Envelope: envelopeJSON{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature}})
	})
	mux.HandleFunc("GET /v1/buckets/b/object/ciphertext", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(ct.Bytes()) })
	mux.HandleFunc("GET /v1/signing-keys/{fp}", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ACTIVE"}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{StorageURL: srv.URL, KeysURL: srv.URL, HTTP: srv.Client(), Recipient: rk, KeyVersion: 1, Signer: sk, Trust: tr, TempDir: t.TempDir()}

	var out bytes.Buffer
	if _, err := c.Get(t.Context(), "b", "k", cryptowire.NewUUID().String(), &out); err == nil || out.Len() != 0 {
		t.Fatalf("Get of version A accepted version B: %v, %q", err, out.String())
	}
	if _, err := c.Get(t.Context(), "b", "k", versionB, &out); err != nil || out.String() != "version B" {
		t.Fatalf("Get of version B = %q, %v", out.String(), err)
	}
}
