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

// TestExportOfTheAllowedSize is the regression test of review v4 F12: the
// storage role allows an export of up to cryptowire.MaxExportBytes, which
// travels base64 encoded; the SDK reads it whole.
func TestExportOfTheAllowedSize(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0xa5}, cryptowire.MaxExportBytes)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/buckets/b/document/export", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"units": []ExportedUnit{{Unit: UnitEntry{Unit: "u1"}, Ciphertext: ciphertext}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{StorageURL: srv.URL, HTTP: srv.Client()}
	units, err := c.Export(t.Context(), "b", "k", "", []string{"u1"}, cryptowire.Digest{})
	if err != nil || len(units) != 1 || len(units[0].Ciphertext) != cryptowire.MaxExportBytes {
		t.Fatalf("an export of the allowed size: %d units, %v", len(units), err)
	}
}

// TestDownloadsPinTheVersion is the regression test of review v4 F13: a
// download asked for the current version fetches every part from the
// version its first answer named, never from one that became current
// meanwhile.
func TestDownloadsPinTheVersion(t *testing.T) {
	dv := cryptowire.NewUUID()
	ctx, err := cryptowire.EnvelopeContext{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), LogicalVersion: cryptowire.NewUUID(),
		CryptoVersion: cryptowire.NewUUID(), Suite: cryptowire.Suite1, Format: cryptowire.Format1, CiphertextLength: 1,
		CiphertextSHA256: cryptowire.Digest{1}, Recipient: cryptowire.Digest{2}, Sharer: cryptowire.Digest{3},
		RecipientKeyVersion: 1, Generation: 1, CreatedAt: time.Unix(1_800_000_000, 0),
		Document: cryptowire.NewUUID(), DocumentVersion: dv, ManifestDigest: cryptowire.Digest{1}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	asked := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/buckets/b/document/original/package", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(packageJSON{Version: VersionInfo{CiphertextLength: 1}, Envelope: envelopeJSON{Context: ctx}})
	})
	mux.HandleFunc("GET /v1/buckets/b/document/original/ciphertext", func(w http.ResponseWriter, r *http.Request) {
		asked["original"] = r.URL.Query().Get("version")
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /v1/buckets/b/document/units", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"document_version_id": dv.String(),
			"units": []UnitEntry{{Unit: "u1", UnitVersion: "uv1", Descriptor: []byte("client-mode")}}})
	})
	mux.HandleFunc("GET /v1/buckets/b/document/unit/package", func(w http.ResponseWriter, r *http.Request) {
		asked["unit"] = r.URL.Query().Get("version")
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rk, _ := crypto.NewRecipientKey()
	c := &Client{StorageURL: srv.URL, HTTP: srv.Client(), Recipient: rk, TempDir: t.TempDir()}
	_ = c.GetOriginal(t.Context(), "b", "k", "", &bytes.Buffer{})
	_, _ = c.GetDocument(t.Context(), "b", "k", "", &bytes.Buffer{})
	if asked["original"] != dv.String() || asked["unit"] != dv.String() {
		t.Fatalf("fetched from %v, want %s for both", asked, dv)
	}
}
