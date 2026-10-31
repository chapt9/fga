package content_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/kek"
	"fga/internal/r1test"
)

// putPlain uploads plaintext to a server-mode bucket.
func putPlain(st *r1test.Stack, c content.Caller, bucket, key, idem string, plain []byte) (content.Published, error) {
	if idem == "" {
		idem = cryptowire.NewUUID().String()
	}
	return st.Content.PutObject(ctx, c, content.BeginRequest{Bucket: bucket, Key: key, IdempotencyKey: idem}, int64(len(plain)), bytes.NewReader(plain))
}

// readPlain reads a server-mode version through the content service.
func readPlain(st *r1test.Stack, c content.Caller, bucket, key, version string) ([]byte, content.VersionInfo, error) {
	s, err := st.Content.ReadObject(ctx, c, bucket, key, version)
	if err != nil {
		return nil, content.VersionInfo{}, err
	}
	defer s.Close()
	b, err := io.ReadAll(s)
	return b, s.Version, err
}

// TestServerObjects covers SSE-001, SSE-003 and SSE-005 on the object
// routes: a member uploads plaintext to a server-mode bucket; the version
// is sealed and recorded without client material; another member reads it
// because policy allows it, with no recipient key or envelope; overwrite,
// history, delete, export, retries and conditions work as in client mode;
// and each route refuses the other mode (V-155, V-156, ENC-002).
func TestServerObjects(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	v1, err := putPlain(st, alice.Caller, "vault", "a.txt", "put-1", []byte("first version"))
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	var plainLen int64
	var signer, descriptor *string
	var sealed []byte
	if err := st.Pool.QueryRow(ctx, `SELECT encryption, plaintext_length, signer, descriptor::text, sealed_key FROM object_versions WHERE id::text = $1`,
		v1.Version).Scan(&mode, &plainLen, &signer, &descriptor, &sealed); err != nil {
		t.Fatal(err)
	}
	if mode != "server" || plainLen != 13 || signer != nil || descriptor != nil || len(sealed) == 0 {
		t.Fatalf("server-mode version: mode %s, length %d, signer %v, descriptor %v", mode, plainLen, signer, descriptor)
	}
	got, info, err := readPlain(st, bob.Caller, "vault", "a.txt", "")
	if err != nil || string(got) != "first version" || info.Encryption != "server" || info.Length != 13 || !info.Current {
		t.Fatalf("bob reads alice's object by policy alone: %q %+v %v", got, info, err)
	}
	if again, err := putPlain(st, alice.Caller, "vault", "a.txt", "put-1", []byte("ignored on retry")); err != nil || again != v1 {
		t.Fatalf("a retry under the same idempotency key: %+v %v", again, err)
	}

	v2, err := putPlain(st, alice.Caller, "vault", "a.txt", "", []byte("second version"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := readPlain(st, bob.Caller, "vault", "a.txt", ""); err != nil || string(got) != "second version" {
		t.Fatalf("current after overwrite: %q %v", got, err)
	}
	if _, _, err := readPlain(st, bob.Caller, "vault", "a.txt", v1.Version); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob has no read-history: %v", err)
	}
	if got, info, err := readPlain(st, alice.Caller, "vault", "a.txt", v1.Version); err != nil || string(got) != "first version" || info.Current {
		t.Fatalf("alice reads the old version with read-history: %q %v", got, err)
	}
	if v, err := st.Content.Stat(ctx, bob.Caller, "vault", "a.txt", ""); err != nil || v.Version != v2.Version || v.Encryption != "server" {
		t.Fatalf("stat: %+v %v", v, err)
	}
	exp, err := st.Content.ExportObjectPlain(ctx, alice.Caller, "vault", "a.txt", "")
	if err != nil {
		t.Fatalf("alice exports her object: %v", err)
	}
	if b, err := io.ReadAll(exp); err != nil || string(b) != "second version" {
		t.Fatalf("export: %q %v", b, err)
	}
	exp.Close()
	if _, err := st.Content.ExportObjectPlain(ctx, bob.Caller, "vault", "a.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob exports without export: %v", err)
	}

	// Conditions (PUB-007).
	if _, err := st.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "a.txt", IdempotencyKey: "c1", IfNoneMatch: true},
		1, strings.NewReader("x")); !errors.Is(err, content.ErrPrecondition) {
		t.Fatalf("If-None-Match on an existing key: %v", err)
	}
	if _, err := st.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "a.txt", IdempotencyKey: "c2", IfMatch: v1.ETag},
		1, strings.NewReader("x")); !errors.Is(err, content.ErrPrecondition) {
		t.Fatalf("If-Match on an old ETag: %v", err)
	}

	// Deletion leaves a marker; history stays readable with its right.
	if _, err := st.Content.DeleteKey(ctx, alice.Caller, "vault", "a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPlain(st, bob.Caller, "vault", "a.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("read after delete: %v", err)
	}
	if got, _, err := readPlain(st, alice.Caller, "vault", "a.txt", v2.Version); err != nil || string(got) != "second version" {
		t.Fatalf("history read after delete: %q %v", got, err)
	}

	// Each route serves its own mode (ENC-002).
	if _, err := putPlain(st, alice.Caller, "reports", "b.txt", "", []byte("x")); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("plaintext to a client-mode bucket: %v", err)
	}
	if _, err := alice.Put("reports", "b.txt", []byte("client")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPlain(st, alice.Caller, "reports", "b.txt", ""); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("V-156: a client-mode version through the server route: %v", err)
	}
	if _, err := st.Content.ReadCiphertext(ctx, alice.Caller, "vault", "a.txt", v2.Version); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("a server-mode version through the ciphertext route: %v", err)
	}
	if _, err := st.Content.ReadPackage(ctx, alice.Caller, "vault", "a.txt", v2.Version, alice.Recipient.Fingerprint().String()); err == nil {
		t.Fatal("a server-mode version has no package")
	}
}

// TestServerObjectRetry covers SSE-005 and CRY-007: an upload whose body is
// short fails without publishing; its data key was issued, so the same
// idempotency key cannot try again, and a new one can.
func TestServerObjectRetry(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	req := content.BeginRequest{Bucket: "vault", Key: "a.txt", IdempotencyKey: "short"}
	if _, err := st.Content.PutObject(ctx, alice.Caller, req, 100, strings.NewReader("only a few bytes")); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a short body: %v", err)
	}
	if _, err := st.Content.PutObject(ctx, alice.Caller, req, 5, strings.NewReader("hello")); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("a retry of an unfinished attempt: %v", err)
	}
	if _, err := putPlain(st, alice.Caller, "vault", "a.txt", "fresh", []byte("hello")); err != nil {
		t.Fatalf("a new attempt: %v", err)
	}
	if n := count(t, st, `SELECT count(*) FROM object_versions WHERE encryption = 'server'`); n != 1 {
		t.Fatalf("%d server-mode versions", n)
	}
}

// TestServerObjectApproval covers APR-001 in server mode: a publication
// that needs an approval keeps the staged upload and names its intent; once
// a lead approves, finalizing the intent publishes it.
func TestServerObjectApproval(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["buckets.json"] = `{"format":"fga.policy/v1","set":"business","resource":"storage.bucket","scope":"","rules":[
	  {"id":"members-use-bucket","effect":"allow","actions":["list"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"members-create-with-approval","effect":"allow","actions":["create-object"],"roles":["member"],"requires":["approval"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"leads-approve-buckets","effect":"allow","actions":["approve"],"roles":["lead"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.User("lena", []string{"lead"}, "p1")
	_, err := putPlain(st, alice.Caller, "vault", "a.txt", "approve-1", []byte("needs a yes"))
	var staged *content.StagedApproval
	if !errors.As(err, &staged) || staged.Intent == "" {
		t.Fatalf("publication without approval: %v", err)
	}
	if n := count(t, st, `SELECT count(*) FROM object_versions`); n != 0 {
		t.Fatal("published before the approval")
	}
	if _, err := st.Content.DecideApproval(ctx, lena, staged.ID, true); err != nil {
		t.Fatal(err)
	}
	intent, _ := cryptowire.ParseUUID(staged.Intent)
	p, err := st.Content.Finalize(ctx, withApproval(alice.Caller, staged.ID), intent, content.FinalizeRequest{})
	if err != nil {
		t.Fatalf("finalize with the approval: %v", err)
	}
	if got, _, err := readPlain(st, alice.Caller, "vault", "a.txt", p.Version); err != nil || string(got) != "needs a yes" {
		t.Fatalf("the approved version: %q %v", got, err)
	}
}

// TestServerPayloadAtRest covers V-164, V-165 and V-168: blobs and the
// catalog hold no plaintext or data key; a corrupted blob or one copied
// from another version (with its digest) fails to read rather than
// returning other or shorter content.
func TestServerPayloadAtRest(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	marker := []byte("PLAINTEXT-MARKER-" + strings.Repeat("x", 64))
	a, err := putPlain(st, alice.Caller, "vault", "a.txt", "", marker)
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.ToUpper(marker)
	b, err := putPlain(st, alice.Caller, "vault", "b.txt", "", other)
	if err != nil {
		t.Fatal(err)
	}
	// V-168: no plaintext in any blob or temporary file, nor in the catalog;
	// no data key in the catalog or audit records.
	err = filepath.WalkDir(st.BlobDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err == nil && (bytes.Contains(raw, marker[:16]) || bytes.Contains(raw, other[:16])) {
			t.Errorf("plaintext in %s", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var tenant cryptowire.UUID
	var obj, ver, cv, blobID cryptowire.UUID
	var sealed []byte
	var kv uint32
	if err := st.Pool.QueryRow(ctx, `SELECT t.id, v.object, v.id, v.crypto_version, v.blob, v.sealed_key, v.kek_version FROM object_versions v
	                                  JOIN tenants t ON t.name = v.tenant WHERE v.id::text = $1`, a.Version).
		Scan(&tenant, &obj, &ver, &cv, &blobID, &sealed, &kv); err != nil {
		t.Fatal(err)
	}
	dataKey, err := st.KEKs.Open(r1test.Tenant, kv, sealed, kek.Binding{Tenant: tenant, Object: obj, Version: ver, CryptoVersion: cv, Blob: blobID})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT coalesce(string_agg(event::text, ''), '') FROM audit_outbox`,
		`SELECT coalesce(string_agg(to_jsonb(v)::text, ''), '') FROM object_versions v`,
		`SELECT coalesce(string_agg(to_jsonb(i)::text, ''), '') FROM upload_intents i`} {
		var dump string
		if err := st.Pool.QueryRow(ctx, q).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(dump, string(marker[:16])) || strings.Contains(dump, base64.StdEncoding.EncodeToString(dataKey)) ||
			strings.Contains(dump, "\\\\x"+hexOf(dataKey)) {
			t.Errorf("plaintext or a data key in: %s", q)
		}
	}

	// V-164: a corrupted blob does not read.
	pathA := blobPath(t, st, a.Version)
	raw, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(raw)
	corrupt[len(corrupt)-5] ^= 1
	if err := os.WriteFile(pathA, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := readPlain(st, alice.Caller, "vault", "a.txt", ""); err == nil {
		t.Fatalf("a corrupted blob read as %q", got)
	}
	// V-165: b's ciphertext under a's identity (digest updated so that only
	// the payload binding can catch it) does not read either.
	rawB, err := os.ReadFile(blobPath(t, st, b.Version))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathA, rawB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET ciphertext_sha256 = (SELECT ciphertext_sha256 FROM object_versions WHERE id::text = $2)
	                                 WHERE id::text = $1`, a.Version, b.Version); err != nil {
		t.Fatal(err)
	}
	if got, _, err := readPlain(st, alice.Caller, "vault", "a.txt", ""); err == nil {
		t.Fatalf("another version's ciphertext read as %q", got)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// blobPath finds a version's blob file in the stack's blob store.
func blobPath(t *testing.T, st *r1test.Stack, version string) string {
	t.Helper()
	var blobID string
	if err := st.Pool.QueryRow(ctx, `SELECT blob::text FROM object_versions WHERE id::text = $1`, version).Scan(&blobID); err != nil {
		t.Fatal(err)
	}
	var found string
	_ = filepath.WalkDir(st.BlobDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == blobID {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no blob file for %s", version)
	}
	return found
}
