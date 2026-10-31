package content_test

import (
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/envelope"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/sdk/go/crypto"
)

// versionMode returns the mode a version was published under.
func versionMode(t *testing.T, st *r1test.Stack, version string) string {
	t.Helper()
	var mode string
	if err := st.Pool.QueryRow(ctx, `SELECT encryption FROM object_versions WHERE id::text = $1`, version).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}

// resourceMode returns a resource's policy-visible mode and metadata
// revision.
func resourceMode(t *testing.T, st *r1test.Stack, id string) (string, uint64) {
	t.Helper()
	var mode string
	var meta uint64
	if err := st.Pool.QueryRow(ctx, `SELECT attributes->>'encryption', metadata_revision FROM resources WHERE id = $1`, id).Scan(&mode, &meta); err != nil {
		t.Fatal(err)
	}
	return mode, meta
}

// TestEncryptionModeRefusals covers ENC-002 and V-155 on the routes that
// exist before server mode: every client-mode upload route refuses a
// server-mode bucket with ErrEncryptionMode, but only to a caller allowed
// to use the bucket; anyone else gets the ordinary not-found (CNT-004).
// Nothing is reserved.
func TestEncryptionModeRefusals(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	oscar := st.Client("oscar", []string{"member"}, "p2")
	if _, err := alice.Put("vault", "a.txt", []byte("secret")); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("client upload to a server-mode bucket: %v", err)
	}
	if _, err := oscar.Put("vault", "a.txt", []byte("secret")); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a caller without create-object learns nothing: %v", err)
	}
	if _, err := alice.PrepareDocument("vault", "d.md", []string{"x"}, nil, alice); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("client document to a server-mode bucket: %v", err)
	}
	if _, err := alice.PrepareCollection("vault", "chat", []string{"x"}, nil, alice); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("client collection to a server-mode bucket: %v", err)
	}
	_, err := st.Content.Begin(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "out", IdempotencyKey: "derived-1", Derived: true})
	if !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("client derived output to a server-mode bucket: %v", err)
	}
	if n := st.Count(`SELECT (SELECT count(*) FROM upload_intents) + (SELECT count(*) FROM document_intents)`); n != 0 {
		t.Fatalf("intents reserved in a server-mode bucket: %d", n)
	}
}

// TestVersionModeGuards covers ENC-002 at the release points: a version
// recorded in server mode is never read, delivered or shared through a
// client route, nor its envelope released by the keys role, even to its
// owner with a valid decision. Server-mode uploads do not exist yet, so
// the test marks a client version as server mode.
func TestVersionModeGuards(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	p, err := alice.Put("reports", "a.txt", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := versionMode(t, st, p.Version); got != "client" {
		t.Fatalf("version mode = %q", got)
	}
	signed, envelopeID, err := alice.DeliveryDecision("reports", "a.txt", alice.Recipient.Fingerprint().String(), registry.OpGetEnvelope, content.KeysAudience)
	if err != nil {
		t.Fatal(err)
	}
	// An envelope for bob, made while the version was still client mode.
	pkg, err := st.Content.ReadPackage(ctx, alice.Caller, "reports", "a.txt", "", alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	forBob, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		alice.Recipient, alice.Trust, crypto.Recipient{Fingerprint: bob.Recipient.Fingerprint(), KeyVersion: bob.KeyVersion}, 2, alice.Signer, *st.Clock)
	if err != nil {
		t.Fatal(err)
	}
	// A server-mode version carries a sealed data key under a KEK version
	// (SSE-002) and its plaintext length; these stand in for them.
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET encryption = 'server', sealed_key = '\x00', kek_version = 1, plaintext_length = 5
	                                 WHERE id::text = $1`, p.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Get("reports", "a.txt", ""); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("client read of a server-mode version: %v", err)
	}
	if _, err := st.Content.ReadCiphertext(ctx, alice.Caller, "reports", "a.txt", ""); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("ciphertext of a server-mode version: %v", err)
	}
	if _, err := st.Envelopes.Deliver(ctx, signed, envelopeID); !errors.Is(err, envelope.ErrDecision) {
		t.Fatalf("keys role released an envelope of a server-mode version: %v", err)
	}
	_, err = st.Envelopes.Publish(ctx, st.KeysCaller("alice"), "reports", "a.txt", p.Version,
		content.EnvelopeIn{Context: forBob.Context, Ciphertext: forBob.Ciphertext, Signature: forBob.Signature})
	if !errors.Is(err, envelope.ErrEncryptionMode) {
		t.Fatalf("envelope published for a server-mode version: %v", err)
	}
}

// TestSetBucketEncryption covers ENC-001 and V-159: only a principal with
// manage on the bucket changes its mode; the change applies to uploads
// begun after it, while an open upload publishes in the mode it began
// under and every version keeps its own; the bucket and its resources
// show the new mode to policy and advance their metadata revision.
func TestSetBucketEncryption(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.Client("lena", []string{"lead"}, "p1")
	old, err := alice.Put("reports", "old.txt", []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "pending.txt"}, []byte("p"), alice)
	if err != nil {
		t.Fatal(err)
	}
	var bucketID string
	if err := st.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'reports'`).Scan(&bucketID); err != nil {
		t.Fatal(err)
	}
	_, objectMeta := resourceMode(t, st, old.Object)

	if _, err := st.Content.SetBucketEncryption(ctx, alice.Caller, "reports", "server"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member without manage changed the mode: %v", err)
	}
	if _, err := st.Content.SetBucketEncryption(ctx, lena.Caller, "reports", "plaintext"); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("an unknown mode: %v", err)
	}
	out, err := st.Content.SetBucketEncryption(ctx, lena.Caller, "reports", "server")
	if err != nil {
		t.Fatal(err)
	}
	if out.Encryption != "server" || out.Previous != "client" || out.Bucket != bucketID {
		t.Fatalf("outcome = %+v", out)
	}
	if mode, _ := resourceMode(t, st, bucketID); mode != "server" {
		t.Fatalf("bucket attribute = %q", mode)
	}
	if mode, meta := resourceMode(t, st, old.Object); mode != "server" || meta != objectMeta+1 {
		t.Fatalf("object attribute = %q, metadata revision %d (was %d)", mode, meta, objectMeta)
	}

	// V-159: the open upload publishes in client mode; versions keep theirs.
	published, err := alice.Finalize(pending)
	if err != nil {
		t.Fatalf("an upload begun before the change: %v", err)
	}
	if versionMode(t, st, published.Version) != "client" || versionMode(t, st, old.Version) != "client" {
		t.Fatal("a version changed mode")
	}
	if mode, _ := resourceMode(t, st, published.Object); mode != "server" {
		t.Fatalf("the new object shows %q, not its bucket's mode", mode)
	}
	if _, err := alice.Get("reports", "old.txt", ""); err != nil {
		t.Fatalf("a client-mode version is still read through the client route: %v", err)
	}
	if _, err := alice.Put("reports", "new.txt", []byte("n")); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("an upload begun after the change: %v", err)
	}

	if _, err := st.Content.SetBucketEncryption(ctx, lena.Caller, "reports", "client"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Put("reports", "new.txt", []byte("n")); err != nil {
		t.Fatalf("back in client mode: %v", err)
	}
}

// TestEncryptionCeiling covers V-158: the mode is visible to policy, so a
// ceiling can require client mode for a label. The ceiling denies a
// restricted bucket in server mode before the route's own refusal.
func TestEncryptionCeiling(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["ceiling-encryption.json"] = `{"format":"fga.policy/v1","set":"ceiling","resource":"storage.bucket","scope":"","rules":[
	  {"id":"restricted-needs-client-mode","effect":"deny","actions":["create-object"],"roles":["*"],
	   "when":"resource.attributes.label == \"restricted\" && resource.attributes.encryption != \"client\""}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.ModeBucket("vault", "p1", "restricted", "server")
	st.ModeBucket("open", "p1", "internal", "server")
	st.ModeBucket("safe", "p1", "restricted", "client")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("vault", "a.txt", []byte("x")); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("restricted in a server-mode bucket: %v", err)
	}
	if _, err := alice.Put("open", "a.txt", []byte("x")); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("internal in a server-mode bucket: %v", err)
	}
	if _, err := alice.Put("safe", "a.txt", []byte("x")); err != nil {
		t.Fatalf("restricted in a client-mode bucket: %v", err)
	}
}

// TestEncryptionAttributeOnEveryResource is the regression test of review
// v3 F08: published document versions and new derived outputs lacked the
// encryption attribute (ENC-001), so policies testing it behaved by
// history. Every resource of a bucket, of every type and in both modes,
// carries the bucket's mode, and follows a mode change.
func TestEncryptionAttributeOnEveryResource(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	st.ModeBucket("vault", "p1", "internal", "server")
	lead := st.Client("lena", []string{"member", "lead"}, "p1")
	alice := st.Client("alice", []string{"member"}, "p1")

	// Client mode: an object, a document, a collection, a derived output.
	obj, err := alice.Put("reports", "doc.bin", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	up, err := alice.PrepareDocument("reports", "doc.md", []string{"One.", "Two."}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	col, err := alice.PrepareCollection("reports", "chat", []string{"hi"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(col); err != nil {
		t.Fatal(err)
	}
	src := []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: obj.Object, Version: obj.Version}}
	if _, err := alice.PutDerived("reports", "summary", []byte("s"), src, ""); err != nil {
		t.Fatal(err)
	}
	// Server mode: the same kinds.
	sobj, err := st.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "doc.bin", IdempotencyKey: "o"}, 1,
		strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []content.TextRequest{{Bucket: "vault", Key: "doc.md", IdempotencyKey: "d"},
		{Bucket: "vault", Key: "chat", IdempotencyKey: "c", Collection: true}} {
		if _, err := st.Content.PutDocumentText(ctx, alice.Caller, r, []byte("One.\n\nTwo.")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "summary", IdempotencyKey: "s"},
		[]cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: sobj.Object, Version: sobj.Version}}, -1, strings.NewReader("s")); err != nil {
		t.Fatal(err)
	}

	check := func(bucket, want string) {
		t.Helper()
		rows, err := st.Pool.Query(ctx, `
			SELECT r.type, coalesce(r.attributes->>'encryption', '') FROM resources r
			 WHERE r.id IN (SELECT o.id::text FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket WHERE b.name = $1)
			    OR r.id IN (SELECT d.id::text FROM document_versions d JOIN objects o ON o.tenant = d.tenant AND o.id = d.document
			                  JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket WHERE b.name = $1)`, bucket)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		types := map[string]bool{}
		for rows.Next() {
			var typ, mode string
			if err := rows.Scan(&typ, &mode); err != nil {
				t.Fatal(err)
			}
			types[typ] = true
			if mode != want {
				t.Errorf("a %s in %s has encryption %q, want %q", typ, bucket, mode, want)
			}
		}
		for _, typ := range []string{"storage.object", "document.version", "document.text_unit", "text.entry", "document.derived"} {
			if !types[typ] {
				t.Errorf("%s has no %s to check", bucket, typ)
			}
		}
	}
	check("reports", "client")
	check("vault", "server")
	if _, err := st.Content.SetBucketEncryption(ctx, lead.Caller, "reports", "server"); err != nil {
		t.Fatal(err)
	}
	check("reports", "server")
}

// TestModeChangeLockOrder is the regression test of review v3 F13 case B:
// a begin on an existing object holds the object's resource row and then
// takes the bucket row, while a mode change took the bucket row and then
// every object's row, so the two could deadlock. The mode change now
// takes the objects' rows before the bucket row, as a begin does.
func TestModeChangeLockOrder(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	lead := st.Client("lena", []string{"member", "lead"}, "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	p, err := alice.Put("reports", "doc", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// As a begin's fence: the object's resource row, for share.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM resources WHERE id = $1 FOR SHARE`, p.Object); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Content.SetBucketEncryption(ctx, lead.Caller, "reports", "server")
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	// As the begin's next step: the bucket row, for share.
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '3s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM buckets WHERE name = 'reports' FOR SHARE`); err != nil {
		t.Fatalf("the begin's bucket lock while a mode change waits: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the mode change: %v", err)
	}
}
