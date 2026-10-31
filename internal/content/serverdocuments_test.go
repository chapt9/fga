package content_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
	"fga/internal/registry"
)

// readUnitPlain reads one server-mode unit through the content service.
func readUnitPlain(st *r1test.Stack, c content.Caller, bucket, key, version, unit string) (string, error) {
	s, err := st.Content.ReadUnitPlain(ctx, c, bucket, key, version, unit)
	if err != nil {
		return "", err
	}
	defer s.Close()
	b, err := io.ReadAll(s)
	return string(b), err
}

// unitIDs lists the units a caller may see in a document version.
func unitIDs(t *testing.T, st *r1test.Stack, c content.Caller, bucket, key, version string) []string {
	t.Helper()
	page, err := st.Content.ListUnits(ctx, c, bucket, key, version, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, u := range page.Units {
		out = append(out, u.Unit)
	}
	return out
}

// TestServerDocument covers DOC-001 to DOC-007 in server mode (S4a): the
// storage role splits uploaded text into units, each sealed and encrypted
// under its own data key, and publishes the version without signatures or
// descriptors; another member reads each unit by policy alone, and a unit
// whose label rises out of her reach disappears from her view while the
// owner still reads it; each route serves its own mode.
func TestServerDocument(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	text := []byte("First paragraph.\n\nSecond paragraph, with a line\nbreak.\n\nThird paragraph.\n")
	req := content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "doc-1"}
	p, err := st.Content.PutDocumentText(ctx, alice.Caller, req, text)
	if err != nil {
		t.Fatal(err)
	}
	if p.Units != 3 || p.Generation != 1 {
		t.Fatalf("published %+v", p)
	}
	var mode string
	var signer, sig *string
	if err := st.Pool.QueryRow(ctx, `SELECT encryption, signer, manifest_signature FROM document_versions WHERE id::text = $1`, p.DocumentVersion).
		Scan(&mode, &signer, &sig); err != nil {
		t.Fatal(err)
	}
	if mode != "server" || signer != nil || sig != nil {
		t.Fatalf("document version: mode %s, signer %v, signature %v", mode, signer, sig)
	}
	if n := count(t, st, `SELECT count(*) FROM document_units u JOIN object_versions v ON v.id = u.unit_version
	                      WHERE u.descriptor IS NULL AND v.encryption = 'server' AND v.sealed_key IS NOT NULL`); n != 3 {
		t.Fatalf("%d server-mode units without descriptors", n)
	}
	units := unitIDs(t, st, bob.Caller, "vault", "q3/notes.md", "")
	want := []string{"First paragraph.", "Second paragraph, with a line\nbreak.", "Third paragraph."}
	if len(units) != 3 {
		t.Fatalf("bob sees %d units", len(units))
	}
	for i, u := range units {
		if got, err := readUnitPlain(st, bob.Caller, "vault", "q3/notes.md", "", u); err != nil || got != want[i] {
			t.Fatalf("bob reads unit %d: %q %v", i, got, err)
		}
	}
	if again, err := st.Content.PutDocumentText(ctx, alice.Caller, req, text); err != nil || again != p {
		t.Fatalf("a retry under the same idempotency key: %+v %v", again, err)
	}

	// Unit-level access (DOC-006): restricted is out of bob's reach.
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "vault", "q3/notes.md", "", units[1], "restricted"); err != nil {
		t.Fatal(err)
	}
	if got := unitIDs(t, st, bob.Caller, "vault", "q3/notes.md", ""); len(got) != 2 || got[0] != units[0] || got[1] != units[2] {
		t.Fatalf("bob's view after the label change: %v", got)
	}
	if _, err := readUnitPlain(st, bob.Caller, "vault", "q3/notes.md", "", units[1]); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob reads the restricted unit: %v", err)
	}
	if got, err := readUnitPlain(st, alice.Caller, "vault", "q3/notes.md", "", units[1]); err != nil || got != want[1] {
		t.Fatalf("the owner reads the restricted unit: %q %v", got, err)
	}

	// A new version; the first stays readable by its version.
	p2, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "doc-2"},
		[]byte("Rewritten.\n\nAll of it."))
	if err != nil || p2.Generation != 2 || p2.Units != 2 {
		t.Fatalf("second version: %+v %v", p2, err)
	}
	if got, err := readUnitPlain(st, bob.Caller, "vault", "q3/notes.md", p.DocumentVersion, units[0]); err != nil || got != want[0] {
		t.Fatalf("a unit of the first version: %q %v", got, err)
	}

	// Each route serves its own mode (ENC-002).
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "reports", Key: "c.md", IdempotencyKey: "doc-3"},
		text); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("server text to a client-mode bucket: %v", err)
	}
	if _, err := st.Content.ReadUnitCiphertext(ctx, bob.Caller, "vault", "q3/notes.md", "", unitIDs(t, st, bob.Caller, "vault", "q3/notes.md", "")[0]); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("a server-mode unit through the ciphertext route: %v", err)
	}
	up, err := alice.PrepareDocument("reports", "client.md", []string{"client unit"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	clientUnit := unitIDs(t, st, alice.Caller, "reports", "client.md", "")[0]
	if _, err := readUnitPlain(st, alice.Caller, "reports", "client.md", "", clientUnit); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("a client-mode unit through the server route: %v", err)
	}
}

// TestServerCollection covers DOC-005 in server mode: a collection is
// created from text, and an append is a new version that keeps every entry
// as it is and adds the new ones, with no client keys; only the owner may
// append in the fixture's policy, appending to a document is refused, and
// an entry that is no longer live is not dropped silently.
func TestServerCollection(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	v1, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "chat", IdempotencyKey: "c1", Collection: true},
		[]byte("hello\n\nhow are you?"))
	if err != nil || v1.Units != 2 {
		t.Fatalf("create: %+v %v", v1, err)
	}
	first := unitIDs(t, st, bob.Caller, "vault", "chat", "")
	appendReq := content.TextRequest{Bucket: "vault", Key: "chat", IdempotencyKey: "c2", Append: true}
	v2, err := st.Content.PutDocumentText(ctx, alice.Caller, appendReq, []byte("fine, thanks"))
	if err != nil || v2.Units != 3 || v2.Generation != 2 {
		t.Fatalf("append: %+v %v", v2, err)
	}
	second := unitIDs(t, st, bob.Caller, "vault", "chat", "")
	if len(second) != 3 || second[0] != first[0] || second[1] != first[1] {
		t.Fatalf("the append did not keep the entries: %v then %v", first, second)
	}
	if got, err := readUnitPlain(st, bob.Caller, "vault", "chat", "", second[2]); err != nil || got != "fine, thanks" {
		t.Fatalf("bob reads the new entry: %q %v", got, err)
	}
	if again, err := st.Content.PutDocumentText(ctx, alice.Caller, appendReq, []byte("fine, thanks")); err != nil || again != v2 {
		t.Fatalf("a retry of the append: %+v %v", again, err)
	}
	if _, err := st.Content.PutDocumentText(ctx, bob.Caller, content.TextRequest{Bucket: "vault", Key: "chat", IdempotencyKey: "c3", Append: true},
		[]byte("me too")); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob appends without new-version: %v", err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "doc.md", IdempotencyKey: "d1"},
		[]byte("a document")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "doc.md", IdempotencyKey: "d2", Append: true},
		[]byte("more")); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("an append to a document: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET state = 'WITHDRAWN' WHERE object::text = $1`, second[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "chat", IdempotencyKey: "c4", Append: true},
		[]byte("anyone?")); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("an append over a withdrawn entry: %v", err)
	}
}

// TestServerOriginal covers CNT-003 in server mode (S4b): an original file
// uploaded beside the text is encrypted under its own data key and read
// only with raw-read and read on every unit; the keys role admits the
// complete-content decisions in the fence of the release, so a unit change
// between the storage role's checks and the release yields no key (V-163);
// selected units are exported whole or not at all.
func TestServerOriginal(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	original := bytes.Repeat([]byte{0, 1, 2, 3, 250}, 300_000)
	p, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "report.md", IdempotencyKey: "o1",
		Original: bytes.NewReader(original)}, []byte("Summary.\n\nDetails."))
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	var plainLen int64
	if err := st.Pool.QueryRow(ctx, `SELECT v.encryption, v.plaintext_length FROM document_versions d JOIN object_versions v ON v.id = d.original_version
	                                  WHERE d.id::text = $1 AND v.sealed_key IS NOT NULL`, p.DocumentVersion).Scan(&mode, &plainLen); err != nil {
		t.Fatal(err)
	}
	if mode != "server" || plainLen != int64(len(original)) {
		t.Fatalf("original: mode %s, length %d", mode, plainLen)
	}
	read := func(c content.Caller) ([]byte, error) {
		s, err := st.Content.ReadOriginalPlain(ctx, c, "vault", "report.md", "")
		if err != nil {
			return nil, err
		}
		defer s.Close()
		return io.ReadAll(s)
	}
	if got, err := read(alice.Caller); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("alice reads the original: %d bytes, %v", len(got), err)
	}
	if _, err := read(bob.Caller); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob without raw-read: %v", err)
	}

	// V-163: a unit changes after the storage role's checks and before the
	// keys role releases the original's key.
	units := unitIDs(t, st, alice.Caller, "vault", "report.md", "")
	st.BeforeDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpKeyReleaseOriginal {
			if _, err := st.Pool.Exec(ctx, `UPDATE resources SET metadata_revision = metadata_revision + 1 WHERE id = $1`, units[1]); err != nil {
				t.Error(err)
			}
		}
	}
	if got, err := read(alice.Caller); err == nil || got != nil {
		t.Fatalf("the original was released after a unit changed: %d bytes, %v", len(got), err)
	}
	st.BeforeDecide = nil
	if got, err := read(alice.Caller); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("a fresh read: %v", err)
	}

	// Export of selected units.
	x, err := st.Content.ExportUnitsPlain(ctx, alice.Caller, "vault", "report.md", "", units)
	if err != nil || len(x.Units) != 2 || x.Units[0].Text != "Summary." || x.Units[1].Text != "Details." {
		t.Fatalf("export: %+v %v", x, err)
	}
	if _, err := st.Content.ExportUnitsPlain(ctx, bob.Caller, "vault", "report.md", "", units); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob exports: %v", err)
	}
	if _, err := st.Content.ReadOriginalPlain(ctx, alice.Caller, "vault", "report.md", "x"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("an unknown version: %v", err)
	}
}
