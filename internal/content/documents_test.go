package content_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"fga/internal/blob"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
	"fga/internal/recovery"
	"fga/sdk/go/crypto"
)

func paragraphs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("Paragraph %d of the report.", i)
	}
	return out
}

// readUnit decrypts one published unit for c from catalog rows, as the
// disclosure API will deliver them (step 4).
func readUnit(t *testing.T, st *r1test.Stack, c *r1test.Client, documentVersion string, position int) (string, error) {
	t.Helper()
	var p crypto.UnitPackage
	var tenant, blobID cryptowire.UUID
	var length int64
	var sum string
	err := st.Pool.QueryRow(ctx, `
		SELECT du.descriptor, du.descriptor_signature, e.context, e.ciphertext, e.signature, t.id, v.blob, v.ciphertext_length, v.ciphertext_sha256
		  FROM document_units du JOIN object_versions v ON v.tenant = du.tenant AND v.id = du.unit_version
		  JOIN envelopes e ON e.tenant = du.tenant AND e.version = du.unit_version AND e.document_version = du.document_version
		  JOIN tenants t ON t.name = du.tenant
		 WHERE du.document_version = $1 AND du.position = $2 AND e.recipient = $3 AND e.status = 'ACTIVE'`,
		documentVersion, position, c.Recipient.Fingerprint().String()).
		Scan(&p.Descriptor, &p.DescriptorSignature, &p.Envelope.Context, &p.Envelope.Ciphertext, &p.Envelope.Signature, &tenant, &blobID, &length, &sum)
	if err != nil {
		return "", err
	}
	d, _ := cryptowire.ParseDigest(sum)
	r, err := st.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenant, Blob: blobID}, Length: length, SHA256: d})
	if err != nil {
		return "", err
	}
	ct, _ := readAll(r)
	var out bytes.Buffer
	_, err = crypto.DecryptUnit(&out, bytes.NewReader(ct), p, c.Recipient, c.Trust)
	return out.String(), err
}

func readAll(r interface {
	Read([]byte) (int, error)
	Close() error
}) ([]byte, error) {
	defer r.Close()
	var b bytes.Buffer
	_, err := b.ReadFrom(r)
	return b.Bytes(), err
}

// TestDocumentPublication covers DOC-001 to DOC-003 and DEC-009: units are
// separately encrypted, staged and published with the signed manifest in
// one transaction, every check is decided in batches of at most 50, each
// recipient can open each unit with its own profile-2 envelope, and units
// stay out of the object API and listings.
func TestDocumentPublication(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	text := paragraphs(13) // 13 units x 2 recipients x 4 checks: three unit batches
	up, err := alice.PrepareDocument("reports", "q3.md", text, nil, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Count(`SELECT count(*) FROM objects WHERE kind = 'unit'`); n != 0 {
		t.Fatalf("units visible before finalize: %d", n)
	}
	before := st.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'kind' = 'decision'`)
	p, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	if p.Units != 13 || p.Generation != 1 || p.DocumentVersion != up.Intent.DocumentVersion {
		t.Fatalf("published = %+v", p)
	}
	// One document decision, one version-share batch, three unit batches.
	if n := st.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'kind' = 'decision'`) - before; n != 5 {
		t.Fatalf("decisions = %d, want 5", n)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM document_versions WHERE state = 'LIVE'`:                                   1,
		`SELECT count(*) FROM document_units`:                                                           13,
		`SELECT count(*) FROM envelopes WHERE document_version IS NOT NULL AND status = 'ACTIVE'`:       26,
		`SELECT count(*) FROM objects WHERE kind = 'unit' AND current_version IS NOT NULL`:              13,
		`SELECT count(*) FROM upload_intents WHERE kind = 'unit' AND state = 'COMMITTED'`:               13,
		`SELECT count(*) FROM objects WHERE kind = 'document' AND current_document_version IS NOT NULL`: 1,
		`SELECT count(*) FROM resources WHERE type = 'document.text_unit'`:                              13,
		`SELECT count(*) FROM resources WHERE type = 'document.version'`:                                1,
	} {
		if got := st.Count(q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	for _, c := range []*r1test.Client{alice, bob} {
		got, err := readUnit(t, st, c, p.DocumentVersion, 7)
		if err != nil || got != text[7] {
			t.Fatalf("%s reads unit 7: %q, %v", c.Caller.Principal, got, err)
		}
	}
	page, err := st.Content.List(ctx, alice.Caller, "reports", "", 100, "")
	if err != nil || len(page.Entries) != 0 {
		t.Fatalf("listing shows documents or units: %+v, %v", page, err)
	}
	if _, err := alice.Put("reports", "q3.md", []byte("x")); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("an object over a document key: %v", err)
	}
	if again, err := alice.FinalizeDocument(up); err != nil || again != p {
		t.Fatalf("retried finalize = %+v, %v", again, err)
	}
}

// TestDocumentIsAtomic covers V-063: if any check of a publication is
// denied, nothing of it becomes visible. Bob may not read restricted
// units, so a document with one restricted unit cannot be published to him.
func TestDocumentIsAtomic(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	text := paragraphs(3)
	specs := []content.DocumentUnitSpec{{}, {Label: "restricted"}, {}}
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "q3.md", text, specs, nil, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("finalize with a denied unit: %v", err)
	}
	for _, q := range []string{`SELECT count(*) FROM document_versions`, `SELECT count(*) FROM objects WHERE kind <> 'object'`,
		`SELECT count(*) FROM envelopes`, `SELECT count(*) FROM document_units`, `SELECT count(*) FROM resources WHERE type LIKE 'document.%'`} {
		if n := st.Count(q); n != 0 {
			t.Errorf("%s = %d after a denied publication", q, n)
		}
	}
	if n := st.Count(`SELECT count(*) FROM upload_intents WHERE kind = 'unit' AND state = 'STAGED'`); n != 3 {
		t.Errorf("staged units = %d, want 3", n)
	}
	// The same document without bob publishes, with the unit's label.
	up, err = alice.PrepareDocumentSpecs(ctx, "reports", "q4.md", text, specs, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	if n := st.Count(`SELECT count(*) FROM resources WHERE type = 'document.text_unit' AND attributes->>'label' = 'restricted'`); n != 1 {
		t.Fatalf("restricted units = %d", n)
	}
}

// TestDocumentReuse covers DOC-002 and V-152: a new document version may
// reuse a LIVE unit (with read on it); the reused unit gets envelopes of
// its own for the new version, distinct from the old version's, and a
// principal without read on the unit cannot reuse it.
func TestDocumentReuse(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	st.Bucket("other", "p2")
	alice := st.Client("alice", []string{"member"}, "p1")
	up, err := alice.PrepareDocument("reports", "q3.md", paragraphs(2), nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	kept := up.Units[0]
	text := []string{"Paragraph 0 of the report.", "A new second paragraph."}
	up2, err := alice.PrepareDocument("reports", "q3.md", text, map[int]*crypto.SealedUnit{0: kept}, alice)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := alice.FinalizeDocument(up2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Generation != 2 || v2.Document != v1.Document {
		t.Fatalf("second version = %+v", v2)
	}
	var contexts [][]byte
	rows, _ := st.Pool.Query(ctx, `SELECT context FROM envelopes WHERE object = $1 AND status = 'ACTIVE' ORDER BY created_at`, kept.Params.Unit)
	for rows.Next() {
		var c []byte
		_ = rows.Scan(&c)
		contexts = append(contexts, c)
	}
	rows.Close()
	if len(contexts) != 2 || bytes.Equal(contexts[0], contexts[1]) {
		t.Fatalf("envelopes of the reused unit: %d, distinct = %t", len(contexts), len(contexts) == 2 && !bytes.Equal(contexts[0], contexts[1]))
	}
	for i, want := range text {
		if got, err := readUnit(t, st, alice, v2.DocumentVersion, i); err != nil || got != want {
			t.Fatalf("v2 unit %d = %q, %v", i, got, err)
		}
	}
	// Carol has no read on alice's unit: preparation refuses the reuse
	// before it returns the unit's ciphertext metadata (review v5 F06).
	carol := st.Client("carol", []string{"member"}, "p2")
	if _, err := carol.PrepareDocument("other", "copy.md", []string{"x", "y"}, map[int]*crypto.SealedUnit{1: kept}, carol); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("reuse without read: %v", err)
	}
	// A retry is answered only while the reuse is still allowed.
	dave := st.Client("dave", []string{"member"}, "p1", "p2")
	req := content.DocumentBeginRequest{Bucket: "other", Key: "copy.md", IdempotencyKey: "reuse-1", Units: []content.DocumentUnitSpec{{},
		{ReuseUnit: kept.Params.Unit.String(), ReuseVersion: kept.Params.UnitVersion.String()}}}
	if _, err := st.Content.BeginDocument(ctx, dave.Caller, req); err != nil {
		t.Fatalf("reuse with read: %v", err)
	}
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "dave", []string{"member"}, map[string]any{"projects": []any{"p2"}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.BeginDocument(ctx, dave.Caller, req); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a retry after read was taken away: %v", err)
	}
}

// TestReferencedUnitIsNotReclaimed covers V-064: reclamation does not
// remove the ciphertext of a unit version that a LIVE document version
// references, even if the version is marked for retirement.
func TestReferencedUnitIsNotReclaimed(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	up, err := alice.PrepareDocument("reports", "q3.md", paragraphs(1), nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	p, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	u := up.Units[0].Params
	// No API withdraws a unit; simulate a withdrawal to exercise the guard.
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET state = 'WITHDRAWN' WHERE id = $1`, u.UnitVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO retirements (tenant, version, blob, requested_at) VALUES ($1, $2, $3, now())`,
		r1test.Tenant, u.UnitVersion, u.Blob); err != nil {
		t.Fatal(err)
	}
	got, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, *st.Clock)
	if err != nil || got.Retired != 0 {
		t.Fatalf("reclaim = %+v, %v", got, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET state = 'LIVE' WHERE id = $1`, u.UnitVersion); err != nil {
		t.Fatal(err)
	}
	if text, err := readUnit(t, st, alice, p.DocumentVersion, 0); err != nil || text != paragraphs(1)[0] {
		t.Fatalf("unit after reclaim = %q, %v", text, err)
	}
}
