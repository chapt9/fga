package content_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
	"fga/internal/registry"
)

var ctx = context.Background()

func TestRoundTrip(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "q3/summary.txt", []byte("quarterly figures")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := alice.Get("reports", "q3/summary.txt", "")
	if err != nil || !bytes.Equal(got, []byte("quarterly figures")) {
		t.Fatalf("get = %q, %v", got, err)
	}
	var events int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE kind = 'mutation' AND event->>'outcome' = 'PUBLISHED'`).Scan(&events)
	if events != 1 {
		t.Errorf("publication audit events = %d, want 1", events)
	}
}

// TestSharingAndEligibility covers KEY-012 and RES-009: initial envelopes
// need the target recipient's eligibility at publication, an eligible
// recipient decrypts with its own key, and a reader without an envelope or
// read permission gets the same not-found answer as for an absent object.
func TestSharingAndEligibility(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	carol := st.Client("carol", []string{"member"}, "p2")
	alice.Pin(bob)
	alice.Pin(carol)
	bob.Pin(alice)

	if _, err := alice.Put("reports", "shared.txt", []byte("for bob"), alice, bob); err != nil {
		t.Fatal(err)
	}
	if got, err := bob.Get("reports", "shared.txt", ""); err != nil || string(got) != "for bob" {
		t.Fatalf("bob reads the shared object: %q, %v", got, err)
	}
	if _, err := carol.Get("reports", "shared.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("carol (other project) reads: %v, want not found", err)
	}
	if _, err := st.Content.Stat(ctx, carol.Caller, "reports", "shared.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("carol stats: %v", err)
	}
	if _, err := st.Content.Stat(ctx, carol.Caller, "reports", "absent.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("absent object: %v", err)
	}
	// Bob may read but has no envelope of his own for a version shared
	// only with alice.
	if _, err := alice.Put("reports", "private.txt", []byte("alice only")); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Get("reports", "private.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob without an envelope: %v", err)
	}
	// Asking for alice's envelope as bob is not a delivery to bob.
	if _, err := st.Content.ReadPackage(ctx, bob.Caller, "reports", "private.txt", "", alice.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob asks for alice's envelope: %v", err)
	}

	// An envelope for a recipient who may not read the object stops the
	// publication, and nothing becomes visible.
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "leak.txt"}, []byte("x"), alice, carol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(u); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("publishing to an ineligible recipient: %v", err)
	}
	if _, err := st.Content.Stat(ctx, alice.Caller, "reports", "leak.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a refused publication is visible: %v", err)
	}
}

// TestDenyOverrides covers V-005 for storage: a contractor role denies read
// even with a member role that allows it.
func TestDenyOverrides(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	dave := st.Client("dave", []string{"member", "contractor"}, "p1")
	alice.Pin(dave)
	if _, err := alice.Put("reports", "a.txt", []byte("x"), alice, dave); err == nil {
		t.Fatal("an envelope for a recipient whose read is denied was published")
	}
	if _, err := alice.Put("reports", "a.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.ReadCiphertext(ctx, dave.Caller, "reports", "a.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("contractor reads: %v", err)
	}
	if _, err := st.Content.Stat(ctx, dave.Caller, "reports", "a.txt", ""); err != nil {
		t.Fatalf("contractor stats (allowed): %v", err)
	}
}

// TestVersionsAndHistory covers the native version semantics and V-146: an
// overwrite creates a version, history needs its own right, deleting a key
// writes a delete marker without touching older versions, and withdrawing
// a version makes it unreadable.
func TestVersionsAndHistory(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	v1, err := alice.Put("reports", "doc", []byte("one"), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := alice.Put("reports", "doc", []byte("two"), alice, bob)
	if err != nil || v2.Generation != v1.Generation+1 || v2.Object != v1.Object {
		t.Fatalf("overwrite = %+v, %v", v2, err)
	}
	if got, _ := alice.Get("reports", "doc", ""); string(got) != "two" {
		t.Fatalf("current = %q", got)
	}
	if got, err := alice.Get("reports", "doc", v1.Version); err != nil || string(got) != "one" {
		t.Fatalf("owner's historical read = %q, %v", got, err)
	}
	if _, err := bob.Get("reports", "doc", v1.Version); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("member's historical read without read-history: %v", err)
	}
	if got, err := bob.Get("reports", "doc", ""); err != nil || string(got) != "two" {
		t.Fatalf("member's current read: %q, %v", got, err)
	}
	vs, err := st.Content.ListVersions(ctx, bob.Caller, "reports", "doc", 0, "")
	if err != nil || len(vs.Versions) != 1 || !vs.Versions[0].Current {
		t.Fatalf("member's version list = %+v, %v; want only the current version", vs, err)
	}
	if vs, err := st.Content.ListVersions(ctx, alice.Caller, "reports", "doc", 0, ""); err != nil || len(vs.Versions) != 2 {
		t.Fatalf("owner's version list = %+v, %v", vs, err)
	}

	del, err := st.Content.DeleteKey(ctx, alice.Caller, "reports", "doc")
	if err != nil || del.State != "DELETE_MARKER" {
		t.Fatalf("delete key = %+v, %v", del, err)
	}
	if _, err := alice.Get("reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("current after delete: %v", err)
	}
	if got, err := alice.Get("reports", "doc", v2.Version); err != nil || string(got) != "two" {
		t.Fatalf("historical read after delete (V-146) = %q, %v", got, err)
	}
	wd, err := st.Content.DeleteVersion(ctx, alice.Caller, "reports", "doc", v1.Version)
	if err != nil || wd.State != "WITHDRAWN" {
		t.Fatalf("delete version = %+v, %v", wd, err)
	}
	if _, err := alice.Get("reports", "doc", v1.Version); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("read of a withdrawn version: %v", err)
	}
	var retirements int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM retirements WHERE done_at IS NULL`).Scan(&retirements)
	if retirements != 1 {
		t.Errorf("pending retirements = %d, want 1", retirements)
	}
	if _, err := st.Content.DeleteVersion(ctx, bob.Caller, "reports", "doc", v2.Version); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("member deletes a version: %v", err)
	}
}

// TestPreconditionsAndConcurrency covers PUB-007: preconditions apply to the
// committed head at commit, and two uploads against the same obsolete
// generation cannot both publish.
func TestPreconditionsAndConcurrency(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	v1, err := alice.Put("reports", "doc", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]content.BeginRequest{
		"if-none-match on a live key": {Bucket: "reports", Key: "doc", IfNoneMatch: true},
		"if-match another etag":       {Bucket: "reports", Key: "doc", IfMatch: content.ETag(cryptowire.NewUUID())},
	} {
		u, err := alice.Prepare(req, []byte("x"), alice)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := alice.Finalize(u); !errors.Is(err, content.ErrPrecondition) {
			t.Errorf("%s: %v, want precondition failed", name, err)
		}
	}
	first, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IfMatch: v1.ETag}, []byte("two"), alice)
	if err != nil {
		t.Fatal(err)
	}
	second, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc"}, []byte("three"), alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(first); err != nil {
		t.Fatalf("first overwrite: %v", err)
	}
	if _, err := alice.Finalize(second); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("second overwrite against the same generation: %v, want conflict", err)
	}
	if got, _ := alice.Get("reports", "doc", ""); string(got) != "two" {
		t.Fatalf("current = %q", got)
	}
	// A new key with If-None-Match, and a recreated key after deletion.
	if _, err := st.Content.DeleteKey(ctx, alice.Caller, "reports", "doc"); err != nil {
		t.Fatal(err)
	}
	u, _ := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IfNoneMatch: true}, []byte("again"), alice)
	if _, err := alice.Finalize(u); err != nil {
		t.Fatalf("if-none-match on a deleted key: %v", err)
	}
}

// TestRetriesAreIdempotent covers the write and retry sequence and
// CRY-007: the same idempotency key and request return the same intent,
// identical bytes the same receipt, and a committed finalize its result;
// a changed request or other bytes conflict.
func TestRetriesAreIdempotent(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	req := content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "upload-1"}
	u, err := alice.Prepare(req, []byte("one"), alice)
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.Content.Begin(ctx, alice.Caller, req)
	if err != nil || again.IntentID != u.Intent.IntentID || again.Blob != u.Intent.Blob {
		t.Fatalf("retried begin = %+v, %v", again, err)
	}
	if _, err := st.Content.Begin(ctx, alice.Caller, content.BeginRequest{Bucket: "reports", Key: "other", IdempotencyKey: "upload-1"}); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("reused idempotency key: %v", err)
	}
	if _, err := st.Content.PutCiphertext(ctx, alice.Caller, u.Intent.IntentID, int64(len(u.Ciphertext)), u.Sealed.CiphertextSHA256, bytes.NewReader(u.Ciphertext)); err != nil {
		t.Fatalf("identical ciphertext retry: %v", err)
	}
	other := bytes.Clone(u.Ciphertext)
	other[0] ^= 1
	if _, err := st.Content.PutCiphertext(ctx, alice.Caller, u.Intent.IntentID, int64(len(other)), cryptowire.Digest(sha(other)), bytes.NewReader(other)); err == nil {
		t.Fatal("other bytes for a staged intent were accepted")
	}
	p1, err := alice.Finalize(u)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := alice.Finalize(u)
	if err != nil || p2 != p1 {
		t.Fatalf("retried finalize = %+v, %v; want %+v", p2, err, p1)
	}
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := st.Content.Finalize(ctx, bob.Caller, u.Intent.IntentID, content.FinalizeRequest{}); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("another principal finalizes the intent: %v", err)
	}
}

// TestUploadValidation covers CRY-004, KEY-003 and RCP-008: the descriptor
// must be signed by an active signing key of the uploader and match the
// intent and the staged ciphertext; envelopes must name active recipients.
func TestUploadValidation(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	forged := u
	forged.Sealed.DescriptorSignature, _ = bob.Signer.Sign(cryptowire.TypeDescriptor, u.Sealed.Descriptor)
	if _, err := alice.Finalize(forged); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("descriptor signed by another user's key: %v", err)
	}
	if _, err := st.Catalog.Pool().Exec(ctx, `UPDATE signing_keys SET status = 'COMPROMISED' WHERE principal = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(u); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("descriptor signed by a compromised key: %v", err)
	}
}

// TestListing covers CNT-005 to CNT-007: per-entry discovery filters names
// and metadata, pages carry a continuation bound to the caller and query,
// and the cursor makes progress.
func TestListing(t *testing.T) {
	st := r1test.New(t)
	st.LabeledBucket("vault", "p1", "secret")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	for _, k := range []string{"a1", "a2", "a3"} {
		if _, err := alice.Put("vault", k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"b1", "b2"} {
		if _, err := bob.Put("vault", k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	var keys []string
	cont := ""
	for pages := 0; ; pages++ {
		page, err := st.Content.List(ctx, bob.Caller, "vault", "", 1, cont)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Entries {
			keys = append(keys, e.Key)
		}
		if page.Continuation == "" || pages > 10 {
			break
		}
		if _, err := st.Content.List(ctx, alice.Caller, "vault", "", 1, page.Continuation); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("another caller replays the token: %v", err)
		}
		if _, err := st.Content.List(ctx, bob.Caller, "vault", "b", 1, page.Continuation); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("token with another prefix: %v", err)
		}
		cont = page.Continuation
	}
	if len(keys) != 2 || keys[0] != "b1" || keys[1] != "b2" {
		t.Fatalf("bob sees %v, want [b1 b2]", keys)
	}
	page, err := st.Content.List(ctx, alice.Caller, "vault", "a", 10, "")
	if err != nil || len(page.Entries) != 3 || page.Continuation != "" {
		t.Fatalf("alice's prefix listing = %+v, %v", page, err)
	}
	carol := st.Client("carol", []string{"member"}, "p2")
	if _, err := st.Content.List(ctx, carol.Caller, "vault", "", 10, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("listing without bucket list: %v", err)
	}
}

// TestStreamLease covers CNT-008: an admitted stream aborts after the bound
// authority changes, and emits nothing at or after valid_until.
func TestStreamLease(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	big := bytes.Repeat([]byte("x"), 3<<20)
	if _, err := alice.Put("reports", "big", big); err != nil {
		t.Fatal(err)
	}
	stream, err := st.Content.ReadCiphertext(ctx, alice.Caller, "reports", "big", "")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := stream.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.TouchIdentity(ctx, r1test.Tenant, "alice"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * r1test.LeaseCheckEvery)
	if _, err := io.ReadAll(stream); !errors.Is(err, content.ErrLease) {
		t.Fatalf("stream after a revision change: %v, want %v", err, content.ErrLease)
	}
	stream.Close()

	alice = st.Client("alice", []string{"member"}, "p1")
	stream, err = st.Content.ReadCiphertext(ctx, alice.Caller, "reports", "big", "")
	if err != nil {
		t.Fatal(err)
	}
	*st.Clock = st.Clock.Add(time.Hour)
	if _, err := stream.Read(buf); !errors.Is(err, content.ErrLease) {
		t.Fatalf("read after valid_until: %v", err)
	}
	stream.Close()
}

// TestRevocationBeforePublish covers V-142's ordering at the service level:
// a principal disabled between prepare and publish cannot publish, and
// nothing becomes visible.
func TestRevocationBeforePublish(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.DisableIdentity(ctx, r1test.Tenant, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(u); err == nil {
		t.Fatal("a disabled principal published")
	}
	var versions int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM object_versions`).Scan(&versions)
	if versions != 0 {
		t.Fatalf("versions = %d, want 0", versions)
	}
}

// TestDefaultDenyUploads covers ruling 7 for the upload steps that used to
// rely on the stored intent alone: an idempotent begin retry and staging
// each take a fresh decision, so a caller who lost the right is refused
// and nothing is staged.
func TestDefaultDenyUploads(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	req := content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "upload-1"}
	in, err := st.Content.Begin(ctx, alice.Caller, req)
	if err != nil {
		t.Fatal(err)
	}
	moved := st.User("alice", []string{"member"}, "p2")
	if _, err := st.Content.Begin(ctx, moved, req); err == nil {
		t.Fatal("a begin retry was answered without the create-object right")
	}
	body := []byte("ciphertext")
	if _, err := st.Content.PutCiphertext(ctx, moved, in.IntentID, int64(len(body)), cryptowire.Digest(sha(body)), bytes.NewReader(body)); err == nil {
		t.Fatal("bytes were staged without the create-object right")
	}
	if state := intentState(t, st, in.IntentID); state != "RESERVED" {
		t.Fatalf("intent state = %s, want RESERVED", state)
	}
}

// TestUploadLease covers DAT-007 for staging: an admitted upload aborts
// when the bound authority changes, and the intent stays RESERVED.
func TestUploadLease(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	in, err := st.Content.Begin(ctx, alice.Caller, content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "upload-1"})
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1<<20)
	body := &slowBody{data: data, chunk: 64 << 10, pause: func() {
		if err := st.Catalog.TouchIdentity(ctx, r1test.Tenant, "alice"); err != nil {
			t.Error(err)
		}
		time.Sleep(3 * r1test.LeaseCheckEvery)
	}}
	_, err = st.Content.PutCiphertext(ctx, alice.Caller, in.IntentID, int64(len(data)), cryptowire.Digest(sha(data)), body)
	if !errors.Is(err, content.ErrLease) {
		t.Fatalf("upload after a revision change: %v, want %v", err, content.ErrLease)
	}
	if state := intentState(t, st, in.IntentID); state != "RESERVED" {
		t.Fatalf("intent state = %s, want RESERVED", state)
	}
}

// slowBody yields data in chunks and calls pause once, before the second.
type slowBody struct {
	data  []byte
	chunk int
	reads int
	pause func()
}

func (b *slowBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	if b.reads++; b.reads == 2 {
		b.pause()
	}
	n := copy(p[:min(len(p), b.chunk)], b.data)
	b.data = b.data[n:]
	return n, nil
}

func intentState(t *testing.T, st *r1test.Stack, id cryptowire.UUID) string {
	t.Helper()
	var state string
	if err := st.Pool.QueryRow(ctx, `SELECT state FROM upload_intents WHERE id = $1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

// TestListVersionsHead is the regression test of review v3 F10: the
// listing read the current-version pointer before its decisions and never
// checked it again, so after an overwrite in between a caller without
// discover-history got the old version marked current. The listing now
// reads the head and the versions in one snapshot and starts again when
// the head moved since its decisions.
func TestListVersionsHead(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	v1, err := alice.Put("reports", "doc", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	var v2 content.Published
	overwritten := false
	st.BeforeDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpListVersions && !overwritten {
			overwritten = true
			if v2, err = alice.Put("reports", "doc", []byte("two")); err != nil {
				t.Error(err)
			}
		}
	}
	vs, err := st.Content.ListVersions(ctx, bob.Caller, "reports", "doc", 0, "")
	st.BeforeDecide = nil
	if err != nil || len(vs.Versions) != 1 || vs.Versions[0].Version != v2.Version || !vs.Versions[0].Current {
		t.Fatalf("bob's list after an overwrite during it: %+v, %v (v1 %s, v2 %s)", vs, err, v1.Version, v2.Version)
	}
}

// TestListVersionsPages is the regression test of review v3 F11: the
// version listing ignored the limit and continuation it documents and
// returned every version at once. It now pages.
func TestListVersionsPages(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	want := map[string]bool{}
	for i := range 5 {
		p, err := alice.Put("reports", "doc", []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		want[p.Version] = true
		*st.Clock = st.Clock.Add(time.Second)
	}
	got := map[string]bool{}
	var sizes []int
	cont := ""
	for range 5 {
		page, err := st.Content.ListVersions(ctx, alice.Caller, "reports", "doc", 2, cont)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(page.Versions))
		for _, v := range page.Versions {
			if got[v.Version] {
				t.Fatalf("version %s listed twice", v.Version)
			}
			got[v.Version] = true
		}
		if cont = page.Continuation; cont == "" {
			break
		}
	}
	if !maps.Equal(got, want) || !slices.Equal(sizes, []int{2, 2, 1}) {
		t.Fatalf("pages of %v, %d versions; want 2, 2, 1 covering all 5", sizes, len(got))
	}
	if _, err := st.Content.ListVersions(ctx, alice.Caller, "reports", "doc", 2, "bogus"); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a forged continuation: %v", err)
	}
}
