package datakeys_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/datakeys"
	"fga/internal/datakeysapi"
	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/kek"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/rpc"
	"fga/internal/signing"
)

var ctx = context.Background()

// fixture is a stack with a server-mode bucket "vault"; the stack's ring
// and catalog hold the tenant's KEK version 1, and its data-key service is
// the keys role's. Server-mode
// uploads and reads are built in stretch S3, so the tests play the storage
// role: they write server-mode intents and versions and ask for decisions.
type fixture struct {
	st     *r1test.Stack
	ring   *kek.Ring
	svc    *datakeys.Service
	vault  string
	tenant cryptowire.UUID
	alice  *r1test.Client
}

func setup(t *testing.T) *fixture {
	t.Helper()
	st := r1test.New(t)
	f := &fixture{st: st, ring: st.KEKs, svc: st.DataKeys}
	f.st.ModeBucket("vault", "p1", "internal", "server")
	f.alice = f.st.Client("alice", []string{"member"}, "p1")
	if err := f.st.Pool.QueryRow(ctx, `SELECT b.id::text, t.id FROM buckets b JOIN tenants t ON t.name = b.tenant WHERE b.name = 'vault'`).
		Scan(&f.vault, &f.tenant); err != nil {
		t.Fatal(err)
	}
	return f
}

// rotate adds the next KEK version and reseals the tenant's data keys
// under it, as fga-admin kek rotate does; want is how many.
func (f *fixture) rotate(t *testing.T, want int) uint32 {
	t.Helper()
	v, err := f.ring.Add(r1test.Tenant, *f.st.Clock)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.st.Catalog.RotateKEK(ctx, r1test.Tenant, v, *f.st.Clock, func(k catalog.SealedKey) ([]byte, error) {
		return f.ring.Reseal(r1test.Tenant, k.KEKVersion, v, k.Sealed,
			kek.Binding{Tenant: k.Tenant, Object: k.Object, Version: k.Version, CryptoVersion: k.CryptoVersion, Blob: k.Blob})
	})
	if err != nil || n != want {
		t.Fatalf("rotation to version %d resealed %d keys (want %d): %v", v, n, want, err)
	}
	return v
}

// decide asks the decision service, as the storage role, for a single-use
// decision for the keys role.
func (f *fixture) decide(t *testing.T, c *r1test.Client, op string, checks ...decisionsvc.Check) signing.Signed {
	t.Helper()
	id, err := f.st.Catalog.GetIdentity(ctx, r1test.Tenant, c.Caller.Principal)
	if err != nil {
		t.Fatal(err)
	}
	resp := f.st.Decisions.Decide(ctx, r1test.StorageAdapter, decisionsvc.Request{RequestID: "r", Tenant: r1test.Tenant, Operation: op,
		OperationID: cryptowire.NewUUID().String(), OperationDigest: "sha256:t", Audience: enforce.KeysAudience, SingleUse: true,
		Actor: decisionsvc.Ref{ID: c.Caller.Principal, Revision: id.Revision}, Evidence: c.Caller.Token, Checks: checks})
	if resp.Outcome != "ALLOW" {
		t.Fatalf("decision %s: %s %s", op, resp.Outcome, resp.Reason)
	}
	payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	return signing.Signed{Payload: payload, JWS: resp.Signed.JWS}
}

func createObject(bucket string) decisionsvc.Check {
	return decisionsvc.Check{ID: "bucket", Role: registry.RoleBucket, Action: "create-object", Resource: decisionsvc.Alias{Type: "storage.bucket", ID: bucket}}
}

func read(object, version string) decisionsvc.Check {
	return decisionsvc.Check{ID: "object", Role: registry.RoleObject, Action: "read", Resource: decisionsvc.Alias{Type: "storage.object", ID: object},
		Version: version}
}

func readHistory(object, version string) decisionsvc.Check {
	return decisionsvc.Check{ID: "history", Role: registry.RoleHistory, Action: "read-history",
		Resource: decisionsvc.Alias{Type: "storage.object", ID: object}, Version: version}
}

// intent writes a RESERVED upload intent of principal for a new key in
// bucket, in mode.
func (f *fixture) intent(t *testing.T, principal, bucket, mode string) (string, kek.Binding) {
	t.Helper()
	id := cryptowire.NewUUID()
	b := kek.Binding{Tenant: f.tenant, Object: cryptowire.NewUUID(), Version: cryptowire.NewUUID(), CryptoVersion: cryptowire.NewUUID(),
		Blob: cryptowire.NewUUID()}
	if _, err := f.st.Pool.Exec(ctx, `
		INSERT INTO upload_intents (tenant, id, principal, actor, idempotency_key, request_digest, bucket, key, object, new_object, version,
		                            crypto_version, blob, attempt, expected_generation, planned_scope, planned_attributes, state, expires_at,
		                            created_at, kind, encryption)
		VALUES ($1, $2, $3, $3, $4, 'd', $5, $6, $7, true, $8, $9, $10, gen_random_uuid(), 0, '', '{}', 'RESERVED', $11, $12, 'object', $13)`,
		r1test.Tenant, id, principal, id.String(), bucket, "k-"+id.String(), b.Object, b.Version, b.CryptoVersion, b.Blob,
		f.st.Clock.Add(time.Hour), *f.st.Clock, mode); err != nil {
		t.Fatal(err)
	}
	return id.String(), b
}

// version publishes a LIVE server-mode version of alice's object at key in
// vault (creating the object first) with a fresh data key sealed under
// KEK version 1, and makes it current, as a server-mode publish will.
func (f *fixture) version(t *testing.T, object cryptowire.UUID, key string) (string, []byte) {
	t.Helper()
	tag, err := f.st.Pool.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		r1test.Tenant, object, f.vault, key)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() == 1 {
		if _, err := f.st.Pool.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'storage.object', '', 1, 0, 1, $3)`, r1test.Tenant, object.String(),
			`{"bucket":"vault","owner":"alice","project":"p1","label":"internal","encryption":"server"}`); err != nil {
			t.Fatal(err)
		}
	}
	b := kek.Binding{Tenant: f.tenant, Object: object, Version: cryptowire.NewUUID(), CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
	dataKey, err := kek.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := f.ring.Seal(r1test.Tenant, 1, dataKey, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `
		INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
		                             created_at, published_at, encryption, sealed_key, kek_version, plaintext_length)
		VALUES ($1, $2, $3, $4, $5, 'LIVE', 10, $6, 1, 2, now(), now(), 'server', $7, 1, 0)`,
		r1test.Tenant, b.Version, b.Object, b.CryptoVersion, b.Blob, "sha256:"+strings.Repeat("0", 64), sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE objects SET current_version = $2 WHERE tenant = $1 AND id = $3`, r1test.Tenant, b.Version, b.Object); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2`,
		r1test.Tenant, b.Object.String()); err != nil {
		t.Fatal(err)
	}
	return b.Version.String(), dataKey
}

// noKeyInAudit: audit records of seals and releases name identities and
// the KEK version, never the key (SSE-004).
func noKeyInAudit(t *testing.T, st *r1test.Stack, outcome string, want int, keys ...[]byte) {
	t.Helper()
	rows, err := st.Pool.Query(ctx, `SELECT event::text FROM audit_outbox WHERE event->>'outcome' = $1`, outcome)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.Contains(ev, `"kek_version"`) {
			t.Errorf("%s record without its KEK version: %s", outcome, ev)
		}
		for _, k := range keys {
			if strings.Contains(ev, base64.StdEncoding.EncodeToString(k)) || strings.Contains(ev, base64.RawURLEncoding.EncodeToString(k)) {
				t.Errorf("%s record holds a data key", outcome)
			}
		}
	}
	if n != want {
		t.Fatalf("%d %s records, want %d", n, outcome, want)
	}
}

// TestSeal covers SSE-001 and SSE-003 for sealing: a server-mode intent
// gets its data key once, against a single-use decision for the intent's
// own principal and bucket; the key is sealed under the active KEK for the
// intent's exact identity and stored with it.
func TestSeal(t *testing.T) {
	f := setup(t)
	id, b := f.intent(t, "alice", f.vault, "server")
	dec := f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault))
	k, err := f.svc.Seal(ctx, dec, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Key) != kek.DataKeySize || k.KEKVersion != 1 {
		t.Fatalf("data key of %d bytes under KEK %d", len(k.Key), k.KEKVersion)
	}
	var stored []byte
	var version uint32
	if err := f.st.Pool.QueryRow(ctx, `SELECT sealed_key, kek_version FROM upload_intents WHERE id::text = $1`, id).Scan(&stored, &version); err != nil {
		t.Fatal(err)
	}
	if got, err := f.ring.Open(r1test.Tenant, version, stored, b); err != nil || !bytes.Equal(got, k.Key) || !bytes.Equal(stored, k.Sealed) {
		t.Fatalf("the stored sealed key does not open to the data key: %v", err)
	}
	if _, err := f.svc.Seal(ctx, dec, id); err == nil {
		t.Fatal("a decision was used twice")
	}
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id); !errors.Is(err, datakeys.ErrConflict) {
		t.Fatalf("an intent got a second data key: %v", err)
	}

	// The decision is about this intent: its bucket, its principal, its
	// mode, and the sealing operation.
	f.st.ModeBucket("other", "p1", "internal", "server")
	var other string
	if err := f.st.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'other'`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	id2, _ := f.intent(t, "alice", f.vault, "server")
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(other)), id2); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a decision about another bucket: %v", err)
	}
	bob := f.st.Client("bob", []string{"member"}, "p1")
	if _, err := f.svc.Seal(ctx, f.decide(t, bob, registry.OpKeySealCreate, createObject(f.vault)), id2); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("bob's decision for alice's intent: %v", err)
	}
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpBeginCreate, createObject(f.vault)), id2); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a decision for another operation: %v", err)
	}
	f.st.Bucket("reports", "p1")
	var reports string
	if err := f.st.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'reports'`).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	id3, _ := f.intent(t, "alice", reports, "client")
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(reports)), id3); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a client-mode intent got a data key: %v", err)
	}
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id2); err != nil {
		t.Fatalf("the intent's own decision: %v", err)
	}
	noKeyInAudit(t, f.st, "DATA_KEY_SEALED", 2, k.Key)
}

// TestSealWithoutKEK: a tenant without an active KEK version gets no data
// key, and nothing is stored.
func TestSealWithoutKEK(t *testing.T) {
	f := setup(t)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE kek_versions SET state = 'RETIRED'`); err != nil {
		t.Fatal(err)
	}
	id, _ := f.intent(t, "alice", f.vault, "server")
	if _, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id); !errors.Is(err, datakeys.ErrUnavailable) {
		t.Fatalf("sealed without an active KEK: %v", err)
	}
	var sealed bool
	if err := f.st.Pool.QueryRow(ctx, `SELECT sealed_key IS NOT NULL FROM upload_intents WHERE id::text = $1`, id).Scan(&sealed); err != nil || sealed {
		t.Fatalf("a key was stored: %v", err)
	}
}

// TestRelease covers SSE-003 for release and the cases V-161 and V-162:
// a version's data key is released only against a single-use decision for
// that exact version; a plain read releases only the current version, so
// an overwrite between decision and release yields no key, while a
// history read releases the old one; a client-mode version has none.
func TestRelease(t *testing.T) {
	f := setup(t)
	obj := cryptowire.NewUUID()
	v1, key1 := f.version(t, obj, "a.txt")
	dec := f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1))
	got, err := f.svc.Release(ctx, dec, v1)
	if err != nil || !bytes.Equal(got, key1) {
		t.Fatalf("release: %v", err)
	}
	if _, err := f.svc.Release(ctx, dec, v1); err == nil {
		t.Fatal("a decision was used twice")
	}

	// V-162: a decision for one version releases no other.
	obj2 := cryptowire.NewUUID()
	other, _ := f.version(t, obj2, "b.txt")
	if _, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1)), other); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a decision for another version: %v", err)
	}
	// The plain object read has the same check, but is not a release.
	if _, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpRead, read(obj.String(), v1)), v1); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a decision for another operation: %v", err)
	}

	// V-161: the head advances between decision and release.
	stale := f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1))
	v2, key2 := f.version(t, obj, "a.txt")
	if got, err := f.svc.Release(ctx, stale, v1); got != nil || !(errors.Is(err, datakeys.ErrDecision) || errors.Is(err, datakeys.ErrNotFound)) {
		t.Fatalf("an old version released as a current read: %v", err)
	}
	if got, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1)), v1); got != nil || err == nil {
		t.Fatalf("a plain read of an old version: %v", err)
	}
	hist := f.decide(t, f.alice, registry.OpKeyReleaseHistory, read(obj.String(), v1), readHistory(obj.String(), v1))
	if got, err := f.svc.Release(ctx, hist, v1); err != nil || !bytes.Equal(got, key1) {
		t.Fatalf("a history read of the old version: %v", err)
	}
	if got, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v2)), v2); err != nil || !bytes.Equal(got, key2) {
		t.Fatalf("the current version: %v", err)
	}

	// A client-mode version has no data key here (ENC-002).
	f.st.Bucket("reports", "p1")
	p, err := f.alice.Put("reports", "c.txt", []byte("client"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(p.Object, p.Version)), p.Version); !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("a client-mode version: %v", err)
	}
	noKeyInAudit(t, f.st, "DATA_KEY_RELEASED", 3, key1, key2)
}

// TestReleaseStaleEpoch covers V-160: a decision made before the tenant's
// policy epoch advanced releases nothing.
func TestReleaseStaleEpoch(t *testing.T) {
	f := setup(t)
	obj := cryptowire.NewUUID()
	v1, _ := f.version(t, obj, "a.txt")
	dec := f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1))
	if _, err := f.st.Pool.Exec(ctx, `UPDATE tenant_epochs SET required_epoch = required_epoch + 1 WHERE tenant = $1`, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.Release(ctx, dec, v1); got != nil || !errors.Is(err, datakeys.ErrDecision) {
		t.Fatalf("released under a stale policy epoch: %v", err)
	}
	noKeyInAudit(t, f.st, "DATA_KEY_RELEASED", 0)
}

// TestRotation covers V-166 and SSE-002: rotating the tenant's KEK
// reseals every data key, of versions and of intents, without changing
// ciphertext; releases return the same data keys; new seals use the new
// version; the old one is retired.
func TestRotation(t *testing.T) {
	f := setup(t)
	obj := cryptowire.NewUUID()
	v1, key1 := f.version(t, obj, "a.txt")
	id, b := f.intent(t, "alice", f.vault, "server")
	k, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id)
	if err != nil {
		t.Fatal(err)
	}
	var sumBefore string
	if err := f.st.Pool.QueryRow(ctx, `SELECT ciphertext_sha256 FROM object_versions WHERE id::text = $1`, v1).Scan(&sumBefore); err != nil {
		t.Fatal(err)
	}
	v := f.rotate(t, 2)
	var states string
	var sumAfter string
	var versionKEK, intentKEK uint32
	var intentSealed []byte
	if err := f.st.Pool.QueryRow(ctx, `SELECT
		(SELECT string_agg(version || ':' || state, ',' ORDER BY version) FROM kek_versions),
		(SELECT ciphertext_sha256 FROM object_versions WHERE id::text = $1), (SELECT kek_version FROM object_versions WHERE id::text = $1),
		(SELECT kek_version FROM upload_intents WHERE id::text = $2), (SELECT sealed_key FROM upload_intents WHERE id::text = $2)`, v1, id).
		Scan(&states, &sumAfter, &versionKEK, &intentKEK, &intentSealed); err != nil {
		t.Fatal(err)
	}
	if states != "1:RETIRED,2:ACTIVE" || sumAfter != sumBefore || versionKEK != v || intentKEK != v {
		t.Fatalf("after rotation: KEKs %s, digest changed %t, version under %d, intent under %d", states, sumAfter != sumBefore, versionKEK, intentKEK)
	}
	if got, err := f.ring.Open(r1test.Tenant, v, intentSealed, b); err != nil || !bytes.Equal(got, k.Key) {
		t.Fatalf("the intent's resealed key: %v", err)
	}
	if got, err := f.svc.Release(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1)), v1); err != nil || !bytes.Equal(got, key1) {
		t.Fatalf("release after rotation: %v", err)
	}
	id2, _ := f.intent(t, "alice", f.vault, "server")
	if k2, err := f.svc.Seal(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id2); err != nil || k2.KEKVersion != v {
		t.Fatalf("a new seal after rotation: version %d, %v", k2.KEKVersion, err)
	}
	if _, err := f.st.Catalog.RotateKEK(ctx, r1test.Tenant, v, *f.st.Clock, nil); err == nil {
		t.Fatal("a rotation to a version that is not newer")
	}
}

type adapterHeader string

func (a adapterHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Adapter", string(a))
	return http.DefaultTransport.RoundTrip(r)
}

// TestRoutes covers the internal routes and the storage role's client:
// only the storage workload may call them, and an absent target is the
// shared not-found.
func TestRoutes(t *testing.T) {
	f := setup(t)
	mux := http.NewServeMux()
	datakeysapi.Register(f.svc, func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Adapter"), nil }, r1test.StorageAdapter)(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	storage := rpc.KeysClient{BaseURL: srv.URL, HTTP: &http.Client{Transport: adapterHeader(r1test.StorageAdapter)}}
	mcp := rpc.KeysClient{BaseURL: srv.URL, HTTP: &http.Client{Transport: adapterHeader("mcp-1")}}

	id, _ := f.intent(t, "alice", f.vault, "server")
	if _, err := mcp.SealDataKey(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("another workload got a data key: %v", err)
	}
	k, err := storage.SealDataKey(ctx, f.decide(t, f.alice, registry.OpKeySealCreate, createObject(f.vault)), id)
	if err != nil || len(k.Key) != kek.DataKeySize || k.KEKVersion != 1 {
		t.Fatalf("seal over the route: %v", err)
	}
	obj := cryptowire.NewUUID()
	v1, key1 := f.version(t, obj, "a.txt")
	if got, err := storage.ReleaseDataKey(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1)), v1); err != nil ||
		!bytes.Equal(got, key1) {
		t.Fatalf("release over the route: %v", err)
	}
	if _, err := storage.ReleaseDataKey(ctx, f.decide(t, f.alice, registry.OpKeyRelease, read(obj.String(), v1)),
		cryptowire.NewUUID().String()); !errors.Is(err, enforce.ErrNotFound) {
		t.Fatalf("an absent version: %v", err)
	}
}
