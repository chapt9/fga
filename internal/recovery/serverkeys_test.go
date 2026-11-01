package recovery_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fga/internal/backupcrypt"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/kek"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

func putServer(t *testing.T, st *r1test.Stack, c content.Caller, key, text string) content.Published {
	t.Helper()
	p, err := st.Content.PutObject(ctx, c, content.BeginRequest{Bucket: "vault", Key: key, IdempotencyKey: cryptowire.NewUUID().String()},
		int64(len(text)), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func readServer(st *r1test.Stack, c content.Caller, key string) (string, error) {
	s, err := st.Content.ReadObject(ctx, c, "vault", key, "")
	if err != nil {
		return "", err
	}
	defer s.Close()
	b, err := io.ReadAll(s)
	return string(b), err
}

// openedKey opens a version's sealed data key under the fixture's ring.
func openedKey(t *testing.T, st *r1test.Stack, version string) (sealed, dataKey []byte) {
	t.Helper()
	var b kek.Binding
	var v uint32
	if err := st.Pool.QueryRow(ctx, `SELECT t.id, o.object, o.id, o.crypto_version, o.blob, o.kek_version, o.sealed_key
	                                    FROM object_versions o JOIN tenants t ON t.name = o.tenant WHERE o.id::text = $1`, version).
		Scan(&b.Tenant, &b.Object, &b.Version, &b.CryptoVersion, &b.Blob, &v, &sealed); err != nil {
		t.Fatal(err)
	}
	dataKey, err := st.KEKs.Open(r1test.Tenant, v, sealed, b)
	if err != nil {
		t.Fatal(err)
	}
	return sealed, dataKey
}

// TestBackupHoldsSealedKeysOnly covers SSE-006: a backup holds each
// server-mode data key sealed, never unsealed, and no KEK.
func TestBackupHoldsSealedKeysOnly(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	p := putServer(t, st, alice.Caller, "plan.txt", "the plan")
	sealed, dataKey := openedKey(t, st, p.Version)
	dir := filepath.Join(t.TempDir(), "plain")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	ring, err := st.KEKs.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var rf struct {
		Tenants map[string][]struct {
			Key []byte `json:"key"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal(ring, &rf); err != nil || len(rf.Tenants[r1test.Tenant]) == 0 {
		t.Fatalf("ring: %v", err)
	}
	secrets := map[string][]byte{"the data key": dataKey, "the data key in hex": []byte(hex.EncodeToString(dataKey))}
	for i, e := range rf.Tenants[r1test.Tenant] {
		secrets["KEK "+string(rune('1'+i))] = e.Key
		secrets["KEK "+string(rune('1'+i))+" in base64"] = []byte(base64.StdEncoding.EncodeToString(e.Key))
		secrets["KEK "+string(rune('1'+i))+" in hex"] = []byte(hex.EncodeToString(e.Key))
	}
	var holdsSealed bool
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for name, secret := range secrets {
			if bytes.Contains(b, secret) {
				t.Errorf("%s holds %s", path, name)
			}
		}
		holdsSealed = holdsSealed || bytes.Contains(b, []byte(hex.EncodeToString(sealed)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !holdsSealed {
		t.Fatal("the backup lacks the sealed data key")
	}
}

// TestReconcileChecksKeys covers SSE-006 and the owner's restore safeguard
// of 1 November 2026: reconcile refuses to reopen admission without the
// KEK ring. A ring that lacks a KEK version the catalog records, or holds
// another key under its number so that none of its data keys opens,
// keeps admission closed and quarantines nothing, since quarantine cannot
// be undone; only an operator's accepted loss, audited, quarantines those
// versions. A sealed key that does not open among keys that do is
// quarantined; with the right ring the keys open and the content reads.
func TestReconcileChecksKeys(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	a := putServer(t, st, alice.Caller, "a.txt", "alpha")
	putServer(t, st, alice.Caller, "b.txt", "bravo")
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		t.Helper()
		if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	quarantined := func() int {
		t.Helper()
		return st.Count(`SELECT count(*) FROM object_versions WHERE state = 'QUARANTINED'`)
	}

	restore()
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); !errors.Is(err, recovery.ErrNoKEKs) {
		t.Fatalf("reconcile without the ring: %v", err)
	}
	if _, err := readServer(st, st.Caller("alice"), "a.txt"); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("a read while admission stays closed: %v", err)
	}
	other := kek.NewRing()
	if _, err := other.Add(r1test.Tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, ring := range map[string]*kek.Ring{"a ring lacking the KEK": kek.NewRing(), "another key under its number": other} {
		rep, err := recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, st.Journal, recovery.Options{KEKs: ring})
		if !errors.Is(err, recovery.ErrKEKsMissing) || len(rep.MissingKEKs) != 1 || rep.MissingKEKs[0] != r1test.Tenant+"/1" {
			t.Fatalf("%s: %+v, %v", name, rep, err)
		}
		if n := quarantined(); n != 0 {
			t.Fatalf("%s: %d versions quarantined", name, n)
		}
		if _, err := readServer(st, st.Caller("alice"), "a.txt"); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("%s: a read: %v", name, err)
		}
	}
	rep, err := recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, st.Journal, recovery.Options{KEKs: other, AcceptKEKLoss: true})
	if err != nil || rep.Quarantined != 2 || len(rep.MissingKEKs) != 1 {
		t.Fatalf("reconcile accepting the KEK's loss: %+v, %v", rep, err)
	}
	if n := st.Count(`SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'KEK_LOSS_ACCEPTED'`); n != 1 {
		t.Fatalf("%d audited acceptances", n)
	}
	if _, err := readServer(st, st.Caller("alice"), "a.txt"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a quarantined version: %v", err)
	}

	restore()
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET sealed_key = sealed_key || '\x00'::bytea WHERE id::text = $1`, a.Version); err != nil {
		t.Fatal(err)
	}
	rep, err = recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, st.Journal, recovery.Options{KEKs: st.KEKs})
	if err != nil || rep.Quarantined != 1 || rep.KeysChecked != 1 || len(rep.MissingKEKs) != 0 {
		t.Fatalf("reconcile with an altered sealed key: %+v, %v", rep, err)
	}
	if got, err := readServer(st, st.Caller("alice"), "b.txt"); err != nil || got != "bravo" {
		t.Fatalf("the intact version: %q %v", got, err)
	}
	if _, err := readServer(st, st.Caller("alice"), "a.txt"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("the version whose key does not open: %v", err)
	}

	restore()
	rep, err = recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, st.Journal, recovery.Options{KEKs: st.KEKs})
	if err != nil || rep.Quarantined != 0 || rep.KeysChecked != 2 {
		t.Fatalf("reconcile with the ring: %+v, %v", rep, err)
	}
	if got, err := readServer(st, st.Caller("alice"), "a.txt"); err != nil || got != "alpha" {
		t.Fatalf("after reconcile: %q %v", got, err)
	}
}

// TestReclaimDestroysKeys covers SSE-006: retiring a withdrawn server-mode
// version destroys its sealed data key, the upload's copy with it, and
// records when; a backup taken before still holds the key and restores
// the content.
func TestReclaimDestroysKeys(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	v1 := putServer(t, st, alice.Caller, "plan.txt", "one")
	putServer(t, st, alice.Caller, "plan.txt", "two")
	if _, err := st.Content.DeleteVersion(ctx, alice.Caller, "vault", "plan.txt", v1.Version); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	at := st.Clock.Add(time.Hour)
	got, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, at)
	if err != nil || got.Retired != 1 || got.KeysDestroyed != 1 || !got.At.Equal(at) {
		t.Fatalf("reclaim = %+v, %v", got, err)
	}
	var sealed int
	var destroyed *time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT key_destroyed_at FROM object_versions WHERE id::text = $1 AND sealed_key IS NULL AND kek_version IS NULL`,
		v1.Version).Scan(&destroyed); err != nil || destroyed == nil || !destroyed.Equal(at) {
		t.Fatalf("the retired version: destroyed at %v, %v", destroyed, err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM upload_intents WHERE sealed_key IS NOT NULL`).Scan(&sealed); err != nil || sealed != 0 {
		t.Fatalf("%d upload intents still hold sealed keys, %v", sealed, err)
	}
	if got, err := readServer(st, alice.Caller, "plan.txt"); err != nil || got != "two" {
		t.Fatalf("the current version: %q %v", got, err)
	}
	if again, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, at); err != nil || again.Retired+again.Aborted+again.KeysDestroyed != 0 {
		t.Fatalf("second run = %+v, %v", again, err)
	}

	// The backup taken before still holds the withdrawn version's key.
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if rep, err := recovery.ReconcileWith(ctx, st.Catalog, st.Blobs, st.Journal, recovery.Options{KEKs: st.KEKs}); err != nil || rep.KeysChecked != 2 {
		t.Fatalf("reconcile: %+v, %v", rep, err)
	}
}
