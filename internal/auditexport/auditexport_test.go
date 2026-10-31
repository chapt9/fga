package auditexport_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"fga/internal/audit"
	"fga/internal/auditexport"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

var ctx = context.Background()

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func newExporter(t *testing.T, st *r1test.Stack, dir string, batch int, key ed25519.PrivateKey, edit ...func(*auditexport.Options)) *auditexport.Exporter {
	t.Helper()
	o := auditexport.Options{Batch: batch, Key: key}
	for _, f := range edit {
		f(&o)
	}
	x, err := auditexport.New(st.Pool, dir, o)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func appendEvents(t *testing.T, st *r1test.Stack, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.Catalog.Append(ctx, audit.Event{ID: fmt.Sprintf("%s-%d", prefix, i), Kind: audit.KindDecision, Tenant: r1test.Tenant,
			Outcome: "ALLOW", At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}

func head(t *testing.T, st *r1test.Stack) auditexport.State {
	t.Helper()
	s, err := auditexport.Head(ctx, st.Pool)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// exportFiles returns the export files of dir, in name order.
func exportFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func readLink(t *testing.T, path string) auditexport.Link {
	t.Helper()
	raw, err := os.ReadFile(path + ".link")
	if err != nil {
		t.Fatal(err)
	}
	var l auditexport.Link
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// removeExport removes an export file with its link and signature.
func removeExport(t *testing.T, path string) {
	t.Helper()
	for _, p := range []string{path, path + ".link", path + ".link.jws"} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
}

// exported reads every exported event and returns the IDs and how many
// lines there were.
func exported(t *testing.T, dir string) (map[string]audit.Event, int) {
	t.Helper()
	events, lines := map[string]audit.Event{}, 0
	for _, f := range exportFiles(t, dir) {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			var e audit.Event
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatal(err)
			}
			events[e.ID] = e
			lines++
		}
		fh.Close()
	}
	return events, lines
}

// TestDrainAndRedelivery covers AUD-002 and AUD-003: the exporter drains
// the outbox into flushed files and marks events delivered only after;
// events exported but not marked (a crash) are exported again and
// deduplicate by ID.
func TestDrainAndRedelivery(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 7)
	dir := t.TempDir()
	pub, key := newKey(t)
	x := newExporter(t, st, dir, 3, key)
	if n, err := x.Drain(ctx); err != nil || n != 7 {
		t.Fatalf("drain = %d, %v", n, err)
	}
	if pending, _ := st.Catalog.Pending(ctx, 100); len(pending) != 0 {
		t.Fatalf("pending after drain = %d", len(pending))
	}
	files := exportFiles(t, dir)
	if len(files) != 3 {
		t.Fatalf("files = %d, want 3 batches", len(files))
	}
	for _, f := range []string{files[0], files[0] + ".link", files[0] + ".link.jws"} {
		if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", filepath.Base(f), info.Mode().Perm())
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_outbox SET delivered_at = NULL WHERE id IN ('e-0', 'e-1')`); err != nil {
		t.Fatal(err)
	}
	if n, _ := x.Drain(ctx); n != 2 {
		t.Fatalf("re-export = %d, want 2", n)
	}
	events, lines := exported(t, dir)
	if len(events) != 7 || lines != 9 {
		t.Fatalf("exported %d unique events in %d lines, want 7 in 9", len(events), lines)
	}
	if rep, err := auditexport.Verify(dir, head(t, st).Head, pub); err != nil || rep.Files != 4 || rep.Events != 9 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
}

// TestChain: each export file's link names its digest and the previous
// link, is signed with the export key, and the catalog records the last.
func TestChain(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 5)
	dir := t.TempDir()
	pub, key := newKey(t)
	if _, err := newExporter(t, st, dir, 2, key).Drain(ctx); err != nil {
		t.Fatal(err)
	}
	files := exportFiles(t, dir)
	prev := ""
	for _, f := range files {
		l := readLink(t, f)
		data, _ := os.ReadFile(f)
		sum := sha256.Sum256(data)
		if l.Previous != prev || l.File != filepath.Base(f) || l.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || l.Reset {
			t.Fatalf("link of %s: %+v (previous %q)", filepath.Base(f), l, prev)
		}
		sig, _ := os.ReadFile(f + ".link.jws")
		raw, _ := os.ReadFile(f + ".link")
		if kid, err := cryptowire.Verify(auditexport.LinkType, string(sig), raw, func(string) (ed25519.PublicKey, error) { return pub, nil }); err != nil ||
			kid != auditexport.KeyID(pub) {
			t.Fatalf("signature of %s: %q %v", filepath.Base(f), kid, err)
		}
		prev = l.Digest
	}
	if s := head(t, st); s.Head != prev || s.File != filepath.Base(files[len(files)-1]) {
		t.Fatalf("catalog head %+v, want %s", s, prev)
	}
	rep, err := auditexport.Verify(dir, prev, pub)
	if err != nil || rep.Files != 3 || rep.Events != 5 || rep.Head != prev || len(rep.Resets) != 0 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
}

func copyDir(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

// TestTamperingIsEvident: a changed, deleted, reordered, added or
// foreign-signed export file breaks the chain, and a truncated directory
// shows against the catalog's head.
func TestTamperingIsEvident(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 6)
	dir := t.TempDir()
	pub, key := newKey(t)
	if _, err := newExporter(t, st, dir, 2, key).Drain(ctx); err != nil {
		t.Fatal(err)
	}
	catalogHead := head(t, st).Head
	_, other := newKey(t)
	for _, c := range []struct {
		name    string
		tamper  func(t *testing.T, files []string)
		offline bool // only the catalog's head shows it
	}{
		{name: "changed file", tamper: func(t *testing.T, f []string) {
			fh, _ := os.OpenFile(f[1], os.O_APPEND|os.O_WRONLY, 0)
			fh.WriteString(`{"id":"forged"}` + "\n")
			fh.Close()
		}},
		{name: "deleted first", tamper: func(t *testing.T, f []string) { removeExport(t, f[0]) }},
		{name: "deleted middle", tamper: func(t *testing.T, f []string) { removeExport(t, f[1]) }},
		{name: "deleted file, link kept", tamper: func(t *testing.T, f []string) { os.Remove(f[2]) }},
		{name: "reordered", tamper: func(t *testing.T, f []string) {
			for _, s := range []string{"", ".link", ".link.jws"} {
				os.Rename(f[0]+s, f[0]+s+".tmp")
				os.Rename(f[1]+s, f[0]+s)
				os.Rename(f[0]+s+".tmp", f[1]+s)
			}
		}},
		{name: "added file", tamper: func(t *testing.T, f []string) {
			os.WriteFile(filepath.Join(filepath.Dir(f[0]), "99999999999999999999-99999999999999999999-1.jsonl"), []byte(`{"id":"forged"}`+"\n"), 0o600)
		}},
		{name: "signed with another key", tamper: func(t *testing.T, f []string) {
			raw, _ := os.ReadFile(f[2] + ".link")
			sig, _ := cryptowire.Sign(auditexport.LinkType, auditexport.KeyID(pub), other, raw)
			os.WriteFile(f[2]+".link.jws", []byte(sig), 0o600)
		}},
		{name: "truncated", offline: true, tamper: func(t *testing.T, f []string) { removeExport(t, f[2]) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := copyDir(t, dir)
			c.tamper(t, exportFiles(t, d))
			_, offline := auditexport.Verify(d, "", pub)
			_, withHead := auditexport.Verify(d, catalogHead, pub)
			if c.offline != (offline == nil) || !errors.Is(withHead, auditexport.ErrChain) {
				t.Fatalf("verify offline: %v; against the catalog's head: %v", offline, withHead)
			}
		})
	}
	if _, err := auditexport.Verify(dir, catalogHead, pub); err != nil {
		t.Fatalf("the untouched directory: %v", err)
	}
}

// TestTruncatedDirectoryStopsExport: an exporter, running or new, does
// not continue a directory that lost the catalog's head; with Reset it
// does, and the reset link records the operator's decision.
func TestTruncatedDirectoryStopsExport(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 4)
	dir := t.TempDir()
	pub, key := newKey(t)
	running := newExporter(t, st, dir, 2, key)
	if _, err := running.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	lost := head(t, st)
	removeExport(t, filepath.Join(dir, lost.File))
	appendEvents(t, st, "f", 1)
	if _, err := running.Once(ctx); !errors.Is(err, auditexport.ErrChain) {
		t.Fatalf("the running exporter: %v", err)
	}
	if _, err := newExporter(t, st, dir, 2, key).Once(ctx); !errors.Is(err, auditexport.ErrChain) {
		t.Fatalf("a new exporter: %v", err)
	}
	if n, err := newExporter(t, st, dir, 2, key, func(o *auditexport.Options) { o.Reset = true }).Once(ctx); err != nil || n != 1 {
		t.Fatalf("with reset: %d %v", n, err)
	}
	now := head(t, st)
	if l := readLink(t, filepath.Join(dir, now.File)); !l.Reset || l.Previous != lost.Head {
		t.Fatalf("reset link %+v, want a reset after %s", l, lost.Head)
	}
	rep, err := auditexport.Verify(dir, now.Head, pub)
	if err != nil || rep.Files != 2 || len(rep.Resets) != 1 || rep.Resets[0] != now.File {
		t.Fatalf("verify after reset: %+v %v", rep, err)
	}
}

// TestIncompleteExportSetAside: the leftovers of an export a crash
// interrupted (a file and link without signature) are set aside, kept,
// and their events exported again.
func TestIncompleteExportSetAside(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 2)
	dir := t.TempDir()
	pub, key := newKey(t)
	if _, err := newExporter(t, st, dir, 10, key).Drain(ctx); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, st, "f", 1)
	partial := filepath.Join(dir, "00000000000000000099-00000000000000000099-1.jsonl")
	os.WriteFile(partial, []byte(`{"id":"f-0"}`+"\n"), 0o600)
	os.WriteFile(partial+".link", []byte(`{}`), 0o600)
	if n, err := newExporter(t, st, dir, 10, key).Once(ctx); err != nil || n != 1 {
		t.Fatalf("export after a crash: %d %v", n, err)
	}
	if rep, err := auditexport.Verify(dir, head(t, st).Head, pub); err != nil || rep.Files != 2 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	if kept, _ := filepath.Glob(filepath.Join(dir, "*.incomplete")); len(kept) != 2 {
		t.Fatalf("set aside: %v", kept)
	}
}

// TestKeyRotation: links of an earlier export key verify while it is
// trusted, and not otherwise.
func TestKeyRotation(t *testing.T) {
	st := r1test.New(t)
	appendEvents(t, st, "e", 2)
	dir := t.TempDir()
	pub1, key1 := newKey(t)
	pub2, key2 := newKey(t)
	if _, err := newExporter(t, st, dir, 10, key1).Drain(ctx); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, st, "f", 1)
	if _, err := newExporter(t, st, dir, 10, key2).Once(ctx); !errors.Is(err, auditexport.ErrChain) {
		t.Fatalf("the earlier key not trusted: %v", err)
	}
	if n, err := newExporter(t, st, dir, 10, key2, func(o *auditexport.Options) { o.Trusted = []ed25519.PublicKey{pub1} }).Once(ctx); err != nil || n != 1 {
		t.Fatalf("the earlier key trusted: %d %v", n, err)
	}
	h := head(t, st).Head
	if rep, err := auditexport.Verify(dir, h, pub1, pub2); err != nil || rep.Files != 2 {
		t.Fatalf("verify with both keys: %+v %v", rep, err)
	}
	if _, err := auditexport.Verify(dir, h, pub2); !errors.Is(err, auditexport.ErrChain) {
		t.Fatalf("verify with the new key alone: %v", err)
	}
}

// TestCollector: export files go to the collector in chain order with
// their signed links; an outage does not hold up the export, and the next
// pass sends what is left.
func TestCollector(t *testing.T) {
	st := r1test.New(t)
	pub, key := newKey(t)
	var mu sync.Mutex
	var got []string
	down := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if down || r.Header.Get("Authorization") != "Bearer collector-token" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw, _ := base64.StdEncoding.DecodeString(r.Header.Get("Fga-Audit-Link"))
		if _, err := cryptowire.Verify(auditexport.LinkType, r.Header.Get("Fga-Audit-Link-Signature"), raw,
			func(string) (ed25519.PublicKey, error) { return pub, nil }); err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		var l auditexport.Link
		_ = json.Unmarshal(raw, &l)
		if sum := sha256.Sum256(body); l.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			http.Error(w, "digest", http.StatusBadRequest)
			return
		}
		got = append(got, l.File)
	}))
	defer srv.Close()
	if _, err := auditexport.New(st.Pool, t.TempDir(), auditexport.Options{Batch: 1, Key: key,
		Collector: &auditexport.Collector{URL: "http://collector.example/audit"}}); err == nil {
		t.Fatal("plain http to a remote collector accepted")
	}
	dir := t.TempDir()
	x := newExporter(t, st, dir, 1, key, func(o *auditexport.Options) {
		o.Collector = &auditexport.Collector{URL: srv.URL, Token: "collector-token"}
	})
	appendEvents(t, st, "e", 3)
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := x.Ship(ctx); err != nil || n != 3 {
		t.Fatalf("ship: %d %v", n, err)
	}
	if n, err := x.Ship(ctx); err != nil || n != 0 {
		t.Fatalf("ship again: %d %v", n, err)
	}
	mu.Lock()
	down = true
	mu.Unlock()
	appendEvents(t, st, "f", 2)
	if n, err := x.Drain(ctx); err != nil || n != 2 {
		t.Fatalf("export during the outage: %d %v", n, err)
	}
	if n, err := x.Ship(ctx); err == nil || n != 0 {
		t.Fatalf("ship during the outage: %d %v", n, err)
	}
	mu.Lock()
	down = false
	mu.Unlock()
	if n, err := x.Ship(ctx); err != nil || n != 2 {
		t.Fatalf("ship after the outage: %d %v", n, err)
	}
	var want []string
	for _, f := range exportFiles(t, dir) {
		want = append(want, filepath.Base(f))
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, want) {
		t.Fatalf("collector received %v, want %v", got, want)
	}
}

func TestOneExporterAtATime(t *testing.T) {
	st := r1test.New(t)
	conn, err := st.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7317)`); err != nil {
		t.Fatal(err)
	}
	_, key := newKey(t)
	if _, err := newExporter(t, st, t.TempDir(), 10, key).Once(ctx); !errors.Is(err, auditexport.ErrBusy) {
		t.Fatalf("second exporter: %v, want %v", err, auditexport.ErrBusy)
	}
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(7317)`)
}

// TestExportSurvivesRestore: events recorded after a backup and exported
// before the restore are kept, although the restore replaces the outbox,
// and the restored catalog's older chain head continues past the links
// exported after the backup.
func TestExportSurvivesRestore(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	exportDir := t.TempDir()
	pub, key := newKey(t)
	x := newExporter(t, st, exportDir, 100, key)
	appendEvents(t, st, "before-backup", 1)
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Put("reports", "after-backup", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	exportedHead := head(t, st).Head
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, nil); err != nil {
		t.Fatal(err)
	}
	if head(t, st).Head == exportedHead {
		t.Fatal("the restore kept the live chain head")
	}
	var inOutbox int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE event->>'outcome' = 'PUBLISHED'`).Scan(&inOutbox)
	published := 0
	events, _ := exported(t, exportDir)
	for _, e := range events {
		if e.Kind == audit.KindMutation && e.Outcome == "PUBLISHED" {
			published++
		}
	}
	if inOutbox != 0 || published != 1 {
		t.Fatalf("publication events: %d in the restored outbox, %d exported; want 0 and 1", inOutbox, published)
	}
	appendEvents(t, st, "after-restore", 1)
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	now := head(t, st)
	if l := readLink(t, filepath.Join(exportDir, now.File)); l.Previous != exportedHead || l.Reset {
		t.Fatalf("after the restore the chain continues %+v, want after %s", l, exportedHead)
	}
	if _, err := auditexport.Verify(exportDir, now.Head, pub); err != nil {
		t.Fatal(err)
	}
}
