package auditexport_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/audit"
	"fga/internal/auditexport"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

var ctx = context.Background()

// exported reads every exported event and returns the IDs and how many
// lines there were.
func exported(t *testing.T, dir string) (map[string]audit.Event, int) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	events, lines := map[string]audit.Event{}, 0
	for _, f := range files {
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
	for i := 0; i < 7; i++ {
		if err := st.Catalog.Append(ctx, audit.Event{ID: "e-" + string(rune('a'+i)), Kind: audit.KindDecision, Tenant: r1test.Tenant,
			Outcome: "ALLOW", At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	x, err := auditexport.New(st.Pool, dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := x.Drain(ctx); err != nil || n != 7 {
		t.Fatalf("drain = %d, %v", n, err)
	}
	if pending, _ := st.Catalog.Pending(ctx, 100); len(pending) != 0 {
		t.Fatalf("pending after drain = %d", len(pending))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 3 {
		t.Fatalf("files = %d, want 3 batches", len(files))
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0o600 {
		t.Errorf("export file mode %v", info.Mode().Perm())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_outbox SET delivered_at = NULL WHERE id IN ('e-a', 'e-b')`); err != nil {
		t.Fatal(err)
	}
	if n, _ := x.Drain(ctx); n != 2 {
		t.Fatalf("re-export = %d, want 2", n)
	}
	events, lines := exported(t, dir)
	if len(events) != 7 || lines != 9 {
		t.Fatalf("exported %d unique events in %d lines, want 7 in 9", len(events), lines)
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
	x, _ := auditexport.New(st.Pool, t.TempDir(), 10)
	if _, err := x.Once(ctx); !errors.Is(err, auditexport.ErrBusy) {
		t.Fatalf("second exporter: %v, want %v", err, auditexport.ErrBusy)
	}
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(7317)`)
}

// TestExportSurvivesRestore: events recorded after a backup and exported
// before the restore are kept, although the restore replaces the outbox.
func TestExportSurvivesRestore(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Put("reports", "after-backup", []byte("x")); err != nil {
		t.Fatal(err)
	}
	exportDir := t.TempDir()
	x, _ := auditexport.New(st.Pool, exportDir, 100)
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, nil); err != nil {
		t.Fatal(err)
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
}
