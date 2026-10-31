// Package auditexport drains the audit outbox into durable files outside
// the catalog (specification 2.5, AUD-002, AUD-003;
// docs/design/audit-export.md). An event is marked delivered only after its
// export file and directory are flushed; a crash in between exports it
// again, and readers deduplicate by event ID.
package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// lockKey is the advisory lock that keeps one exporter active.
const lockKey = 7317

// ErrBusy is returned when another exporter holds the lock.
var ErrBusy = errors.New("auditexport: another exporter is running")

// Exporter exports one catalog's outbox into a directory.
type Exporter struct {
	pool  *pgxpool.Pool
	dir   string
	batch int
}

// New returns an exporter writing batches of at most batch events.
func New(pool *pgxpool.Pool, dir string, batch int) (*Exporter, error) {
	if batch <= 0 {
		return nil, errors.New("auditexport: batch must be positive")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Exporter{pool: pool, dir: dir, batch: batch}, nil
}

// Once exports at most one batch and returns how many events it exported.
func (e *Exporter) Once(ctx context.Context) (int, error) {
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&locked); err != nil {
		return 0, err
	}
	if !locked {
		return 0, ErrBusy
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey) //nolint:errcheck // released with the session too

	rows, err := conn.Query(ctx, `SELECT seq, id, event FROM audit_outbox WHERE delivered_at IS NULL ORDER BY seq LIMIT $1`, e.batch)
	if err != nil {
		return 0, err
	}
	var ids []string
	var lines []byte
	var first, last int64
	for rows.Next() {
		var seq int64
		var id string
		var event json.RawMessage
		if err := rows.Scan(&seq, &id, &event); err != nil {
			rows.Close()
			return 0, err
		}
		if len(ids) == 0 {
			first = seq
		}
		last = seq
		ids = append(ids, id)
		lines = append(append(lines, event...), '\n')
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return 0, err
	}
	name := fmt.Sprintf("%020d-%020d-%d.jsonl", first, last, time.Now().UnixNano())
	if err := e.write(name, lines); err != nil {
		return 0, err
	}
	if _, err := conn.Exec(ctx, `UPDATE audit_outbox SET delivered_at = now() WHERE id = ANY($1) AND delivered_at IS NULL`, ids); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// write creates the file exclusively, flushes it and its directory.
func (e *Exporter) write(name string, data []byte) error {
	path := filepath.Join(e.dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(e.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Drain exports batches until the outbox is empty and returns the total.
func (e *Exporter) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		n, err := e.Once(ctx)
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
}
