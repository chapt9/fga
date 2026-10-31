// Package recovery backs up and restores the R1 catalog and blob store and
// reconciles authority after a restore (specification 2.5, AVL-005,
// AVL-008, KEY-017, PUB-006; docs/design/storage-r1b.md, "Backup and
// restore").
//
// A backup holds catalog rows, ciphertext, signed descriptors and opaque
// envelopes only: no payload key and no client private key exists on the
// server to back up. A restore leaves admission closed and moves to a new
// recovery incarnation, so every decision made before it is refused.
// Reconcile replays the security journal, quarantines versions whose
// ciphertext is missing or altered, and only then reopens admission.
package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/journal"
	"fga/internal/strictjson"
)

// Tables are the catalog tables a backup holds, in an order that satisfies
// every foreign key except the deferred head pointer. Enrollment
// challenges hold short-lived secrets and are not backed up. The optional
// executor's tables are not part of an R1 backup.
var Tables = []string{
	"tenants", "identities", "delegations", "capabilities", "tenant_epochs", "authority_state", "resources", "aliases",
	"recipient_keys", "signing_keys", "buckets", "objects", "object_versions", "upload_intents", "envelopes",
	"read_admissions", "retirements", "approvals", "consumed_decisions", "audit_outbox",
}

// Format is the manifest format of a backup.
const Format = "fga.backup/v1"

// Manifest describes a backup and the digest of every file in it.
type Manifest struct {
	Format      string      `json:"format"`
	CreatedAt   time.Time   `json:"created_at"`
	Incarnation uint64      `json:"incarnation"`
	Tables      []FileEntry `json:"tables"`
	Blobs       []BlobEntry `json:"blobs"`
}

// FileEntry is one table file.
type FileEntry struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// BlobEntry is one ciphertext blob.
type BlobEntry struct {
	Tenant string `json:"tenant"`
	Blob   string `json:"blob"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
	File   string `json:"file"`
}

// Backup writes one consistent snapshot of the catalog and the blobs it
// references to dir, which must not exist yet.
func Backup(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, dir string) (Manifest, error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	for _, d := range []string{"catalog", "blobs"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			return Manifest{}, err
		}
	}
	m := Manifest{Format: Format, CreatedAt: time.Now().UTC()}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer conn.Release()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Manifest{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only
	if err := tx.QueryRow(ctx, `SELECT incarnation FROM authority_state WHERE id = 1`).Scan(&m.Incarnation); err != nil {
		return Manifest{}, err
	}
	for _, t := range Tables {
		file := filepath.Join("catalog", t+".copy")
		sum, err := writeFile(filepath.Join(dir, file), func(w io.Writer) error {
			_, err := conn.Conn().PgConn().CopyTo(ctx, w, "COPY "+pgx.Identifier{t}.Sanitize()+" TO STDOUT")
			return err
		})
		if err != nil {
			return Manifest{}, fmt.Errorf("recovery: back up %s: %w", t, err)
		}
		m.Tables = append(m.Tables, FileEntry{Name: t, File: file, SHA256: sum})
	}
	rows, err := tx.Query(ctx, `
		SELECT t.id, v.blob, v.ciphertext_length, v.ciphertext_sha256 FROM object_versions v JOIN tenants t ON t.name = v.tenant
		 WHERE v.blob IS NOT NULL AND v.state IN ('LIVE', 'WITHDRAWN', 'QUARANTINED')`)
	if err != nil {
		return Manifest{}, err
	}
	type ref struct {
		tenant, blob cryptowire.UUID
		length       int64
		sum          string
	}
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.tenant, &r.blob, &r.length, &r.sum); err != nil {
			rows.Close()
			return Manifest{}, err
		}
		refs = append(refs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Manifest{}, err
	}
	for _, r := range refs {
		d, err := cryptowire.ParseDigest(r.sum)
		if err != nil {
			return Manifest{}, err
		}
		rc, err := blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: r.tenant, Blob: r.blob}, Length: r.length, SHA256: d})
		if err != nil {
			// A blob that is already missing is recorded as such by
			// reconcile after a restore; the backup does not invent it.
			continue
		}
		file := filepath.Join("blobs", r.blob.String())
		sum, err := writeFile(filepath.Join(dir, file), func(w io.Writer) error { _, err := io.Copy(w, rc); return err })
		rc.Close()
		if err != nil {
			return Manifest{}, err
		}
		m.Blobs = append(m.Blobs, BlobEntry{Tenant: r.tenant.String(), Blob: r.blob.String(), Length: r.length, SHA256: sum, File: file})
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if _, err := writeFile(filepath.Join(dir, "manifest.json"), func(w io.Writer) error { _, err := w.Write(b); return err }); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// writeFile creates path (0600) exclusively, fills it, flushes it and
// returns the SHA-256 of what was written.
func writeFile(path string, fill func(io.Writer) error) (string, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if err := fill(io.MultiWriter(f, h)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	var d cryptowire.Digest
	copy(d[:], h.Sum(nil))
	return d.String(), f.Close()
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	var d cryptowire.Digest
	copy(d[:], h.Sum(nil))
	return d.String(), nil
}

// ReadManifest reads a backup's manifest and checks every file's digest.
func ReadManifest(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return m, err
	}
	if err := strictjson.Decode(b, &m); err != nil || m.Format != Format {
		return m, fmt.Errorf("recovery: malformed manifest: %v", err)
	}
	for _, f := range m.Tables {
		if sum, err := fileDigest(filepath.Join(dir, f.File)); err != nil || sum != f.SHA256 {
			return m, fmt.Errorf("recovery: table file %s does not match the manifest", f.File)
		}
	}
	for _, f := range m.Blobs {
		if sum, err := fileDigest(filepath.Join(dir, f.File)); err != nil || sum != f.SHA256 {
			return m, fmt.Errorf("recovery: blob file %s does not match the manifest", f.File)
		}
	}
	return m, nil
}

// Restore replaces the catalog with the backup in dir and restores its
// blobs. Admission stays closed, and the deployment moves to a recovery
// incarnation above the backup's, the current one and every incarnation in
// the journal; the new incarnation is journaled. It returns that
// incarnation.
func Restore(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, j *journal.Journal, dir string) (uint64, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return 0, err
	}
	entries, err := j.Entries()
	if err != nil {
		return 0, fmt.Errorf("recovery: security journal: %w", err)
	}
	next := m.Incarnation
	var current uint64
	if err := pool.QueryRow(ctx, `SELECT incarnation FROM authority_state WHERE id = 1`).Scan(&current); err == nil && current > next {
		next = current
	}
	for _, e := range entries {
		if e.Kind == journal.Incarnation {
			if n, err := strconv.ParseUint(e.Subject, 10, 64); err == nil && n > next {
				next = n
			}
		}
	}
	next++
	if err := j.Append(journal.Incarnation, "", strconv.FormatUint(next, 10)); err != nil {
		return 0, fmt.Errorf("recovery: security journal: %w", err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		ids := make([]string, len(Tables))
		for i, t := range Tables {
			ids[i] = pgx.Identifier{t}.Sanitize()
		}
		for _, t := range slices.Backward(ids) {
			if _, err := tx.Exec(ctx, "DELETE FROM "+t); err != nil {
				return err
			}
		}
		for _, f := range m.Tables {
			r, err := os.Open(filepath.Join(dir, f.File))
			if err != nil {
				return err
			}
			_, err = conn.Conn().PgConn().CopyFrom(ctx, r, "COPY "+pgx.Identifier{f.Name}.Sanitize()+" FROM STDIN")
			r.Close()
			if err != nil {
				return fmt.Errorf("recovery: restore %s: %w", f.Name, err)
			}
		}
		_, err := tx.Exec(ctx, `UPDATE authority_state SET admission_open = false, incarnation = $1, changed_at = now() WHERE id = 1`, next)
		return err
	})
	if err != nil {
		return 0, err
	}
	for _, b := range m.Blobs {
		tenant, err1 := cryptowire.ParseUUID(b.Tenant)
		id, err2 := cryptowire.ParseUUID(b.Blob)
		sum, err3 := cryptowire.ParseDigest(b.SHA256)
		if err := errors.Join(err1, err2, err3); err != nil {
			return 0, err
		}
		f, err := os.Open(filepath.Join(dir, b.File))
		if err != nil {
			return 0, err
		}
		_, err = blobs.Put(blob.Ref{Tenant: tenant, Blob: id}, f, b.Length, sum)
		f.Close()
		if err != nil && !errors.Is(err, blob.ErrConflict) {
			return 0, err
		}
	}
	return next, nil
}

// Report summarizes a reconciliation.
type Report struct {
	Replayed    int
	Quarantined int
}

// Reconcile replays the security journal onto the catalog, quarantines
// versions whose ciphertext is missing or does not match its receipt, and
// reopens admission (AVL-008, KEY-017, PUB-006). If the journal cannot be
// read, admission stays closed: lost revocations are not assumed away.
func Reconcile(ctx context.Context, store *catalog.Store, blobs *blob.Store, j *journal.Journal) (Report, error) {
	var rep Report
	entries, err := j.Entries()
	if err != nil {
		return rep, fmt.Errorf("recovery: security journal unavailable, admission stays closed: %w", err)
	}
	pool := store.Pool()
	for _, e := range entries {
		var sql string
		args := []any{e.Tenant, e.Subject}
		switch e.Kind {
		case journal.IdentityDisabled:
			sql = `UPDATE identities SET disabled = true, revision = revision + 1 WHERE tenant = $1 AND id = $2 AND NOT disabled`
		case journal.DelegationRevoked:
			sql = `UPDATE delegations SET revoked = true, revision = revision + 1 WHERE tenant = $1 AND id = $2 AND NOT revoked`
		case journal.RecipientRevoked:
			sql = `WITH k AS (UPDATE recipient_keys SET status = 'REVOKED', revision = revision + 1
			                   WHERE tenant = $1 AND fingerprint = $2 AND status <> 'REVOKED' RETURNING fingerprint)
			       UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"REVOKED"}'
			        WHERE tenant = $1 AND type = 'crypto.recipient' AND id IN (SELECT fingerprint FROM k)`
		case journal.SignerCompromised:
			sql = `UPDATE signing_keys SET status = 'COMPROMISED', revision = revision + 1, changed_at = now()
			        WHERE tenant = $1 AND fingerprint = $2 AND status <> 'COMPROMISED'`
		case journal.EpochRaised:
			sql = `INSERT INTO tenant_epochs VALUES ($1, $2::bigint) ON CONFLICT (tenant) DO UPDATE SET required_epoch = excluded.required_epoch
			        WHERE tenant_epochs.required_epoch < excluded.required_epoch`
		default:
			continue
		}
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			return rep, fmt.Errorf("recovery: replay %s: %w", e.Kind, err)
		}
		rep.Replayed++
	}
	rows, err := pool.Query(ctx, `
		SELECT v.tenant, v.id, t.id, v.blob, v.ciphertext_length, v.ciphertext_sha256 FROM object_versions v JOIN tenants t ON t.name = v.tenant
		 WHERE v.blob IS NOT NULL AND v.state IN ('LIVE', 'WITHDRAWN')`)
	if err != nil {
		return rep, err
	}
	type bad struct {
		tenant  string
		version cryptowire.UUID
	}
	var quarantine []bad
	for rows.Next() {
		var tenant, sum string
		var version, tenantID, blobID cryptowire.UUID
		var length int64
		if err := rows.Scan(&tenant, &version, &tenantID, &blobID, &length, &sum); err != nil {
			rows.Close()
			return rep, err
		}
		d, err := cryptowire.ParseDigest(sum)
		if err != nil || blobs.Verify(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: blobID}, Length: length, SHA256: d}) != nil {
			quarantine = append(quarantine, bad{tenant, version})
		}
	}
	rows.Close()
	for _, q := range quarantine {
		if _, err := pool.Exec(ctx, `UPDATE object_versions SET state = 'QUARANTINED' WHERE tenant = $1 AND id = $2`, q.tenant, q.version); err != nil {
			return rep, err
		}
		rep.Quarantined++
	}
	return rep, store.SetAdmission(ctx, true, 0)
}
