// Package recovery backs up and restores the R1 catalog and blob store and
// reconciles authority after a restore (specification 2.5, AVL-005,
// AVL-008, KEY-017, PUB-006; docs/design/storage-r1b.md, "Backup and
// restore").
//
// A backup holds catalog rows, ciphertext, signed descriptors, opaque
// envelopes and server-mode data keys sealed under the keys role's KEKs:
// no KEK, unsealed data key or client private key is in it (SSE-006). The
// KEK ring is recovered apart from backups. A restore leaves admission
// closed and moves to a new recovery incarnation, so every decision made
// before it is refused. Reconcile replays the security journal,
// quarantines versions whose ciphertext is missing or altered or whose
// data key does not open under the ring, and only then reopens admission.
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
	"fga/internal/kek"
	"fga/internal/strictjson"
)

// Tables are the catalog tables a backup holds, in an order that satisfies
// every foreign key except the deferred head pointer. Enrollment
// challenges hold short-lived secrets and are not backed up. The optional
// executor's tables are not part of an R1 backup. kek_versions holds which
// server-mode KEK versions exist, never a key: the keys live in the keys
// role's ring and are recovered apart from backups (SSE-006).
var Tables = []string{
	"tenants", "identities", "delegations", "capabilities", "tenant_epochs", "authority_state", "resources", "aliases", "share_grants",
	"recipient_keys", "signing_keys", "kek_versions", "buckets", "objects", "object_versions", "document_versions", "document_units",
	"document_intents", "upload_intents", "derived_versions", "lineage", "envelopes",
	"read_admissions", "retirements", "approvals", "consumed_decisions", "audit_outbox",
	"label_orders", "label_order_active", "label_proposals", "journal_state",
}

// Format is the manifest format of a backup.
const Format = "fga.backup/v1"

// Manifest describes a backup and the digest of every file in it.
type Manifest struct {
	Format      string    `json:"format"`
	CreatedAt   time.Time `json:"created_at"`
	Incarnation uint64    `json:"incarnation"`
	// JournalID and JournalEntries are the catalog's journal binding at the
	// backup (review finding 1); empty when it had none.
	JournalID      string      `json:"journal_id,omitempty"`
	JournalEntries int         `json:"journal_entries,omitempty"`
	Tables         []FileEntry `json:"tables"`
	Blobs          []BlobEntry `json:"blobs"`
}

// Options are the operator's explicit choices for a recovery.
type Options struct {
	// AcceptJournalLoss proceeds although the security journal cannot be
	// shown complete: revocations, compromised signers and epoch raises
	// after the backup may be lost. Only an operator who has restored
	// those changes by other means may set it.
	AcceptJournalLoss bool
	// KEKs is the keys role's KEK ring, recovered apart from backups
	// (SSE-006). Reconcile needs it when the catalog holds server-mode
	// data keys, and quarantines every version whose key does not open
	// under it.
	KEKs *kek.Ring
}

// ErrNoKEKs means the catalog holds server-mode data keys and no KEK ring
// was given to check them. Admission stays closed.
var ErrNoKEKs = errors.New("recovery: server-mode data keys need the KEK ring to be checked; admission stays closed")

// ErrJournalContinuity means the security journal is not the one the
// catalog is bound to, or has fewer entries than the catalog recorded, so
// changes after the backup may be missing. Admission stays closed.
var ErrJournalContinuity = errors.New("recovery: the security journal cannot be shown complete; admission stays closed")

// continuity compares the journal with a recorded binding.
func continuity(j journal.State, id string, entries int, ok bool, opts Options) error {
	if ok && j.ID == id && j.Entries >= entries || opts.AcceptJournalLoss {
		return nil
	}
	return fmt.Errorf("%w (journal %s with %d entries; recorded %q with %d)", ErrJournalContinuity, j.ID, j.Entries, id, entries)
}

// FileEntry is one table file.
type FileEntry struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// BlobEntry is one ciphertext blob: its length and digest as the catalog
// records them, and the digest of its backup file (which differs when the
// backup is encrypted).
type BlobEntry struct {
	Tenant     string `json:"tenant"`
	Blob       string `json:"blob"`
	Length     int64  `json:"length"`
	SHA256     string `json:"sha256"`
	File       string `json:"file"`
	FileSHA256 string `json:"file_sha256"`
}

// Sealer encrypts and decrypts backup files, bound to their path
// (AVL-005). backupcrypt.Key implements it. A nil Sealer writes plain
// files; fga-admin always passes one.
type Sealer interface {
	Seal(w io.Writer, aad []byte) (io.WriteCloser, error)
	Open(r io.Reader, aad []byte) (io.Reader, error)
}

// marker names the file that records that a backup is encrypted, and how.
const marker = "ENCRYPTED"

func aad(name string) []byte { return []byte("fga.backup/v1\x00" + filepath.ToSlash(name)) }

// Backup writes one consistent snapshot of the catalog and the blobs it
// references to dir, which must not exist yet. With a sealer, every file,
// the manifest included, is encrypted and bound to its path.
func Backup(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, dir string, sealer Sealer, scheme string) (Manifest, error) {
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
	if m.JournalID, m.JournalEntries, _, err = catalog.JournalState(ctx, tx); err != nil {
		return Manifest{}, err
	}
	for _, t := range Tables {
		file := filepath.Join("catalog", t+".copy")
		sum, err := writeFile(dir, file, sealer, func(w io.Writer) error {
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
		sum, err := writeFile(dir, file, sealer, func(w io.Writer) error { _, err := io.Copy(w, rc); return err })
		rc.Close()
		if err != nil {
			return Manifest{}, err
		}
		m.Blobs = append(m.Blobs, BlobEntry{Tenant: r.tenant.String(), Blob: r.blob.String(), Length: r.length, SHA256: r.sum,
			File: file, FileSHA256: sum})
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if sealer != nil {
		if _, err := writeFile(dir, marker, nil, func(w io.Writer) error { _, err := io.WriteString(w, scheme+"\n"); return err }); err != nil {
			return Manifest{}, err
		}
	}
	if _, err := writeFile(dir, "manifest.json", sealer, func(w io.Writer) error { _, err := w.Write(b); return err }); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// writeFile creates dir/name (0600) exclusively, fills it through the
// sealer if there is one, flushes it and returns the SHA-256 of the bytes
// on disk.
func writeFile(dir, name string, sealer Sealer, fill func(io.Writer) error) (string, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var w io.Writer = io.MultiWriter(f, h)
	var sealed io.WriteCloser
	if sealer != nil {
		if sealed, err = sealer.Seal(w, aad(name)); err != nil {
			f.Close()
			return "", err
		}
		w = sealed
	}
	if err := fill(w); err != nil {
		f.Close()
		return "", err
	}
	if sealed != nil {
		if err := sealed.Close(); err != nil {
			f.Close()
			return "", err
		}
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

// openFile opens dir/name, decrypting it when the backup is encrypted.
func openFile(dir, name string, sealer Sealer) (io.Reader, io.Closer, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, nil, err
	}
	if sealer == nil {
		return f, f, nil
	}
	r, err := sealer.Open(f, aad(name))
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, f, nil
}

// ReadManifest reads a backup's manifest and checks every file's digest.
// An encrypted backup needs its sealer, and a plain one must have none.
func ReadManifest(dir string, sealer Sealer) (Manifest, error) {
	var m Manifest
	_, statErr := os.Stat(filepath.Join(dir, marker))
	switch encrypted := statErr == nil; {
	case encrypted && sealer == nil:
		return m, errors.New("recovery: the backup is encrypted; the backup key is required")
	case !encrypted && sealer != nil:
		return m, errors.New("recovery: the backup is not encrypted")
	}
	r, c, err := openFile(dir, "manifest.json", sealer)
	if err != nil {
		return m, err
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<20))
	c.Close()
	if err != nil {
		return m, fmt.Errorf("recovery: manifest: %w", err)
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
		if sum, err := fileDigest(filepath.Join(dir, f.File)); err != nil || sum != f.FileSHA256 {
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
func Restore(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, j *journal.Journal, dir string, sealer Sealer) (uint64, error) {
	return RestoreWith(ctx, pool, blobs, j, dir, sealer, Options{})
}

// RestoreWith is Restore with the operator's options. Before anything is
// replaced, the journal must be the one the live catalog is bound to (or,
// on an empty catalog, the backup's) and hold at least the entries
// recorded there; otherwise restore refuses (review finding 1).
func RestoreWith(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, j *journal.Journal, dir string, sealer Sealer, opts Options) (uint64, error) {
	m, err := ReadManifest(dir, sealer)
	if err != nil {
		return 0, err
	}
	entries, err := j.Entries()
	if err != nil {
		return 0, fmt.Errorf("recovery: security journal: %w", err)
	}
	js := journal.State{ID: j.ID(), Entries: len(entries)}
	id, recorded, ok, err := catalog.JournalState(ctx, pool)
	if err != nil {
		return 0, err
	}
	if !ok {
		id, recorded, ok = m.JournalID, m.JournalEntries, m.JournalID != ""
	}
	if err := continuity(js, id, recorded, ok, opts); err != nil {
		return 0, err
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
			r, c, err := openFile(dir, f.File, sealer)
			if err != nil {
				return err
			}
			_, err = conn.Conn().PgConn().CopyFrom(ctx, r, "COPY "+pgx.Identifier{f.Name}.Sanitize()+" FROM STDIN")
			c.Close()
			if err != nil {
				return fmt.Errorf("recovery: restore %s: %w", f.Name, err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE authority_state SET admission_open = false, incarnation = $1, changed_at = now() WHERE id = 1`, next); err != nil {
			return err
		}
		// A backup holds no staged ciphertext, so uploads in flight at the
		// backup are aborted; clients start them again (review finding 5).
		if _, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'ABORTED' WHERE state IN ('RESERVED', 'STAGED')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE document_intents SET state = 'ABORTED' WHERE state = 'RESERVED'`); err != nil {
			return err
		}
		// The restored catalog is bound to the journal it was restored
		// with, including the incarnation entry just appended.
		return catalog.SetJournal(ctx, tx, js.ID, js.Entries+1)
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
		r, c, err := openFile(dir, b.File, sealer)
		if err != nil {
			return 0, err
		}
		_, err = blobs.Put(blob.Ref{Tenant: tenant, Blob: id}, r, b.Length, sum)
		c.Close()
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
	// KeysChecked counts the server-mode data keys opened under the ring;
	// MissingKEKs names the KEK versions the catalog records that the
	// ring lacks, as "tenant/version".
	KeysChecked int
	MissingKEKs []string
}

// Reconcile replays the security journal onto the catalog, quarantines
// versions whose ciphertext is missing or does not match its receipt, and
// reopens admission (AVL-008, KEY-017, PUB-006). If the journal cannot be
// read, admission stays closed: lost revocations are not assumed away. A
// catalog with server-mode data keys needs ReconcileWith and the KEK ring
// (SSE-006).
func Reconcile(ctx context.Context, store *catalog.Store, blobs *blob.Store, j *journal.Journal) (Report, error) {
	return ReconcileWith(ctx, store, blobs, j, Options{})
}

// ReconcileWith is Reconcile with the operator's options. The journal must
// be the one the catalog is bound to and hold at least the recorded
// entries (review finding 1).
func ReconcileWith(ctx context.Context, store *catalog.Store, blobs *blob.Store, j *journal.Journal, opts Options) (Report, error) {
	var rep Report
	entries, err := j.Entries()
	if err != nil {
		return rep, fmt.Errorf("recovery: security journal unavailable, admission stays closed: %w", err)
	}
	pool := store.Pool()
	js := journal.State{ID: j.ID(), Entries: len(entries)}
	id, recorded, ok, err := catalog.JournalState(ctx, pool)
	if err != nil {
		return rep, err
	}
	if err := continuity(js, id, recorded, ok, opts); err != nil {
		return rep, err
	}
	// A catalog with server-mode data keys is not reopened unchecked; the
	// refusal comes before anything is changed.
	if opts.KEKs == nil {
		var sealedKeys bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM object_versions WHERE sealed_key IS NOT NULL)`).Scan(&sealedKeys); err != nil {
			return rep, err
		}
		if sealedKeys {
			return rep, ErrNoKEKs
		}
	}
	if opts.AcceptJournalLoss {
		if err := catalog.SetJournal(ctx, pool, js.ID, js.Entries); err != nil {
			return rep, err
		}
	}
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
			sql = `WITH k AS (UPDATE signing_keys SET status = 'COMPROMISED', revision = revision + 1, changed_at = now()
			                   WHERE tenant = $1 AND fingerprint = $2 AND status <> 'COMPROMISED' RETURNING fingerprint)
			       UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"COMPROMISED"}'
			        WHERE tenant = $1 AND type = 'crypto.signing-key' AND id IN (SELECT fingerprint FROM k)`
		case journal.GrantRemoved:
			sql = `WITH g AS (UPDATE share_grants SET removed_at = now(), removed_by = 'recovery'
			                   WHERE tenant = $1 AND id::text = $2 AND removed_at IS NULL RETURNING resource_id)
			       UPDATE resources SET metadata_revision = metadata_revision + 1
			        WHERE tenant = $1 AND id IN (SELECT resource_id FROM g)`
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
	locked, err := checkKeys(ctx, pool, opts.KEKs, &rep)
	if err != nil {
		return rep, err
	}
	for _, l := range locked {
		quarantine = append(quarantine, bad{l.tenant, l.version})
	}
	for _, q := range quarantine {
		tag, err := pool.Exec(ctx, `UPDATE object_versions SET state = 'QUARANTINED' WHERE tenant = $1 AND id = $2 AND state <> 'QUARANTINED'`,
			q.tenant, q.version)
		if err != nil {
			return rep, err
		}
		rep.Quarantined += int(tag.RowsAffected())
	}
	return rep, store.SetAdmission(ctx, true, 0)
}

type keyed struct {
	tenant  string
	version cryptowire.UUID
}

// checkKeys verifies the server-mode data keys of a restored catalog
// against the KEK ring (SSE-006): every KEK version the catalog records
// must be in the ring, and the sealed key of every LIVE or WITHDRAWN
// server-mode version must open under its tenant's KEK version and its
// binding. The opened key is cleared at once. It returns the versions
// whose key does not open; without a ring (the catalog then holds no
// sealed key) there is nothing to check.
func checkKeys(ctx context.Context, pool *pgxpool.Pool, ring *kek.Ring, rep *Report) ([]keyed, error) {
	if ring == nil {
		return nil, nil
	}
	rows, err := pool.Query(ctx, `SELECT tenant, version FROM kek_versions ORDER BY tenant, version`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tenant string
		var version uint32
		if err := rows.Scan(&tenant, &version); err != nil {
			rows.Close()
			return nil, err
		}
		if !slices.Contains(ring.Versions(tenant), version) {
			rep.MissingKEKs = append(rep.MissingKEKs, tenant+"/"+strconv.FormatUint(uint64(version), 10))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = pool.Query(ctx, `
		SELECT v.tenant, t.id, v.object, v.id, v.crypto_version, v.blob, v.kek_version, v.sealed_key
		  FROM object_versions v JOIN tenants t ON t.name = v.tenant
		 WHERE v.sealed_key IS NOT NULL AND v.state IN ('LIVE', 'WITHDRAWN')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var locked []keyed
	for rows.Next() {
		var k keyed
		var b kek.Binding
		var version uint32
		var sealed []byte
		if err := rows.Scan(&k.tenant, &b.Tenant, &b.Object, &k.version, &b.CryptoVersion, &b.Blob, &version, &sealed); err != nil {
			return nil, err
		}
		b.Version = k.version
		dataKey, err := ring.Open(k.tenant, version, sealed, b)
		clear(dataKey)
		if err != nil {
			locked = append(locked, k)
			continue
		}
		rep.KeysChecked++
	}
	return locked, rows.Err()
}
