package content

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/cryptowire"
	"fga/internal/registry"
	"fga/internal/signing"
	"fga/internal/strictjson"
)

// Entry is one visible object of a listing.
type Entry struct {
	Key              string    `json:"key"`
	Version          string    `json:"version_id"`
	CiphertextLength int64     `json:"ciphertext_length"`
	CreatedAt        time.Time `json:"created_at"`
}

// Page is one listing page. A short or empty page may carry a
// continuation; the cursor always advances (CNT-005).
type Page struct {
	Entries      []Entry `json:"entries"`
	Continuation string  `json:"continuation,omitempty"`
}

// cursor is the sealed content of a continuation token. It binds the
// listing to its caller, query and authority state.
type cursor struct {
	Tenant      string    `json:"tenant"`
	Principal   string    `json:"principal"`
	Revision    uint64    `json:"revision"`
	Bucket      string    `json:"bucket"`
	Prefix      string    `json:"prefix"`
	Epoch       uint64    `json:"epoch"`
	Incarnation uint64    `json:"incarnation"`
	Expires     time.Time `json:"expires"`
	After       string    `json:"after"`
}

// discoverBatch is the number of candidates per decision batch (DEC-009
// allows 50 checks).
const discoverBatch = 50

// List returns the objects of a bucket that the caller may discover, in key
// order (CNT-005 to CNT-007). It checks bucket list once, scans committed
// heads with a live current version after the cursor, and batch-checks
// discover for each candidate; entries the caller may not discover are
// omitted, with their metadata. Listing changes nothing.
func (s *Service) List(ctx context.Context, c Caller, bucketName, prefix string, limit int, continuation string) (Page, error) {
	if limit <= 0 || limit > s.d.Limits.ListPageMax {
		limit = min(100, s.d.Limits.ListPageMax)
	}
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return Page{}, err
	}
	_, rec, err := s.decide(ctx, c, registry.OpListBucket, Audience, false,
		[]check{{id: "bucket", role: registry.RoleBucket, action: "list", ref: canonical("storage.bucket", b.ID.String())}})
	if err != nil {
		return Page{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return Page{}, err
	}
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: rec.Actor.Revision, Bucket: b.ID.String(), Prefix: prefix,
		Epoch: rec.PolicyEpoch, Incarnation: rec.RecoveryIncarnation}
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || prev.Prefix != cur.Prefix || prev.Epoch != cur.Epoch || prev.Incarnation != cur.Incarnation ||
			!s.d.Now().Before(prev.Expires) {
			return Page{}, ErrInvalid
		}
		cur.After = prev.After
	}

	page := Page{Entries: []Entry{}}
	scanned := 0
	exhausted := false
	singles := s.d.Limits.ListSingleChecks
	for len(page.Entries) < limit && scanned < s.d.Limits.ListScanBudget && !exhausted {
		candidates, err := s.candidates(ctx, c.Tenant, b.ID, prefix, cur.After, min(discoverBatch, s.d.Limits.ListScanBudget-scanned))
		if err != nil {
			return Page{}, err
		}
		if len(candidates) < min(discoverBatch, s.d.Limits.ListScanBudget-scanned) {
			exhausted = true
		}
		if len(candidates) == 0 {
			break
		}
		visible, decided, err := s.discoverable(ctx, c, candidates, &singles)
		if err != nil {
			return Page{}, err
		}
		for i, cand := range candidates[:decided] {
			scanned++
			cur.After = cand.key
			if visible[i] {
				page.Entries = append(page.Entries, cand.entry)
				if len(page.Entries) == limit {
					exhausted = exhausted && i == len(candidates)-1
					break
				}
			}
		}
		if decided < len(candidates) {
			// The single checks of this request are spent: the page ends
			// here, and the continuation resumes after the last candidate
			// decided.
			exhausted = false
			break
		}
	}
	if !exhausted {
		cur.Expires = s.d.Now().Add(s.d.Limits.TokenLifetime)
		if page.Continuation, err = s.sealToken(cur); err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

type candidate struct {
	key    string
	object cryptowire.UUID
	entry  Entry
}

// candidates are committed heads whose current version is a live payload
// version, in key order after the cursor. This is a sound superset: every
// one still gets its own decision (CNT-007).
func (s *Service) candidates(ctx context.Context, tenant string, bucket cryptowire.UUID, prefix, after string, n int) ([]candidate, error) {
	rows, err := s.d.Catalog.Pool().Query(ctx, `
		SELECT o.key, o.id, v.id, v.ciphertext_length, v.created_at
		  FROM objects o JOIN object_versions v ON v.tenant = o.tenant AND v.id = o.current_version
		 WHERE o.tenant = $1 AND o.bucket = $2 AND o.kind = 'object' AND o.key > $3 AND starts_with(o.key, $4)
		   AND v.state = 'LIVE' AND NOT v.delete_marker
		 ORDER BY o.key LIMIT $5`, tenant, bucket, after, prefix, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var c candidate
		var version cryptowire.UUID
		if err := rows.Scan(&c.key, &c.object, &version, &c.entry.CiphertextLength, &c.entry.CreatedAt); err != nil {
			return nil, err
		}
		c.entry.Key, c.entry.Version, c.entry.CreatedAt = c.key, version.String(), c.entry.CreatedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// discoverable decides discover for each candidate (eachAllowed).
func (s *Service) discoverable(ctx context.Context, c Caller, cands []candidate, singles *int) ([]bool, int, error) {
	checks := make([]check, len(cands))
	for i, cand := range cands {
		checks[i] = check{id: "object-" + strconv.Itoa(i), role: registry.RoleObject, action: "discover",
			ref: canonical("storage.object", cand.object.String()), version: cand.entry.Version}
	}
	return s.eachAllowed(ctx, c, registry.OpDiscover, checks, singles)
}

// eachAllowed decides op with checks in one batch and reports which checks
// are allowed. The batch is denied as a whole if any check is, so a denial
// is narrowed down by deciding the checks one by one; a failed item never
// grants its peers (DEC-004). Each single check spends one of singles, the
// request's remaining single checks; when they are spent, the checks after
// the last one decided are left undecided, and the count of decided checks
// says how many were (security review of 4 November 2026, finding 2).
func (s *Service) eachAllowed(ctx context.Context, c Caller, op string, checks []check, singles *int) ([]bool, int, error) {
	allowed := make([]bool, len(checks))
	_, rec, err := s.decide(ctx, c, op, Audience, false, checks)
	if err == nil {
		if err := s.checked(ctx, rec); err != nil {
			return nil, 0, err
		}
		for i := range allowed {
			allowed[i] = true
		}
		return allowed, len(checks), nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, 0, err
	}
	for i := range checks {
		if *singles <= 0 {
			return allowed, i, nil
		}
		*singles--
		_, rec, err := s.decide(ctx, c, op, Audience, false, checks[i:i+1])
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return nil, 0, err
		}
		allowed[i] = true
	}
	return allowed, len(checks), nil
}

// VersionEntry is one visible version of a key.
type VersionEntry struct {
	Version      string    `json:"version_id"`
	Current      bool      `json:"current"`
	DeleteMarker bool      `json:"delete_marker"`
	CreatedAt    time.Time `json:"created_at"`
}

// VersionPage is one page of a key's versions, newest first.
type VersionPage struct {
	Versions     []VersionEntry `json:"versions"`
	Continuation string         `json:"continuation,omitempty"`
}

// errHeadMoved: the key's head changed after the listing's decisions.
var errHeadMoved = errors.New("content: the key's head moved")

// ListVersions lists a key's versions (Table "Native version and visibility
// semantics"): bucket list and object discover show the current entry, and
// discover-history is needed for every other one. Unauthorized entries are
// omitted, with no total count. Withdrawn versions are not listed. Pages
// hold at most limit entries and continue with an opaque continuation
// bound to the caller and the key (review v3 F11). The head and the
// versions are read in one snapshot after the decisions, and the listing
// starts again when the head moved since the decisions were made, so an
// old version is never shown as current (review v3 F10).
func (s *Service) ListVersions(ctx context.Context, c Caller, bucketName, key string, limit int, continuation string) (VersionPage, error) {
	for range 3 {
		page, err := s.listVersions(ctx, c, bucketName, key, limit, continuation)
		if !errors.Is(err, errHeadMoved) {
			return page, err
		}
	}
	return VersionPage{}, fmt.Errorf("%w: the key keeps changing", ErrConflict)
}

func (s *Service) listVersions(ctx context.Context, c Caller, bucketName, key string, limit int, continuation string) (VersionPage, error) {
	if limit <= 0 || limit > s.d.Limits.ListPageMax {
		limit = min(100, s.d.Limits.ListPageMax)
	}
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return VersionPage{}, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, key)
	if err != nil || o.Current == nil {
		return VersionPage{}, ErrNotFound
	}
	ref := canonical("storage.object", o.ID.String())
	_, rec, err := s.decide(ctx, c, registry.OpListVersions, Audience, false, []check{
		{id: "bucket", role: registry.RoleBucket, action: "list", ref: canonical("storage.bucket", b.ID.String())},
		{id: "object", role: registry.RoleObject, action: "discover", ref: ref}})
	if err != nil {
		return VersionPage{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return VersionPage{}, err
	}
	history := false
	var histRec signing.Record
	if _, histRec, err = s.decide(ctx, c, registry.OpDiscoverHistory, Audience, false, []check{
		{id: "object", role: registry.RoleObject, action: "discover", ref: ref},
		{id: "history", role: registry.RoleHistory, action: "discover-history", ref: ref}}); err == nil {
		history = s.checked(ctx, histRec) == nil
	} else if err != ErrNotFound {
		return VersionPage{}, err
	}
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: rec.Actor.Revision, Bucket: b.ID.String(), Prefix: "versions:" + o.ID.String(),
		Epoch: rec.PolicyEpoch, Incarnation: rec.RecoveryIncarnation}
	var afterTime time.Time
	var afterID string
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || prev.Prefix != cur.Prefix || prev.Epoch != cur.Epoch || prev.Incarnation != cur.Incarnation ||
			!s.d.Now().Before(prev.Expires) {
			return VersionPage{}, ErrInvalid
		}
		at, id, ok := strings.Cut(prev.After, "|")
		if afterTime, err = time.Parse(time.RFC3339Nano, at); !ok || err != nil {
			return VersionPage{}, ErrInvalid
		}
		afterID = id
	}

	tx, err := s.d.Catalog.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VersionPage{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only
	var head *cryptowire.UUID
	var generation uint64
	if err := tx.QueryRow(ctx, `SELECT o.current_version, r.generation FROM objects o JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
	                             WHERE o.tenant = $1 AND o.id = $2`, c.Tenant, o.ID).Scan(&head, &generation); err != nil {
		return VersionPage{}, err
	}
	if head == nil || *head != *o.Current || generation != o.Generation {
		return VersionPage{}, errHeadMoved
	}
	page := VersionPage{Versions: []VersionEntry{}}
	sql := `SELECT id, delete_marker, created_at FROM object_versions WHERE tenant = $1 AND object = $2 AND state = 'LIVE'`
	args := []any{c.Tenant, o.ID}
	switch {
	case !history && continuation != "":
		// Without discover-history only the current version is listed,
		// on the first page.
		return page, nil
	case !history:
		sql += ` AND id = $3`
		args = append(args, *head)
	case continuation != "":
		sql += ` AND (created_at < $3 OR created_at = $3 AND id::text > $4)`
		args = append(args, afterTime, afterID)
	}
	sql += ` ORDER BY created_at DESC, id::text LIMIT ` + strconv.Itoa(limit+1)
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return VersionPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var e VersionEntry
		var id cryptowire.UUID
		if err := rows.Scan(&id, &e.DeleteMarker, &e.CreatedAt); err != nil {
			return VersionPage{}, err
		}
		if len(page.Versions) == limit {
			last := page.Versions[limit-1]
			cur.After, cur.Expires = last.CreatedAt.Format(time.RFC3339Nano)+"|"+last.Version, s.d.Now().Add(s.d.Limits.TokenLifetime)
			if page.Continuation, err = s.sealToken(cur); err != nil {
				return VersionPage{}, err
			}
			break
		}
		e.Version, e.Current, e.CreatedAt = id.String(), id == *head, e.CreatedAt.UTC()
		page.Versions = append(page.Versions, e)
	}
	return page, rows.Err()
}

func (s *Service) sealToken(c cursor) (string, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	aead, err := s.tokenAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte("fga.list-token/v1"))), nil
}

func (s *Service) openToken(token string) (cursor, error) {
	var c cursor
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || strings.ContainsAny(token, "=+/") {
		return c, ErrInvalid
	}
	aead, err := s.tokenAEAD()
	if err != nil {
		return c, err
	}
	if len(raw) < aead.NonceSize() {
		return c, ErrInvalid
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("fga.list-token/v1"))
	if err != nil {
		return c, ErrInvalid
	}
	return c, strictjson.Decode(plain, &c)
}

func (s *Service) tokenAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.d.TokenKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DocumentVersionEntry is one listed version of a document (DOC-010).
type DocumentVersionEntry struct {
	DocumentVersion string `json:"document_version_id"`
	// PublishedAt is the server's publication time; versions published
	// before it was recorded have none (DOC-011, D-E).
	PublishedAt string `json:"published_at,omitempty"`
	Current     bool   `json:"current"`
}

// DocumentVersionPage is a page of a document's versions, newest first.
type DocumentVersionPage struct {
	Versions     []DocumentVersionEntry `json:"versions"`
	Continuation string                 `json:"continuation,omitempty"`
}

// ListDocumentVersions lists a document's LIVE versions, newest first
// (DOC-010). discover on the current version admits the listing, and a
// superseded entry needs discover-history on the document too; every
// entry needs discover on its own version, so a rule on publication time
// can bound history (DOC-011). Entries the caller may not discover are
// left out without a count. The continuation is sealed and bound to the
// caller, the document, the policy epoch and the incarnation, and the
// listing starts again when the head moves, as ListVersions does.
func (s *Service) ListDocumentVersions(ctx context.Context, c Caller, bucketName, key string, limit int, continuation string) (DocumentVersionPage, error) {
	return s.documentVersionsIn(ctx, c, bucketName, key, limit, continuation, window{})
}

// window bounds a listing of document versions by publication time: since
// inclusive, until exclusive, zero unbounded. A bounded listing leaves out
// versions without published_at.
type window struct{ since, until time.Time }

func (s *Service) documentVersionsIn(ctx context.Context, c Caller, bucketName, key string, limit int, continuation string,
	w window) (DocumentVersionPage, error) {
	for range 3 {
		page, err := s.listDocumentVersions(ctx, c, bucketName, key, limit, continuation, w)
		if !errors.Is(err, errHeadMoved) {
			return page, err
		}
	}
	return DocumentVersionPage{}, fmt.Errorf("%w: the document keeps changing", ErrConflict)
}

func (s *Service) listDocumentVersions(ctx context.Context, c Caller, bucketName, key string, limit int, continuation string,
	w window) (DocumentVersionPage, error) {
	if limit <= 0 || limit > s.d.Limits.ListPageMax {
		limit = min(100, s.d.Limits.ListPageMax)
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, "")
	if err != nil {
		return DocumentVersionPage{}, err
	}
	current := []check{{id: "version", role: registry.RoleVersion, action: "discover", ref: canonical("document.version", d.id.String())}}
	_, rec, err := s.decide(ctx, c, registry.OpDocDiscover, Audience, false, current)
	if err != nil {
		return DocumentVersionPage{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return DocumentVersionPage{}, err
	}
	history := false
	if _, histRec, err := s.decide(ctx, c, registry.HistoryOp(registry.OpDocDiscover), Audience, false,
		append(current, d.historyCheck("discover-history"))); err == nil {
		history = s.checked(ctx, histRec) == nil
	} else if !errors.Is(err, ErrNotFound) {
		return DocumentVersionPage{}, err
	}
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: rec.Actor.Revision, Bucket: "document-versions", Prefix: d.document.String(),
		Epoch: rec.PolicyEpoch, Incarnation: rec.RecoveryIncarnation}
	var afterTime time.Time
	var afterID string
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || prev.Prefix != cur.Prefix || prev.Epoch != cur.Epoch || prev.Incarnation != cur.Incarnation ||
			!s.d.Now().Before(prev.Expires) {
			return DocumentVersionPage{}, ErrInvalid
		}
		at, id, ok := strings.Cut(prev.After, "|")
		if afterTime, err = time.Parse(time.RFC3339Nano, at); !ok || err != nil {
			return DocumentVersionPage{}, ErrInvalid
		}
		afterID = id
	}
	page := DocumentVersionPage{Versions: []DocumentVersionEntry{}}
	if !history && continuation != "" {
		// Without discover-history only the current version is listed, on
		// the first page.
		return page, nil
	}
	type candidate struct {
		id          string
		createdAt   time.Time
		publishedAt string
	}
	var cands []candidate
	err = func() error {
		tx, err := s.d.Catalog.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck // read-only
		var head *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_document_version FROM objects WHERE tenant = $1 AND id = $2`, c.Tenant, d.document).
			Scan(&head); err != nil {
			return err
		}
		if head == nil || *head != d.id {
			return errHeadMoved
		}
		sql := `SELECT v.id::text, v.created_at, coalesce(r.attributes->>'published_at', '') FROM document_versions v
		          JOIN resources r ON r.tenant = v.tenant AND r.id = v.id::text
		         WHERE v.tenant = $1 AND v.document = $2 AND v.state = 'LIVE'`
		args := []any{c.Tenant, d.document}
		switch {
		case !history:
			sql += ` AND v.id = $3`
			args = append(args, d.id)
		case continuation != "":
			sql += ` AND (v.created_at < $3 OR v.created_at = $3 AND v.id::text > $4)`
			args = append(args, afterTime, afterID)
		}
		for _, b := range []struct {
			at time.Time
			op string
		}{{w.since, ">="}, {w.until, "<"}} {
			if !b.at.IsZero() {
				args = append(args, b.at)
				sql += ` AND (r.attributes->>'published_at')::timestamptz ` + b.op + ` $` + strconv.Itoa(len(args))
			}
		}
		sql += ` ORDER BY v.created_at DESC, v.id::text LIMIT ` + strconv.Itoa(limit+1)
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x candidate
			if err := rows.Scan(&x.id, &x.createdAt, &x.publishedAt); err != nil {
				return err
			}
			cands = append(cands, x)
		}
		return rows.Err()
	}()
	if err != nil {
		return DocumentVersionPage{}, err
	}
	more := len(cands) > limit
	if more {
		cands = cands[:limit]
	}
	singles := s.d.Limits.ListSingleChecks
	for start := 0; start < len(cands); start += discoverBatch {
		batch := cands[start:min(len(cands), start+discoverBatch)]
		results := make([]SearchResult, len(batch))
		for i, x := range batch {
			results[i] = SearchResult{DocumentVersion: x.id}
		}
		visible, decided, err := s.discoverVersions(ctx, c, results, &singles)
		if err != nil {
			return DocumentVersionPage{}, err
		}
		for i, x := range batch[:decided] {
			if visible[i] {
				page.Versions = append(page.Versions, DocumentVersionEntry{DocumentVersion: x.id, PublishedAt: x.publishedAt, Current: x.id == d.id.String()})
			}
		}
		if decided < len(batch) {
			// The single checks of this request are spent (finding 2 of the
			// security review of 4 November 2026): the page ends after the
			// last version decided.
			cands, more = cands[:start+decided], true
			break
		}
	}
	if more {
		if n := len(cands); n > 0 {
			last := cands[n-1]
			cur.After = last.createdAt.Format(time.RFC3339Nano) + "|" + last.id
		}
		cur.Expires = s.d.Now().Add(s.d.Limits.TokenLifetime)
		if page.Continuation, err = s.sealToken(cur); err != nil {
			return DocumentVersionPage{}, err
		}
	}
	return page, nil
}
