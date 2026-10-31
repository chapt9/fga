package content

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

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
		visible, err := s.discoverable(ctx, c, candidates)
		if err != nil {
			return Page{}, err
		}
		for i, cand := range candidates {
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

// discoverable decides discover for each candidate in one batch. The batch
// is denied as a whole if any check is, so a denial is narrowed down by
// deciding the candidates one by one; a failed item never grants its
// peers (DEC-004).
func (s *Service) discoverable(ctx context.Context, c Caller, cands []candidate) ([]bool, error) {
	checks := func(cs []candidate, offset int) []check {
		out := make([]check, len(cs))
		for i, cand := range cs {
			out[i] = check{id: "object-" + strconv.Itoa(offset+i), role: registry.RoleObject, action: "discover",
				ref: canonical("storage.object", cand.object.String()), version: cand.entry.Version}
		}
		return out
	}
	visible := make([]bool, len(cands))
	_, rec, err := s.decide(ctx, c, registry.OpDiscover, Audience, false, checks(cands, 0))
	if err == nil {
		if err := s.checked(ctx, rec); err != nil {
			return nil, err
		}
		for i := range visible {
			visible[i] = true
		}
		return visible, nil
	}
	if err != ErrNotFound {
		return nil, err
	}
	for i := range cands {
		_, rec, err := s.decide(ctx, c, registry.OpDiscover, Audience, false, checks(cands[i:i+1], i))
		switch {
		case err == ErrNotFound:
			continue
		case err != nil:
			return nil, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return nil, err
		}
		visible[i] = true
	}
	return visible, nil
}

// VersionEntry is one visible version of a key.
type VersionEntry struct {
	Version      string    `json:"version_id"`
	Current      bool      `json:"current"`
	DeleteMarker bool      `json:"delete_marker"`
	CreatedAt    time.Time `json:"created_at"`
}

// ListVersions lists a key's versions (Table "Native version and visibility
// semantics"): bucket list and object discover show the current entry, and
// discover-history is needed for every other one. Unauthorized entries are
// omitted, with no total count. Withdrawn versions are not listed.
func (s *Service) ListVersions(ctx context.Context, c Caller, bucketName, key string) ([]VersionEntry, error) {
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return nil, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, key)
	if err != nil || o.Current == nil {
		return nil, ErrNotFound
	}
	ref := canonical("storage.object", o.ID.String())
	_, rec, err := s.decide(ctx, c, registry.OpListVersions, Audience, false, []check{
		{id: "bucket", role: registry.RoleBucket, action: "list", ref: canonical("storage.bucket", b.ID.String())},
		{id: "object", role: registry.RoleObject, action: "discover", ref: ref}})
	if err != nil {
		return nil, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return nil, err
	}
	history := false
	var histRec signing.Record
	if _, histRec, err = s.decide(ctx, c, registry.OpDiscoverHistory, Audience, false, []check{
		{id: "object", role: registry.RoleObject, action: "discover", ref: ref},
		{id: "history", role: registry.RoleHistory, action: "discover-history", ref: ref}}); err == nil {
		history = s.checked(ctx, histRec) == nil
	} else if err != ErrNotFound {
		return nil, err
	}
	rows, err := s.d.Catalog.Pool().Query(ctx, `
		SELECT id, delete_marker, created_at FROM object_versions
		 WHERE tenant = $1 AND object = $2 AND state = 'LIVE' ORDER BY created_at DESC, id`, c.Tenant, o.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VersionEntry{}
	for rows.Next() {
		var e VersionEntry
		var id cryptowire.UUID
		if err := rows.Scan(&id, &e.DeleteMarker, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Version, e.Current, e.CreatedAt = id.String(), id == *o.Current, e.CreatedAt.UTC()
		if e.Current || history {
			out = append(out, e)
		}
	}
	return out, rows.Err()
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
