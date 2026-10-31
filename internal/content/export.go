package content

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/labels"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Export of document units (Table "Compound operations", KEY-012,
// V-132 to V-136) and metadata search (SRH-001 to SRH-004).

// MaxExportBytes bounds the ciphertext one export package carries.
const MaxExportBytes = 32 << 20

// ExportUnit is one exported unit: its descriptor, its exact ciphertext and
// the target recipient's existing envelope with a delivery receipt.
type ExportUnit struct {
	Unit       UnitEntry `json:"unit"`
	Ciphertext []byte    `json:"ciphertext"`
	Envelope   Delivered `json:"envelope"`
}

// Export is an encrypted remote export package: ciphertext and existing
// envelopes only. The server never creates or rewraps an envelope; a
// target without one gets nothing.
type Export struct {
	DocumentVersion string       `json:"document_version_id"`
	Recipient       string       `json:"recipient"`
	Units           []ExportUnit `json:"units"`
}

// ExportUnits exports the named units of a document version to the target
// recipient key. The caller needs export on the version, read-units, and
// read and export-key on every unit; each envelope is released by the keys
// role against a decision carrying all of those plus the envelope's
// release and the target's read-units, read and receive-key, and nothing
// less (V-132 to V-136). Any denial or missing envelope is a generic
// denial.
func (s *Service) ExportUnits(ctx context.Context, c Caller, bucketName, key, versionSel string, units []string, recipient string) (Export, error) {
	if _, err := cryptowire.ParseDigest(recipient); err != nil || len(units) == 0 || len(units) > MaxSelect {
		return Export{}, ErrInvalid
	}
	sorted := slices.Clone(units)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(units) {
		return Export{}, ErrInvalid
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return Export{}, err
	}
	ms, err := s.members(ctx, c.Tenant, d.id, 0, 0, units)
	if err != nil {
		return Export{}, err
	}
	if len(ms) != len(units) {
		return Export{}, ErrNotFound
	}
	var total int64
	for _, m := range ms {
		total += m.entry.CiphertextLength
	}
	if total > MaxExportBytes {
		return Export{}, ErrTooLarge
	}
	versionRef := canonical("document.version", d.id.String())
	// The storage role's own decisions, for disclosing the ciphertext.
	var recs []signing.Record
	for start := 0; start < len(ms); start += (maxBatch - 2) / 2 {
		batch := ms[start:min(len(ms), start+(maxBatch-2)/2)]
		checks := []check{{id: "version", role: registry.RoleVersion, action: "export", ref: versionRef},
			{id: "version-read", role: registry.RoleVersionRead, action: "read-units", ref: versionRef}}
		for i, m := range batch {
			ref, n := canonical("document.text_unit", m.entry.Unit), strconv.Itoa(i)
			checks = append(checks,
				check{id: "unit-" + n, role: registry.RoleUnit, action: "read", ref: ref, version: m.entry.UnitVersion},
				check{id: "unit-export-" + n, role: registry.RoleUnitExport, action: "export-key", ref: ref, version: m.entry.UnitVersion})
		}
		_, rec, err := s.decide(ctx, c, registry.OpDocExport, Audience, true, checks)
		if err != nil {
			return Export{}, err
		}
		recs = append(recs, rec)
	}
	// The target's existing envelopes, released by the keys role.
	out := Export{DocumentVersion: d.id.String(), Recipient: recipient}
	for _, m := range ms {
		var envelopeID string
		err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT id::text FROM envelopes WHERE tenant = $1 AND version::text = $2 AND recipient = $3
		                                          AND document_version = $4 AND status = 'ACTIVE'`, c.Tenant, m.entry.UnitVersion, recipient, d.id).Scan(&envelopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return Export{}, ErrNotFound
		}
		if err != nil {
			return Export{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		ref := canonical("document.text_unit", m.entry.Unit)
		signed, _, err := s.decide(ctx, c, registry.OpDocExportEnvelope, KeysAudience, true, []check{
			{id: "version", role: registry.RoleVersion, action: "export", ref: versionRef},
			{id: "version-read", role: registry.RoleVersionRead, action: "read-units", ref: versionRef},
			{id: "unit", role: registry.RoleUnit, action: "read", ref: ref, version: m.entry.UnitVersion},
			{id: "unit-export", role: registry.RoleUnitExport, action: "export-key", ref: ref, version: m.entry.UnitVersion},
			{id: "envelope", role: registry.RoleEnvelope, action: "release", ref: canonical("crypto.envelope", envelopeID), version: m.entry.UnitVersion},
			{id: "recipient-version", role: registry.RoleRecipientVersion, action: "read-units", ref: versionRef, recipient: recipient},
			{id: "recipient-read", role: registry.RoleRecipientRead, action: "read", ref: ref, version: m.entry.UnitVersion, recipient: recipient},
			{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", recipient), recipient: recipient}})
		if err != nil {
			return Export{}, err
		}
		env, err := s.d.Keys.Deliver(ctx, signed, envelopeID)
		if err != nil {
			return Export{}, err
		}
		out.Units = append(out.Units, ExportUnit{Unit: m.entry, Envelope: env})
	}
	// The ciphertext is admitted under the fence over every storage
	// decision, and read whole.
	bindings := make([]fence.Binding, len(recs))
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return Export{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return Export{}, err
	}
	versions := make([]version, len(ms))
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		targets := []audit.Target{{Type: "document.version", ID: d.id.String(), Recipient: recipient}}
		for i, m := range ms {
			id, _ := cryptowire.ParseUUID(m.entry.UnitVersion)
			v, err := s.versionByID(ctx, tx, c.Tenant, id, true)
			if err != nil || v.State != "LIVE" {
				return ErrNotFound
			}
			versions[i] = v
			targets = append(targets, audit.Target{Type: "document.text_unit", ID: m.entry.Unit, Version: m.entry.UnitVersion, Digest: v.SHA256})
		}
		if _, err := tx.Exec(ctx, `INSERT INTO read_admissions VALUES ($1, $2, $3, $4, $5)`,
			c.Tenant, recs[0].DecisionID, versions[0].ID, s.d.Now(), recs[0].ValidUntil); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindReadAdmission, recs[0], "EXPORTED", targets...))
	}))
	if err != nil {
		return Export{}, err
	}
	for i, v := range versions {
		digest, err := cryptowire.ParseDigest(v.SHA256)
		if err != nil {
			return Export{}, fmt.Errorf("%w: stored digest", ErrUnavailable)
		}
		r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
		if err != nil {
			return Export{}, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
		}
		b, err := io.ReadAll(io.LimitReader(r, v.Length+1))
		r.Close()
		if err != nil || int64(len(b)) != v.Length {
			return Export{}, fmt.Errorf("%w: backend: short ciphertext", ErrUnavailable)
		}
		out.Units[i].Ciphertext = b
	}
	return out, nil
}

// SearchQuery filters documents by permitted catalog metadata only
// (SRH-001): key prefix, project and highest label. There is no plaintext,
// snippet or embedding search on the server.
type SearchQuery struct {
	Prefix   string
	Project  string
	MaxLabel string
}

// SearchResult is one discoverable document.
type SearchResult struct {
	Key             string    `json:"key"`
	Document        string    `json:"document_id"`
	DocumentVersion string    `json:"document_version_id"`
	CreatedAt       time.Time `json:"created_at"`
}

// SearchPage is a page of search results.
type SearchPage struct {
	Results      []SearchResult `json:"results"`
	Continuation string         `json:"continuation,omitempty"`
}

// SearchDocuments returns the documents of a bucket that match q and whose
// current version the caller may discover, in key order. It needs list on
// the bucket; each candidate then gets its own discover decision, so
// results, order and continuation depend only on what the caller may see
// and no total is reported (SRH-004, V-070).
func (s *Service) SearchDocuments(ctx context.Context, c Caller, bucketName string, q SearchQuery, limit int, continuation string) (SearchPage, error) {
	if limit <= 0 || limit > s.d.Limits.ListPageMax {
		limit = min(100, s.d.Limits.ListPageMax)
	}
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return SearchPage{}, err
	}
	_, rec, err := s.decide(ctx, c, registry.OpListBucket, Audience, false,
		[]check{{id: "bucket", role: registry.RoleBucket, action: "list", ref: canonical("storage.bucket", b.ID.String())}})
	if err != nil {
		return SearchPage{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return SearchPage{}, err
	}
	maxRank := -1
	if q.MaxLabel != "" {
		_, order, err := catalog.LabelOrder(ctx, s.d.Catalog.Pool(), false)
		if err != nil {
			return SearchPage{}, fmt.Errorf("%w: no label order is active", ErrInvalid)
		}
		r, known := labels.Rank(order, q.MaxLabel)
		if !known {
			return SearchPage{}, ErrInvalid
		}
		maxRank = r
	}
	query := strings.Join([]string{q.Prefix, q.Project, q.MaxLabel}, "\x00")
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: rec.Actor.Revision, Bucket: "search:" + b.ID.String(), Prefix: query,
		Epoch: rec.PolicyEpoch, Incarnation: rec.RecoveryIncarnation}
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || prev.Prefix != cur.Prefix || prev.Epoch != cur.Epoch || prev.Incarnation != cur.Incarnation ||
			!s.d.Now().Before(prev.Expires) {
			return SearchPage{}, ErrInvalid
		}
		cur.After = prev.After
	}
	var order []string
	if maxRank >= 0 {
		_, order, _ = catalog.LabelOrder(ctx, s.d.Catalog.Pool(), false)
	}
	page := SearchPage{Results: []SearchResult{}}
	scanned, exhausted := 0, false
	for len(page.Results) < limit && scanned < s.d.Limits.ListScanBudget && !exhausted {
		n := min(maxBatch, s.d.Limits.ListScanBudget-scanned)
		rows, err := s.d.Catalog.Pool().Query(ctx, `
			SELECT o.key, o.id::text, dv.id::text, dv.created_at, coalesce(r.attributes->>'label', '')
			  FROM objects o JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
			  JOIN document_versions dv ON dv.tenant = o.tenant AND dv.id = o.current_document_version
			 WHERE o.tenant = $1 AND o.bucket = $2 AND o.kind = 'document' AND o.key > $3 AND starts_with(o.key, $4)
			   AND ($5 = '' OR r.attributes->>'project' = $5) AND dv.state = 'LIVE'
			 ORDER BY o.key LIMIT $6`, c.Tenant, b.ID, cur.After, q.Prefix, q.Project, n)
		if err != nil {
			return SearchPage{}, err
		}
		var cands []SearchResult
		var candLabels []string
		for rows.Next() {
			var r SearchResult
			var label string
			if err := rows.Scan(&r.Key, &r.Document, &r.DocumentVersion, &r.CreatedAt, &label); err != nil {
				rows.Close()
				return SearchPage{}, err
			}
			cands, candLabels = append(cands, r), append(candLabels, label)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return SearchPage{}, err
		}
		exhausted = len(cands) < n
		if len(cands) == 0 {
			break
		}
		visible, err := s.discoverVersions(ctx, c, cands)
		if err != nil {
			return SearchPage{}, err
		}
		for i, r := range cands {
			scanned++
			cur.After = r.Key
			if r2, _ := labels.Rank(order, candLabels[i]); visible[i] && (maxRank < 0 || r2 <= maxRank) {
				r.CreatedAt = r.CreatedAt.UTC()
				page.Results = append(page.Results, r)
				if len(page.Results) == limit {
					exhausted = exhausted && i == len(cands)-1
					break
				}
			}
		}
	}
	if !exhausted {
		cur.Expires = s.d.Now().Add(s.d.Limits.TokenLifetime)
		if page.Continuation, err = s.sealToken(cur); err != nil {
			return SearchPage{}, err
		}
	}
	return page, nil
}

// discoverVersions decides discover on each candidate's document version:
// one batch, and one decision per candidate if the batch is denied.
func (s *Service) discoverVersions(ctx context.Context, c Caller, cands []SearchResult) ([]bool, error) {
	checks := func(cs []SearchResult, offset int) []check {
		out := make([]check, len(cs))
		for i, r := range cs {
			out[i] = check{id: "version-" + strconv.Itoa(offset+i), role: registry.RoleVersion, action: "discover",
				ref: canonical("document.version", r.DocumentVersion)}
		}
		return out
	}
	visible := make([]bool, len(cands))
	_, rec, err := s.decide(ctx, c, registry.OpDocSearch, Audience, false, checks(cands, 0))
	if err == nil {
		if err := s.checked(ctx, rec); err != nil {
			return nil, err
		}
		for i := range visible {
			visible[i] = true
		}
		return visible, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	for i := range cands {
		_, rec, err := s.decide(ctx, c, registry.OpDocSearch, Audience, false, checks(cands[i:i+1], i))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return nil, err
		}
		visible[i] = true
	}
	return visible, nil
}
