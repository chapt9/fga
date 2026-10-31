package content

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Disclosure of document units (DOC-006, DOC-007, DSC-001 to DSC-005,
// docs/design/documents.md). Permission on the document version to read
// its units never grants a unit by itself: every unit needs its own read,
// and every envelope the keys role's full check set. Only ciphertext,
// signed descriptors and existing envelopes leave the server.

// UnitEntry is one disclosed unit: its identity, ciphertext length and
// signed descriptor for this document version. It carries no position.
type UnitEntry struct {
	Unit                string `json:"unit_id"`
	UnitVersion         string `json:"unit_version_id"`
	CiphertextLength    int64  `json:"ciphertext_length"`
	Descriptor          []byte `json:"descriptor"`
	DescriptorSignature string `json:"descriptor_signature"`
}

// UnitPage is a page of an authorized-subset listing.
type UnitPage struct {
	Units        []UnitEntry `json:"units"`
	Continuation string      `json:"continuation,omitempty"`
	// DocumentVersion is the version listed, so that a reader can read
	// every unit from it.
	DocumentVersion string `json:"document_version_id,omitempty"`
	// Kind is "collection" for a text collection's entries, otherwise
	// "document" (DOC-005); the MCP role reads each only through its own
	// tool (MCP-003).
	Kind string `json:"kind"`
}

type docVersion struct {
	document cryptowire.UUID
	id       cryptowire.UUID
	manifest []byte
	sig      string
	units    unitTypes
}

type member struct {
	position int
	entry    UnitEntry
}

// documentVersion resolves a document key and an optional version to a
// LIVE document version: the current one, or a named version of this
// document.
func (s *Service) documentVersion(ctx context.Context, tenant, bucketName, key, versionSel string) (docVersion, error) {
	b, err := s.bucketByName(ctx, tenant, bucketName)
	if err != nil {
		return docVersion{}, err
	}
	var d docVersion
	var current *cryptowire.UUID
	var kind string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT o.id, o.current_document_version, coalesce(r.attributes->>'kind', '') FROM objects o
	                                         JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
	                                         WHERE o.tenant = $1 AND o.bucket = $2 AND o.key = $3 AND o.kind = 'document'`, tenant, b.ID, key).
		Scan(&d.document, &current, &kind)
	d.units = unitsOf(kind)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current == nil && versionSel == "" {
		return docVersion{}, ErrNotFound
	}
	if err != nil {
		return docVersion{}, err
	}
	if versionSel == "" {
		d.id = *current
	} else if d.id, err = cryptowire.ParseUUID(versionSel); err != nil {
		return docVersion{}, ErrNotFound
	}
	var state string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT state, manifest, coalesce(manifest_signature, '') FROM document_versions
	                                         WHERE tenant = $1 AND id = $2 AND document = $3`, tenant, d.id, d.document).Scan(&state, &d.manifest, &d.sig)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != "LIVE" {
		return docVersion{}, ErrNotFound
	}
	return d, err
}

// members returns membership rows of a document version in document
// order: those after position after, at most n; or, with units, exactly
// those units (in any order).
func (s *Service) members(ctx context.Context, tenant string, dv cryptowire.UUID, after, n int, units []string) ([]member, error) {
	return s.memberRows(ctx, tenant, dv, after, n, units, true)
}

// allMembers returns every unit a document version lists, whatever the
// state of its unit version. A disclosure of the whole document (the
// manifest, the original file) is authorized against them all: a unit
// quarantined after a restore is still named by the manifest and still in
// the original (review v3 F05).
func (s *Service) allMembers(ctx context.Context, tenant string, dv cryptowire.UUID) ([]member, error) {
	return s.memberRows(ctx, tenant, dv, -1, cryptowire.MaxUnits, nil, false)
}

func (s *Service) memberRows(ctx context.Context, tenant string, dv cryptowire.UUID, after, n int, units []string, live bool) ([]member, error) {
	sql := `SELECT u.position, u.unit::text, u.unit_version::text, v.ciphertext_length, u.descriptor, coalesce(u.descriptor_signature, '')
	          FROM document_units u JOIN object_versions v ON v.tenant = u.tenant AND v.id = u.unit_version
	         WHERE u.tenant = $1 AND u.document_version = $2`
	if live {
		sql += ` AND v.state = 'LIVE'`
	}
	args := []any{tenant, dv}
	if units != nil {
		sql += ` AND u.unit::text = ANY($3) ORDER BY u.position`
		args = append(args, units)
	} else {
		sql += ` AND u.position > $3 ORDER BY u.position LIMIT $4`
		args = append(args, after, n)
	}
	rows, err := s.d.Catalog.Pool().Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.position, &m.entry.Unit, &m.entry.UnitVersion, &m.entry.CiphertextLength, &m.entry.Descriptor,
			&m.entry.DescriptorSignature); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// selectChecks are read-units on the version and read on each unit.
func selectChecks(d docVersion, ms []member) []check {
	out := []check{{id: "version", role: registry.RoleVersion, action: "read-units", ref: canonical("document.version", d.id.String())}}
	for i, m := range ms {
		out = append(out, check{id: "unit-" + strconv.Itoa(i), role: registry.RoleUnit, action: "read",
			ref: canonical(d.units.typ, m.entry.Unit), version: m.entry.UnitVersion})
	}
	return out
}

// allowed decides read-units on the version and read on every one of ms,
// in batches, and reports whether all are allowed. Any other failure is
// returned. It always decides at least the version's read-units: an empty
// ms is never permission by itself (review v3 F05).
func (s *Service) allowed(ctx context.Context, c Caller, op string, d docVersion, ms []member) (bool, error) {
	for start := 0; start == 0 || start < len(ms); start += maxBatch - 1 {
		_, rec, err := s.decide(ctx, c, op, Audience, false, selectChecks(d, ms[start:min(len(ms), start+maxBatch-1)]))
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return false, err
		}
	}
	return true, nil
}

// MaxSelect bounds an explicit unit selection.
const MaxSelect = 100

// SelectUnits is the explicit unit-ID request (DOC-007): it returns every
// named unit, or a generic denial if any is absent or denied, with no
// hint which (V-054).
func (s *Service) SelectUnits(ctx context.Context, c Caller, bucketName, key, versionSel string, units []string) ([]UnitEntry, error) {
	if len(units) == 0 || len(units) > MaxSelect {
		return nil, ErrInvalid
	}
	sorted := slices.Clone(units)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(units) {
		return nil, ErrInvalid
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	ms, err := s.members(ctx, c.Tenant, d.id, 0, 0, units)
	if err != nil {
		return nil, err
	}
	if len(ms) != len(units) {
		return nil, ErrNotFound
	}
	ok, err := s.allowed(ctx, c, d.units.selectOp, d, ms)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	byID := map[string]UnitEntry{}
	for _, m := range ms {
		byID[m.entry.Unit] = m.entry
	}
	out := make([]UnitEntry, len(units))
	for i, u := range units {
		out[i] = byID[u]
	}
	return out, nil
}

// ListUnits is the authorized-subset request (DOC-007): it returns only
// the units the caller may read, in document order, with an opaque
// continuation. It reveals no hidden IDs, positions or counts (V-055,
// V-070).
func (s *Service) ListUnits(ctx context.Context, c Caller, bucketName, key, versionSel string, limit int, continuation string) (UnitPage, error) {
	if limit <= 0 || limit > s.d.Limits.ListPageMax {
		limit = min(100, s.d.Limits.ListPageMax)
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return UnitPage{}, err
	}
	// Nothing of a version is answered, not even that it exists or that a
	// continuation is malformed, to a caller who may not discover it: a
	// hidden document looks like an absent one (CNT-004).
	_, rec, err := s.decide(ctx, c, registry.OpDocDiscover, Audience, false,
		[]check{{id: "version", role: registry.RoleVersion, action: "discover", ref: canonical("document.version", d.id.String())}})
	if err != nil {
		return UnitPage{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return UnitPage{}, err
	}
	id, err := s.d.Catalog.GetIdentity(ctx, c.Tenant, c.Principal)
	if err != nil {
		return UnitPage{}, ErrNotFound
	}
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: id.Revision, Bucket: "document-version:" + d.id.String(), After: "-1"}
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || !s.d.Now().Before(prev.Expires) {
			return UnitPage{}, ErrInvalid
		}
		cur.After = prev.After
	}
	after, err := strconv.Atoi(cur.After)
	if err != nil {
		return UnitPage{}, ErrInvalid
	}
	page := UnitPage{Units: []UnitEntry{}, DocumentVersion: d.id.String(), Kind: d.units.kind()}
	scanned, exhausted := 0, false
	for len(page.Units) < limit && scanned < s.d.Limits.ListScanBudget && !exhausted {
		n := min(maxBatch-1, s.d.Limits.ListScanBudget-scanned)
		ms, err := s.members(ctx, c.Tenant, d.id, after, n, nil)
		if err != nil {
			return UnitPage{}, err
		}
		exhausted = len(ms) < n
		if len(ms) == 0 {
			break
		}
		visible := make([]bool, len(ms))
		all, err := s.allowed(ctx, c, d.units.selectOp, d, ms)
		if err != nil {
			return UnitPage{}, err
		}
		for i := range ms {
			if visible[i] = all; !all {
				if visible[i], err = s.allowed(ctx, c, d.units.selectOp, d, ms[i:i+1]); err != nil {
					return UnitPage{}, err
				}
			}
		}
		for i, m := range ms {
			scanned++
			after = m.position
			if visible[i] {
				page.Units = append(page.Units, m.entry)
				if len(page.Units) == limit {
					exhausted = exhausted && i == len(ms)-1
					break
				}
			}
		}
	}
	if !exhausted {
		cur.After, cur.Expires = strconv.Itoa(after), s.d.Now().Add(s.d.Limits.TokenLifetime)
		if page.Continuation, err = s.sealToken(cur); err != nil {
			return UnitPage{}, err
		}
	}
	return page, nil
}

// Manifest returns a document version's signed manifest only if the
// caller may read every unit it lists (DOC-007): the manifest names them
// all.
func (s *Service) Manifest(ctx context.Context, c Caller, bucketName, key, versionSel string) ([]byte, string, error) {
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, "", err
	}
	ms, err := s.allMembers(ctx, c.Tenant, d.id)
	if err != nil {
		return nil, "", err
	}
	ok, err := s.allowed(ctx, c, d.units.manifestOp, d, ms)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, "", ErrNotFound
	}
	return d.manifest, d.sig, nil
}

// unitTarget resolves one unit of a document version.
func (s *Service) unitTarget(ctx context.Context, c Caller, bucketName, key, versionSel, unit string) (docVersion, member, error) {
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return docVersion{}, member{}, err
	}
	ms, err := s.members(ctx, c.Tenant, d.id, 0, 0, []string{unit})
	if err != nil {
		return docVersion{}, member{}, err
	}
	if len(ms) != 1 {
		return docVersion{}, member{}, ErrNotFound
	}
	return d, ms[0], nil
}

func unitReadChecks(d docVersion, m member) []check {
	return []check{
		{id: "version", role: registry.RoleVersion, action: "read-units", ref: canonical("document.version", d.id.String())},
		{id: "unit", role: registry.RoleUnit, action: "read", ref: canonical(d.units.typ, m.entry.Unit), version: m.entry.UnitVersion},
	}
}

// UnitPackageOut is a unit's descriptor and the recipient's envelope.
type UnitPackageOut struct {
	Unit     UnitEntry `json:"unit"`
	Envelope Delivered `json:"envelope"`
}

// UnitPackage returns a unit's signed descriptor and the caller's existing
// envelope for it in this document version. The envelope is released by
// the keys role against a single-use decision with the caller's read-units
// and read, the envelope's release, and the recipient's read-units, read
// and receive-key (DOC-007, KEY-012).
func (s *Service) UnitPackage(ctx context.Context, c Caller, bucketName, key, versionSel, unit, recipient string) (UnitPackageOut, error) {
	if _, err := cryptowire.ParseDigest(recipient); err != nil {
		return UnitPackageOut{}, ErrInvalid
	}
	d, m, err := s.unitTarget(ctx, c, bucketName, key, versionSel, unit)
	if err != nil {
		return UnitPackageOut{}, err
	}
	_, rec, err := s.decide(ctx, c, d.units.readOp, Audience, false, unitReadChecks(d, m))
	if err != nil {
		return UnitPackageOut{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return UnitPackageOut{}, err
	}
	// A server-mode unit has no envelopes; the authorized caller is told
	// its mode rather than that none exists (ENC-002).
	versionID, _ := cryptowire.ParseUUID(m.entry.UnitVersion)
	uv, err := s.versionByID(ctx, s.d.Catalog.Pool(), c.Tenant, versionID, false)
	if err != nil {
		return UnitPackageOut{}, err
	}
	if err := clientMode(uv.Encryption); err != nil {
		return UnitPackageOut{}, err
	}
	var envelopeID string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id::text FROM envelopes WHERE tenant = $1 AND version::text = $2 AND recipient = $3
	                                         AND document_version = $4 AND status = 'ACTIVE'`, c.Tenant, m.entry.UnitVersion, recipient, d.id).Scan(&envelopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return UnitPackageOut{}, ErrNotFound
	}
	if err != nil {
		return UnitPackageOut{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	version, unitRef := canonical("document.version", d.id.String()), canonical(d.units.typ, m.entry.Unit)
	checks := append(unitReadChecks(d, m),
		check{id: "envelope", role: registry.RoleEnvelope, action: "release", ref: canonical("crypto.envelope", envelopeID), version: m.entry.UnitVersion},
		check{id: "recipient-version", role: registry.RoleRecipientVersion, action: "read-units", ref: version, recipient: recipient},
		check{id: "recipient-read", role: registry.RoleRecipientRead, action: "read", ref: unitRef, version: m.entry.UnitVersion, recipient: recipient},
		check{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", recipient), recipient: recipient})
	signed, _, err := s.decide(ctx, c, d.units.envelopeOp, KeysAudience, true, checks)
	if err != nil {
		return UnitPackageOut{}, err
	}
	env, err := s.d.Keys.Deliver(ctx, signed, envelopeID)
	if err != nil {
		return UnitPackageOut{}, err
	}
	return UnitPackageOut{Unit: m.entry, Envelope: env}, nil
}

// ReadUnitCiphertext admits the read of one unit's exact ciphertext in
// one document version under the fence and returns its stream with the
// read lease (CNT-008, DSC-001). It never falls back to another version.
func (s *Service) ReadUnitCiphertext(ctx context.Context, c Caller, bucketName, key, versionSel, unit string) (*Stream, error) {
	d, m, err := s.unitTarget(ctx, c, bucketName, key, versionSel, unit)
	if err != nil {
		return nil, err
	}
	_, rec, err := s.decide(ctx, c, d.units.readOp, Audience, true, unitReadChecks(d, m))
	if err != nil {
		return nil, err
	}
	return s.admitUnit(ctx, c, rec, d, m)
}

func (s *Service) admitUnit(ctx context.Context, c Caller, rec signing.Record, d docVersion, m member) (*Stream, error) {
	v, tenantID, err := s.admitUnitRead(ctx, c, rec, d, m, "client")
	if err != nil {
		return nil, err
	}
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(r, b), Version: info(v, true)}, nil
}

// admitUnitRead admits the read of one unit of a document version under
// rec, recording the admission (CNT-008, DSC-001). The unit version must
// be in mode; another mode is ErrEncryptionMode, after authorization
// (ENC-002).
func (s *Service) admitUnitRead(ctx context.Context, c Caller, rec signing.Record, d docVersion, m member, mode string) (version, cryptowire.UUID, error) {
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return version{}, tenantID, err
	}
	versionID, _ := cryptowire.ParseUUID(m.entry.UnitVersion)
	v, err := s.versionByID(ctx, s.d.Catalog.Pool(), c.Tenant, versionID, false)
	if err != nil {
		return v, tenantID, err
	}
	if v.Encryption != mode {
		return v, tenantID, ErrEncryptionMode
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		var unitState, docState string
		if err := tx.QueryRow(ctx, `SELECT v.state, d.state FROM object_versions v, document_versions d
		                             WHERE v.tenant = $1 AND v.id = $2 AND d.tenant = $1 AND d.id = $3 FOR SHARE`,
			c.Tenant, versionID, d.id).Scan(&unitState, &docState); err != nil {
			return err
		}
		if unitState != "LIVE" || docState != "LIVE" {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `INSERT INTO read_admissions VALUES ($1, $2, $3, $4, $5)`,
			c.Tenant, rec.DecisionID, versionID, s.d.Now(), rec.ValidUntil); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindReadAdmission, rec, "ADMITTED",
			audit.Target{Type: d.units.typ, ID: m.entry.Unit, Version: m.entry.UnitVersion, Digest: v.SHA256},
			audit.Target{Type: "document.version", ID: d.id.String()}))
	})
	return v, tenantID, err
}

// original returns a document version's original file object and version,
// or ErrNotFound when it has none.
func (s *Service) original(ctx context.Context, tenant string, d docVersion) (cryptowire.UUID, version, error) {
	var object, versionID *cryptowire.UUID
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT original, original_version FROM document_versions WHERE tenant = $1 AND id = $2`,
		tenant, d.id).Scan(&object, &versionID); err != nil {
		return cryptowire.UUID{}, version{}, err
	}
	if object == nil {
		return cryptowire.UUID{}, version{}, ErrNotFound
	}
	v, err := s.versionByID(ctx, s.d.Catalog.Pool(), tenant, *versionID, false)
	if err != nil || v.State != "LIVE" {
		return cryptowire.UUID{}, version{}, ErrNotFound
	}
	return *object, v, nil
}

// completeContent decides raw-read on the version and read on every unit
// (CNT-003): the original discloses everything, so it needs everything.
// Any denial is ErrNotFound. The decisions are for audience: the storage
// role's own, or the keys role's when they go with an envelope release.
func (s *Service) completeContent(ctx context.Context, c Caller, d docVersion, singleUse bool, audience string) ([]signing.Signed, []signing.Record, error) {
	ms, err := s.allMembers(ctx, c.Tenant, d.id)
	if err != nil {
		return nil, nil, err
	}
	var signed []signing.Signed
	var recs []signing.Record
	for start := 0; start == 0 || start < len(ms); start += maxBatch - 1 {
		checks := selectChecks(d, ms[start:min(len(ms), start+maxBatch-1)])
		checks[0].action = "raw-read"
		sg, rec, err := s.decide(ctx, c, registry.OpDocRawRead, audience, singleUse, checks)
		if err != nil {
			return nil, nil, err
		}
		signed, recs = append(signed, sg), append(recs, rec)
	}
	return signed, recs, nil
}

// OriginalPackage returns the original file's signed object descriptor and
// the recipient's existing envelope for it (CNT-003, DOC-006). It needs
// raw-read on the version and read on every unit; the keys role releases
// the envelope against raw-read for the caller and the recipient.
func (s *Service) OriginalPackage(ctx context.Context, c Caller, bucketName, key, versionSel, recipient string) (Package, error) {
	if _, err := cryptowire.ParseDigest(recipient); err != nil {
		return Package{}, ErrInvalid
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return Package{}, err
	}
	_, v, err := s.original(ctx, c.Tenant, d)
	if err != nil {
		return Package{}, err
	}
	// The complete-content decisions are for the keys role, which binds
	// them in its delivery fence (review finding 3).
	complete, _, err := s.completeContent(ctx, c, d, true, KeysAudience)
	if err != nil {
		return Package{}, err
	}
	if err := clientMode(v.Encryption); err != nil {
		return Package{}, err
	}
	var envelopeID string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id::text FROM envelopes WHERE tenant = $1 AND version = $2 AND recipient = $3
	                                         AND document_version = $4 AND status = 'ACTIVE'`, c.Tenant, v.ID, recipient, d.id).Scan(&envelopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Package{}, ErrNotFound
	}
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	ref := canonical("document.version", d.id.String())
	signed, _, err := s.decide(ctx, c, registry.OpDocGetOriginalEnvelope, KeysAudience, true, []check{
		{id: "version", role: registry.RoleVersion, action: "raw-read", ref: ref},
		{id: "envelope", role: registry.RoleEnvelope, action: "release", ref: canonical("crypto.envelope", envelopeID), version: v.ID.String()},
		{id: "recipient-version", role: registry.RoleRecipientVersion, action: "raw-read", ref: ref, recipient: recipient},
		{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", recipient), recipient: recipient},
	})
	if err != nil {
		return Package{}, err
	}
	env, err := s.d.Keys.Deliver(ctx, signed, envelopeID, complete...)
	if err != nil {
		return Package{}, err
	}
	return Package{Version: info(v, true), Descriptor: v.Descriptor, DescriptorSignature: v.DescriptorSig, Envelope: env}, nil
}

// ReadOriginal admits the read of a document version's original file under
// the fence, after single-use decisions for raw-read and read on every
// unit, and returns its stream with a read lease over all of them.
func (s *Service) ReadOriginal(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	object, v, err := s.original(ctx, c.Tenant, d)
	if err != nil {
		return nil, err
	}
	_, recs, err := s.completeContent(ctx, c, d, true, Audience)
	if err != nil {
		return nil, err
	}
	if err := clientMode(v.Encryption); err != nil {
		return nil, err
	}
	merged, tenantID, err := s.admitOriginal(ctx, c, d, object, v, recs)
	if err != nil {
		return nil, err
	}
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(r, merged), Version: info(v, true)}, nil
}

// admitOriginal admits the read of an original file under the fence over
// its complete-content decisions recs, recording the admission, and
// returns their merged binding for the read lease.
func (s *Service) admitOriginal(ctx context.Context, c Caller, d docVersion, object cryptowire.UUID, v version,
	recs []signing.Record) (fence.Binding, cryptowire.UUID, error) {
	bindings := make([]fence.Binding, len(recs))
	var err error
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return fence.Binding{}, cryptowire.UUID{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return fence.Binding{}, tenantID, err
	}
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		var originalState, docState string
		if err := tx.QueryRow(ctx, `SELECT v.state, d.state FROM object_versions v, document_versions d
		                             WHERE v.tenant = $1 AND v.id = $2 AND d.tenant = $1 AND d.id = $3 FOR SHARE`,
			c.Tenant, v.ID, d.id).Scan(&originalState, &docState); err != nil {
			return err
		}
		if originalState != "LIVE" || docState != "LIVE" {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `INSERT INTO read_admissions VALUES ($1, $2, $3, $4, $5)`,
			c.Tenant, recs[0].DecisionID, v.ID, s.d.Now(), recs[0].ValidUntil); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindReadAdmission, recs[0], "ADMITTED",
			audit.Target{Type: "document.original", ID: object.String(), Version: v.ID.String(), Digest: v.SHA256},
			audit.Target{Type: "document.version", ID: d.id.String()}))
	}))
	if err != nil {
		return fence.Binding{}, tenantID, err
	}
	merged, err := fence.Merge(bindings)
	if err != nil {
		return fence.Binding{}, tenantID, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return merged, tenantID, nil
}
