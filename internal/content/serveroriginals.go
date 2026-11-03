package content

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/payload"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Server-mode original files and unit exports (D-12 stretch S4b, CNT-003,
// DOC-006; docs/design/server-documents.md).

// ReadOriginalPlain reads a server-mode document version's original file
// as plaintext. Like the client-mode original, it needs raw-read on the
// version and read on every unit (CNT-003): the storage role's own
// complete-content decisions admit the read, and a second set, made for
// the keys role, goes with the release of the original's data key, so the
// keys role admits all of them in the fence of the release and a change to
// any unit in between blocks it (review finding 3, V-163).
func (s *Service) ReadOriginalPlain(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	if s.d.DataKeys == nil {
		return nil, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
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
	if v.Encryption != "server" {
		return nil, ErrEncryptionMode
	}
	merged, tenantID, err := s.admitOriginal(ctx, c, d, object, v, recs)
	if err != nil {
		return nil, err
	}
	complete, _, err := s.completeContent(ctx, c, d, true, KeysAudience)
	if err != nil {
		return nil, err
	}
	releaseOp, releaseChecks := d.historic(registry.OpKeyReleaseOriginal,
		[]check{{id: "version", role: registry.RoleVersion, action: "raw-read", ref: canonical("document.version", d.id.String())}})
	signed, _, err := s.decide(ctx, c, releaseOp, KeysAudience, true, releaseChecks)
	if err != nil {
		return nil, err
	}
	dataKey, err := s.d.DataKeys.ReleaseOriginalKey(ctx, signed, complete, d.id.String())
	if err != nil {
		return nil, keysError(err)
	}
	defer clear(dataKey)
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	plain, err := payload.Decrypt(dataKey, binding(tenantID, object, v.ID, v.CryptoVersion, v.Blob), r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(readCloser{Reader: plain, Closer: r}, merged), Version: info(v, true)}, nil
}

// UnitText is one exported server-mode unit.
type UnitText struct {
	Unit        string `json:"unit_id"`
	UnitVersion string `json:"unit_version_id"`
	Text        string `json:"text"`
}

// PlainExport is a server-mode export of selected units.
type PlainExport struct {
	DocumentVersion string     `json:"document_version_id"`
	Units           []UnitText `json:"units"`
}

// ExportUnitsPlain exports the plaintext of selected units of a server-mode
// document version to the caller (DOC-006). Like the client-mode export it
// needs export and read-units on the version and read and export-key on
// every selected unit, all allowed or none; the storage role admits the
// export under the fence over those decisions, then has the keys role
// release each unit's data key under that unit's read checks. Text
// entries cannot be exported (DOC-005).
func (s *Service) ExportUnitsPlain(ctx context.Context, c Caller, bucketName, key, versionSel string, units []string) (PlainExport, error) {
	if s.d.DataKeys == nil {
		return PlainExport{}, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	if len(units) == 0 || len(units) > MaxSelect {
		return PlainExport{}, ErrInvalid
	}
	sorted := slices.Clone(units)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(units) {
		return PlainExport{}, ErrInvalid
	}
	d, err := s.documentVersion(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return PlainExport{}, err
	}
	if d.units != textUnits {
		return PlainExport{}, ErrNotFound
	}
	ms, err := s.members(ctx, c.Tenant, d.id, 0, 0, units)
	if err != nil {
		return PlainExport{}, err
	}
	if len(ms) != len(units) {
		return PlainExport{}, ErrNotFound
	}
	versionRef := canonical("document.version", d.id.String())
	var recs []signing.Record
	per := (d.room() - 2) / 2
	for start := 0; start < len(ms); start += per {
		batch := ms[start:min(len(ms), start+per)]
		checks := []check{{id: "version", role: registry.RoleVersion, action: "export", ref: versionRef},
			{id: "version-read", role: registry.RoleVersionRead, action: "read-units", ref: versionRef}}
		for i, m := range batch {
			ref, n := canonical("document.text_unit", m.entry.Unit), strconv.Itoa(i)
			checks = append(checks,
				check{id: "unit-" + n, role: registry.RoleUnit, action: "read", ref: ref, version: m.entry.UnitVersion},
				check{id: "unit-export-" + n, role: registry.RoleUnitExport, action: "export-key", ref: ref, version: m.entry.UnitVersion})
		}
		op, checks := d.historic(registry.OpDocExport, checks)
		_, rec, err := s.decide(ctx, c, op, Audience, true, checks)
		if err != nil {
			return PlainExport{}, err
		}
		recs = append(recs, rec)
	}
	if exportSize(ms) > MaxExportBytes {
		return PlainExport{}, ErrTooLarge
	}
	bindings := make([]fence.Binding, len(recs))
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return PlainExport{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return PlainExport{}, err
	}
	versions := make([]version, len(ms))
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.stillCurrent(ctx, tx, c.Tenant, d, true); err != nil {
			return err
		}
		targets := []audit.Target{{Type: "document.version", ID: d.id.String()}}
		for i, m := range ms {
			id, _ := cryptowire.ParseUUID(m.entry.UnitVersion)
			v, err := s.versionByID(ctx, tx, c.Tenant, id, true)
			if err != nil || v.State != "LIVE" {
				return ErrNotFound
			}
			if v.Encryption != "server" {
				return ErrEncryptionMode
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
		return PlainExport{}, err
	}
	out := PlainExport{DocumentVersion: d.id.String()}
	for i, m := range ms {
		text, err := s.unitText(ctx, c, d, m, versions[i], tenantID)
		if err != nil {
			return PlainExport{}, err
		}
		out.Units = append(out.Units, UnitText{Unit: m.entry.Unit, UnitVersion: m.entry.UnitVersion, Text: text})
	}
	return out, nil
}

// unitText has the keys role release one unit's data key under the unit
// read's checks and decrypts the unit whole.
func (s *Service) unitText(ctx context.Context, c Caller, d docVersion, m member, v version, tenantID cryptowire.UUID) (string, error) {
	op, checks := d.historic(d.units.releaseOp, unitReadChecks(d, m))
	signed, _, err := s.decide(ctx, c, op, KeysAudience, true, checks)
	if err != nil {
		return "", err
	}
	dataKey, err := s.d.DataKeys.ReleaseUnitKey(ctx, signed, d.id.String(), m.entry.Unit)
	if err != nil {
		return "", keysError(err)
	}
	defer clear(dataKey)
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return "", fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	defer r.Close()
	plain, err := payload.Decrypt(dataKey, binding(tenantID, v.Object, v.ID, v.CryptoVersion, v.Blob), r)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, io.LimitReader(plain, v.PlaintextLength+1)); err != nil || int64(b.Len()) != v.PlaintextLength {
		return "", fmt.Errorf("%w: the unit did not decrypt whole", ErrUnavailable)
	}
	return b.String(), nil
}
