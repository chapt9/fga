package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/payload"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Server-mode derived outputs (D-12 stretch S4b, DRV-001 to DRV-003,
// DRV-007 to DRV-009; docs/design/derived-outputs.md). The uploader sends
// plaintext and declares its lineage in the authenticated request; the
// storage role records that lineage, bound to the caller's decision
// instead of a client signature, and publishes the output with the label,
// source and approval rules of client mode. A reader has no recipient key:
// it reads under deliver on the output and its own reader path, the read
// of every source of the transitive lineage or a declassification for it,
// which the keys role checks again in the fence of the key release.

// PutDerivedPlain publishes length bytes of plaintext from body (length -1
// when unknown) as a derived output at r.Key in a server-mode bucket, with
// sources as its declared lineage. A retry under the same idempotency key
// returns the committed version to a caller who may still deliver it, or
// publishes a staged upload; an attempt whose encryption began and did not
// finish cannot be retried (CRY-007). When the publication needs an
// approval, FinalizeDerivedPlain finishes the staged upload once it is
// given.
func (s *Service) PutDerivedPlain(ctx context.Context, c Caller, r BeginRequest, sources []cryptowire.LineageSource, length int64,
	body io.Reader) (Published, error) {
	if s.d.DataKeys == nil {
		return Published{}, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	if len(sources) == 0 || len(sources) > cryptowire.MaxLineageSources || length < -1 {
		return Published{}, ErrInvalid
	}
	if length >= 0 && payload.CiphertextSize(length) > s.d.Limits.MaxCiphertext {
		return Published{}, ErrTooLarge
	}
	r.Derived = true
	in, err := s.begin(ctx, c, r, "server")
	if err != nil {
		return Published{}, err
	}
	switch {
	case in.state == "COMMITTED":
		var p Published
		if err := json.Unmarshal(in.result, &p); err != nil {
			return Published{}, fmt.Errorf("%w: stored result", ErrUnavailable)
		}
		_, rec, err := s.decide(ctx, c, registry.OpDerivedDeliver, Audience, false, []check{{id: "output", role: registry.RoleOutput,
			action: "deliver", ref: canonical("document.derived", in.Object.String()), version: in.LogicalVersion.String()}})
		if err != nil {
			return Published{}, err
		}
		return p, s.checked(ctx, rec)
	case in.state == "RESERVED" && in.sealed:
		return Published{}, fmt.Errorf("%w: an earlier attempt of this upload did not finish; begin again under a new idempotency key", ErrConflict)
	case in.state == "RESERVED":
		if err := s.stageServer(ctx, c, in, length, body); err != nil {
			return Published{}, err
		}
	}
	staged, err := s.intent(ctx, s.d.Catalog.Pool(), c, in.IntentID, false)
	if err != nil {
		return Published{}, err
	}
	return s.publishDerivedPlain(ctx, c, staged, sources)
}

// FinalizeDerivedPlain publishes the caller's staged server-mode derived
// upload with sources as its lineage, typically once the approval its
// publication needed is given; the content is not sent again.
func (s *Service) FinalizeDerivedPlain(ctx context.Context, c Caller, intentID cryptowire.UUID, sources []cryptowire.LineageSource) (Published, error) {
	if len(sources) == 0 || len(sources) > cryptowire.MaxLineageSources {
		return Published{}, ErrInvalid
	}
	in, err := s.intent(ctx, s.d.Catalog.Pool(), c, intentID, false)
	if err != nil {
		return Published{}, err
	}
	if in.kind != "derived" {
		return Published{}, ErrNotFound
	}
	if in.encryption != "server" {
		return Published{}, ErrEncryptionMode
	}
	if in.state == "COMMITTED" {
		var p Published
		if err := json.Unmarshal(in.result, &p); err != nil {
			return Published{}, fmt.Errorf("%w: stored result", ErrUnavailable)
		}
		_, rec, err := s.decide(ctx, c, registry.OpDerivedDeliver, Audience, false, []check{{id: "output", role: registry.RoleOutput,
			action: "deliver", ref: canonical("document.derived", in.Object.String()), version: in.LogicalVersion.String()}})
		if err != nil {
			return Published{}, err
		}
		return p, s.checked(ctx, rec)
	}
	return s.publishDerivedPlain(ctx, c, in, sources)
}

// publishDerivedPlain records sources as the staged version's lineage,
// bound to the caller's publication decision, and publishes it. The
// lineage is dated when its upload began, so a publication repeated with
// an approval presents the plan that was approved (APR-002).
func (s *Service) publishDerivedPlain(ctx context.Context, c Caller, staged storedIntent, sources []cryptowire.LineageSource) (Published, error) {
	if staged.state != "STAGED" {
		return Published{}, fmt.Errorf("%w: intent is %s", ErrConflict, staged.state)
	}
	if err := s.stagedBlob(staged); err != nil {
		return Published{}, err
	}
	l := cryptowire.Lineage{TenantID: staged.Tenant.String(), ObjectID: staged.Object.String(), VersionID: staged.LogicalVersion.String(),
		Sources: sources, CreatedAt: staged.createdAt.UTC()}
	raw, err := l.MarshalServer()
	if err != nil {
		return Published{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	p, err := s.publishDerived(ctx, c, staged, derivedPublication{lineage: l, raw: raw})
	var need *ApprovalRequired
	if errors.As(err, &need) {
		return Published{}, &StagedApproval{ApprovalRequired: need, Intent: staged.IntentID.String()}
	}
	return p, err
}

// readerPath decides the caller's own path to a derived version: read
// (deliver for derived sources) on every source of its transitive lineage,
// or, failing that, deliver and declassify on the output for the caller
// (DRV-002). The decisions are single-use, for audience.
func (s *Service) readerPath(ctx context.Context, c Caller, output cryptowire.UUID, v version, audience string) ([]signing.Signed, []signing.Record, error) {
	sources, err := s.transitive(ctx, s.d.Catalog.Pool(), c.Tenant, v.ID)
	if err != nil {
		return nil, nil, err
	}
	signed, recs, err := s.decideBatches(ctx, c, registry.OpDerivedSources, audience, true, sourceGroups(sources, ""))
	if !errors.Is(err, ErrNotFound) {
		return signed, recs, err
	}
	ref := canonical("document.derived", output.String())
	sg, rec, err := s.decide(ctx, c, registry.OpDerivedDeclassifyReader, audience, true, []check{
		{id: "output", role: registry.RoleOutput, action: "deliver", ref: ref, version: v.ID.String()},
		{id: "declassify", role: registry.RoleDeclassify, action: "declassify", ref: ref, version: v.ID.String()}})
	if err != nil {
		return nil, nil, err
	}
	return []signing.Signed{sg}, []signing.Record{rec}, nil
}

// ReadDerivedPlain reads a server-mode derived version's plaintext for the
// caller (DRV-002): deliver on the output and the caller's reader path
// admit the read; the keys role then releases the version's data key
// against deliver and a reader path decided for it, admitted in the fence
// of the release. A source change while the output's own authority holds
// ends the stream with ErrLineageChanged (V-145).
func (s *Service) ReadDerivedPlain(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	if s.d.DataKeys == nil {
		return nil, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	output, v, err := s.derivedTarget(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	deliver := []check{{id: "output", role: registry.RoleOutput, action: "deliver", ref: canonical("document.derived", output.String()), version: v.ID.String()}}
	_, own, err := s.decide(ctx, c, registry.OpDerivedDeliver, Audience, true, deliver)
	if err != nil {
		return nil, err
	}
	_, path, err := s.readerPath(ctx, c, output, v, Audience)
	if err != nil {
		return nil, err
	}
	if v.Encryption != "server" {
		return nil, ErrEncryptionMode
	}
	merged, ownBinding, tenantID, err := s.admitDerived(ctx, c, output, v, append([]signing.Record{own}, path...), "")
	if err != nil {
		return nil, err
	}
	keyPath, _, err := s.readerPath(ctx, c, output, v, KeysAudience)
	if err != nil {
		return nil, err
	}
	signed, _, err := s.decide(ctx, c, registry.OpKeyReleaseDerived, KeysAudience, true, deliver)
	if err != nil {
		return nil, err
	}
	dataKey, err := s.d.DataKeys.ReleaseDerivedKey(ctx, signed, keyPath, v.ID.String())
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
	plain, err := payload.Decrypt(dataKey, binding(tenantID, output, v.ID, v.CryptoVersion, v.Blob), r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.derivedLease(readCloser{Reader: plain, Closer: r}, merged, ownBinding), Version: info(v, true)}, nil
}
