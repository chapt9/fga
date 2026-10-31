package content

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/payload"
	"fga/internal/registry"
	"fga/internal/textunits"
)

// Server-mode documents and text collections (specification 2.6, D-12
// stretch S4a, DOC-001 to DOC-007, SSE-001, SSE-003, SSE-005;
// docs/design/server-documents.md). The caller sends UTF-8 text; the
// storage role splits it under fga.text/nfc-paragraphs-v1, has the keys
// role seal one data key per new unit, encrypts each unit into its own
// blob, builds the manifest and publishes the version with the document's
// checks, explicit labels and reused units, as in client mode but without
// signatures, descriptors or envelopes. Each unit is read alone, under its
// own checks and its own key release.

// TextRequest is a server-mode text upload.
type TextRequest struct {
	Bucket, Key, IdempotencyKey string
	// Collection makes a new key a text collection (DOC-005). Append adds
	// the text's paragraphs to the collection at Key as a new version
	// that keeps every current entry; the caller must be allowed to read
	// each of them.
	Collection, Append bool
}

// PutDocumentText publishes text as a new version of the document or
// collection at r.Key in a server-mode bucket. A retry under the same
// idempotency key returns the outcome of the attempt it names: the
// committed version, or the publication of staged units (for instance
// once an approval is given). An attempt whose units got their data keys
// but were not all staged cannot be finished; the caller begins again
// under a new idempotency key (CRY-007).
func (s *Service) PutDocumentText(ctx context.Context, c Caller, r TextRequest, text []byte) (DocumentPublished, error) {
	if s.d.DataKeys == nil {
		return DocumentPublished{}, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	paragraphs, err := textunits.Split(text)
	if err != nil {
		return DocumentPublished{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	in, err := s.docIntentByIdempotency(ctx, c, r.IdempotencyKey)
	switch {
	case err == nil:
		// A retry: the attempt it names, whatever the collection holds now.
		if in.encryption != "server" {
			return DocumentPublished{}, ErrEncryptionMode
		}
		if in.state == "COMMITTED" {
			return s.FinalizeDocument(ctx, c, in.IntentID, DocumentFinalizeRequest{})
		}
	case !errors.Is(err, ErrNotFound):
		return DocumentPublished{}, err
	default:
		specs, err := s.textSpecs(ctx, c, r, len(paragraphs))
		if err != nil {
			return DocumentPublished{}, err
		}
		if in, err = s.beginDocument(ctx, c, DocumentBeginRequest{Bucket: r.Bucket, Key: r.Key, IdempotencyKey: r.IdempotencyKey,
			Units: specs, Collection: r.Collection || r.Append}, "server"); err != nil {
			return DocumentPublished{}, err
		}
	}
	if in.state != "RESERVED" {
		return DocumentPublished{}, fmt.Errorf("%w: document intent is %s", ErrConflict, in.state)
	}
	var fresh []UnitIntent
	for _, u := range in.Units {
		if !u.Reused {
			fresh = append(fresh, u)
		}
	}
	if len(fresh) != len(paragraphs) {
		return DocumentPublished{}, fmt.Errorf("%w: the idempotency key was used for another text", ErrConflict)
	}
	staged, sealed, err := s.unitStates(ctx, c, in)
	if err != nil {
		return DocumentPublished{}, err
	}
	switch {
	case staged == len(fresh):
	case sealed > 0:
		return DocumentPublished{}, fmt.Errorf("%w: an earlier attempt of this upload did not finish; begin again under a new idempotency key", ErrConflict)
	default:
		if err := s.stageText(ctx, c, in, fresh, paragraphs); err != nil {
			return DocumentPublished{}, err
		}
	}
	p, err := s.FinalizeDocument(ctx, c, in.IntentID, DocumentFinalizeRequest{})
	var need *ApprovalRequired
	if errors.As(err, &need) {
		return DocumentPublished{}, &StagedApproval{ApprovalRequired: need, Intent: in.IntentID}
	}
	return p, err
}

// textSpecs are the unit specs of a text upload: for an append, every
// entry of the collection's current version, kept as it is, then one new
// unit per paragraph. An append refuses a version with an entry that is no
// longer LIVE rather than dropping it silently.
func (s *Service) textSpecs(ctx context.Context, c Caller, r TextRequest, paragraphs int) ([]DocumentUnitSpec, error) {
	var specs []DocumentUnitSpec
	if r.Append {
		d, err := s.documentVersion(ctx, c.Tenant, r.Bucket, r.Key, "")
		if err != nil {
			return nil, err
		}
		if d.units != textEntries {
			return nil, fmt.Errorf("%w: only a text collection is appended to", ErrInvalid)
		}
		ms, err := s.members(ctx, c.Tenant, d.id, -1, cryptowire.MaxUnits+1, nil)
		if err != nil {
			return nil, err
		}
		var all int
		if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT count(*) FROM document_units WHERE tenant = $1 AND document_version = $2`,
			c.Tenant, d.id).Scan(&all); err != nil {
			return nil, err
		}
		if all != len(ms) {
			return nil, fmt.Errorf("%w: an entry of the collection is no longer live", ErrConflict)
		}
		for _, m := range ms {
			specs = append(specs, DocumentUnitSpec{ReuseUnit: m.entry.Unit, ReuseVersion: m.entry.UnitVersion})
		}
	}
	for range paragraphs {
		specs = append(specs, DocumentUnitSpec{})
	}
	return specs, nil
}

// unitStates counts the new units of a document intent that are staged,
// and those that have a data key.
func (s *Service) unitStates(ctx context.Context, c Caller, in storedDocIntent) (staged, sealed int, err error) {
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'STAGED'), count(*) FILTER (WHERE sealed_key IS NOT NULL)
		  FROM upload_intents WHERE tenant = $1 AND document_intent::text = $2 AND kind = 'unit'`, c.Tenant, in.IntentID).Scan(&staged, &sealed)
	return staged, sealed, err
}

// stageText has the keys role seal the new units' data keys, under one
// decision for the document's write, and encrypts each paragraph into its
// unit's blob. Staging is admitted by a fresh single-use decision for the
// same right, as for client units (ruling 7, DAT-007).
func (s *Service) stageText(ctx context.Context, c Caller, in storedDocIntent, fresh []UnitIntent, paragraphs []string) error {
	op, ch := docChecks(in, registry.OpKeySealDocCreate, registry.OpKeySealDocVersion)
	signed, _, err := s.decide(ctx, c, op, KeysAudience, true, []check{ch})
	if err != nil {
		return err
	}
	keys, err := s.d.DataKeys.SealDocumentKeys(ctx, signed, in.IntentID)
	if err != nil {
		return keysError(err)
	}
	byIntent := map[string][]byte{}
	for _, k := range keys {
		byIntent[k.Intent] = k.Key
	}
	defer func() {
		for _, k := range keys {
			clear(k.Key)
		}
	}()
	units := make([]storedIntent, len(fresh))
	for i, u := range fresh {
		id, _ := cryptowire.ParseUUID(u.IntentID)
		if units[i], err = s.intent(ctx, s.d.Catalog.Pool(), c, id, false); err != nil {
			return err
		}
		if byIntent[u.IntentID] == nil {
			return fmt.Errorf("%w: the keys role sealed no key for unit %d", ErrUnavailable, u.Position)
		}
	}
	stageOp, checks := s.intentChecks(units[0], registry.OpStageCreate, registry.OpStageVersion)
	_, rec, err := s.decide(ctx, c, stageOp, Audience, true, checks)
	if err != nil {
		return err
	}
	if err := s.fenced(ctx, rec, nil, func(context.Context, pgx.Tx) error { return nil }); err != nil {
		return err
	}
	for i, u := range units {
		if err := s.encryptStaged(ctx, c, u, byIntent[fresh[i].IntentID], int64(len(paragraphs[i])), strings.NewReader(paragraphs[i])); err != nil {
			return err
		}
	}
	return nil
}

// finalizeDocumentServer publishes a staged server-mode document version:
// the storage role builds its manifest from the staged and reused units;
// the decisions are the document's, explicit unit labels' and reused
// units', as in client mode; the commit is the same fenced transaction,
// without signatures, descriptors or envelopes.
func (s *Service) finalizeDocumentServer(ctx context.Context, c Caller, in storedDocIntent, r DocumentFinalizeRequest) (DocumentPublished, error) {
	if len(r.Manifest) > 0 || r.ManifestSignature != "" || len(r.Units) > 0 || r.Original != nil {
		return DocumentPublished{}, fmt.Errorf("%w: a server-mode document has no client manifest, descriptors or envelopes", ErrInvalid)
	}
	if in.Original != nil {
		return DocumentPublished{}, fmt.Errorf("%w: server-mode original files are not supported yet", ErrInvalid)
	}
	m := cryptowire.Manifest{TenantID: in.Tenant, DocumentID: in.Document, DocumentVersionID: in.DocumentVersion,
		NormalizationVersion: textunits.NormalizationVersion}
	units := make([]checkedUnit, len(in.Units))
	for i, u := range in.Units {
		cu := checkedUnit{UnitIntent: u}
		sum, length := u.CiphertextSHA256, u.CiphertextLength
		if !u.Reused {
			id, _ := cryptowire.ParseUUID(u.IntentID)
			st, err := s.intent(ctx, s.d.Catalog.Pool(), c, id, false)
			if err != nil {
				return DocumentPublished{}, err
			}
			if st.state != "STAGED" || st.encryption != "server" {
				return DocumentPublished{}, fmt.Errorf("%w: unit %d is %s", ErrConflict, i, st.state)
			}
			cu.staged, sum, length = st, st.ciphertextSHA256, st.ciphertextLength
		}
		cu.descriptor = cryptowire.UnitDescriptor{CiphertextSHA256: sum, CiphertextLength: uint64(length), Suite: payload.Suite, Format: payload.Format}
		units[i] = cu
		m.Units = append(m.Units, cryptowire.ManifestUnit{UnitID: u.Unit, UnitVersionID: u.UnitVersion, CryptoVersionID: u.CryptoVersion,
			CiphertextSHA256: sum, CiphertextLength: uint64(length), Suite: payload.Suite, Format: payload.Format})
	}
	raw, err := m.MarshalServer()
	if err != nil {
		return DocumentPublished{}, err
	}
	digest := cryptowire.ManifestDigest(raw)
	recs, err := s.documentDecisions(ctx, c, in, units, nil, digest)
	if err != nil {
		return DocumentPublished{}, err
	}
	return s.commitDocument(ctx, c, in, DocumentFinalizeRequest{Manifest: raw, Units: make([]UnitFinal, len(units))}, m, digest, "", units, nil, recs)
}

// ReadUnitPlain reads one unit or entry of a server-mode document version
// as plaintext: the unit read's checks (read-units on the version, read on
// the unit) admit it like a ciphertext unit read; the keys role then
// releases that unit's data key against its own decision, and the stream
// decrypts under the read's lease (DOC-006, DOC-007, SSE-003, SSE-005).
func (s *Service) ReadUnitPlain(ctx context.Context, c Caller, bucketName, key, versionSel, unit string) (*Stream, error) {
	if s.d.DataKeys == nil {
		return nil, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	d, m, err := s.unitTarget(ctx, c, bucketName, key, versionSel, unit)
	if err != nil {
		return nil, err
	}
	_, rec, err := s.decide(ctx, c, d.units.readOp, Audience, true, unitReadChecks(d, m))
	if err != nil {
		return nil, err
	}
	v, tenantID, err := s.admitUnitRead(ctx, c, rec, d, m, "server")
	if err != nil {
		return nil, err
	}
	signed, _, err := s.decide(ctx, c, d.units.releaseOp, KeysAudience, true, unitReadChecks(d, m))
	if err != nil {
		return nil, err
	}
	dataKey, err := s.d.DataKeys.ReleaseUnitKey(ctx, signed, d.id.String(), m.entry.Unit)
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
	plain, err := payload.Decrypt(dataKey, binding(tenantID, v.Object, v.ID, v.CryptoVersion, v.Blob), r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(readCloser{Reader: plain, Closer: r}, b), Version: info(v, true)}, nil
}
