package content

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/opplan"
	"fga/internal/payload"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Documents and text units (docs/design/documents.md, DOC-001 to
// DOC-004). A document version is published in three steps: BeginDocument
// reserves the document version and one unit intent per new unit;
// the client stages each unit's ciphertext with PutCiphertext; and
// FinalizeDocument verifies the signed manifest, unit descriptors and
// envelopes, obtains every decision in batches of at most 50 checks
// (DEC-009) and commits all of it in one fenced transaction (V-063).

// DocumentUnitSpec is one unit of a new document version, in document
// order: a new unit (with an optional explicit label) or an existing LIVE
// unit version to reuse (DOC-002).
type DocumentUnitSpec struct {
	ReuseUnit    string `json:"reuse_unit,omitempty"`
	ReuseVersion string `json:"reuse_version,omitempty"`
	Label        string `json:"label,omitempty"`
}

// DocumentBeginRequest asks to publish a new version of a document key.
type DocumentBeginRequest struct {
	Bucket         string
	Key            string
	IdempotencyKey string
	Units          []DocumentUnitSpec
	// Original reserves an encrypted original file (CNT-003): a separate
	// ciphertext under its own key, disclosed only with raw-read on the
	// version and read on every unit.
	Original bool
	// Collection makes a new key a text collection (DOC-005): its units are
	// text.entry resources, and a new version replaces or appends entries
	// by reusing earlier ones. A key keeps its kind.
	Collection bool
	// BaseVersion is the document version the reused units were selected
	// from. The begin refuses unless it is still the document's current
	// version, read together with the generation the publication checks,
	// so entries appended in between are not dropped (review v2 finding
	// 3). A new collection version that reuses entries must name it.
	BaseVersion string
}

func (r DocumentBeginRequest) digest() string {
	h := sha256.New()
	fmt.Fprintf(h, "fga.document-begin/v1\n%q\n%q\n", r.Bucket, r.Key)
	for _, u := range r.Units {
		fmt.Fprintf(h, "%q %q %q\n", u.ReuseUnit, u.ReuseVersion, u.Label)
	}
	if r.Original {
		fmt.Fprintf(h, "original\n")
	}
	if r.Collection {
		fmt.Fprintf(h, "collection\n")
	}
	if r.BaseVersion != "" {
		fmt.Fprintf(h, "base %q\n", r.BaseVersion)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// UnitIntent is one position of a document intent. A new unit has its own
// upload intent and identifiers; a reused unit names its existing version
// and ciphertext.
type UnitIntent struct {
	Position         int    `json:"position"`
	IntentID         string `json:"intent_id,omitempty"`
	Unit             string `json:"unit_id"`
	UnitVersion      string `json:"unit_version_id"`
	CryptoVersion    string `json:"crypto_version_id"`
	Blob             string `json:"blob_id"`
	Attempt          string `json:"attempt_id,omitempty"`
	Reused           bool   `json:"reused"`
	Label            string `json:"label,omitempty"`
	CiphertextSHA256 string `json:"ciphertext_sha256,omitempty"`
	CiphertextLength int64  `json:"ciphertext_length,omitempty"`
}

// DocumentIntent is a reserved document version.
type DocumentIntent struct {
	IntentID        string       `json:"intent_id"`
	Tenant          string       `json:"tenant_id"`
	Document        string       `json:"document_id"`
	DocumentVersion string       `json:"document_version_id"`
	Units           []UnitIntent `json:"units"`
	// Original is the original file's intent and identifiers, if reserved.
	Original      *UnitIntent `json:"original,omitempty"`
	MaxCiphertext int64       `json:"max_ciphertext_length"`
	ExpiresAt     time.Time   `json:"expires_at"`
}

type storedDocIntent struct {
	DocumentIntent
	principal     string
	requestDigest string
	state         string
	bucket        cryptowire.UUID
	key           string
	newDocument   bool
	expectedGen   uint64
	scope         string
	attributes    map[string]any
	result        []byte
	// encryption is the mode the document version began under (ENC-001).
	encryption string
	// post marks a reading of a source, whose steps decide post-reading
	// (ING-012).
	post bool
}

// BeginDocument reserves a document version (DOC-002 step 1). A new key
// needs create-object on the bucket, an existing document new-version on
// it. It allocates the document version and, per new unit, a unit intent
// whose ciphertext the client stages like an object's; reused units must
// be LIVE units of the tenant. An identical retry under the same
// idempotency key returns the same intent after a fresh decision.
func (s *Service) BeginDocument(ctx context.Context, c Caller, r DocumentBeginRequest) (DocumentIntent, error) {
	in, err := s.beginDocument(ctx, c, r, "client", nil)
	return in.DocumentIntent, err
}

// beginDocument is BeginDocument for a bucket in mode; it returns the
// stored intent. Reused units must be LIVE units of that mode. reading is
// set for a reading of a source (ING-003, ING-006): its owner, its group
// labels and its attributes are the source version's, and only then may
// the bucket be a source's (ING-002).
func (s *Service) beginDocument(ctx context.Context, c Caller, r DocumentBeginRequest, mode string, reading *readingSpec) (storedDocIntent, error) {
	if !ValidKey(r.Key) || r.IdempotencyKey == "" || len(r.IdempotencyKey) > 128 || len(r.Units) == 0 || len(r.Units) > cryptowire.MaxUnits {
		return storedDocIntent{}, ErrInvalid
	}
	digest := r.digest()
	if reading != nil {
		if len(r.Units) != len(reading.groups) || r.Collection || r.Original || r.BaseVersion != "" ||
			slices.ContainsFunc(r.Units, func(u DocumentUnitSpec) bool { return u != DocumentUnitSpec{} }) {
			return storedDocIntent{}, fmt.Errorf("%w: a reading is one new unit per group", ErrInvalid)
		}
		digest = reading.digest(digest)
	}
	if in, err := s.docIntentByIdempotency(ctx, c, r.IdempotencyKey); err == nil {
		if in.state == "ABORTED" || in.requestDigest != digest {
			return storedDocIntent{}, fmt.Errorf("%w: the idempotency key was used for another request", ErrConflict)
		}
		op, ch := docChecks(in, registry.OpDocBeginCreate, registry.OpDocBeginVersion)
		_, rec, err := s.decide(ctx, c, op, Audience, false, []check{ch})
		if err != nil {
			return storedDocIntent{}, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return storedDocIntent{}, err
		}
		kind, _ := in.attributes["kind"].(string)
		if err := s.decideReuse(ctx, c, unitsOf(kind), in.Units); err != nil {
			return storedDocIntent{}, err
		}
		if in.encryption != mode {
			return storedDocIntent{}, ErrEncryptionMode
		}
		b, err := s.bucketByName(ctx, c.Tenant, r.Bucket)
		if err != nil {
			return storedDocIntent{}, err
		}
		if err := sourceBound(b, in.attributes, reading); err != nil {
			return storedDocIntent{}, err
		}
		return in, nil
	} else if !errors.Is(err, ErrNotFound) {
		return storedDocIntent{}, err
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return storedDocIntent{}, err
	}
	b, err := s.bucketByName(ctx, c.Tenant, r.Bucket)
	if err != nil {
		return storedDocIntent{}, err
	}
	in := storedDocIntent{DocumentIntent: DocumentIntent{IntentID: cryptowire.NewUUID().String(), Tenant: tenantID.String(),
		DocumentVersion: cryptowire.NewUUID().String(), MaxCiphertext: s.d.Limits.MaxCiphertext, ExpiresAt: s.d.Now().Add(s.d.Limits.IntentLifetime)},
		principal: c.Principal, requestDigest: digest, bucket: b.ID, key: r.Key, scope: b.Scope, encryption: b.Encryption, post: reading != nil}
	var kind, current string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT o.id::text, o.kind, coalesce(o.current_document_version::text, ''), r.generation, r.scope,
	                                               r.attributes FROM objects o
	                                         JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
	                                        WHERE o.tenant = $1 AND o.bucket = $2 AND o.key = $3 AND o.kind IN ('object', 'document')`,
		c.Tenant, b.ID, r.Key).Scan(&in.Document, &kind, &current, &in.expectedGen, &in.scope, &in.attributes)
	// A refusal that depends on the key's state (its kind, its current
	// version) is answered only once the caller is authorized, so a denied
	// caller learns nothing about the key (CNT-004; security review of 4
	// November 2026, finding 1). The first refusal found is the one answered.
	var refusal error
	if (err == nil || errors.Is(err, pgx.ErrNoRows)) && r.BaseVersion != "" && r.BaseVersion != current {
		refusal = fmt.Errorf("%w: the document has a newer version than the one its units were selected from", ErrConflict)
	}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		in.Document, in.newDocument = cryptowire.NewUUID().String(), true
		in.attributes = map[string]any{"bucket": b.Name, "owner": c.Represented(), "project": b.Project, "label": b.Label, "kind": "document",
			"encryption": b.Encryption}
		if r.Collection {
			in.attributes["kind"] = "collection"
		}
		// A reading belongs to its source's owner, not to the system
		// that posts it (D-C). A document keeps the owner it was created
		// with.
		if reading != nil {
			in.attributes["owner"], in.attributes["source"] = reading.owner, reading.source
		}
	case err != nil:
		return storedDocIntent{}, err
	case kind != "document" && refusal == nil:
		// Decided as a new version of what the key holds, then refused.
		refusal = fmt.Errorf("%w: the key holds an object", ErrConflict)
	}
	docLabel, _ := in.attributes["label"].(string)
	docKind, _ := in.attributes["kind"].(string)
	types := unitsOf(docKind)
	if (r.Collection != (docKind == "collection") || types == textEntries && r.Original) && refusal == nil {
		refusal = fmt.Errorf("%w: a key keeps its kind, and a collection has no original", ErrInvalid)
	}
	if types == textEntries && !in.newDocument && r.BaseVersion == "" && refusal == nil &&
		slices.ContainsFunc(r.Units, func(u DocumentUnitSpec) bool { return u.ReuseUnit != "" }) {
		refusal = fmt.Errorf("%w: a collection version that keeps entries names the version it extends", ErrInvalid)
	}
	op, ch := docChecks(in, registry.OpDocBeginCreate, registry.OpDocBeginVersion)
	_, rec, err := s.decide(ctx, c, op, Audience, true, []check{ch})
	if err != nil {
		return storedDocIntent{}, err
	}
	if refusal != nil {
		return storedDocIntent{}, refusal
	}
	var reused []UnitIntent
	for i, u := range r.Units {
		if u.ReuseUnit != "" {
			reused = append(reused, UnitIntent{Position: i, Unit: u.ReuseUnit, Reused: true})
		}
	}
	if err := s.decideReuse(ctx, c, types, reused); err != nil {
		return storedDocIntent{}, err
	}
	for i, u := range r.Units {
		ui := UnitIntent{Position: i, Label: u.Label}
		switch {
		case u.ReuseUnit != "":
			if u.Label != "" {
				return storedDocIntent{}, fmt.Errorf("%w: a reused unit keeps its label", ErrInvalid)
			}
			if ui, err = s.reusable(ctx, c.Tenant, i, u, types.typ, mode); err != nil {
				return storedDocIntent{}, err
			}
		default:
			if u.Label != "" && types == textEntries {
				return storedDocIntent{}, fmt.Errorf("%w: entries take their collection's label", ErrInvalid)
			}
			if u.Label != "" {
				if err := s.labelAllowed(ctx, u.Label, b.Label); err != nil {
					return storedDocIntent{}, err
				}
			}
			// A group's label is checked for every reading (ING-006).
			if reading != nil {
				if err := s.labelAllowed(ctx, reading.labels[i], b.Label); err != nil {
					return storedDocIntent{}, err
				}
			}
			ui.IntentID, ui.Unit, ui.UnitVersion = cryptowire.NewUUID().String(), cryptowire.NewUUID().String(), cryptowire.NewUUID().String()
			ui.CryptoVersion, ui.Blob, ui.Attempt = cryptowire.NewUUID().String(), cryptowire.NewUUID().String(), cryptowire.NewUUID().String()
		}
		in.Units = append(in.Units, ui)
	}
	if r.Original {
		in.Original = &UnitIntent{Position: -1, IntentID: cryptowire.NewUUID().String(), Unit: cryptowire.NewUUID().String(),
			UnitVersion: cryptowire.NewUUID().String(), CryptoVersion: cryptowire.NewUUID().String(), Blob: cryptowire.NewUUID().String(),
			Attempt: cryptowire.NewUUID().String()}
	}
	// Each route publishes in its own mode only (ENC-002), and only the
	// source routes begin in a source's bucket (ING-002).
	if b.Encryption != mode {
		return storedDocIntent{}, ErrEncryptionMode
	}
	if err := sourceBound(b, in.attributes, reading); err != nil {
		return storedDocIntent{}, err
	}
	versionAttrs := map[string]any{"document": in.Document}
	for _, k := range []string{"bucket", "owner", "project", "label", "kind", "encryption"} {
		versionAttrs[k] = in.attributes[k]
	}
	if reading != nil {
		versionAttrs["source"], versionAttrs["source_version"] = reading.source, reading.version
	}
	va, _ := json.Marshal(versionAttrs)
	units, _ := json.Marshal(in.Units)
	var original []byte
	if in.Original != nil {
		original, _ = json.Marshal(in.Original)
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := modeHolds(ctx, tx, c.Tenant, b); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO document_intents (tenant, id, principal, idempotency_key, request_digest, bucket, key, document, new_document,
			  document_version, expected_generation, planned_scope, planned_attributes, units, state, expires_at, created_at, original,
			  encryption)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'RESERVED',$15,$16,$17,$18)`,
			c.Tenant, in.IntentID, c.Principal, r.IdempotencyKey, in.requestDigest, b.ID, r.Key, in.Document, in.newDocument,
			in.DocumentVersion, in.expectedGen, in.scope, va, units, in.ExpiresAt, s.d.Now(), original, in.encryption)
		if isUnique(err) {
			return fmt.Errorf("%w: the idempotency key is in use", ErrConflict)
		}
		if err != nil {
			return err
		}
		if o := in.Original; o != nil {
			if _, err := tx.Exec(ctx, `
				INSERT INTO upload_intents (tenant, id, principal, actor, idempotency_key, request_digest, bucket, key, object, new_object,
				  version, crypto_version, blob, attempt, expected_generation, planned_scope, planned_attributes, state, expires_at,
				  created_at, kind, document_intent, encryption)
				VALUES ($1,$2,$3,$3,$4,$5,$6,'',$7,true,$8,$9,$10,$11,0,$12,$13,'RESERVED',$14,$15,'original',$16,$17)`,
				c.Tenant, o.IntentID, c.Principal, "document-intent:"+in.IntentID+":original", in.requestDigest, b.ID,
				o.Unit, o.UnitVersion, o.CryptoVersion, o.Blob, o.Attempt, in.scope, va, in.ExpiresAt, s.d.Now(), in.IntentID,
				in.encryption); err != nil {
				return err
			}
		}
		for _, u := range in.Units {
			if u.Reused {
				continue
			}
			attrs := map[string]any{"document": in.Document, "label": docLabel}
			for _, k := range []string{"bucket", "owner", "project", "encryption"} {
				attrs[k] = in.attributes[k]
			}
			if u.Label != "" {
				attrs["label"] = u.Label
			}
			if types == textEntries {
				attrs["entry"] = true
			}
			// A reading's unit is its group's: the group's label, set
			// as a default is, without a label decision (ING-006, D-B).
			if reading != nil {
				attrs["label"], attrs["group"], attrs["source"] = reading.labels[u.Position], reading.groups[u.Position], reading.source
			}
			ua, _ := json.Marshal(attrs)
			if _, err := tx.Exec(ctx, `
				INSERT INTO upload_intents (tenant, id, principal, actor, idempotency_key, request_digest, bucket, key, object, new_object,
				  version, crypto_version, blob, attempt, expected_generation, planned_scope, planned_attributes, state, expires_at,
				  created_at, label, kind, document_intent, encryption)
				VALUES ($1,$2,$3,$3,$4,$5,$6,'',$7,true,$8,$9,$10,$11,0,$12,$13,'RESERVED',$14,$15,$16,'unit',$17,$18)`,
				c.Tenant, u.IntentID, c.Principal, "document-intent:"+in.IntentID+":"+strconv.Itoa(u.Position), in.requestDigest, b.ID,
				u.Unit, u.UnitVersion, u.CryptoVersion, u.Blob, u.Attempt, in.scope, ua, in.ExpiresAt, s.d.Now(), u.Label, in.IntentID,
				in.encryption); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return storedDocIntent{}, err
	}
	in.state = "RESERVED"
	return in, nil
}

// reusable returns the unit intent of an existing LIVE unit version of the
// tenant.
func (s *Service) reusable(ctx context.Context, tenant string, position int, u DocumentUnitSpec, typ, mode string) (UnitIntent, error) {
	ui := UnitIntent{Position: position, Unit: u.ReuseUnit, UnitVersion: u.ReuseVersion, Reused: true}
	err := s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT v.crypto_version::text, v.blob::text, v.ciphertext_sha256, v.ciphertext_length FROM object_versions v
		  JOIN objects o ON o.tenant = v.tenant AND o.id = v.object
		  JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text AND r.type = $4
		 WHERE v.tenant = $1 AND o.id::text = $2 AND v.id::text = $3 AND o.kind = 'unit' AND v.state = 'LIVE'
		   AND v.encryption = $5`,
		tenant, u.ReuseUnit, u.ReuseVersion, typ, mode).Scan(&ui.CryptoVersion, &ui.Blob, &ui.CiphertextSHA256, &ui.CiphertextLength)
	if errors.Is(err, pgx.ErrNoRows) {
		return ui, ErrNotFound
	}
	return ui, err
}

// decideReuse decides read on every unit a document intent reuses, before
// begin returns their ciphertext metadata (review v5 F06); finalize
// decides the same checks with the publication.
func (s *Service) decideReuse(ctx context.Context, c Caller, types unitTypes, units []UnitIntent) error {
	var groups [][]check
	for _, u := range units {
		if u.Reused {
			groups = append(groups, reuseCheck(strconv.Itoa(u.Position), u.Unit, types))
		}
	}
	for _, batch := range batches(groups, maxBatch) {
		_, rec, err := s.decide(ctx, c, types.reuseOp, Audience, false, batch)
		if err != nil {
			return err
		}
		if err := s.checked(ctx, rec); err != nil {
			return err
		}
	}
	return nil
}

// reuseCheck is the check that the caller may read a reused unit.
func reuseCheck(n, unit string, types unitTypes) []check {
	return []check{{id: "unit-" + n, role: registry.RoleUnit, action: "read", ref: canonical(types.typ, unit)}}
}

// docChecks is the check on the document: create-object on the bucket for
// a new key, new-version on the document otherwise. A reading's steps are
// the operations' reading twins, which decide post-reading on the same
// resources, so no rule for uploads or owners reaches a post (ING-012).
func docChecks(in storedDocIntent, create, version string) (string, check) {
	createAction, versionAction := "create-object", "new-version"
	if in.post {
		create, version = registry.ReadingOp(create), registry.ReadingOp(version)
		createAction, versionAction = "post-reading", "post-reading"
	}
	if in.newDocument {
		return create, check{id: "bucket", role: registry.RoleBucket, action: createAction, ref: canonical("storage.bucket", in.bucket.String())}
	}
	return version, check{id: "document", role: registry.RoleDocument, action: versionAction, ref: canonical("storage.object", in.Document)}
}

func (s *Service) docIntentByIdempotency(ctx context.Context, c Caller, key string) (storedDocIntent, error) {
	var id string
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT id::text FROM document_intents WHERE tenant = $1 AND principal = $2 AND idempotency_key = $3`,
		c.Tenant, c.Principal, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedDocIntent{}, ErrNotFound
	}
	if err != nil {
		return storedDocIntent{}, err
	}
	return s.docIntent(ctx, s.d.Catalog.Pool(), c, id, false)
}

// docIntent loads a document intent owned by the caller.
func (s *Service) docIntent(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, c Caller, id string, lock bool) (storedDocIntent, error) {
	var in storedDocIntent
	var units, attrs []byte
	sql := `SELECT d.id::text, t.id::text, d.document::text, d.document_version::text, d.units, d.expires_at, d.principal, d.request_digest,
	               d.state, d.bucket, d.key, d.new_document, d.expected_generation, d.planned_scope, d.planned_attributes,
	               coalesce(d.result::text, ''), coalesce(d.original::text, ''), d.encryption
	          FROM document_intents d JOIN tenants t ON t.name = d.tenant
	         WHERE d.tenant = $1 AND d.id::text = $2 AND d.principal = $3`
	if lock {
		sql += ` FOR UPDATE OF d`
	}
	var result, original string
	err := q.QueryRow(ctx, sql, c.Tenant, id, c.Principal).Scan(&in.IntentID, &in.Tenant, &in.Document, &in.DocumentVersion, &units,
		&in.ExpiresAt, &in.principal, &in.requestDigest, &in.state, &in.bucket, &in.key, &in.newDocument, &in.expectedGen, &in.scope, &attrs, &result,
		&original, &in.encryption)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, ErrNotFound
	}
	if err != nil {
		return in, err
	}
	in.MaxCiphertext, in.result = s.d.Limits.MaxCiphertext, []byte(result)
	if original != "" {
		if err := json.Unmarshal([]byte(original), &in.Original); err != nil {
			return in, err
		}
	}
	if err := json.Unmarshal(units, &in.Units); err != nil {
		return in, err
	}
	if err := json.Unmarshal(attrs, &in.attributes); err != nil {
		return in, err
	}
	// Only a reading's begin plans the source attribute (ING-012).
	_, in.post = in.attributes["source"]
	return in, nil
}

// UnitFinal is one unit's signed descriptor and initial envelopes.
type UnitFinal struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelopes           []EnvelopeIn
}

// DocumentFinalizeRequest carries the signed manifest and, in manifest
// order, every unit's descriptor and envelopes.
type DocumentFinalizeRequest struct {
	Manifest          []byte
	ManifestSignature string
	Units             []UnitFinal
	// Original is the original file's object descriptor (fga.descriptor/v1)
	// and profile-2 envelopes, when the intent reserved one.
	Original *UnitFinal
}

// DocumentPublished is the result of a document commit.
type DocumentPublished struct {
	Document        string `json:"document_id"`
	DocumentVersion string `json:"document_version_id"`
	ManifestDigest  string `json:"manifest_digest"`
	Generation      uint64 `json:"generation"`
	Units           int    `json:"units"`
}

type checkedUnit struct {
	UnitIntent
	staged     storedIntent
	descriptor cryptowire.UnitDescriptor
	envs       []checkedEnvelope
}

// FinalizeDocument publishes a reserved document version (DOC-001 to
// DOC-003, PUB-003): it verifies the manifest and every descriptor and
// envelope against the intent and the staged receipts, obtains decisions
// for the document, explicit unit labels, reused units, the document
// version per recipient, and each unit per recipient, and commits all of
// it at once. If anything is missing nothing is visible (V-063). A
// finalize that already committed returns its stored result while the
// caller may still discover the version.
func (s *Service) FinalizeDocument(ctx context.Context, c Caller, intentID string, r DocumentFinalizeRequest) (DocumentPublished, error) {
	in, err := s.docIntent(ctx, s.d.Catalog.Pool(), c, intentID, false)
	if err != nil {
		return DocumentPublished{}, err
	}
	if in.state == "COMMITTED" {
		var p DocumentPublished
		if err := json.Unmarshal(in.result, &p); err != nil {
			return DocumentPublished{}, fmt.Errorf("%w: stored result", ErrUnavailable)
		}
		_, rec, err := s.decide(ctx, c, registry.OpDocDiscover, Audience, false,
			[]check{{id: "version", role: registry.RoleVersion, action: "discover", ref: canonical("document.version", in.DocumentVersion)}})
		if err != nil {
			return DocumentPublished{}, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return DocumentPublished{}, err
		}
		return p, nil
	}
	if in.state != "RESERVED" || !s.d.Now().Before(in.ExpiresAt) {
		return DocumentPublished{}, fmt.Errorf("%w: document intent is %s or expired", ErrConflict, in.state)
	}
	if in.encryption == "server" {
		return s.finalizeDocumentServer(ctx, c, in, r)
	}
	if len(r.Units) != len(in.Units) {
		return DocumentPublished{}, fmt.Errorf("%w: one descriptor per unit", ErrInvalid)
	}
	manifest, digest, signer, err := s.checkManifest(ctx, c, in, r)
	if err != nil {
		return DocumentPublished{}, err
	}
	units, err := s.checkUnits(ctx, c, in, r, digest, signer)
	if err != nil {
		return DocumentPublished{}, err
	}
	if in.post {
		if err := s.readingEnvelopes(ctx, c.Tenant, in, manifest, units); err != nil {
			return DocumentPublished{}, err
		}
	}
	original, err := s.checkOriginal(ctx, c, in, r, digest, signer)
	if err != nil {
		return DocumentPublished{}, err
	}
	recs, err := s.documentDecisions(ctx, c, in, units, original, digest)
	if err != nil {
		return DocumentPublished{}, err
	}
	return s.commitDocument(ctx, c, in, r, manifest, digest, signer, units, original, recs)
}

// checkManifest verifies the manifest's signature by an active signing key
// of the caller and that it names exactly the intent's document version
// and units in order, with the staged or reused ciphertext of each.
func (s *Service) checkManifest(ctx context.Context, c Caller, in storedDocIntent, r DocumentFinalizeRequest) (cryptowire.Manifest, cryptowire.Digest, string, error) {
	signer := ""
	if _, err := cryptowire.Verify(cryptowire.TypeManifest, r.ManifestSignature, r.Manifest, func(kid string) (ed25519.PublicKey, error) {
		pub, err := s.signerActive(ctx, c.Tenant, c.Principal, kid)
		signer = kid
		return pub, err
	}); err != nil {
		return cryptowire.Manifest{}, cryptowire.Digest{}, "", fmt.Errorf("%w: manifest signature", ErrInvalid)
	}
	m, err := cryptowire.ParseManifest(r.Manifest)
	if err != nil || m.TenantID != in.Tenant || m.DocumentID != in.Document || m.DocumentVersionID != in.DocumentVersion ||
		(m.Original == nil) != (in.Original == nil) || (r.Original == nil) != (in.Original == nil) || len(m.Units) != len(in.Units) {
		return cryptowire.Manifest{}, cryptowire.Digest{}, "", fmt.Errorf("%w: manifest does not match the intent", ErrInvalid)
	}
	for i, u := range in.Units {
		e := m.Units[i]
		if e.UnitID != u.Unit || e.UnitVersionID != u.UnitVersion || e.CryptoVersionID != u.CryptoVersion {
			return cryptowire.Manifest{}, cryptowire.Digest{}, "", fmt.Errorf("%w: manifest unit %d", ErrInvalid, i)
		}
	}
	return m, cryptowire.ManifestDigest(r.Manifest), signer, nil
}

// checkUnits verifies each unit: a new unit's staged receipt, every unit's
// descriptor (signed by the manifest's signer, bound to this document
// version and manifest) and its profile-2 envelopes.
func (s *Service) checkUnits(ctx context.Context, c Caller, in storedDocIntent, r DocumentFinalizeRequest, digest cryptowire.Digest, signer string) ([]checkedUnit, error) {
	signerPub, err := s.signerActive(ctx, c.Tenant, c.Principal, signer)
	if err != nil {
		return nil, err
	}
	keyFor := func(kid string) (ed25519.PublicKey, error) {
		if kid != signer {
			return nil, errors.New("signed by another key")
		}
		return signerPub, nil
	}
	tenant, _ := cryptowire.ParseUUID(in.Tenant)
	docID, _ := cryptowire.ParseUUID(in.Document)
	dvID, _ := cryptowire.ParseUUID(in.DocumentVersion)
	var out []checkedUnit
	for i, u := range in.Units {
		f := r.Units[i]
		cu := checkedUnit{UnitIntent: u}
		sum, length := u.CiphertextSHA256, u.CiphertextLength
		if !u.Reused {
			id, _ := cryptowire.ParseUUID(u.IntentID)
			st, err := s.intent(ctx, s.d.Catalog.Pool(), c, id, false)
			if err != nil {
				return nil, err
			}
			if st.state != "STAGED" {
				return nil, fmt.Errorf("%w: unit %d is %s", ErrConflict, i, st.state)
			}
			if err := s.stagedBlob(st); err != nil {
				return nil, err
			}
			cu.staged, sum, length = st, st.ciphertextSHA256, st.ciphertextLength
		}
		if _, err := cryptowire.Verify(cryptowire.TypeUnitDescriptor, f.DescriptorSignature, f.Descriptor, keyFor); err != nil {
			return nil, fmt.Errorf("%w: unit %d descriptor signature", ErrInvalid, i)
		}
		d, err := cryptowire.ParseUnitDescriptor(f.Descriptor)
		if err != nil || d.TenantID != in.Tenant || d.DocumentID != in.Document || d.DocumentVersionID != in.DocumentVersion ||
			d.ManifestDigest != digest.String() || d.UnitID != u.Unit || d.UnitVersionID != u.UnitVersion || d.CryptoVersionID != u.CryptoVersion ||
			d.BlobID != u.Blob || d.CiphertextSHA256 != sum || int64(d.CiphertextLength) != length || d.Signer != signer ||
			d.KeyCommitment == "" {
			return nil, fmt.Errorf("%w: unit %d descriptor does not match, or commits to no key", ErrInvalid, i)
		}
		cu.descriptor = d
		if len(f.Envelopes) == 0 || len(f.Envelopes) > s.d.Limits.MaxEnvelopes {
			return nil, ErrInvalid
		}
		seen := map[cryptowire.Digest]bool{}
		for _, e := range f.Envelopes {
			if len(e.Ciphertext) == 0 || len(e.Ciphertext) > cryptowire.MaxHPKECiphertext {
				return nil, ErrInvalid
			}
			ctxv, err := cryptowire.ParseEnvelopeContext(e.Context)
			if err != nil || ctxv.Profile() != 2 {
				return nil, fmt.Errorf("%w: unit %d envelope context", ErrInvalid, i)
			}
			if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, e.Signature, cryptowire.EnvelopeSigningInput(e.Context, e.Ciphertext), keyFor); err != nil {
				return nil, fmt.Errorf("%w: unit %d envelope signature", ErrInvalid, i)
			}
			if ctxv.Tenant != tenant || ctxv.Object.String() != u.Unit || ctxv.LogicalVersion.String() != u.UnitVersion ||
				ctxv.CryptoVersion.String() != u.CryptoVersion || ctxv.CiphertextSHA256.String() != sum || int64(ctxv.CiphertextLength) != length ||
				ctxv.Document != docID || ctxv.DocumentVersion != dvID || ctxv.ManifestDigest != digest || ctxv.Sharer.String() != signer ||
				ctxv.Generation != 1 || seen[ctxv.Recipient] {
				return nil, fmt.Errorf("%w: unit %d envelope bindings", ErrInvalid, i)
			}
			seen[ctxv.Recipient] = true
			keyVersion, err := s.recipientKey(ctx, c.Tenant, ctxv.Recipient.String())
			if err != nil {
				return nil, err
			}
			if keyVersion != ctxv.RecipientKeyVersion {
				return nil, fmt.Errorf("%w: recipient key version", ErrInvalid)
			}
			cu.envs = append(cu.envs, checkedEnvelope{EnvelopeIn: e, id: cryptowire.NewUUID(), ctx: ctxv, keyVersion: keyVersion,
				digest: cryptowire.EnvelopeDigest(e.Context, e.Ciphertext)})
		}
		out = append(out, cu)
	}
	return out, nil
}

// maxBatch is the most checks one decision request carries (DEC-009).
const maxBatch = 50

// documentDecisions obtains every decision of a publication, each check
// group kept within one batch.
func (s *Service) documentDecisions(ctx context.Context, c Caller, in storedDocIntent, units []checkedUnit, original *checkedUnit,
	digest cryptowire.Digest) ([]signing.Record, error) {
	// The document's own decision carries the plan, so a policy can make
	// publication subject to an approval (APR-001, APR-005); the plan names
	// the exact version, manifest and recipients.
	op, ch := docChecks(in, registry.OpDocPublishCreate, registry.OpDocPublishVersion)
	plan := opplan.Summary{Action: ch.action, Changes: map[string]string{"manifest": digest.String(), "units": strconv.Itoa(len(units))},
		Details: details(map[string]string{"key": in.key})}
	if in.newDocument {
		plan.Targets = []opplan.Target{{Role: registry.RoleBucket, Type: "storage.bucket", ID: in.bucket.String()},
			{Role: registry.RoleDocument, Type: "storage.object", ID: in.Document, Version: in.DocumentVersion}}
	} else {
		plan.Targets = []opplan.Target{{Role: registry.RoleDocument, Type: "storage.object", ID: in.Document, Version: in.DocumentVersion}}
	}
	targets := map[string]bool{}
	for _, u := range units {
		for _, e := range u.envs {
			targets[e.ctx.Recipient.String()] = true
		}
	}
	plan.Changes["recipients"] = strings.Join(slices.Sorted(maps.Keys(targets)), ",")
	rec, err := s.decidePlanned(ctx, c, op, []check{ch}, plan)
	if err != nil {
		return nil, err
	}
	recs := []signing.Record{rec}
	kind, _ := in.attributes["kind"].(string)
	types := unitsOf(kind)
	unitRef := func(u checkedUnit) (string, decisionsvc.Alias) {
		if u.Reused {
			return u.Unit, canonical(types.typ, u.Unit)
		}
		return "intent:" + u.IntentID, planned(registry.PlannedObject, u.IntentID)
	}
	var labels, reuse, versions, shares, originals [][]check
	recipients := map[string]bool{}
	for i, u := range units {
		n := strconv.Itoa(i)
		name, ref := unitRef(u)
		switch {
		case u.Reused:
			reuse = append(reuse, reuseCheck(n, u.Unit, types))
		case u.Label != "":
			labels = append(labels, []check{{id: "label-" + n, role: registry.RoleLabel, action: "label", ref: ref}})
		}
		for j, e := range u.envs {
			fp, m := e.ctx.Recipient.String(), n+"-"+strconv.Itoa(j)
			recipients[fp] = true
			shares = append(shares, []check{
				{id: "share-" + m, role: registry.RoleShare, action: types.write, ref: ref},
				{id: "envelope-" + m, role: registry.RoleEnvelope, action: "create", ref: planned(registry.PlannedEnvelope, name+"|"+fp+"|"+e.id.String())},
				{id: "recipient-read-" + m, role: registry.RoleRecipientRead, action: "read", ref: ref, recipient: fp},
				{id: "recipient-key-" + m, role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", fp), recipient: fp},
			})
		}
	}
	version := planned(registry.PlannedDocumentVersion, in.IntentID)
	fps := make([]string, 0, len(recipients))
	for fp := range recipients {
		fps = append(fps, fp)
	}
	slices.Sort(fps)
	for i, fp := range fps {
		n := strconv.Itoa(i)
		versions = append(versions, []check{
			{id: "share-" + n, role: registry.RoleShare, action: "share", ref: version},
			{id: "recipient-read-units-" + n, role: registry.RoleRecipientRead, action: "read-units", ref: version, recipient: fp},
		})
	}
	if original != nil {
		for j, e := range original.envs {
			fp, n := e.ctx.Recipient.String(), strconv.Itoa(j)
			originals = append(originals, []check{
				{id: "share-" + n, role: registry.RoleShare, action: "share", ref: version},
				{id: "envelope-" + n, role: registry.RoleEnvelope, action: "create",
					ref: planned(registry.PlannedEnvelope, "docintent:"+in.IntentID+"|"+fp+"|"+e.id.String())},
				{id: "recipient-raw-read-" + n, role: registry.RoleRecipientVersion, action: "raw-read", ref: version, recipient: fp},
				{id: "recipient-key-" + n, role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", fp), recipient: fp},
			})
		}
	}
	for _, g := range []struct {
		op     string
		groups [][]check
	}{{registry.OpDocLabelUnits, labels}, {types.reuseOp, reuse}, {registry.OpDocShareVersion, versions}, {types.shareOp, shares},
		{registry.OpDocShareOriginal, originals}} {
		for _, batch := range batches(g.groups, maxBatch) {
			_, rec, err := s.decide(ctx, c, g.op, Audience, true, batch)
			if err != nil {
				return nil, err
			}
			recs = append(recs, rec)
		}
	}
	return recs, nil
}

// batches packs check groups into batches of at most max checks, never
// splitting a group.
func batches(groups [][]check, max int) [][]check {
	var out [][]check
	var cur []check
	for _, g := range groups {
		if len(cur)+len(g) > max {
			out, cur = append(out, cur), nil
		}
		cur = append(cur, g...)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// commitDocument publishes everything under the authority fence in one
// transaction (DOC-002, PUB-003): the document (new or next generation),
// the document version, new unit versions, membership, envelopes and the
// document head; reused unit versions must still be LIVE.
func (s *Service) commitDocument(ctx context.Context, c Caller, in storedDocIntent, r DocumentFinalizeRequest, m cryptowire.Manifest,
	digest cryptowire.Digest, signer string, units []checkedUnit, original *checkedUnit, recs []signing.Record) (DocumentPublished, error) {
	bindings := make([]fence.Binding, 0, len(recs))
	for _, rec := range recs {
		b, err := fence.FromRecord(rec)
		if err != nil {
			return DocumentPublished{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		bindings = append(bindings, b)
	}
	mutate := []string{in.Document}
	var result DocumentPublished
	err := mapFence(s.d.Fence.RunAll(ctx, bindings, mutate, func(ctx context.Context, tx pgx.Tx) error {
		now := s.d.Now()
		// A server-mode version has no client signature (ENC-002).
		server := in.encryption == "server"
		if !server {
			if err := catalog.SignerActiveTx(ctx, tx, c.Tenant, c.Principal, signer); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalid, err)
			}
		}
		var manifestSig, signerArg any = r.ManifestSignature, signer
		if server {
			manifestSig, signerArg = nil, nil
		}
		locked, err := s.docIntent(ctx, tx, c, in.IntentID, true)
		if err != nil {
			return err
		}
		if locked.state != "RESERVED" || !now.Before(locked.ExpiresAt) {
			return fmt.Errorf("%w: document intent is %s or expired", ErrConflict, locked.state)
		}
		for _, u := range units {
			if u.Label != "" {
				if err := s.labelOrderHolds(ctx, tx, recs[0], u.Label, in.bucket); err != nil {
					return err
				}
			}
		}
		var generation uint64
		if in.newDocument {
			// The document's own attributes: the intent's, without the
			// version's link to its document.
			docAttrs := maps.Clone(in.attributes)
			delete(docAttrs, "document")
			delete(docAttrs, "source_version")
			attrs, _ := json.Marshal(docAttrs)
			if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'storage.object', $3, 1, 1, 1, $4)`, c.Tenant, in.Document, in.scope, attrs); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key, kind) VALUES ($1, $2, $3, $4, 'document')`, c.Tenant, in.Document, in.bucket, in.key)
			if isUnique(err) {
				return fmt.Errorf("%w: the key was created concurrently", ErrConflict)
			}
			if err != nil {
				return err
			}
			generation = 1
		} else if err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1, version = version + 1
		                                    WHERE tenant = $1 AND id = $2 AND generation = $3 RETURNING generation`,
			c.Tenant, in.Document, in.expectedGen).Scan(&generation); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: the document changed since begin", ErrConflict)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO document_versions (tenant, id, document, manifest, manifest_signature, manifest_digest, signer, extraction_version,
			                               normalization_version, state, created_at, encryption)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'LIVE', $10, $11)`,
			c.Tenant, in.DocumentVersion, in.Document, r.Manifest, manifestSig, digest.String(), signerArg, m.ExtractionVersion,
			m.NormalizationVersion, now, in.encryption); err != nil {
			return err
		}
		// The same protected attributes as the planned version, the
		// bucket's encryption mode included (ENC-001, review v3 F08).
		versionAttrs := map[string]any{"document": in.Document}
		for _, k := range []string{"bucket", "owner", "project", "label", "kind", "encryption"} {
			versionAttrs[k] = in.attributes[k]
		}
		// A reading's version names its source and the source version
		// it was split under (ING-006).
		for _, k := range []string{"source", "source_version"} {
			if v, ok := in.attributes[k]; ok {
				versionAttrs[k] = v
			}
		}
		// The server's publication time, in RFC 3339 UTC, for policies that
		// bound history by time (DOC-011, D-E).
		versionAttrs["published_at"] = now.UTC().Format(time.RFC3339Nano)
		va, _ := json.Marshal(versionAttrs)
		if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'document.version', $3, 1, 1, 1, $4)`, c.Tenant, in.DocumentVersion, in.scope, va); err != nil {
			return err
		}
		dv, _ := cryptowire.ParseUUID(in.DocumentVersion)
		docKind, _ := in.attributes["kind"].(string)
		unitType := unitsOf(docKind).typ
		targets := []audit.Target{{Type: "document.version", ID: in.DocumentVersion, Signer: signer, Digest: digest.String()}}
		for i, u := range units {
			unitID, _ := cryptowire.ParseUUID(u.Unit)
			versionID, _ := cryptowire.ParseUUID(u.UnitVersion)
			attrs := u.staged.attributes
			if u.Reused {
				var state string
				if err := tx.QueryRow(ctx, `SELECT v.state, r.attributes FROM object_versions v JOIN resources r ON r.tenant = v.tenant AND r.id = v.object::text
				                             WHERE v.tenant = $1 AND v.id = $2 FOR SHARE OF v`, c.Tenant, versionID).Scan(&state, &attrs); err != nil {
					return err
				}
				if state != "LIVE" {
					return fmt.Errorf("%w: reused unit %d is no longer live", ErrConflict, i)
				}
			} else if err := s.publishUnit(ctx, tx, c, u, r.Units[i], unitType, now); err != nil {
				return err
			}
			var descriptor, descriptorSig any = r.Units[i].Descriptor, r.Units[i].DescriptorSignature
			if server {
				descriptor, descriptorSig = nil, nil
			}
			if _, err := tx.Exec(ctx, `INSERT INTO document_units VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				c.Tenant, in.DocumentVersion, i, u.Unit, u.UnitVersion, descriptor, descriptorSig); err != nil {
				return err
			}
			for _, e := range u.envs {
				if err := envelope.InsertUnitEnvelope(ctx, tx, c.Tenant, in.scope, attrs, e.id, unitID, versionID, &dv, e.ctx, e.keyVersion,
					e.EnvelopeIn, e.digest, now); err != nil {
					return err
				}
			}
			targets = append(targets, audit.Target{Type: unitType, ID: u.Unit, Version: u.UnitVersion, Digest: u.descriptor.CiphertextSHA256})
		}
		if original != nil {
			if err := s.publishOriginal(ctx, tx, c, in, original, *r.Original, &dv, now); err != nil {
				return err
			}
			targets = append(targets, audit.Target{Type: "document.original", ID: original.Unit, Version: original.UnitVersion, Digest: original.staged.ciphertextSHA256})
		}
		if _, err := tx.Exec(ctx, `UPDATE objects SET current_document_version = $3 WHERE tenant = $1 AND id = $2`, c.Tenant, in.Document, in.DocumentVersion); err != nil {
			return err
		}
		result = DocumentPublished{Document: in.Document, DocumentVersion: in.DocumentVersion, ManifestDigest: digest.String(),
			Generation: generation, Units: len(units)}
		stored, _ := json.Marshal(result)
		if _, err := tx.Exec(ctx, `UPDATE document_intents SET state = 'COMMITTED', result = $3 WHERE tenant = $1 AND id = $2`,
			c.Tenant, in.IntentID, stored); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, recs[0], "DOCUMENT_PUBLISHED",
			append([]audit.Target{{Type: "storage.object", ID: in.Document, Generation: generation}}, targets...)...))
	}))
	if err != nil {
		return DocumentPublished{}, err
	}
	return result, nil
}

// publishUnit makes a staged unit LIVE: its object, resource and single
// immutable version, and consumes its intent.
func (s *Service) publishUnit(ctx context.Context, tx pgx.Tx, c Caller, u checkedUnit, f UnitFinal, typ string, now time.Time) error {
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM upload_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, u.staged.IntentID).Scan(&state); err != nil {
		return err
	}
	if state != "STAGED" {
		return fmt.Errorf("%w: unit intent is %s", ErrConflict, state)
	}
	attrs, _ := json.Marshal(u.staged.attributes)
	if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, $5, $3, 1, 1, 1, $4)`, c.Tenant, u.Unit, u.staged.scope, attrs, typ); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key, kind) VALUES ($1, $2, $3, '', 'unit')`, c.Tenant, u.Unit, u.staged.bucket); err != nil {
		return err
	}
	d := u.descriptor
	if u.staged.encryption == "server" {
		// The unit's sealed data key moves from its intent to its version
		// (SSE-002); there is no client descriptor.
		if _, err := tx.Exec(ctx, `
			INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
			                             created_at, published_at, encryption, sealed_key, kek_version, plaintext_length)
			SELECT $1, $2, $3, $4, $5, 'LIVE', i.ciphertext_length, i.ciphertext_sha256, $6, $7, $8, $8, 'server', i.sealed_key, i.kek_version,
			       i.plaintext_length
			  FROM upload_intents i WHERE i.tenant = $1 AND i.id = $9 AND i.sealed_key IS NOT NULL AND i.plaintext_length IS NOT NULL`,
			c.Tenant, u.UnitVersion, u.Unit, u.CryptoVersion, u.Blob, int(payload.Suite), int(payload.Format), now, u.staged.IntentID); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `
		INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
		                             signer, descriptor, descriptor_signature, created_at, published_at, encryption)
		VALUES ($1, $2, $3, $4, $5, 'LIVE', $6, $7, $8, $9, $10, $11, $12, $13, $13, $14)`,
		c.Tenant, u.UnitVersion, u.Unit, u.CryptoVersion, u.Blob, int64(d.CiphertextLength), d.CiphertextSHA256, int(d.Suite), int(d.Format),
		d.Signer, f.Descriptor, f.DescriptorSignature, now, u.staged.encryption); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE objects SET current_version = $3 WHERE tenant = $1 AND id = $2`, c.Tenant, u.Unit, u.UnitVersion); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'COMMITTED' WHERE tenant = $1 AND id = $2`, c.Tenant, u.staged.IntentID)
	return err
}

// checkOriginal verifies the original file's staged receipt, its object
// descriptor (signed by the manifest's signer and matching the manifest's
// original entry) and its profile-2 envelopes. It returns nil when the
// intent reserved no original.
func (s *Service) checkOriginal(ctx context.Context, c Caller, in storedDocIntent, r DocumentFinalizeRequest, digest cryptowire.Digest, signer string) (*checkedUnit, error) {
	o := in.Original
	if o == nil {
		return nil, nil
	}
	f := *r.Original
	id, _ := cryptowire.ParseUUID(o.IntentID)
	st, err := s.intent(ctx, s.d.Catalog.Pool(), c, id, false)
	if err != nil {
		return nil, err
	}
	if st.state != "STAGED" {
		return nil, fmt.Errorf("%w: the original is %s", ErrConflict, st.state)
	}
	if err := s.stagedBlob(st); err != nil {
		return nil, err
	}
	m, _ := cryptowire.ParseManifest(r.Manifest)
	if mo := m.Original; mo.ObjectID != o.Unit || mo.VersionID != o.UnitVersion || mo.CiphertextSHA256 != st.ciphertextSHA256 ||
		int64(mo.CiphertextLength) != st.ciphertextLength {
		return nil, fmt.Errorf("%w: manifest original", ErrInvalid)
	}
	signerPub, err := s.signerActive(ctx, c.Tenant, c.Principal, signer)
	if err != nil {
		return nil, err
	}
	keyFor := func(kid string) (ed25519.PublicKey, error) {
		if kid != signer {
			return nil, errors.New("signed by another key")
		}
		return signerPub, nil
	}
	if _, err := cryptowire.Verify(cryptowire.TypeDescriptor, f.DescriptorSignature, f.Descriptor, keyFor); err != nil {
		return nil, fmt.Errorf("%w: original descriptor signature", ErrInvalid)
	}
	d, err := cryptowire.ParseDescriptor(f.Descriptor)
	if err != nil || d.TenantID != in.Tenant || d.ObjectID != o.Unit || d.LogicalVersionID != o.UnitVersion || d.CryptoVersionID != o.CryptoVersion ||
		d.BlobID != o.Blob || d.AttemptID != o.Attempt || d.CiphertextSHA256 != st.ciphertextSHA256 || int64(d.CiphertextLength) != st.ciphertextLength ||
		d.Signer != signer || d.KeyCommitment == "" {
		return nil, fmt.Errorf("%w: original descriptor does not match, or commits to no key", ErrInvalid)
	}
	cu := &checkedUnit{UnitIntent: *o, staged: st}
	tenant, _ := cryptowire.ParseUUID(in.Tenant)
	docID, _ := cryptowire.ParseUUID(in.Document)
	dvID, _ := cryptowire.ParseUUID(in.DocumentVersion)
	if len(f.Envelopes) == 0 || len(f.Envelopes) > s.d.Limits.MaxEnvelopes {
		return nil, ErrInvalid
	}
	seen := map[cryptowire.Digest]bool{}
	for _, e := range f.Envelopes {
		ctxv, err := cryptowire.ParseEnvelopeContext(e.Context)
		if err != nil || ctxv.Profile() != 2 || len(e.Ciphertext) == 0 || len(e.Ciphertext) > cryptowire.MaxHPKECiphertext {
			return nil, fmt.Errorf("%w: original envelope", ErrInvalid)
		}
		if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, e.Signature, cryptowire.EnvelopeSigningInput(e.Context, e.Ciphertext), keyFor); err != nil {
			return nil, fmt.Errorf("%w: original envelope signature", ErrInvalid)
		}
		if ctxv.Tenant != tenant || ctxv.Object.String() != o.Unit || ctxv.LogicalVersion.String() != o.UnitVersion ||
			ctxv.CryptoVersion.String() != o.CryptoVersion || ctxv.CiphertextSHA256.String() != st.ciphertextSHA256 ||
			int64(ctxv.CiphertextLength) != st.ciphertextLength || ctxv.Document != docID || ctxv.DocumentVersion != dvID ||
			ctxv.ManifestDigest != digest || ctxv.Sharer.String() != signer || ctxv.Generation != 1 || seen[ctxv.Recipient] {
			return nil, fmt.Errorf("%w: original envelope bindings", ErrInvalid)
		}
		seen[ctxv.Recipient] = true
		keyVersion, err := s.recipientKey(ctx, c.Tenant, ctxv.Recipient.String())
		if err != nil {
			return nil, err
		}
		if keyVersion != ctxv.RecipientKeyVersion {
			return nil, fmt.Errorf("%w: recipient key version", ErrInvalid)
		}
		cu.envs = append(cu.envs, checkedEnvelope{EnvelopeIn: e, id: cryptowire.NewUUID(), ctx: ctxv, keyVersion: keyVersion,
			digest: cryptowire.EnvelopeDigest(e.Context, e.Ciphertext)})
	}
	return cu, nil
}

// publishOriginal makes the staged original LIVE: an objects row of kind
// original without a resource, its single version and its envelopes, and
// links it from the document version.
func (s *Service) publishOriginal(ctx context.Context, tx pgx.Tx, c Caller, in storedDocIntent, o *checkedUnit, f UnitFinal, dv *cryptowire.UUID, now time.Time) error {
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM upload_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, o.staged.IntentID).Scan(&state); err != nil {
		return err
	}
	if state != "STAGED" {
		return fmt.Errorf("%w: the original is %s", ErrConflict, state)
	}
	d, _ := cryptowire.ParseDescriptor(f.Descriptor)
	if _, err := tx.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key, kind) VALUES ($1, $2, $3, '', 'original')`, c.Tenant, o.Unit, in.bucket); err != nil {
		return err
	}
	if o.staged.encryption == "server" {
		// The original's sealed data key moves from its intent to its
		// version (SSE-002); there is no client descriptor.
		if _, err := tx.Exec(ctx, `
			INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
			                             created_at, published_at, encryption, sealed_key, kek_version, plaintext_length)
			SELECT $1, $2, $3, $4, $5, 'LIVE', i.ciphertext_length, i.ciphertext_sha256, $6, $7, $8, $8, 'server', i.sealed_key, i.kek_version,
			       i.plaintext_length
			  FROM upload_intents i WHERE i.tenant = $1 AND i.id = $9 AND i.sealed_key IS NOT NULL AND i.plaintext_length IS NOT NULL`,
			c.Tenant, o.UnitVersion, o.Unit, o.CryptoVersion, o.Blob, int(payload.Suite), int(payload.Format), now, o.staged.IntentID); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `
		INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
		                             signer, descriptor, descriptor_signature, created_at, published_at, encryption)
		VALUES ($1, $2, $3, $4, $5, 'LIVE', $6, $7, $8, $9, $10, $11, $12, $13, $13, $14)`,
		c.Tenant, o.UnitVersion, o.Unit, o.CryptoVersion, o.Blob, int64(d.CiphertextLength), d.CiphertextSHA256, int(d.Suite), int(d.Format),
		d.Signer, f.Descriptor, f.DescriptorSignature, now, o.staged.encryption); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE objects SET current_version = $3 WHERE tenant = $1 AND id = $2`, c.Tenant, o.Unit, o.UnitVersion); err != nil {
		return err
	}
	objectID, _ := cryptowire.ParseUUID(o.Unit)
	versionID, _ := cryptowire.ParseUUID(o.UnitVersion)
	for _, e := range o.envs {
		if err := envelope.InsertUnitEnvelope(ctx, tx, c.Tenant, in.scope, o.staged.attributes, e.id, objectID, versionID, dv, e.ctx, e.keyVersion,
			e.EnvelopeIn, e.digest, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE document_versions SET original = $3, original_version = $4 WHERE tenant = $1 AND id = $2`,
		c.Tenant, in.DocumentVersion, o.Unit, o.UnitVersion); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'COMMITTED' WHERE tenant = $1 AND id = $2`, c.Tenant, o.staged.IntentID)
	return err
}
