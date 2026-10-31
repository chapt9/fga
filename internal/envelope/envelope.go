// Package envelope is the keys role (specification 2.5, KEY-002, KEY-011,
// KEY-012, RCP-001, RCP-002, RCP-005, TRU-005; docs/design/envelope-service.md):
// the registry of recipient keys and the store of opaque, client-created
// recipient envelopes. It authorizes their publication and delivery and
// cannot open them: it links no HPKE or payload-decryption code (MOD-004).
package envelope

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/enforce"
	"fga/internal/fence"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Errors of the service. Like the content service's, they carry no
// protected identifiers.
var (
	ErrInvalid     = errors.New("envelope: invalid request")
	ErrNotFound    = errors.New("envelope: not found")
	ErrConflict    = errors.New("envelope: conflict")
	ErrUnavailable = errors.New("envelope: a dependency is unavailable")
	ErrDecision    = errors.New("envelope: decision does not authorize this delivery")
)

// Deps are the service's collaborators. Every field is required.
type Deps struct {
	Catalog *catalog.Store
	Fence   *fence.Fence
	// Decider obtains decisions for the keys role's own client-facing
	// operations; Verifier verifies decisions for audience fga-keys.
	Decider  enforce.Decider
	Verifier *signing.Verifier
	// ReceiptKey signs delivery receipts; it is used for nothing else
	// (RCP-001).
	ReceiptKeyID string
	ReceiptKey   ed25519.PrivateKey
	// Journal, when set, records revocations before they commit.
	Journal Journal
	Now     func() time.Time
}

// Service is the keys role.
type Service struct {
	d   Deps
	ops *registry.Operations
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Catalog == nil || d.Fence == nil || d.Decider == nil || d.Verifier == nil || d.ReceiptKeyID == "" ||
		len(d.ReceiptKey) != ed25519.PrivateKeySize || d.Now == nil {
		return nil, errors.New("envelope: every dependency is required")
	}
	return &Service{d: d, ops: registry.R1Operations(registry.R1Types())}, nil
}

// Delivered is an envelope released by the keys role, with its signed
// delivery receipt.
type Delivered struct {
	EnvelopeID       string
	Context          []byte
	Ciphertext       []byte
	Signature        string
	Receipt          []byte
	ReceiptSignature string
}

// EnvelopeIn is one recipient envelope as a client sends it.
type EnvelopeIn struct {
	Context    []byte
	Ciphertext []byte
	Signature  string
}

// InsertEnvelope stores an envelope and its crypto.envelope resource. The
// publication transaction of the content service and the keys role's
// PublishRecipientEnvelope both use it, inside their fences.
func InsertEnvelope(ctx context.Context, tx pgx.Tx, tenant, scope string, objectAttrs map[string]any, id, object, version cryptowire.UUID,
	ctxv cryptowire.EnvelopeContext, keyVersion uint64, e EnvelopeIn, digest cryptowire.Digest, now time.Time) error {
	return InsertUnitEnvelope(ctx, tx, tenant, scope, objectAttrs, id, object, version, nil, ctxv, keyVersion, e, digest, now)
}

// InsertUnitEnvelope is InsertEnvelope for a unit envelope, which belongs
// to one document version (profile 2); documentVersion is nil for an
// ordinary object.
func InsertUnitEnvelope(ctx context.Context, tx pgx.Tx, tenant, scope string, objectAttrs map[string]any, id, object, version cryptowire.UUID,
	documentVersion *cryptowire.UUID, ctxv cryptowire.EnvelopeContext, keyVersion uint64, e EnvelopeIn, digest cryptowire.Digest, now time.Time) error {
	var principal string
	if err := tx.QueryRow(ctx, `SELECT principal FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2`, tenant, ctxv.Recipient.String()).Scan(&principal); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO envelopes (tenant, id, object, version, recipient, key_version, generation, context, ciphertext, signature, signer, digest,
		                       status, created_at, document_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'ACTIVE', $13, $14)`,
		tenant, id, object, version, ctxv.Recipient.String(), int64(keyVersion), int64(ctxv.Generation), e.Context, e.Ciphertext, e.Signature,
		ctxv.Sharer.String(), digest.String(), now, documentVersion); err != nil {
		if isUnique(err) {
			return fmt.Errorf("%w: an active envelope exists for this recipient", ErrConflict)
		}
		return err
	}
	attrs := map[string]any{"object": object.String(), "version": version.String(), "recipient": ctxv.Recipient.String(),
		"recipient_principal": principal, "status": "ACTIVE"}
	if documentVersion != nil {
		attrs["document_version"] = documentVersion.String()
	}
	for _, k := range []string{"owner", "project", "label", "bucket"} {
		if v, ok := objectAttrs[k]; ok {
			attrs[k] = v
		}
	}
	b, _ := json.Marshal(attrs)
	_, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'crypto.envelope', $3, 1, 1, 1, $4)`, tenant, id.String(), scope, b)
	return err
}

// exactly reports whether rec's checks are exactly those of the registered
// operation: the same resource types, actions and kinds, each as often as
// registered (TRU-005: the complete result, not a subset).
func (s *Service) exactly(rec signing.Record) bool {
	op, ok := s.ops.Lookup(rec.Operation)
	if !ok {
		return false
	}
	// Each check fills one registered role of its type, action and kind; a
	// role is filled at most once (these operations repeat none), and
	// every role that is not optional is filled.
	used := make([]bool, len(op.Checks))
	for _, c := range rec.Checks {
		matched := false
		for i, spec := range op.Checks {
			if !used[i] && c.ResourceType == spec.ResourceType && c.Action == spec.Action && c.Kind == string(spec.CheckKind()) {
				used[i], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for i, spec := range op.Checks {
		if !used[i] && !spec.Optional {
			return false
		}
	}
	return true
}

type stored struct {
	ID         cryptowire.UUID
	Object     cryptowire.UUID
	Version    cryptowire.UUID
	Recipient  string
	Generation uint64
	Context    []byte
	Ciphertext []byte
	Signature  string
	Signer     string
	Digest     string
	Status     string
	// DocumentVersion is set for a unit envelope (profile 2).
	DocumentVersion *cryptowire.UUID
}

func (s *Service) envelope(ctx context.Context, q catalog.Querier, tenant string, id cryptowire.UUID, lock string) (stored, error) {
	var e stored
	err := q.QueryRow(ctx, `SELECT id, object, version, recipient, generation, context, ciphertext, signature, signer, digest, status, document_version
	                          FROM envelopes WHERE tenant = $1 AND id = $2 `+lock, tenant, id).
		Scan(&e.ID, &e.Object, &e.Version, &e.Recipient, &e.Generation, &e.Context, &e.Ciphertext, &e.Signature, &e.Signer, &e.Digest, &e.Status,
			&e.DocumentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// Deliver releases one stored envelope against a decision signed for the
// keys role whose checks are exactly the GetRecipientEnvelope mapping and
// are bound to this envelope's object, version and recipient (TRU-005,
// KEY-002). Inside the authority fence it consumes the decision, rechecks
// every bound revision and that the version is LIVE and the envelope
// ACTIVE, and records the delivery. It returns the exact stored envelope
// with a signed receipt; it never selects another recipient or creates an
// envelope (RCP-005, KEY-015).
//
// The original file's envelope also needs the complete-content decisions
// (raw-read on the version and read on every unit) as extra, signed for
// the keys role; they must cover every unit of the version and are
// admitted in the same fence, so a change to any unit between the storage
// role's checks and the release is seen (review finding 3).
func (s *Service) Deliver(ctx context.Context, decision signing.Signed, envelopeID string, extra ...signing.Signed) (Delivered, error) {
	rec, err := s.d.Verifier.Check(decision)
	exported := rec.Operation == registry.OpDocExportEnvelope
	objectExport := rec.Operation == registry.OpObjectExportEnvelope
	unit := rec.Operation == registry.OpDocGetUnitEnvelope || rec.Operation == registry.OpDocGetEntryEnvelope || exported
	original := rec.Operation == registry.OpDocGetOriginalEnvelope
	derived := rec.Operation == registry.OpDerivedGetEnvelope
	if err != nil || !rec.SingleUse || (rec.Operation != registry.OpGetEnvelope && rec.Operation != registry.OpGetEnvelopeOld && !unit && !original && !derived &&
		!objectExport) ||
		!s.exactly(rec) {
		return Delivered{}, ErrDecision
	}
	id, err := cryptowire.ParseUUID(envelopeID)
	if err != nil {
		return Delivered{}, ErrInvalid
	}
	e, err := s.envelope(ctx, s.d.Catalog.Pool(), rec.Tenant, id, "")
	if err != nil {
		return Delivered{}, err
	}
	// A unit or original envelope is delivered only for its document
	// operation, bound to its document version, and an object envelope
	// only for the object operations.
	if (unit || original) != (e.DocumentVersion != nil) {
		return Delivered{}, ErrDecision
	}
	for _, c := range rec.Checks {
		var ok bool
		holder := c.Kind == string(registry.KindOperation) || c.PrincipalBinding == e.Recipient
		switch c.ResourceType + " " + c.Action {
		case "crypto.envelope release":
			ok = c.ResourceID == e.ID.String() && c.Version == e.Version.String()
		case "storage.object read", "storage.object read-history":
			ok = !unit && c.ResourceID == e.Object.String() && c.Version == e.Version.String() && holder
		case "document.text_unit read", "text.entry read":
			ok = unit && c.ResourceID == e.Object.String() && c.Version == e.Version.String() && holder
		case "document.version read-units":
			ok = unit && c.ResourceID == e.DocumentVersion.String() && holder
		case "document.version raw-read":
			ok = original && c.ResourceID == e.DocumentVersion.String() && holder
		case "document.version export":
			// Export: the caller's export on the version and export-key on
			// the unit, besides the full envelope check set (V-132 to V-136).
			ok = exported && c.ResourceID == e.DocumentVersion.String() && c.Kind == string(registry.KindOperation)
		case "storage.object export":
			ok = objectExport && c.ResourceID == e.Object.String() && c.Version == e.Version.String() && c.Kind == string(registry.KindOperation)
		case "document.text_unit export-key":
			ok = exported && c.ResourceID == e.Object.String() && c.Version == e.Version.String() && c.Kind == string(registry.KindOperation)
		case "document.derived deliver":
			ok = derived && c.ResourceID == e.Object.String() && c.Version == e.Version.String() && holder
		case "crypto.recipient receive-key":
			ok = c.ResourceID == e.Recipient && c.PrincipalBinding == e.Recipient
		}
		if !ok {
			return Delivered{}, ErrDecision
		}
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return Delivered{}, ErrDecision
	}
	bindings := []fence.Binding{b}
	if (original || derived) != (len(extra) > 0) {
		return Delivered{}, ErrDecision
	}
	var more []fence.Binding
	switch {
	case original:
		more, err = s.completeContent(ctx, rec, *e.DocumentVersion, extra)
	case derived:
		more, err = s.recipientPath(ctx, rec, e, extra)
	}
	if err != nil {
		return Delivered{}, err
	}
	bindings = append(bindings, more...)
	var tenantID cryptowire.UUID
	var recipientPrincipal string
	err = s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM object_versions WHERE tenant = $1 AND id = $2 FOR SHARE`, rec.Tenant, e.Version).Scan(&state); err != nil {
			return err
		}
		locked, err := s.envelope(ctx, tx, rec.Tenant, id, "FOR SHARE")
		if err != nil {
			return err
		}
		if state != "LIVE" || locked.Status != "ACTIVE" {
			return ErrNotFound
		}
		// A plain read releases only the current version's envelope; an
		// older version needs the history operation (review finding 2).
		history := slices.ContainsFunc(rec.Checks, func(c signing.Check) bool { return c.Action == "read-history" })
		if rec.Operation == registry.OpGetEnvelope || objectExport && !history {
			var head *cryptowire.UUID
			if err := tx.QueryRow(ctx, `SELECT current_version FROM objects WHERE tenant = $1 AND id = $2 FOR SHARE`,
				rec.Tenant, e.Object).Scan(&head); err != nil {
				return err
			}
			if head == nil || *head != e.Version {
				return ErrNotFound
			}
		}
		if e.DocumentVersion != nil {
			var originalObject *cryptowire.UUID
			if err := tx.QueryRow(ctx, `SELECT state, original FROM document_versions WHERE tenant = $1 AND id = $2 FOR SHARE`,
				rec.Tenant, *e.DocumentVersion).Scan(&state, &originalObject); err != nil {
				return err
			}
			// The original's envelope only for the original operation, and
			// never a unit's for it.
			isOriginal := originalObject != nil && *originalObject == e.Object
			if state != "LIVE" || isOriginal != original {
				return ErrNotFound
			}
		}
		if err := tx.QueryRow(ctx, `SELECT t.id, k.principal FROM tenants t, recipient_keys k
		                             WHERE t.name = $1 AND k.tenant = $1 AND k.fingerprint = $2`, rec.Tenant, e.Recipient).
			Scan(&tenantID, &recipientPrincipal); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, audit.Event{ID: cryptowire.NewUUID().String(), Kind: audit.KindKeyRelease, Tenant: rec.Tenant,
			DecisionID: rec.DecisionID, OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: "DELIVERED",
			BundleDigest: rec.BundleDigest, PolicyEpoch: rec.PolicyEpoch, At: s.d.Now(),
			Targets: []audit.Target{{Type: "crypto.envelope", ID: e.Object.String(), Version: e.Version.String(), Recipient: e.Recipient,
				Envelope: e.ID.String(), Generation: e.Generation, Signer: e.Signer, Digest: e.Digest}}})
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Delivered{}, ErrNotFound
		}
		return Delivered{}, fmt.Errorf("%w: %v", ErrDecision, err)
	}
	receipt, err := json.Marshal(cryptowire.Receipt{Version: cryptowire.ReceiptVersion, EnvelopeID: e.ID.String(), EnvelopeDigest: e.Digest,
		TenantID: tenantID.String(), ObjectID: e.Object.String(), LogicalVersionID: e.Version.String(), Recipient: e.Recipient,
		Audience: recipientPrincipal, DecisionID: rec.DecisionID, OperationID: rec.OperationID, RecoveryIncarnation: rec.RecoveryIncarnation,
		IssuedAt: s.d.Now().UTC(), ValidUntil: rec.ValidUntil.UTC()})
	if err != nil {
		return Delivered{}, err
	}
	sig, err := cryptowire.Sign(cryptowire.TypeReceipt, s.d.ReceiptKeyID, s.d.ReceiptKey, receipt)
	if err != nil {
		return Delivered{}, err
	}
	return Delivered{EnvelopeID: e.ID.String(), Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature,
		Receipt: receipt, ReceiptSignature: sig}, nil
}

// completeContent verifies the complete-content decisions of an original's
// delivery: each is a single-use document.raw-read decision for the keys
// role, by the same tenant and actor as the delivery decision, with
// raw-read on this document version and read on units of it; together
// they name every unit version of the version exactly once.
func (s *Service) completeContent(ctx context.Context, primary signing.Record, documentVersion cryptowire.UUID, extra []signing.Signed) ([]fence.Binding, error) {
	members := map[string]string{}
	rows, err := s.d.Catalog.Pool().Query(ctx, `SELECT unit::text, unit_version::text FROM document_units WHERE tenant = $1 AND document_version = $2`,
		primary.Tenant, documentVersion)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var unit, version string
		if err := rows.Scan(&unit, &version); err != nil {
			rows.Close()
			return nil, err
		}
		members[unit] = version
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	var out []fence.Binding
	for _, x := range extra {
		rec, err := s.d.Verifier.Check(x)
		if err != nil || !rec.SingleUse || rec.Operation != registry.OpDocRawRead || rec.Tenant != primary.Tenant || rec.Actor != primary.Actor {
			return nil, ErrDecision
		}
		version := false
		for _, c := range rec.Checks {
			switch {
			case c.Kind != string(registry.KindOperation):
				return nil, ErrDecision
			case c.ResourceType == "document.version" && c.Action == "raw-read" && c.ResourceID == documentVersion.String():
				version = true
			case c.ResourceType == "document.text_unit" && c.Action == "read" && members[c.ResourceID] == c.Version && !covered[c.ResourceID]:
				covered[c.ResourceID] = true
			default:
				return nil, ErrDecision
			}
		}
		if !version {
			return nil, ErrDecision
		}
		b, err := fence.FromRecord(rec)
		if err != nil {
			return nil, ErrDecision
		}
		out = append(out, b)
	}
	if len(covered) != len(members) {
		return nil, ErrDecision
	}
	return out, nil
}

// recipientPath verifies the recipient-path decisions of a derived
// output's delivery (DRV-002): either one declassify decision for this
// output, version and recipient, or recipient-source decisions whose
// checks, all for this recipient, name the version's transitive lineage
// exactly. Each is single-use, of the same tenant and actor as the
// delivery, and is admitted in the same fence (DRV-009).
func (s *Service) recipientPath(ctx context.Context, primary signing.Record, e stored, extra []signing.Signed) ([]fence.Binding, error) {
	var recs []signing.Record
	for _, x := range extra {
		rec, err := s.d.Verifier.Check(x)
		if err != nil || !rec.SingleUse || rec.Tenant != primary.Tenant || rec.Actor != primary.Actor {
			return nil, ErrDecision
		}
		recs = append(recs, rec)
	}
	forRecipient := func(c signing.Check) bool {
		return c.Kind == string(registry.KindRecipientEligibility) && c.PrincipalBinding == e.Recipient
	}
	if len(recs) == 1 && recs[0].Operation == registry.OpDerivedDeclassify {
		declassified := false
		for _, c := range recs[0].Checks {
			same := c.ResourceType == "document.derived" && c.ResourceID == e.Object.String() && c.Version == e.Version.String()
			switch {
			case same && c.Action == "declassify" && forRecipient(c):
				declassified = true
			case same && c.Action == "deliver" && c.Kind == string(registry.KindOperation):
			default:
				return nil, ErrDecision
			}
		}
		if !declassified {
			return nil, ErrDecision
		}
	} else {
		want, err := catalog.TransitiveLineage(ctx, s.d.Catalog.Pool(), primary.Tenant, e.Version, 32)
		if err != nil {
			return nil, err
		}
		need := map[cryptowire.LineageSource]bool{}
		for _, src := range want {
			need[src] = true
		}
		for _, rec := range recs {
			if rec.Operation != registry.OpDerivedRecipientSources {
				return nil, ErrDecision
			}
			for _, c := range rec.Checks {
				src := cryptowire.LineageSource{Type: c.ResourceType, ID: c.ResourceID, Version: c.Version}
				if !forRecipient(c) || !need[src] {
					return nil, ErrDecision
				}
				delete(need, src)
			}
		}
		if len(need) != 0 {
			return nil, ErrDecision
		}
	}
	out := make([]fence.Binding, len(recs))
	for i, rec := range recs {
		b, err := fence.FromRecord(rec)
		if err != nil {
			return nil, ErrDecision
		}
		out[i] = b
	}
	return out, nil
}
