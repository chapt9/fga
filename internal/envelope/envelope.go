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
	"fga/internal/content"
	"fga/internal/cryptowire"
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
	Decider  content.Decider
	Verifier *signing.Verifier
	// ReceiptKey signs delivery receipts; it is used for nothing else
	// (RCP-001).
	ReceiptKeyID string
	ReceiptKey   ed25519.PrivateKey
	Now          func() time.Time
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

var _ content.EnvelopeDelivery = (*Service)(nil)

// exactly reports whether rec's checks are exactly those of the registered
// operation: the same resource types, actions and kinds, each as often as
// registered (TRU-005: the complete result, not a subset).
func (s *Service) exactly(rec signing.Record) bool {
	op, ok := s.ops.Lookup(rec.Operation)
	if !ok || len(rec.Checks) != len(op.Checks) {
		return false
	}
	want := make([]string, 0, len(op.Checks))
	for _, c := range op.Checks {
		want = append(want, c.ResourceType+" "+c.Action+" "+string(c.CheckKind()))
	}
	got := make([]string, 0, len(rec.Checks))
	for _, c := range rec.Checks {
		got = append(got, c.ResourceType+" "+c.Action+" "+c.Kind)
	}
	slices.Sort(want)
	slices.Sort(got)
	return slices.Equal(want, got)
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
}

func (s *Service) envelope(ctx context.Context, q catalog.Querier, tenant string, id cryptowire.UUID, lock string) (stored, error) {
	var e stored
	err := q.QueryRow(ctx, `SELECT id, object, version, recipient, generation, context, ciphertext, signature, signer, digest, status
	                          FROM envelopes WHERE tenant = $1 AND id = $2 `+lock, tenant, id).
		Scan(&e.ID, &e.Object, &e.Version, &e.Recipient, &e.Generation, &e.Context, &e.Ciphertext, &e.Signature, &e.Signer, &e.Digest, &e.Status)
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
func (s *Service) Deliver(ctx context.Context, decision signing.Signed, envelopeID string) (content.Delivered, error) {
	rec, err := s.d.Verifier.Check(decision)
	if err != nil || !rec.SingleUse || (rec.Operation != registry.OpGetEnvelope && rec.Operation != registry.OpGetEnvelopeOld) || !s.exactly(rec) {
		return content.Delivered{}, ErrDecision
	}
	id, err := cryptowire.ParseUUID(envelopeID)
	if err != nil {
		return content.Delivered{}, ErrInvalid
	}
	e, err := s.envelope(ctx, s.d.Catalog.Pool(), rec.Tenant, id, "")
	if err != nil {
		return content.Delivered{}, err
	}
	for _, c := range rec.Checks {
		var ok bool
		switch c.ResourceType + " " + c.Action {
		case "crypto.envelope release":
			ok = c.ResourceID == e.ID.String() && c.Version == e.Version.String()
		case "storage.object read", "storage.object read-history":
			ok = c.ResourceID == e.Object.String() && c.Version == e.Version.String() &&
				(c.Kind == string(registry.KindOperation) || c.PrincipalBinding == e.Recipient)
		case "crypto.recipient receive-key":
			ok = c.ResourceID == e.Recipient && c.PrincipalBinding == e.Recipient
		}
		if !ok {
			return content.Delivered{}, ErrDecision
		}
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return content.Delivered{}, ErrDecision
	}
	var tenantID cryptowire.UUID
	var recipientPrincipal string
	err = s.d.Fence.Run(ctx, b, nil, func(ctx context.Context, tx pgx.Tx) error {
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
			return content.Delivered{}, ErrNotFound
		}
		return content.Delivered{}, fmt.Errorf("%w: %v", ErrDecision, err)
	}
	receipt, err := json.Marshal(cryptowire.Receipt{Version: cryptowire.ReceiptVersion, EnvelopeID: e.ID.String(), EnvelopeDigest: e.Digest,
		TenantID: tenantID.String(), ObjectID: e.Object.String(), LogicalVersionID: e.Version.String(), Recipient: e.Recipient,
		Audience: recipientPrincipal, DecisionID: rec.DecisionID, OperationID: rec.OperationID, RecoveryIncarnation: rec.RecoveryIncarnation,
		IssuedAt: s.d.Now().UTC(), ValidUntil: rec.ValidUntil.UTC()})
	if err != nil {
		return content.Delivered{}, err
	}
	sig, err := cryptowire.Sign(cryptowire.TypeReceipt, s.d.ReceiptKeyID, s.d.ReceiptKey, receipt)
	if err != nil {
		return content.Delivered{}, err
	}
	return content.Delivered{EnvelopeID: e.ID.String(), Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature,
		Receipt: receipt, ReceiptSignature: sig}, nil
}
