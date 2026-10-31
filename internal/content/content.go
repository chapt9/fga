// Package content is the storage application service (specification 2.5,
// CNT-001, CNT-002, PUB-001 to PUB-008, KEY-012; docs/design/storage-r1b.md).
// It is the single layer for encrypted uploads, reads, stat, listing and
// deletion: the native HTTP API delegates to it in R1, and MCP and S3 will
// in later releases.
//
// Every protected operation obtains a fresh decision from the decision
// role for its registered operation, verifies the signed record and that it
// is bound to exactly the operation planned here, and then runs its catalog
// transition or admission inside the authority fence. The service handles
// ciphertext, signed descriptors and opaque envelopes only; it never sees a
// key or plaintext (CRY-005, KEY-013).
package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/approval"
	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/opplan"
	"fga/internal/signing"
)

// Errors returned to adapters. They carry no protected identifiers; an
// adapter maps them to its own redacted errors (CNT-004, DEC-010).
var (
	ErrInvalid      = errors.New("content: invalid request")
	ErrNotFound     = enforce.ErrNotFound
	ErrConflict     = errors.New("content: conflict")
	ErrPrecondition = errors.New("content: precondition failed")
	ErrTooLarge     = errors.New("content: too large")
	// ErrEncryptionMode: the target is in the other encryption mode than
	// the route serves (ENC-002). It is returned only after the caller's
	// authorization, so it reveals nothing to a caller without it.
	ErrEncryptionMode = errors.New("content: wrong encryption mode")
	ErrUnavailable    = enforce.ErrUnavailable
	// ErrApprovalNotUsable: the presented approval does not cover the
	// operation.
	ErrApprovalNotUsable = enforce.ErrApprovalNotUsable
)

// Shared enforcement types, kept under their content names.
type (
	// Caller is an authenticated user of the native API.
	Caller = enforce.Caller
	// Decider obtains decisions from the decision role.
	Decider = enforce.Decider
	// Check is one check of a registered operation.
	Check = enforce.Check
	// Delivered is an envelope released by the keys role.
	Delivered = envelope.Delivered
	// EnvelopeIn is one recipient envelope as a client sends it.
	EnvelopeIn = envelope.EnvelopeIn
	// ApprovalRequired is returned when an operation needs an approval; it
	// names the pending approval.
	ApprovalRequired = enforce.ApprovalRequired
)

// Authorize is enforce.Authorize.
var Authorize = enforce.Authorize

// EnvelopeDelivery is the keys role's internal delivery endpoint (TB3,
// TRU-005).
type EnvelopeDelivery interface {
	Deliver(ctx context.Context, decision signing.Signed, envelopeID string, extra ...signing.Signed) (Delivered, error)
}

// DataKey is a server-mode data key from the keys role.
type DataKey = envelope.DataKey

// DataKeys is the keys role's server-mode data-key service (SSE-003): it
// seals a data key for an upload intent and releases a version's data key,
// each against a single-use decision for the keys role. The storage role
// clears every key after one stream (SSE-004).
type DataKeys interface {
	SealDataKey(ctx context.Context, decision signing.Signed, intentID string) (DataKey, error)
	ReleaseDataKey(ctx context.Context, decision signing.Signed, versionID string) ([]byte, error)
	// SealDocumentKeys seals one key per new unit of a document intent;
	// ReleaseUnitKey releases one unit's key in one document version.
	SealDocumentKeys(ctx context.Context, decision signing.Signed, docIntentID string) ([]DataKey, error)
	ReleaseUnitKey(ctx context.Context, decision signing.Signed, documentVersionID, unitID string) ([]byte, error)
}

// Limits bound requests (CNT-009, AVL-006). D-10 is open; these are
// configuration values.
type Limits struct {
	MaxCiphertext   int64
	MaxEnvelopes    int
	IntentLifetime  time.Duration
	ListPageMax     int
	ListScanBudget  int
	TokenLifetime   time.Duration
	LeaseCheckEvery time.Duration
}

// DefaultLimits are the values of the native API design record.
var DefaultLimits = Limits{MaxCiphertext: 256 << 20, MaxEnvelopes: 16, IntentLifetime: time.Hour, ListPageMax: 1000,
	ListScanBudget: 5000, TokenLifetime: 15 * time.Minute, LeaseCheckEvery: 5 * time.Second}

// Audiences of the storage and keys roles.
const (
	Audience     = enforce.Audience
	KeysAudience = enforce.KeysAudience
)

// Deps are the service's collaborators. Every field is required.
type Deps struct {
	Catalog  *catalog.Store
	Blobs    *blob.Store
	Fence    *fence.Fence
	Decider  Decider
	Verifier *signing.Verifier
	Keys     EnvelopeDelivery
	// DataKeys serves server mode; without it a server-mode upload or read
	// is unavailable.
	DataKeys DataKeys
	// TokenKey seals listing continuation tokens (32 bytes, AES-256-GCM).
	TokenKey []byte
	Limits   Limits
	Now      func() time.Time
}

// Service is the content service.
type Service struct {
	d         Deps
	approvals *approval.Store
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Catalog == nil || d.Blobs == nil || d.Fence == nil || d.Decider == nil || d.Verifier == nil || d.Keys == nil ||
		len(d.TokenKey) != 32 || d.Now == nil || d.Limits.MaxCiphertext <= 0 {
		return nil, errors.New("content: every dependency is required")
	}
	return &Service{d: d, approvals: approval.New(d.Catalog.Pool(), d.Now)}, nil
}

// check is one planned check of an operation.
type check struct {
	id      string
	role    string
	action  string
	ref     decisionsvc.Alias
	version string
	// recipient is the key fingerprint of a recipient-eligibility check.
	recipient string
}

func canonical(typ, id string) decisionsvc.Alias { return decisionsvc.Alias{Type: typ, ID: id} }

func planned(namespace, name string) decisionsvc.Alias {
	return decisionsvc.Alias{Namespace: namespace, Name: name}
}

// decide asks for a decision for operation op with checks, as caller, for
// audience, and returns the verified signed decision.
func (s *Service) decide(ctx context.Context, c Caller, op, audience string, singleUse bool, checks []check) (signing.Signed, signing.Record, error) {
	out := make([]Check, len(checks))
	for i, ch := range checks {
		out[i] = Check{ID: ch.id, Role: ch.role, Action: ch.action, Resource: ch.ref, Version: ch.version, Recipient: ch.recipient}
	}
	return Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, op, audience, singleUse, out)
}

// decidePlanned is decide for an operation that may need an approval: the
// plan is what an approver is shown and what the approval binds, and the
// caller's presented approval goes with it (APR-001, APR-005).
func (s *Service) decidePlanned(ctx context.Context, c Caller, op string, checks []check, plan opplan.Summary) (signing.Record, error) {
	out := make([]Check, len(checks))
	for i, ch := range checks {
		out[i] = Check{ID: ch.id, Role: ch.role, Action: ch.action, Resource: ch.ref, Version: ch.version, Recipient: ch.recipient}
	}
	_, rec, err := enforce.AuthorizeWith(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, op, Audience, true, out, enforce.Options{Plan: &plan})
	return rec, err
}

// details encodes a plan's canonical arguments.
func details(v map[string]string) json.RawMessage {
	b, _ := json.Marshal(v) // a string map always encodes
	return b
}

// fenced runs fn in the authority fence for rec.
func (s *Service) fenced(ctx context.Context, rec signing.Record, mutate []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	b, err := fence.FromRecord(rec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return mapFence(s.d.Fence.Run(ctx, b, mutate, fn))
}

// checked rechecks rec's bindings without a transition, for reads that
// record nothing (stat, listing).
func (s *Service) checked(ctx context.Context, rec signing.Record) error {
	b, err := fence.FromRecord(rec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return mapFence(s.d.Fence.Check(ctx, b))
}

// mapFence turns fence failures into service errors: stale authority is a
// conflict the caller may retry with a fresh decision.
func mapFence(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fence.ErrAdmissionClosed):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case errors.Is(err, fence.ErrIncarnation), errors.Is(err, fence.ErrEpoch), errors.Is(err, fence.ErrIdentity),
		errors.Is(err, fence.ErrDelegation), errors.Is(err, fence.ErrRecipientKey), errors.Is(err, fence.ErrResource),
		errors.Is(err, fence.ErrExpired), errors.Is(err, fence.ErrReplayed), errors.Is(err, fence.ErrApproval):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, ErrConflict), errors.Is(err, ErrPrecondition), errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalid),
		errors.Is(err, audit.ErrFull):
		return err
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// event returns an audit event for an outcome under rec. An approval the
// decision relied on, consumed in the same transaction, is a target too
// (AUD-001, APR-002).
func (s *Service) event(kind audit.Kind, rec signing.Record, outcome string, targets ...audit.Target) audit.Event {
	if a := rec.Context.Approval; a.ID != "" {
		targets = append(targets, audit.Target{Type: "platform.approval", ID: a.ID, Generation: a.Revision})
	}
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: kind, Tenant: rec.Tenant, DecisionID: rec.DecisionID,
		OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: outcome, BundleDigest: rec.BundleDigest,
		PolicyEpoch: rec.PolicyEpoch, Targets: targets, At: s.d.Now()}
}
