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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/fence"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Errors returned to adapters. They carry no protected identifiers; an
// adapter maps them to its own redacted errors (CNT-004, DEC-010).
var (
	ErrInvalid      = errors.New("content: invalid request")
	ErrNotFound     = errors.New("content: not found")
	ErrConflict     = errors.New("content: conflict")
	ErrPrecondition = errors.New("content: precondition failed")
	ErrTooLarge     = errors.New("content: too large")
	ErrUnavailable  = errors.New("content: a dependency is unavailable")
)

// Caller is an authenticated user of the native API: the subject of a
// verified access token, acting for itself (TB1).
type Caller struct {
	Tenant    string
	Principal string
	// Token is the user's access token, passed to the decision role as
	// first-hop evidence (TRU-003).
	Token string
}

// Decider obtains decisions from the decision role.
type Decider interface {
	Decide(ctx context.Context, req decisionsvc.Request) (decisionsvc.Response, error)
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

// EnvelopeDelivery is the keys role's internal delivery endpoint (TB3,
// TRU-005).
type EnvelopeDelivery interface {
	Deliver(ctx context.Context, decision signing.Signed, envelopeID string) (Delivered, error)
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

// Audience is the audience of decisions the storage role enforces, and the
// token audience of its users.
const Audience = "fga-storage"

// KeysAudience is the audience of decisions the keys role enforces.
const KeysAudience = "fga-keys"

// Deps are the service's collaborators. Every field is required.
type Deps struct {
	Catalog  *catalog.Store
	Blobs    *blob.Store
	Fence    *fence.Fence
	Decider  Decider
	Verifier *signing.Verifier
	Keys     EnvelopeDelivery
	// TokenKey seals listing continuation tokens (32 bytes, AES-256-GCM).
	TokenKey []byte
	Limits   Limits
	Now      func() time.Time
}

// Service is the content service.
type Service struct {
	d Deps
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Catalog == nil || d.Blobs == nil || d.Fence == nil || d.Decider == nil || d.Verifier == nil || d.Keys == nil ||
		len(d.TokenKey) != 32 || d.Now == nil || d.Limits.MaxCiphertext <= 0 {
		return nil, errors.New("content: every dependency is required")
	}
	return &Service{d: d}, nil
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
// audience, and returns the verified signed decision. Only an ALLOW whose
// record is bound to exactly this operation counts (DEC-002).
func (s *Service) decide(ctx context.Context, c Caller, op, audience string, singleUse bool, checks []check) (signing.Signed, signing.Record, error) {
	id, err := s.d.Catalog.GetIdentity(ctx, c.Tenant, c.Principal)
	if err != nil {
		return signing.Signed{}, signing.Record{}, ErrNotFound
	}
	req := decisionsvc.Request{RequestID: cryptowire.NewUUID().String(), Tenant: c.Tenant, Operation: op,
		OperationID: cryptowire.NewUUID().String(), Audience: audience, SingleUse: singleUse,
		Actor: decisionsvc.Ref{ID: c.Principal, Revision: id.Revision}, Evidence: c.Token}
	h := sha256.New()
	fmt.Fprintf(h, "fga.storage-operation/v1\n%s\n%s\n", op, c.Tenant)
	for _, ch := range checks {
		dc := decisionsvc.Check{ID: ch.id, Role: ch.role, Action: ch.action, Resource: ch.ref, Version: ch.version}
		if ch.recipient != "" {
			dc.Kind, dc.PrincipalBinding = string(registry.KindRecipientEligibility), ch.recipient
		}
		req.Checks = append(req.Checks, dc)
		fmt.Fprintf(h, "%s %s %s %s/%s/%s/%s %s %s\n", ch.id, ch.role, ch.action, ch.ref.Namespace, ch.ref.Name, ch.ref.Type, ch.ref.ID, ch.version, ch.recipient)
	}
	req.OperationDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))

	resp, err := s.d.Decider.Decide(ctx, req)
	switch {
	case err != nil:
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision: %v", ErrUnavailable, err)
	case resp.Outcome == "ERROR":
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision %s", ErrUnavailable, resp.Reason)
	case resp.Outcome != "ALLOW" || resp.Signed == nil:
		// Absent and denied look the same to the caller (DEC-010).
		return signing.Signed{}, signing.Record{}, ErrNotFound
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	if err != nil {
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: malformed decision", ErrUnavailable)
	}
	signed := signing.Signed{Payload: payload, JWS: resp.Signed.JWS}
	verifier := s.d.Verifier
	if audience != Audience {
		// A decision for another role is checked for integrity here and
		// verified for its audience by that role.
		rec, err := verifier.Inspect(signed)
		if err != nil || !bound(rec, req) {
			return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision does not verify", ErrUnavailable)
		}
		return signed, rec, nil
	}
	rec, err := verifier.Check(signed)
	if err != nil || !bound(rec, req) {
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision does not verify", ErrUnavailable)
	}
	return signed, rec, nil
}

// bound reports whether rec is the decision for exactly req: tenant,
// actor, operation, digest and every check's role, action and version.
func bound(rec signing.Record, req decisionsvc.Request) bool {
	if rec.Tenant != req.Tenant || rec.Actor.ID != req.Actor.ID || rec.Operation != req.Operation ||
		rec.OperationDigest != req.OperationDigest || rec.SingleUse != req.SingleUse || len(rec.Checks) != len(req.Checks) {
		return false
	}
	for i, c := range req.Checks {
		r := rec.Checks[i]
		if r.ID != c.ID || r.Version != c.Version || r.PrincipalBinding != c.PrincipalBinding ||
			(c.Resource.ID != "" && r.ResourceID != c.Resource.ID) || (c.Resource.Type != "" && r.ResourceType != c.Resource.Type) {
			return false
		}
	}
	return true
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
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case errors.Is(err, fence.ErrIncarnation), errors.Is(err, fence.ErrEpoch), errors.Is(err, fence.ErrIdentity),
		errors.Is(err, fence.ErrDelegation), errors.Is(err, fence.ErrRecipientKey), errors.Is(err, fence.ErrResource),
		errors.Is(err, fence.ErrExpired), errors.Is(err, fence.ErrReplayed):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case errors.Is(err, ErrConflict), errors.Is(err, ErrPrecondition), errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalid),
		errors.Is(err, audit.ErrFull):
		return err
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// event returns an audit event for an outcome under rec.
func (s *Service) event(kind audit.Kind, rec signing.Record, outcome string, targets ...audit.Target) audit.Event {
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: kind, Tenant: rec.Tenant, DecisionID: rec.DecisionID,
		OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: outcome, BundleDigest: rec.BundleDigest,
		PolicyEpoch: rec.PolicyEpoch, Targets: targets, At: s.d.Now()}
}
