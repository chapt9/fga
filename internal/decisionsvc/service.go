// Package decisionsvc is the decision service: it turns an adapter's
// DecideBatch request into a decision, records it in the audit outbox and,
// for an allow, returns a signed decision for the named audience
// (specification 2.2, DEC-001 to DEC-010, AUD-002).
//
// Requests carry references (aliases) and identity revisions, never trusted
// facts: resources, attributes, roles and the principal come from
// authoritative state (ID-003).
package decisionsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"fga/internal/audit"
	"fga/internal/decision"
	"fga/internal/gate"
	"fga/internal/registry"
	"fga/internal/release"
	"fga/internal/signing"
)

// Reasons the service adds to those of the decision and gate packages.
const (
	ReasonInvalidRequest     decision.Reason = "INVALID_REQUEST"
	ReasonUnknownResource    decision.Reason = "UNKNOWN_RESOURCE"
	ReasonUnknownAction      decision.Reason = "UNKNOWN_ACTION"
	ReasonPolicyUnavailable  decision.Reason = "POLICY_UNAVAILABLE"
	ReasonCatalogUnavailable decision.Reason = "CATALOG_UNAVAILABLE"
	ReasonAuditUnavailable   decision.Reason = "AUDIT_UNAVAILABLE"
	ReasonSigningFailed      decision.Reason = "SIGNING_FAILED"
)

// Ref names an identity at the revision the adapter built the request from.
type Ref struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// Alias is a resource reference in one protocol namespace.
type Alias struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Check asks for one action on one referenced resource.
type Check struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Resource Alias  `json:"resource"`
}

// Request is the body of a DecideBatch call. The adapter's identity is not
// part of it; it comes from the authenticated connection (DEC-007).
type Request struct {
	RequestID       string  `json:"request_id"`
	Tenant          string  `json:"tenant"`
	OperationID     string  `json:"operation_id"`
	OperationDigest string  `json:"operation_digest"`
	Audience        string  `json:"audience"`
	SingleUse       bool    `json:"single_use"`
	Actor           Ref     `json:"actor"`
	Subject         *Ref    `json:"subject,omitempty"`
	Delegation      string  `json:"delegation,omitempty"`
	Checks          []Check `json:"checks"`
}

// Result reports one check, with the business and ceiling effects kept apart
// from the effective result (DEC-003).
type Result struct {
	CheckID  string `json:"check_id"`
	Business string `json:"business"`
	Ceiling  string `json:"ceiling"`
	Effect   string `json:"effect"`
	Reason   string `json:"reason,omitempty"`
}

// SignedDecision is the exact signed record (base64) and its detached JWS.
type SignedDecision struct {
	Payload string `json:"payload"`
	JWS     string `json:"jws"`
}

// Response is the result of a DecideBatch call. Only Outcome "ALLOW" with a
// signed decision authorizes anything (DEC-002).
type Response struct {
	DecisionID   string          `json:"decision_id"`
	Outcome      string          `json:"outcome"`
	Reason       string          `json:"reason,omitempty"`
	BundleDigest string          `json:"bundle_digest,omitempty"`
	PolicyEpoch  uint64          `json:"policy_epoch,omitempty"`
	Results      []Result        `json:"results"`
	ValidUntil   *time.Time      `json:"valid_until,omitempty"`
	Signed       *SignedDecision `json:"signed,omitempty"`
}

// Limits bound a request (DEC-009).
type Limits struct {
	MaxChecks int
	Deadline  time.Duration
}

// DefaultLimits are the initial qualification limits of DEC-009.
var DefaultLimits = Limits{MaxChecks: 50, Deadline: 250 * time.Millisecond}

// Deps are the service's collaborators. Every field is required.
type Deps struct {
	Decider   *decision.Decider
	Gate      *gate.Gate
	Releases  *release.Manager
	Resolver  *registry.Resolver
	Types     *registry.Types
	Signer    *signing.Signer
	Outbox    audit.Outbox
	Audiences []string
	MaxAge    time.Duration
	Limits    Limits
	Now       func() time.Time
}

// Service decides batches.
type Service struct {
	d         Deps
	audiences map[string]bool
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Decider == nil || d.Gate == nil || d.Releases == nil || d.Resolver == nil || d.Types == nil ||
		d.Signer == nil || d.Outbox == nil || d.Now == nil || d.MaxAge <= 0 || d.Limits.MaxChecks <= 0 || d.Limits.Deadline <= 0 {
		return nil, errors.New("decisionsvc: every dependency and limit is required")
	}
	s := &Service{d: d, audiences: map[string]bool{}}
	for _, a := range d.Audiences {
		s.audiences[a] = true
	}
	return s, nil
}

// Ready reports whether a policy snapshot is active (REL-006).
func (s *Service) Ready() bool { return s.d.Releases.Ready() }

// Decide handles one request from the authenticated adapter.
func (s *Service) Decide(ctx context.Context, adapter string, req Request) Response {
	ctx, cancel := context.WithTimeout(ctx, s.d.Limits.Deadline)
	defer cancel()
	resp := Response{DecisionID: newID(), Results: []Result{}}
	ev := audit.Event{ID: resp.DecisionID, Kind: audit.KindDecision, Tenant: req.Tenant, DecisionID: resp.DecisionID,
		OperationID: req.OperationID, Actor: req.Actor.ID, Delegation: req.Delegation, At: s.d.Now()}
	if req.Subject != nil {
		ev.Subject = req.Subject.ID
	}

	resp, bound := s.decide(ctx, adapter, req, resp)

	// The decision is recorded before it is returned; without evidence there
	// is no decision (AUD-002). Checks name canonical resources once they
	// are resolved.
	ev.Outcome, ev.Reason, ev.BundleDigest, ev.PolicyEpoch = resp.Outcome, resp.Reason, resp.BundleDigest, resp.PolicyEpoch
	for i, r := range resp.Results {
		c := audit.Check{ID: r.CheckID, Action: req.Checks[i].Action, Effect: r.Effect, Reason: r.Reason}
		if i < len(bound) {
			c.ResourceType, c.ResourceID = bound[i].Type, bound[i].ID
		}
		ev.Checks = append(ev.Checks, c)
	}
	if err := s.d.Outbox.Append(ctx, ev); err != nil {
		return Response{DecisionID: resp.DecisionID, Outcome: decision.OutcomeError.String(), Reason: string(ReasonAuditUnavailable), Results: []Result{}}
	}
	return resp
}

// decide returns the response and the resources it resolved, in check order.
func (s *Service) decide(ctx context.Context, adapter string, req Request, resp Response) (Response, []registry.Resource) {
	var bound []registry.Resource
	deny := func(r decision.Reason) (Response, []registry.Resource) {
		resp.Outcome, resp.Reason = decision.OutcomeDeny.String(), string(r)
		return resp, bound
	}
	fail := func(r decision.Reason) (Response, []registry.Resource) {
		resp.Outcome, resp.Reason = decision.OutcomeError.String(), string(r)
		return resp, bound
	}
	if req.Tenant == "" || adapter == "" || len(req.Checks) == 0 || len(req.Checks) > s.d.Limits.MaxChecks || !s.audiences[req.Audience] {
		return deny(ReasonInvalidRequest)
	}

	snap, err := s.d.Releases.Snapshot(ctx, req.Tenant)
	if err != nil {
		return fail(ReasonPolicyUnavailable)
	}
	resp.BundleDigest, resp.PolicyEpoch = snap.Digest, snap.Epoch

	checks := make([]decision.Check, 0, len(req.Checks))
	for _, c := range req.Checks {
		res, err := s.d.Resolver.Resolve(ctx, req.Tenant, registry.Alias{Namespace: c.Resource.Namespace, Name: c.Resource.Name})
		switch {
		case errors.Is(err, registry.ErrUnknownAlias), errors.Is(err, registry.ErrUnknownResource), errors.Is(err, registry.ErrUnknownType):
			return deny(ReasonUnknownResource)
		case err != nil:
			return fail(ReasonCatalogUnavailable)
		}
		action, ok := s.d.Types.CanonicalAction(res.Type, c.Action)
		if !ok {
			return deny(ReasonUnknownAction)
		}
		checks = append(checks, decision.Check{ID: c.ID, Action: action, Resource: res.PolicyResource()})
		bound = append(bound, res)
	}

	env := decision.Envelope{Tenant: req.Tenant, Adapter: adapter, Actor: decision.Ref(req.Actor), Delegation: req.Delegation}
	if req.Subject != nil {
		env.Subject = decision.Ref(*req.Subject)
	}
	d := s.d.Decider.DecideBatch(ctx, decision.Batch{Envelope: env, SnapshotDigest: snap.Digest, Checks: checks})
	resp.Outcome, resp.Reason = d.Outcome.String(), string(d.Reason)
	for _, r := range d.Results {
		resp.Results = append(resp.Results, Result{CheckID: r.CheckID, Business: r.Business.String(), Ceiling: r.Ceiling.String(),
			Effect: effectName(r.Effect), Reason: string(r.Reason)})
	}
	if d.Outcome != decision.OutcomeAllow {
		return resp, bound
	}

	binding, err := s.d.Gate.Bind(ctx, env, bound, snap.Epoch, s.d.MaxAge)
	if err != nil {
		var rej *decision.Rejection
		if errors.As(err, &rej) {
			return deny(rej.Reason)
		}
		return fail(ReasonCatalogUnavailable)
	}
	signed, err := s.d.Signer.Sign(s.record(resp.DecisionID, req, binding, bound, snap))
	if err != nil {
		return fail(ReasonSigningFailed)
	}
	resp.ValidUntil = &binding.ValidUntil
	resp.Signed = &SignedDecision{Payload: encode(signed.Payload), JWS: signed.JWS}
	return resp, bound
}

func (s *Service) record(id string, req Request, b gate.Binding, bound []registry.Resource, snap *release.Snapshot) signing.Record {
	rec := signing.Record{
		DecisionID: id, Audience: req.Audience, Tenant: req.Tenant,
		Actor: signing.Ref(b.Envelope.Actor), Subject: signing.Ref(b.Envelope.Subject), Delegation: req.Delegation,
		DelegationRevisions: b.DelegationRevisions, OperationDigest: req.OperationDigest,
		BundleDigest: snap.Digest, PolicyEpoch: snap.Epoch, SingleUse: req.SingleUse,
		IssuedAt: s.d.Now(), ValidUntil: b.ValidUntil,
	}
	for i, c := range req.Checks {
		action, _ := s.d.Types.CanonicalAction(bound[i].Type, c.Action)
		rec.Checks = append(rec.Checks, signing.Check{ID: c.ID, ResourceType: bound[i].Type, ResourceID: bound[i].ID,
			Generation: bound[i].Generation, MetadataRevision: bound[i].MetadataRevision, Action: action})
	}
	return rec
}

func effectName(e decision.CheckEffect) string {
	switch e {
	case decision.CheckAllow:
		return "ALLOW"
	case decision.CheckDeny:
		return "DENY"
	default:
		return "NOT_EVALUATED"
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("decisionsvc: random ID: %v", err)) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}
