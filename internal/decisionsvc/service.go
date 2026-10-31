// Package decisionsvc is the decision service: it turns an adapter's
// DecideBatch request into a decision, records it in the audit outbox and,
// for an allow, returns a signed decision for the named audience
// (specification 2.5, DEC-001 to DEC-010, AUD-002).
//
// Requests carry references (aliases) and identity revisions, never trusted
// facts: resources, attributes, roles and the principal come from
// authoritative state (ID-003).
package decisionsvc

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"fga/internal/admission"
	"fga/internal/approval"
	"fga/internal/audit"
	"fga/internal/authn"
	"fga/internal/decision"
	"fga/internal/gate"
	"fga/internal/opplan"
	"fga/internal/policy"
	"fga/internal/registry"
	"fga/internal/release"
	"fga/internal/signing"
)

// Reasons the service adds to those of the decision and gate packages.
const (
	ReasonInvalidRequest    decision.Reason = "INVALID_REQUEST"
	ReasonUnknownResource   decision.Reason = "UNKNOWN_RESOURCE"
	ReasonUnknownAction     decision.Reason = "UNKNOWN_ACTION"
	ReasonUnknownOperation  decision.Reason = "UNKNOWN_OPERATION"
	ReasonOperationMismatch decision.Reason = "OPERATION_MISMATCH"
	// ReasonTargetMismatch is a check whose resolved target is not of the
	// type, or its action not the action, its role names. It depends on
	// the target, so the public projection does not tell it from an
	// absent target (review v4 F05).
	ReasonTargetMismatch     decision.Reason = "TARGET_MISMATCH"
	ReasonPolicyUnavailable  decision.Reason = "POLICY_UNAVAILABLE"
	ReasonCatalogUnavailable decision.Reason = "CATALOG_UNAVAILABLE"
	ReasonAuditUnavailable   decision.Reason = "AUDIT_UNAVAILABLE"
	ReasonSigningFailed      decision.Reason = "SIGNING_FAILED"
	ReasonAdmissionClosed    decision.Reason = "ADMISSION_CLOSED"
	ReasonAuthentication     decision.Reason = "AUTHENTICATION_FAILED"
	ReasonApprovalNotUsable  decision.Reason = "APPROVAL_NOT_USABLE"
)

// Ref names an identity at the revision the adapter built the request from.
type Ref struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// Alias references a resource either by an alias in one protocol namespace
// or canonically by type and ID. Exactly one form is used.
type Alias struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	ID        string `json:"id,omitempty"`
}

// Check asks for one action on one referenced resource. Role names the
// check of the registered operation it fills; Kind and PrincipalBinding say
// whose authority it evaluates (RES-009). Version, when set, is the exact
// immutable version the check is bound to.
type Check struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	Action           string `json:"action"`
	Kind             string `json:"kind,omitempty"`
	PrincipalBinding string `json:"principal_binding,omitempty"`
	Resource         Alias  `json:"resource"`
	Version          string `json:"version,omitempty"`
}

// Request is the body of a DecideBatch call. The adapter's identity is not
// part of it; it comes from the authenticated connection (DEC-007).
type Request struct {
	RequestID string `json:"request_id"`
	Tenant    string `json:"tenant"`
	// Operation is the registered operation; its checks are fixed by the
	// registry, not chosen by the caller (RES-001, DEC-001).
	Operation       string `json:"operation"`
	OperationID     string `json:"operation_id"`
	OperationDigest string `json:"operation_digest"`
	Audience        string `json:"audience"`
	SingleUse       bool   `json:"single_use"`
	Actor           Ref    `json:"actor"`
	Subject         *Ref   `json:"subject,omitempty"`
	Delegation      string `json:"delegation,omitempty"`
	// Evidence is the user's bearer access token, passed on unchanged by the
	// adapter (TRU-003), or, on a later hop, a gateway's decision for an MCP
	// tool call in signing.Evidence form (TB3). It authenticates the actor.
	Evidence string  `json:"evidence,omitempty"`
	Checks   []Check `json:"checks"`
	// Plan is the operation's canonical plan, as the enforcing role renders
	// it for an approver (APR-005). When present, OperationDigest must be
	// its digest, and a NEEDS_APPROVAL outcome opens a pending approval for
	// it.
	Plan *opplan.Summary `json:"plan,omitempty"`
	// Approval names an approval the caller was given for this operation.
	Approval string `json:"approval,omitempty"`
}

// Result reports one check, with the business and ceiling effects kept apart
// from the effective result (DEC-003).
type Result struct {
	CheckID     string `json:"check_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	Business    string `json:"business"`
	Ceiling     string `json:"ceiling"`
	Effect      string `json:"effect"`
	Reason      string `json:"reason,omitempty"`
	// Outputs are the policy outputs of an allowed check (DEC-003); they
	// are data, and authorize nothing on their own.
	Outputs []map[string]any `json:"outputs,omitempty"`
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
	Requires     []string        `json:"requires,omitempty"`
	ValidUntil   *time.Time      `json:"valid_until,omitempty"`
	Signed       *SignedDecision `json:"signed,omitempty"`
	// ApprovalID names the pending approval of a NEEDS_APPROVAL outcome.
	ApprovalID string `json:"approval_id,omitempty"`
	// Obligations repeats the obligations of the signed decision, which
	// alone is authoritative (DEC-003).
	Obligations []signing.Obligation `json:"obligations,omitempty"`
}

// Approvals is the approval store as the decision role uses it: it opens
// pending approvals for plans and reads the approvals requests name.
type Approvals interface {
	Open(ctx context.Context, a approval.Approval) (approval.Approval, error)
	Get(ctx context.Context, tenant, id string) (approval.Approval, error)
}

// Lineage returns a derived version's transitive lineage as dependencies
// at their current state; the catalog implements it.
type Lineage interface {
	Dependencies(ctx context.Context, tenant, version string) ([]signing.Dependency, error)
}

// ToolOperations returns a tenant's registered tool operation, if any.
type ToolOperations interface {
	ToolOperation(ctx context.Context, tenant, name string) (registry.Operation, bool, error)
}

// TokenVerifier verifies a bearer access token for an audience.
// authn.Verifier implements it.
type TokenVerifier interface {
	Verify(token, audience string) (authn.Claims, error)
}

// PublicAdapter is the adapter name of requests that arrive through the
// public facade. No authenticated adapter can use it.
const PublicAdapter = "fga-public"

// Authority reports the deployment's recovery incarnation and whether
// admission is open (AVL-008).
type Authority interface {
	AuthorityState(ctx context.Context) (incarnation uint64, admissionOpen bool, err error)
}

// FixedAuthority is an Authority with a constant state, for tests and the
// development profile without a catalog.
type FixedAuthority struct {
	Incarnation uint64
	Closed      bool
}

// AuthorityState implements Authority.
func (f FixedAuthority) AuthorityState(context.Context) (uint64, bool, error) {
	return f.Incarnation, !f.Closed, nil
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
	Decider    *decision.Decider
	Gate       *gate.Gate
	Releases   *release.Manager
	Resolver   *registry.Resolver
	Types      *registry.Types
	Operations *registry.Operations
	Authority  Authority
	// Authn verifies first-hop evidence. AdapterAudiences maps each adapter
	// to the token audiences of the users it serves (one per role in
	// production; the single development adapter may serve several), and
	// PublicAudience is the audience of tokens presented to the public
	// facade.
	Authn            TokenVerifier
	AdapterAudiences map[string][]string
	// Gateways maps each gateway adapter (the MCP role) to the audiences
	// its decisions for MCP tool calls may be addressed to. Such a decision
	// is accepted as evidence from an adapter serving that audience, for
	// the same tenant and user, while it is valid and from the current
	// recovery incarnation (TB3). SelfVerifier checks this role's own
	// signature on it.
	Gateways     map[string][]string
	SelfVerifier *signing.Verifier
	// ToolOperations, if set, holds the tenants' registered tool
	// operations (the executor, AGT-001); the catalog implements it.
	ToolOperations ToolOperations
	// Lineage binds the dependencies of operations that name one
	// (registry.Operation.BindsLineage); without it they fail closed.
	Lineage        Lineage
	PublicAudience string
	Signer         *signing.Signer
	Outbox         audit.Outbox
	// Approvals is optional; without it, NEEDS_APPROVAL is final.
	Approvals Approvals
	Audiences []string
	MaxAge    time.Duration
	Limits    Limits
	// Admission bounds concurrent HTTP requests per calling workload (the
	// public facade counts as one) and in total, so that no caller can
	// exhaust the role every other role depends on (AVL-006). Nil leaves
	// them unbounded, as in-process tests do.
	Admission *admission.Limiter
	Now       func() time.Time
}

// Service decides batches.
type Service struct {
	d         Deps
	audiences map[string]bool
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Decider == nil || d.Gate == nil || d.Releases == nil || d.Resolver == nil || d.Types == nil || d.Operations == nil || d.Authority == nil ||
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
	authOK, chained := s.authenticated(adapter, req)
	if !authOK {
		return deny(ReasonAuthentication)
	}
	var chainedIncarnation uint64
	via := ""
	if chained != nil {
		chainedIncarnation = chained.RecoveryIncarnation
		if chained.Delegation != "" {
			via = chained.Adapter
		}
	}
	op, ok := s.d.Operations.Lookup(req.Operation)
	if !ok && strings.HasPrefix(req.Operation, registry.ToolOperationPrefix) && s.d.ToolOperations != nil {
		// A tenant's registered tool is an operation too (AGT-001); its
		// registration recorded exactly its checks.
		var err error
		if op, ok, err = s.d.ToolOperations.ToolOperation(ctx, req.Tenant, req.Operation); err != nil {
			return fail(ReasonCatalogUnavailable)
		}
		if ok {
			if _, err := registry.NewOperations(s.d.Types, []registry.Operation{op}); err != nil {
				return deny(ReasonUnknownOperation)
			}
		}
	}
	if !ok {
		return deny(ReasonUnknownOperation)
	}
	// A gateway keeps no identity store: for its own MCP operations, on
	// the user's token, it asks with revision 0 and the decision binds the
	// actor's current revision (TB3). An agent there names its delegation
	// and never its subject: the subject is the one the delegation names,
	// at its current revision, and the whole chain is still admitted.
	if req.Actor.Revision == 0 && len(s.d.Gateways[adapter]) > 0 && chained == nil && req.Evidence != "" &&
		req.Subject == nil && (req.Operation == registry.OpMCPInvoke || req.Operation == registry.OpMCPDiscover) {
		var rej *decision.Rejection
		rev, err := s.d.Gate.CurrentRevision(ctx, req.Tenant, req.Actor.ID)
		if err == nil && req.Delegation != "" {
			var subject decision.Ref
			subject, err = s.d.Gate.DelegatedSubject(ctx, req.Tenant, req.Delegation)
			req.Subject = &Ref{ID: subject.ID, Revision: subject.Revision}
		}
		switch {
		case errors.As(err, &rej):
			return deny(rej.Reason)
		case err != nil:
			return fail(ReasonCatalogUnavailable)
		}
		req.Actor.Revision = rev
	}
	// Recovery closes admission until security-critical changes are
	// reconciled; no decision is made meanwhile, and every decision binds
	// the incarnation it was made in (AVL-008, DEC-011).
	incarnation, open, err := s.d.Authority.AuthorityState(ctx)
	switch {
	case err != nil:
		return fail(ReasonCatalogUnavailable)
	case !open:
		return fail(ReasonAdmissionClosed)
	case chainedIncarnation != 0 && chainedIncarnation != incarnation:
		// A gateway decision from before a restore proves nothing now.
		return deny(ReasonAuthentication)
	}

	snap, err := s.d.Releases.Snapshot(ctx, req.Tenant)
	if err != nil {
		return fail(ReasonPolicyUnavailable)
	}
	resp.BundleDigest, resp.PolicyEpoch = snap.Digest, snap.Epoch

	// The request's own shape is checked before any target is resolved,
	// so its answer never depends on whether a target exists (DEC-010).
	if !shapeMatches(op, req.Checks) {
		return deny(ReasonOperationMismatch)
	}
	checks := make([]decision.Check, 0, len(req.Checks))
	var grantsUntil time.Time
	for _, c := range req.Checks {
		res, err := s.resolve(ctx, req.Tenant, c.Resource)
		switch {
		case errors.Is(err, errBadReference):
			return deny(ReasonInvalidRequest)
		case errors.Is(err, registry.ErrUnknownAlias), errors.Is(err, registry.ErrUnknownResource), errors.Is(err, registry.ErrUnknownType):
			return deny(ReasonUnknownResource)
		case err != nil:
			return fail(ReasonCatalogUnavailable)
		}
		res = sharedWith(res, s.d.Now(), &grantsUntil)
		action, ok := s.d.Types.CanonicalAction(res.Type, c.Action)
		if !ok {
			return deny(ReasonUnknownAction)
		}
		checks = append(checks, decision.Check{ID: c.ID, Action: action, Resource: res.PolicyResource(),
			Kind: decision.CheckKind(c.Kind), PrincipalBinding: c.PrincipalBinding})
		bound = append(bound, res)
	}
	if !targetsMatch(op, req.Checks, checks, bound) {
		return deny(ReasonTargetMismatch)
	}

	env := decision.Envelope{Tenant: req.Tenant, Adapter: adapter, Actor: decision.Ref(req.Actor), Delegation: req.Delegation, Via: via}
	if req.Subject != nil {
		env.Subject = decision.Ref(*req.Subject)
	}
	if req.Plan != nil && (req.Plan.Operation != req.Operation || opplan.Digest(*req.Plan) != req.OperationDigest) {
		return deny(ReasonInvalidRequest)
	}
	d := s.d.Decider.DecideBatch(ctx, decision.Batch{Envelope: env, SnapshotDigest: snap.Digest, Checks: checks,
		LabelOrder: snap.Info.LabelOrder, Operation: operationFacts(req.Plan)})
	for _, r := range d.Results {
		resp.Results = append(resp.Results, Result{CheckID: r.CheckID, PrincipalID: r.Principal.ID, Business: r.Business.String(),
			Ceiling: ceilingName(r.Ceiling), Effect: effectName(r.Effect), Reason: string(r.Reason)})
	}
	// A preparatory operation defers an approval to its commit, which
	// decides the same rights again and consumes the approval there
	// (APR-003); nothing it prepares is visible.
	if op.Preparatory && d.Outcome == decision.OutcomeNeedsApproval {
		deferApproval(&d)
	}
	var used *approval.Approval
	if d.Outcome == decision.OutcomeNeedsApproval {
		a, reason, err := s.settleApproval(ctx, req, snap.Epoch, bound, &d)
		switch {
		case err != nil:
			return fail(ReasonCatalogUnavailable)
		case reason != "":
			return deny(reason)
		case d.Outcome == decision.OutcomeAllow:
			used = &a
		default:
			resp.ApprovalID = a.ID
		}
	}
	// The release's obligation mapping may turn a reservation prerequisite
	// into an obligation the enforcing role meets, and mapped outputs into
	// obligations (POL-011, APR-007).
	mapping, obligations := applyObligations(snap.Info.ObligationMapping, &d)
	resp.Outcome, resp.Reason, resp.Requires = d.Outcome.String(), string(d.Reason), d.Requires
	for i, r := range d.Results {
		if i < len(resp.Results) {
			resp.Results[i].Outputs = r.Outputs
		}
	}
	if d.Outcome != decision.OutcomeAllow {
		return resp, bound
	}

	principals := make([]decision.Ref, 0, len(d.Results))
	for _, r := range d.Results {
		principals = append(principals, r.Principal)
	}
	binding, err := s.d.Gate.Bind(ctx, env, bound, principals, snap.Epoch, s.d.MaxAge)
	if err != nil {
		var rej *decision.Rejection
		if errors.As(err, &rej) {
			return deny(rej.Reason)
		}
		return fail(ReasonCatalogUnavailable)
	}
	// A time condition bounds validity (POL-008, DEC-005), and so does the
	// expiry of an approval the decision relies on or of a share grant it
	// saw. A bound that has already arrived leaves nothing to sign.
	if !d.NextChange.IsZero() && d.NextChange.Before(binding.ValidUntil) {
		binding.ValidUntil = d.NextChange
	}
	if !grantsUntil.IsZero() && grantsUntil.Before(binding.ValidUntil) {
		binding.ValidUntil = grantsUntil
	}
	if used != nil && used.ExpiresAt.Before(binding.ValidUntil) {
		binding.ValidUntil = used.ExpiresAt
	}
	if !s.d.Now().Before(binding.ValidUntil) {
		return deny(gate.ReasonDecisionExpired)
	}
	rec := s.record(resp.DecisionID, adapter, req, binding, bound, snap, d.Results, incarnation)
	rec.ObligationMappingVersion, rec.Obligations = mapping, obligations
	if op.BindsLineage != "" {
		// A derived version decided without its sources still depends on
		// them: their current state is bound with it (DRV-009).
		if rec.Dependencies, err = s.dependencies(ctx, req, op.BindsLineage); err != nil {
			return fail(ReasonCatalogUnavailable)
		}
	}
	resp.Obligations = obligations
	if used != nil {
		rec.Context.Approval = signing.Ref{ID: used.ID, Revision: used.Revision}
	}
	signed, err := s.d.Signer.Sign(rec)
	if err != nil {
		return fail(ReasonSigningFailed)
	}
	resp.ValidUntil = &binding.ValidUntil
	resp.Signed = &SignedDecision{Payload: encode(signed.Payload), JWS: signed.JWS}
	return resp, bound
}

// dependencies returns the transitive lineage of the version the check of
// role names, as bound dependencies.
func (s *Service) dependencies(ctx context.Context, req Request, role string) ([]signing.Dependency, error) {
	if s.d.Lineage == nil {
		return nil, errors.New("decisionsvc: no lineage source")
	}
	for _, c := range req.Checks {
		if c.Role == role {
			deps, err := s.d.Lineage.Dependencies(ctx, req.Tenant, c.Version)
			if err == nil && len(deps) == 0 {
				err = errors.New("decisionsvc: a derived version without lineage")
			}
			return deps, err
		}
	}
	return nil, errors.New("decisionsvc: no check names the lineage")
}

func (s *Service) record(id, adapter string, req Request, b gate.Binding, bound []registry.Resource, snap *release.Snapshot,
	results []decision.CheckResult, incarnation uint64) signing.Record {
	rec := signing.Record{
		DecisionID: id, Audience: req.Audience, Tenant: req.Tenant, RecoveryIncarnation: incarnation, Adapter: adapter,
		Actor: signing.Ref(b.Envelope.Actor), Subject: signing.Ref(b.Envelope.Subject), Delegation: req.Delegation,
		DelegationChain: []signing.Ref{}, Context: signing.Context{LabelOrderGeneration: snap.Info.LabelGeneration},
		Operation: req.Operation, OperationID: req.OperationID, OperationDigest: req.OperationDigest,
		BundleDigest: snap.Digest, PolicyEpoch: snap.Epoch, EvaluatorVersion: snap.Info.EvaluatorVersion, SingleUse: req.SingleUse,
		IssuedAt: s.d.Now(), ValidUntil: b.ValidUntil,
	}
	for _, l := range b.DelegationChain {
		rec.DelegationChain = append(rec.DelegationChain, signing.Ref{ID: string(l.ID), Revision: l.Revision})
	}
	for i, c := range req.Checks {
		action, _ := s.d.Types.CanonicalAction(bound[i].Type, c.Action)
		r := results[i]
		rec.Checks = append(rec.Checks, signing.Check{ID: c.ID, Kind: string(kindOf(c.Kind)), PrincipalBinding: c.PrincipalBinding,
			Principal: signing.Ref(r.Principal), KeyRevision: r.KeyRevision, ResourceType: bound[i].Type, ResourceID: bound[i].ID,
			Version: c.Version, Generation: bound[i].Generation, MetadataRevision: bound[i].MetadataRevision, Action: action,
			BusinessEffect: r.Business.String(), CeilingEffect: ceilingName(r.Ceiling), Requires: append([]string{}, r.Requires...)})
	}
	return rec
}

// authenticated checks first-hop evidence (TRU-003, DEC-007). A request
// with evidence must carry a token for the adapter's user audience, issued
// to the actor in the request's tenant, or a gateway's earlier decision,
// which it returns. A request without evidence must name a delegation,
// which the gate verifies against authoritative state; otherwise
// caller-asserted identity plus a workload identity would be enough, which
// TRU-003 forbids.
func (s *Service) authenticated(adapter string, req Request) (bool, *signing.Record) {
	if req.Evidence == "" {
		return req.Delegation != "" && adapter != PublicAdapter, nil
	}
	if signed, ok := signing.ParseEvidence(req.Evidence); ok {
		rec, ok := s.chained(adapter, req, signed)
		return ok, rec
	}
	audiences := s.d.AdapterAudiences[adapter]
	if adapter == PublicAdapter {
		audiences = []string{s.d.PublicAudience}
	}
	if s.d.Authn == nil {
		return false, nil
	}
	for _, audience := range audiences {
		if audience == "" {
			continue
		}
		if c, err := s.d.Authn.Verify(req.Evidence, audience); err == nil {
			return c.Tenant == req.Tenant && c.Subject == req.Actor.ID, nil
		}
	}
	return false, nil
}

// chained accepts a gateway's earlier decision as the user's evidence
// (TB3): signed by this role, for an MCP tool call, requested by a
// configured gateway and addressed to an audience the gateway may address
// and the requesting adapter serves, for the same tenant, actor, subject
// and delegation, and still valid. A delegated actor's request is then
// presented via the gateway, which its delegation must name. The caller
// compares the returned record's recovery incarnation with the current
// one.
func (s *Service) chained(adapter string, req Request, signed signing.Signed) (*signing.Record, bool) {
	if s.d.SelfVerifier == nil || adapter == PublicAdapter {
		return nil, false
	}
	rec, err := s.d.SelfVerifier.Inspect(signed)
	subject := ""
	if req.Subject != nil {
		subject = req.Subject.ID
	}
	switch {
	case err != nil, rec.Operation != registry.OpMCPInvoke,
		!slices.Contains(s.d.Gateways[rec.Adapter], rec.Audience), !slices.Contains(s.d.AdapterAudiences[adapter], rec.Audience),
		rec.Tenant != req.Tenant, rec.Actor.ID != req.Actor.ID, rec.Delegation != req.Delegation, rec.Subject.ID != subject,
		(req.Delegation == "") != (subject == ""):
		return nil, false
	}
	return &rec, true
}

// DecidePublic serves the public facade: the caller is the token's subject
// acting for itself, and only the public projection is returned (DEC-001,
// DEC-010).
func (s *Service) DecidePublic(ctx context.Context, token string, req Request) PublicResponse {
	req.Evidence = token
	if token == "" || req.Delegation != "" || req.Subject != nil {
		req.Evidence = ""
		req.Delegation = ""
	}
	return s.Decide(ctx, PublicAdapter, req).Public()
}

// ceilingName reports a ceiling result as the Decision API names it: an
// absence of objection is PASS, never ALLOW (POL-007).
func ceilingName(e policy.Effect) string {
	switch e {
	case policy.EffectAllow:
		return "PASS"
	case policy.EffectDeny:
		return "DENY"
	default:
		return "NOT_EVALUATED"
	}
}

func kindOf(k string) decision.CheckKind {
	if k == "" {
		return decision.KindOperation
	}
	return decision.CheckKind(k)
}

// errBadReference marks a resource reference that uses neither or both
// forms.
var errBadReference = errors.New("a resource is referenced by alias or by type and ID")

// resolve resolves a check's resource reference.
// sharedWith shows a resource's unexpired share grants to policy as
// resource.attributes.shared_with: a map from each grantable action of its
// type to the grantee IDs, present with empty lists when there are none,
// so a rule may test it on any resource of the type (SHR-002). until is
// lowered to the earliest expiry among those grants: a decision that saw a
// grant ends when the grant does, whichever rule allowed it (DEC-005).
func sharedWith(res registry.Resource, now time.Time, until *time.Time) registry.Resource {
	actions, ok := registry.GrantableActions[res.Type]
	if !ok {
		return res
	}
	lists := make(map[string][]any, len(actions))
	for _, a := range actions {
		lists[a] = []any{}
	}
	for _, g := range res.Grants {
		if !now.Before(g.ExpiresAt) {
			continue
		}
		for _, a := range g.Actions {
			if l, ok := lists[a]; ok {
				lists[a] = append(l, g.Grantee)
			}
		}
		if until.IsZero() || g.ExpiresAt.Before(*until) {
			*until = g.ExpiresAt
		}
	}
	shared := make(map[string]any, len(lists))
	for a, l := range lists {
		shared[a] = l
	}
	attrs := make(map[string]any, len(res.Attributes)+1)
	maps.Copy(attrs, res.Attributes)
	attrs["shared_with"] = shared
	res.Attributes = attrs
	return res
}

func (s *Service) resolve(ctx context.Context, tenant string, ref Alias) (registry.Resource, error) {
	switch byAlias, byID := ref.Namespace != "" || ref.Name != "", ref.Type != "" || ref.ID != ""; {
	case byAlias && !byID && ref.Namespace != "" && ref.Name != "":
		return s.d.Resolver.Resolve(ctx, tenant, registry.Alias{Namespace: ref.Namespace, Name: ref.Name})
	case byID && !byAlias && ref.Type != "" && ref.ID != "":
		return s.d.Resolver.ResolveID(ctx, tenant, ref.Type, ref.ID)
	default:
		return registry.Resource{}, errBadReference
	}
}

// matchesOperation reports whether the request's checks are exactly the
// registered operation's: every check fills a registered role with that
// role's resource type, canonical action and kind; a role that is not
// repeated is filled once and a repeated role at least once; an optional
// role may be left unfilled (RES-001,
// RES-006, KEY-012). Absence of a required check fails the match.
// shapeMatches reports whether the request's checks have the roles, kinds
// and counts the operation registers, from the request alone.
func shapeMatches(op registry.Operation, reqs []Check) bool {
	count := map[string]int{}
	for _, c := range reqs {
		spec, ok := op.Spec(c.Role)
		if !ok || kindOf(c.Kind) != spec.CheckKind() {
			return false
		}
		count[c.Role]++
	}
	for _, spec := range op.Checks {
		if n := count[spec.Role]; n == 0 && !spec.Optional || !spec.Repeated && n > 1 {
			return false
		}
	}
	return true
}

// targetsMatch reports whether each check's resolved target and canonical
// action are the ones its role registers.
func targetsMatch(op registry.Operation, reqs []Check, checks []decision.Check, bound []registry.Resource) bool {
	for i, c := range reqs {
		spec, _ := op.Spec(c.Role)
		if bound[i].Type != spec.ResourceType || checks[i].Action != spec.Action {
			return false
		}
	}
	return true
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

// approvable are the resource types an approval can target in R1-C
// (ruling 6; storage-role operations only).
var approvable = map[string]bool{"storage.object": true, "storage.bucket": true, "document.text_unit": true, "document.derived": true,
	"document.version": true, "text.entry": true, "agent.tool": true, "crypto.envelope": true, "crypto.recipient": true,
	"crypto.signing-key": true}

// operationFacts are a verified plan's arguments and amount, which policy
// conditions see as request.operation (AGT-003 step 3): the plan's digest
// is the operation digest the decision binds, so the facts are those of
// exactly this operation.
func operationFacts(p *opplan.Summary) map[string]any {
	if p == nil || len(p.Details) == 0 {
		return nil
	}
	var facts map[string]any
	if json.Unmarshal(p.Details, &facts) != nil {
		return nil
	}
	if p.Currency != "" {
		facts["amount_minor"], facts["currency"] = p.AmountMinor, p.Currency
	}
	return facts
}

// settleApproval handles a NEEDS_APPROVAL outcome (APR-001 to APR-003).
// Without an approval in the request it opens a pending approval for the
// request's plan, if any. With one, an approval that is approved, unexpired,
// for this operation, digest, requester and actor, given by someone else,
// and requested under the current policy epoch and resource revisions
// satisfies the approval prerequisite: d becomes ALLOW (or
// NEEDS_RESERVATION) and the approval is returned for binding. A pending
// approval is returned unchanged; anything else is a reason to deny.
func (s *Service) settleApproval(ctx context.Context, req Request, epoch uint64, bound []registry.Resource, d *decision.Decision) (approval.Approval, decision.Reason, error) {
	if s.d.Approvals == nil {
		return approval.Approval{}, "", nil
	}
	requester := req.Actor.ID
	if req.Subject != nil {
		requester = req.Subject.ID
	}
	bindings := approvalBindings(bound)
	if req.Approval == "" {
		if req.Plan == nil {
			return approval.Approval{}, "", nil
		}
		target, ok := planTarget(*req.Plan, bound)
		if !ok {
			return approval.Approval{}, ReasonInvalidRequest, nil
		}
		plan := *req.Plan
		plan.OperationDigest = req.OperationDigest
		a, err := s.d.Approvals.Open(ctx, approval.Approval{Tenant: req.Tenant, Operation: req.Operation, OperationDigest: req.OperationDigest,
			Summary: plan, RequestedBy: requester, Actor: req.Actor.ID, ExpiresAt: s.d.Now().Add(approval.Lifetime),
			TargetType: target.Type, TargetID: target.ID, PolicyEpoch: epoch, Bindings: bindings})
		return a, "", err
	}
	a, err := s.d.Approvals.Get(ctx, req.Tenant, req.Approval)
	if errors.Is(err, approval.ErrNotFound) {
		return approval.Approval{}, ReasonApprovalNotUsable, nil
	}
	if err != nil {
		return approval.Approval{}, "", err
	}
	same := a.Operation == req.Operation && a.OperationDigest == req.OperationDigest && a.RequestedBy == requester && a.Actor == req.Actor.ID
	switch {
	case same && a.State == approval.StatePending && s.d.Now().Before(a.ExpiresAt):
		return a, "", nil
	case !same || a.State != approval.StateApproved || !s.d.Now().Before(a.ExpiresAt) || a.Approver == requester ||
		a.Approver == req.Actor.ID || a.PolicyEpoch != epoch || !slices.Equal(a.Bindings, bindings):
		return approval.Approval{}, ReasonApprovalNotUsable, nil
	}
	d.Requires = slices.DeleteFunc(d.Requires, func(p string) bool { return p == policy.RequireApproval })
	d.Outcome, d.Reason = decision.OutcomeAllow, ""
	if len(d.Requires) > 0 {
		d.Outcome, d.Reason = decision.OutcomeNeedsReservation, decision.ReasonReservationRequired
	}
	return a, "", nil
}

// approvalBindings are the revisions of the existing resources a request
// is bound to, in a canonical order; planned resources have none.
func approvalBindings(bound []registry.Resource) []approval.Binding {
	out := []approval.Binding{}
	for _, r := range bound {
		b := approval.Binding{Type: r.Type, ID: r.ID, Generation: r.Generation, MetadataRevision: r.MetadataRevision}
		if r.Generation == 0 || slices.Contains(out, b) {
			continue
		}
		out = append(out, b)
	}
	slices.SortFunc(out, func(x, y approval.Binding) int { return cmp.Or(cmp.Compare(x.Type, y.Type), cmp.Compare(x.ID, y.ID)) })
	return out
}

// planTarget returns the plan's approval target: its first target, which
// must be an approvable type and one of the request's bound resources.
func planTarget(p opplan.Summary, bound []registry.Resource) (opplan.Target, bool) {
	if len(p.Targets) == 0 || !approvable[p.Targets[0].Type] {
		return opplan.Target{}, false
	}
	t := p.Targets[0]
	for _, r := range bound {
		if r.Type == t.Type && r.ID == t.ID && r.Generation > 0 {
			return t, true
		}
	}
	return opplan.Target{}, false
}

// deferApproval removes the approval prerequisite from d and its results.
func deferApproval(d *decision.Decision) {
	strip := func(r []string) []string {
		return slices.DeleteFunc(slices.Clone(r), func(p string) bool { return p == policy.RequireApproval })
	}
	d.Requires = strip(d.Requires)
	for i := range d.Results {
		d.Results[i].Requires = strip(d.Results[i].Requires)
	}
	d.Outcome, d.Reason = decision.OutcomeAllow, ""
	if len(d.Requires) > 0 {
		d.Outcome, d.Reason = decision.OutcomeNeedsReservation, decision.ReasonReservationRequired
	}
}
