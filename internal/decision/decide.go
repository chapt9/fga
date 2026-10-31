// Package decision decides a batch of checks by combining the platform gate,
// the ceiling set and the business set (specification 2.5, POL-003, POL-007,
// DEC-002 to DEC-004).
package decision

import (
	"context"
	"errors"
	"slices"
	"time"

	"fga/internal/policy"
)

// Outcome is the decision for a whole batch.
type Outcome int

const (
	// OutcomeUnknown is the zero value and never authorizes anything.
	OutcomeUnknown Outcome = iota
	// OutcomeAllow means every check was allowed. It is the only outcome on
	// which an enforcement point may proceed (DEC-002).
	OutcomeAllow
	// OutcomeDeny means the batch was rejected or a check was not allowed.
	OutcomeDeny
	// OutcomeError means the service could not decide.
	OutcomeError
	// OutcomeNeedsApproval and OutcomeNeedsReservation mean every check is
	// allowed only once a prerequisite is satisfied through the control
	// plane; a new decision is then needed (DEC-002, APR-001). Approval is
	// reported first when both are required.
	OutcomeNeedsApproval
	OutcomeNeedsReservation
)

func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "ALLOW"
	case OutcomeDeny:
		return "DENY"
	case OutcomeError:
		return "ERROR"
	case OutcomeNeedsApproval:
		return "NEEDS_APPROVAL"
	case OutcomeNeedsReservation:
		return "NEEDS_RESERVATION"
	default:
		return "UNKNOWN"
	}
}

// CheckEffect is the effective result of one check.
type CheckEffect int

const (
	// CheckNotEvaluated means evaluation stopped before the check was decided
	// (DEC-003). It never authorizes anything.
	CheckNotEvaluated CheckEffect = iota
	CheckAllow
	CheckDeny
)

// Reason identifies why a batch or check was not allowed. Reasons are stable
// identifiers and carry no protected details (DEC-010).
type Reason string

const (
	ReasonEmptyBatch          Reason = "EMPTY_BATCH"
	ReasonDuplicateCheckID    Reason = "DUPLICATE_CHECK_ID"
	ReasonMalformedCheck      Reason = "MALFORMED_CHECK"
	ReasonGateUnavailable     Reason = "GATE_UNAVAILABLE"
	ReasonEngineUnavailable   Reason = "ENGINE_UNAVAILABLE"
	ReasonCancelled           Reason = "CANCELLED"
	ReasonCeilingDeny         Reason = "CEILING_DENY"
	ReasonCeilingError        Reason = "CEILING_ERROR"
	ReasonBusinessDeny        Reason = "BUSINESS_DENY"
	ReasonBusinessError       Reason = "BUSINESS_ERROR"
	ReasonMissingResult       Reason = "MISSING_RESULT"
	ReasonApprovalRequired    Reason = "APPROVAL_REQUIRED"
	ReasonReservationRequired Reason = "RESERVATION_REQUIRED"
)

// CheckKind says whose authority a check evaluates (specification 2.5,
// "Decision API", check kinds).
type CheckKind string

const (
	// KindOperation checks are evaluated for the request principal: the
	// represented subject, or the actor acting for itself (DLG-003). The
	// zero value means KindOperation.
	KindOperation CheckKind = "OPERATION"
	// KindRecipientEligibility checks are evaluated for the recipient that
	// the check's principal binding, a recipient-key fingerprint, resolves
	// to in authoritative state (RES-009).
	KindRecipientEligibility CheckKind = "RECIPIENT_ELIGIBILITY"
)

// Check is one action on one resource (specification 2.5, "Resources,
// actions and canonical identity").
type Check struct {
	ID       string
	Action   string
	Resource policy.Resource
	Kind     CheckKind
	// PrincipalBinding is the recipient-key fingerprint of a recipient
	// check and empty for an operation check.
	PrincipalBinding string
}

// IsRecipient reports whether the check is a recipient-eligibility check.
func (c Check) IsRecipient() bool { return c.Kind == KindRecipientEligibility }

// Ref names an identity at the revision the request was built from.
type Ref struct {
	ID       string
	Revision uint64
}

// Envelope is the authority a batch is evaluated under. The gate validates
// it before any policy runs (POL-003 step 1).
type Envelope struct {
	Tenant string
	// Adapter is the executor presenting the batch; a delegation must name it
	// as its audience (DLG-001).
	Adapter string
	Actor   Ref
	// Subject and Delegation are empty when the actor acts for itself.
	Subject    Ref
	Delegation string
}

// Batch is a set of checks evaluated under one authority envelope and one
// policy snapshot (DEC-004). A compound operation is one batch and is allowed
// only if every check is allowed (RES-006).
type Batch struct {
	Envelope       Envelope
	SnapshotDigest string
	Checks         []Check
	// Operation holds the validated operation facts shared by every check.
	Operation map[string]any
}

// CheckResult reports one check. The business and ceiling effects are kept
// apart from the effective result (DEC-003).
type CheckResult struct {
	CheckID string
	// Principal is the identity the check was evaluated for, at the
	// revision read from authoritative state, and KeyRevision the recipient
	// key's revision for a recipient check.
	Principal   Ref
	KeyRevision uint64
	Business    policy.Effect
	Ceiling     policy.Effect
	Effect      CheckEffect
	Reason      Reason
	// Requires lists the prerequisites of an allowed check.
	Requires []string
	// NextChange is the earliest next change of a time condition in either
	// set for this check; zero means none (DEC-005).
	NextChange time.Time
}

// Decision is the result for a batch. Results follow the order of the
// batch's checks.
type Decision struct {
	Outcome Outcome
	Reason  Reason
	Results []CheckResult
	// Requires is the union of the checks' prerequisites, sorted.
	Requires []string
	// NextChange is the earliest NextChange of any check; zero means none.
	// The decision is valid only before it (POL-008, DEC-005).
	NextChange time.Time
}

// Rejection is the error a Gate returns to deny a batch before any policy is
// evaluated. Any other error from a Gate is a service failure.
type Rejection struct {
	Reason Reason
}

func (r *Rejection) Error() string { return "rejected: " + string(r.Reason) }

// Admission is the authority a gate admitted a batch under: the request
// principal and every recipient its checks bind, all read from
// authoritative state.
type Admission struct {
	Principal    policy.Principal
	PrincipalRef Ref
	// Recipients maps each recipient check's principal binding to the
	// recipient it resolved to.
	Recipients map[string]Recipient
}

// Recipient is a recipient key resolved to its principal (RES-009).
type Recipient struct {
	Principal   policy.Principal
	Ref         Ref
	KeyVersion  uint64
	KeyRevision uint64
}

// Gate validates the execution envelope (identity, tenant binding,
// delegation, freshness) before policy evaluation (POL-003 step 1) and
// returns the principals built from authoritative state. A batch never
// supplies its own principal, roles or attributes (ID-002).
type Gate interface {
	Admit(ctx context.Context, b Batch) (Admission, error)
}

// Decider decides batches.
type Decider struct {
	gate      Gate
	evaluator policy.Evaluator
	now       func() time.Time
}

// NewDecider returns a Decider. The clock is read once per batch (POL-008).
func NewDecider(gate Gate, evaluator policy.Evaluator, now func() time.Time) (*Decider, error) {
	if gate == nil || evaluator == nil || now == nil {
		return nil, errors.New("decision: gate, evaluator and clock are required")
	}
	return &Decider{gate: gate, evaluator: evaluator, now: now}, nil
}

// DecideBatch evaluates every check of b. It returns OutcomeAllow only when
// the gate admitted the batch and every check has an explicit business allow
// and no ceiling objection.
func (d *Decider) DecideBatch(ctx context.Context, b Batch) Decision {
	results := make([]CheckResult, len(b.Checks))
	for i, c := range b.Checks {
		results[i] = CheckResult{CheckID: c.ID}
	}
	if reason := malformed(b); reason != "" {
		return Decision{Outcome: OutcomeDeny, Reason: reason, Results: results}
	}
	admission, err := d.gate.Admit(ctx, b)
	if err != nil {
		var rejection *Rejection
		if errors.As(err, &rejection) {
			return Decision{Outcome: OutcomeDeny, Reason: rejection.Reason, Results: results}
		}
		return Decision{Outcome: OutcomeError, Reason: ReasonGateUnavailable, Results: results}
	}

	now := d.now()
	decision := Decision{Outcome: OutcomeAllow, Results: results}
	for i, c := range b.Checks {
		principal, ref, keyRevision := admission.Principal, admission.PrincipalRef, uint64(0)
		if c.IsRecipient() {
			r, ok := admission.Recipients[c.PrincipalBinding]
			if !ok {
				// A gate that admitted the batch without resolving the
				// recipient cannot authorize it (DEC-004).
				return Decision{Outcome: OutcomeError, Reason: ReasonGateUnavailable, Results: results}
			}
			principal, ref, keyRevision = r.Principal, r.Ref, r.KeyRevision
		}
		result, err := d.decideCheck(ctx, b, principal, c, now)
		result.Principal, result.KeyRevision = ref, keyRevision
		if err != nil {
			reason := ReasonEngineUnavailable
			if ctx.Err() != nil {
				reason = ReasonCancelled
			}
			return Decision{Outcome: OutcomeError, Reason: reason, Results: results}
		}
		results[i] = result
		decision.NextChange = earliest(decision.NextChange, result.NextChange)
		if result.Effect != CheckAllow && decision.Outcome == OutcomeAllow {
			decision.Outcome = OutcomeDeny
			decision.Reason = result.Reason
		}
		for _, p := range result.Requires {
			if !slices.Contains(decision.Requires, p) {
				decision.Requires = append(decision.Requires, p)
			}
		}
	}
	slices.Sort(decision.Requires)
	if decision.Outcome == OutcomeAllow && len(decision.Requires) > 0 {
		decision.Outcome = OutcomeNeedsReservation
		decision.Reason = ReasonReservationRequired
		if slices.Contains(decision.Requires, policy.RequireApproval) {
			decision.Outcome = OutcomeNeedsApproval
			decision.Reason = ReasonApprovalRequired
		}
	}
	return decision
}

// malformed returns the reason a batch cannot be evaluated, or "".
func malformed(b Batch) Reason {
	if len(b.Checks) == 0 {
		return ReasonEmptyBatch
	}
	seen := make(map[string]bool, len(b.Checks))
	for _, c := range b.Checks {
		if seen[c.ID] {
			return ReasonDuplicateCheckID
		}
		seen[c.ID] = true
		switch c.Kind {
		case "", KindOperation:
			if c.PrincipalBinding != "" {
				return ReasonMalformedCheck
			}
		case KindRecipientEligibility:
			if c.PrincipalBinding == "" {
				return ReasonMalformedCheck
			}
		default:
			return ReasonMalformedCheck
		}
	}
	return ""
}

// decideCheck evaluates the ceiling set and then the business set. Both are
// always evaluated, so the ceiling result never depends on the business
// result (POL-003 step 1b) and the response reports both effects.
func (d *Decider) decideCheck(ctx context.Context, b Batch, principal policy.Principal, c Check, now time.Time) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	ceiling, err := d.evaluate(ctx, policy.SetCeiling, b, principal, c, now)
	if err != nil {
		return CheckResult{}, err
	}
	business, err := d.evaluate(ctx, policy.SetBusiness, b, principal, c, now)
	if err != nil {
		return CheckResult{}, err
	}
	effect, reason := combine(ceiling, business)
	return CheckResult{
		CheckID:    c.ID,
		Business:   business.Effect,
		Ceiling:    ceiling.Effect,
		Effect:     effect,
		Reason:     reason,
		Requires:   requiresOf(effect, business),
		NextChange: earliest(ceiling.NextChange, business.NextChange),
	}, nil
}

// earliest returns the earlier of two bounds, where zero means no bound.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	default:
		return b
	}
}

// requiresOf returns the prerequisites of an allowed check.
func requiresOf(effect CheckEffect, business policy.ActionResult) []string {
	if effect != CheckAllow {
		return nil
	}
	return business.Requires
}

// evaluate returns the result for the check's action. An action the engine
// did not answer gets the zero ActionResult, whose effect is EffectUnknown.
func (d *Decider) evaluate(ctx context.Context, set policy.Set, b Batch, principal policy.Principal, c Check, now time.Time) (policy.ActionResult, error) {
	res, err := d.evaluator.Evaluate(ctx, policy.Request{
		SnapshotDigest: b.SnapshotDigest,
		Operation:      b.Operation,
		Set:            set,
		Principal:      principal,
		Resource:       c.Resource,
		Actions:        []string{c.Action},
		Now:            now,
	})
	if err != nil {
		return policy.ActionResult{}, err
	}
	return res.Actions[c.Action], nil
}

// combine applies POL-007 and POL-005. A ceiling objection or ceiling error
// always denies. Otherwise the business result applies unchanged, except
// that an errored business rule denies the action. A missing result from
// either set denies.
func combine(ceiling, business policy.ActionResult) (CheckEffect, Reason) {
	switch {
	case ceiling.Errored:
		return CheckDeny, ReasonCeilingError
	case ceiling.Effect == policy.EffectDeny:
		return CheckDeny, ReasonCeilingDeny
	case ceiling.Effect != policy.EffectAllow:
		return CheckDeny, ReasonMissingResult
	case business.Errored:
		return CheckDeny, ReasonBusinessError
	case business.Effect == policy.EffectAllow:
		return CheckAllow, ""
	case business.Effect == policy.EffectDeny:
		return CheckDeny, ReasonBusinessDeny
	default:
		return CheckDeny, ReasonMissingResult
	}
}
