// Package policy defines the contract between the decision service and the
// business-policy engine (specification 2.5, Section "Evaluator contract", POL-001).
//
// The engine behind the contract is the project's own evaluator for its own
// policy format (decision D-01). Code outside the evaluator implementation
// does not depend on how the engine works.
package policy

import (
	"context"
	"time"
)

// Set selects the policy set a request is evaluated against.
type Set int

const (
	// SetBusiness is the tenant-authored business policy set.
	SetBusiness Set = iota + 1
	// SetCeiling is the platform ceiling set (POL-007). EffectAllow from this
	// set means only that no ceiling objects; it never grants anything.
	SetCeiling
)

func (s Set) String() string {
	switch s {
	case SetBusiness:
		return "BUSINESS"
	case SetCeiling:
		return "CEILING"
	default:
		return "UNKNOWN"
	}
}

// Prerequisites an allow can carry (APR-001). Their names match the policy
// format's "requires" values.
const (
	RequireApproval    = "approval"
	RequireReservation = "reservation"
)

// Effect is an engine's result for one action.
type Effect int

const (
	// EffectUnknown is the zero value. It is never treated as an allow.
	EffectUnknown Effect = iota
	EffectAllow
	EffectDeny
)

func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "ALLOW"
	case EffectDeny:
		return "DENY"
	default:
		return "UNKNOWN"
	}
}

// Principal is the business principal: the represented subject, or the actor
// when no delegation applies (DLG-003). Roles and attributes come from
// authoritative state, never from the caller (ID-002, ID-003).
type Principal struct {
	ID         string
	Roles      []string
	Attributes map[string]any
}

// Resource is one canonical resource with its trusted attributes (RES-002).
type Resource struct {
	Kind       string
	ID         string
	Scope      string
	Attributes map[string]any
}

// Request asks for the effect of each action on one resource.
type Request struct {
	SnapshotDigest string
	Set            Set
	Principal      Principal
	Resource       Resource
	Actions        []string
	// Now is captured once per batch by the caller (POL-008).
	Now time.Time
	// Operation holds the operation facts the adapter validated against
	// its schema, such as a tool's arguments. They are bound to the
	// operation digest and visible to conditions as request.operation.
	Operation map[string]any
}

// ActionResult is the engine's result for one requested action.
type ActionResult struct {
	Effect Effect
	// Errored reports that a rule able to affect the action failed to
	// evaluate. The production profile denies such an action (POL-005).
	Errored bool
	// Requires lists the prerequisites of an allow, sorted and without
	// duplicates: the union over every matching allow rule (APR-007).
	Requires []string
	// Outputs are the outputs of every matching allow rule that has any, in
	// rule order (POL-011); a release's obligation mapping decides what, if
	// anything, they become.
	Outputs []map[string]any
	// NextChange is the earliest time, not before the request time, at
	// which a time condition of any rule listing the action can change its
	// value. Zero means no time condition applies. A decision is valid only
	// before it (POL-008, DEC-005).
	NextChange time.Time
}

// Result maps each requested action to its result. An action that is absent
// from the map has no result and is never allowed (DEC-004).
type Result struct {
	Actions map[string]ActionResult
}

// Evaluator evaluates one request against one policy set.
//
// A returned error means the engine could not decide: it was unavailable,
// timed out, was cancelled or exhausted a resource limit. Callers report it as
// a service failure, never as an effect.
type Evaluator interface {
	Evaluate(ctx context.Context, req Request) (Result, error)
}
