// Package executor is the tools role (R2, optional feature executor,
// docs/design/executor.md): it carries out a registered tool's call on an
// external destination for an authorized user, in the fixed order of
// AGT-003, and records its durable state (INV-001 to INV-009). Every call
// is a decision of the decision role for the tool's registered operation;
// the dispatch commits in the authority fence of that decision, which
// consumes the decision and any approval, holds any reserved budget and
// moves the invocation to DISPATCHING in one transaction (INV-002).
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/fence"
	"fga/internal/invocation"
	"fga/internal/opplan"
	"fga/internal/registry"
	"fga/internal/reservation"
	"fga/internal/signing"
	"fga/internal/tools"
	"fga/internal/tools/connector"
	"fga/internal/toolstore"
)

// Audience is the tools role's decision audience and users' token audience.
const Audience = "fga-tools"

// Applies reports the obligations the tools role applies: a reservation on
// a tool operation (APR-004). Anything else fails closed.
func Applies(operation, obligation string) bool {
	return obligation == signing.Reservation && strings.HasPrefix(operation, registry.ToolOperationPrefix)
}

// Connector performs calls on registered destinations; connector.HTTP
// implements it.
type Connector interface {
	Do(ctx context.Context, d tools.Destination, call connector.Call) connector.Result
	Status(ctx context.Context, d tools.Destination, key string) (connector.Outcome, bool, error)
}

// Deps are the service's collaborators. Every field but Logger is required.
type Deps struct {
	Catalog      *catalog.Store
	Tools        *toolstore.Store
	Invocations  *invocation.Store
	Reservations *reservation.Store
	Decider      enforce.Decider
	// Verifier verifies decisions for Audience and applies Applies.
	Verifier  *signing.Verifier
	Fence     *fence.Fence
	Connector Connector
	// Worker names this replica as a lease owner; Lease is how long a
	// dispatch may take before another worker may reconcile it.
	Worker string
	Lease  time.Duration
	Now    func() time.Time
	Logger *slog.Logger
}

// Service is the tools role.
type Service struct{ d Deps }

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Catalog == nil || d.Tools == nil || d.Invocations == nil || d.Reservations == nil || d.Decider == nil || d.Verifier == nil ||
		d.Fence == nil || d.Connector == nil || d.Worker == "" || d.Lease <= 0 || d.Now == nil {
		return nil, errors.New("executor: every dependency is required")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	d.Verifier.Applying(Applies)
	return &Service{d: d}, nil
}

// Errors. A tool that is unknown, unreviewed or not allowed answers alike.
var (
	ErrNotFound    = errors.New("executor: not found")
	ErrInvalid     = errors.New("executor: invalid request")
	ErrConflict    = errors.New("executor: conflict")
	ErrBudget      = errors.New("executor: the budget cannot cover the call")
	ErrUnavailable = errors.New("executor: a dependency is unavailable")
)

// Request is one tool call.
type Request struct {
	Tool    string          `json:"tool"`
	Version int             `json:"version"`
	Args    json.RawMessage `json:"arguments"`
	// IdempotencyKey identifies the call: a retry with the same key and
	// arguments returns the same invocation and never dispatches twice
	// (INV-004).
	IdempotencyKey string `json:"idempotency_key"`
	// Note is the caller's unverified explanation, shown to an approver.
	Note string `json:"note,omitempty"`
}

// Result is an invocation's state as its caller sees it.
type Result struct {
	Invocation string `json:"invocation_id"`
	State      string `json:"state"`
	Receipt    string `json:"receipt,omitempty"`
}

// planned is a call mapped to its operation, checks and plan (AGT-003
// steps 2 and 3).
type planned struct {
	tool   tools.Tool
	args   tools.Args
	op     string
	checks []enforce.Check
	plan   opplan.Summary
	digest string
}

// plan resolves the tool and its version, validates the arguments against
// its strict schema, and maps the call to its resources, checks and
// canonical plan.
func (s *Service) plan(ctx context.Context, tenant string, r Request) (planned, error) {
	if r.Tool == "" || r.Version <= 0 || r.IdempotencyKey == "" || len(r.IdempotencyKey) > 128 {
		return planned{}, ErrInvalid
	}
	t, err := s.d.Tools.Tool(ctx, tenant, r.Tool)
	switch {
	case errors.Is(err, toolstore.ErrUnknownTool), errors.Is(err, toolstore.ErrToolNotReviewed):
		return planned{}, ErrNotFound
	case err != nil:
		return planned{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case t.Version != r.Version:
		// The approved and the dispatched version are one (AGT-004).
		return planned{}, ErrNotFound
	}
	args, err := t.ParseArguments(r.Args)
	if err != nil {
		return planned{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	p := planned{tool: t, args: args, op: registry.ToolOperationPrefix + t.ID}
	resources := map[string]string{}
	for _, spec := range t.Operation().Checks {
		var alias string
		switch spec.Role {
		case "tool":
			p.checks = append(p.checks, enforce.Check{ID: spec.Role, Role: spec.Role, Action: spec.Action,
				Resource: alias2(registry.ToolNamespace, t.ID)})
			continue
		case "destination":
			p.checks = append(p.checks, enforce.Check{ID: spec.Role, Role: spec.Role, Action: spec.Action,
				Resource: alias2(registry.DestinationNamespace, t.Destination)})
			continue
		default:
			alias, _ = args.String(spec.Role)
		}
		arg := argSpec(t, spec.Role)
		resources[spec.Role] = arg.Namespace + ":" + alias
		p.checks = append(p.checks, enforce.Check{ID: spec.Role, Role: spec.Role, Action: spec.Action, Resource: alias2(arg.Namespace, alias)})
	}
	p.plan = tools.Summarize(t, args, resources, r.Note)
	// The approval's target is the tool's catalog resource (APR-005).
	p.plan.Targets[0].ID = registry.ToolOperationPrefix + t.ID
	p.plan.Operation = p.op
	p.plan.OperationDigest = ""
	if t.AmountArgument != "" {
		if m, ok := args.Money(t.AmountArgument); ok {
			p.plan.AmountMinor, p.plan.Currency = m.Minor, m.Currency
		}
	}
	p.digest = opplan.Digest(p.plan)
	return p, nil
}

func argSpec(t tools.Tool, name string) tools.ArgSpec {
	for _, a := range t.Arguments {
		if a.Name == name {
			return a
		}
	}
	return tools.ArgSpec{}
}

// Invoke carries out one call (AGT-003): (1) the caller is the verified
// token's subject acting for itself; (2, 3) the tool, version and
// arguments are planned; (4) the decision role decides the tool's
// operation for the plan, which may need an approval; (5) the dispatch
// commits in the decision's fence, with the reservation the decision
// obliges; (6) the destination is called once under the invocation and the
// outcome recorded. A retry under the same idempotency key returns the
// invocation as it stands and never dispatches again (INV-003, INV-004).
func (s *Service) Invoke(ctx context.Context, c enforce.Caller, r Request) (Result, error) {
	p, err := s.plan(ctx, c.Tenant, r)
	if err != nil {
		return Result{}, err
	}
	inv, err := s.d.Invocations.Create(ctx, invocation.Invocation{Tenant: c.Tenant, IdempotencyKey: r.IdempotencyKey,
		OperationDigest: p.digest, Tool: p.tool.ID, ToolVersion: p.tool.Version, Arguments: p.args.Canonical(), Actor: c.Principal})
	switch {
	case errors.Is(err, invocation.ErrIdempotencyConflict):
		return Result{}, ErrConflict
	case err != nil:
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case inv.State != invocation.StatePrepared && inv.State != invocation.StateReserved:
		return result(inv), nil
	}

	_, rec, err := enforce.AuthorizeWith(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, p.op, Audience, true, p.checks,
		enforce.Options{Plan: &p.plan})
	if err != nil {
		return Result{}, mapEnforce(err)
	}
	var amount tools.Money
	reserve := rec.Has(signing.Reservation)
	if reserve {
		m, ok := p.args.Money(p.tool.AmountArgument)
		if !ok || p.tool.Budget == "" {
			// A reservation this tool cannot make cannot be applied.
			return Result{}, ErrNotFound
		}
		amount = m
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	leased, err := s.d.Invocations.Acquire(ctx, c.Tenant, inv.ID, s.d.Worker, s.d.Lease)
	if err != nil {
		if errors.Is(err, invocation.ErrLeased) {
			return Result{}, ErrConflict
		}
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	err = s.d.Fence.Run(ctx, b, nil, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.d.Invocations.DispatchTx(ctx, tx, c.Tenant, inv.ID, leased.FencingToken); err != nil {
			return err
		}
		if reserve {
			if _, err := s.d.Reservations.ReserveTx(ctx, tx, c.Tenant, p.tool.Budget, inv.ID, amount); err != nil {
				return err
			}
		}
		return s.d.Catalog.AppendTx(ctx, tx, event(rec, inv.ID, "DISPATCHING", p))
	})
	switch {
	case errors.Is(err, reservation.ErrInsufficient), errors.Is(err, reservation.ErrCurrency), errors.Is(err, reservation.ErrUnknownBudget):
		return Result{}, ErrBudget
	case errors.Is(err, fence.ErrReplayed), errors.Is(err, fence.ErrApproval), isAuthorityChange(err):
		return Result{}, ErrConflict
	case err != nil:
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	dest, err := s.d.Tools.Destination(ctx, c.Tenant, p.tool.Destination)
	var res connector.Result
	if err != nil {
		res = connector.Result{Outcome: connector.Failed, Detail: "destination not registered"}
	} else {
		res = s.d.Connector.Do(ctx, dest, connector.Call{Method: p.tool.Endpoint.Method, Path: p.tool.Endpoint.Path,
			Body: p.args.Canonical(), IdempotencyKey: inv.ID})
	}
	outcome := map[connector.Outcome]invocation.State{connector.Succeeded: invocation.StateSucceeded,
		connector.Failed: invocation.StateFailed, connector.Unknown: invocation.StateUnknown}[res.Outcome]
	if err := s.d.Invocations.Complete(ctx, c.Tenant, inv.ID, leased.FencingToken, outcome, res.Receipt); err != nil {
		// The call happened (or may have); a later reconciliation records
		// it (INV-003).
		s.d.Logger.Error("executor: recording an outcome", "invocation", inv.ID, "outcome", outcome, "error", err)
		return Result{Invocation: inv.ID, State: string(invocation.StateDispatching)}, nil
	}
	if err := s.d.Catalog.Append(ctx, event(rec, inv.ID, string(outcome), p)); err != nil {
		s.d.Logger.Error("executor: audit", "invocation", inv.ID, "error", err)
	}
	return Result{Invocation: inv.ID, State: string(outcome), Receipt: res.Receipt}, nil
}

// Get returns an invocation to its actor, or to a principal who may
// resolve it.
func (s *Service) Get(ctx context.Context, c enforce.Caller, id string) (Result, error) {
	inv, err := s.d.Invocations.Get(ctx, c.Tenant, id)
	if errors.Is(err, invocation.ErrNotFound) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if inv.Actor != c.Principal {
		if _, _, err := enforce.Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, registry.OpToolResolve, Audience, false,
			[]enforce.Check{{ID: "tool", Role: registry.RoleTool, Action: "resolve", Resource: alias2(registry.ToolNamespace, inv.Tool)}}); err != nil {
			return Result{}, ErrNotFound
		}
	}
	return result(inv), nil
}

// Resolve closes an UNKNOWN invocation with evidence (INV-006): resolve on
// the tool, by a principal other than its actor, in the fence of that
// decision. ABANDONED keeps the reservation charged (INV-009).
func (s *Service) Resolve(ctx context.Context, c enforce.Caller, id string, outcome invocation.State, evidence string) (Result, error) {
	return s.settle(ctx, c, id, registry.OpToolResolve, "resolve", func(ctx context.Context, tx pgx.Tx) error {
		return s.d.Invocations.ResolveTx(ctx, tx, c.Tenant, id, c.Principal, outcome, evidence)
	})
}

// WriteOff releases an ABANDONED invocation's charge as an accepted risk
// (INV-009): write-off on the tool, by a principal other than its actor.
func (s *Service) WriteOff(ctx context.Context, c enforce.Caller, id, note string) (Result, error) {
	return s.settle(ctx, c, id, registry.OpToolWriteOff, "write-off", func(ctx context.Context, tx pgx.Tx) error {
		return s.d.Invocations.WriteOffTx(ctx, tx, c.Tenant, id, c.Principal, note)
	})
}

func (s *Service) settle(ctx context.Context, c enforce.Caller, id, op, action string, fn func(context.Context, pgx.Tx) error) (Result, error) {
	inv, err := s.d.Invocations.Get(ctx, c.Tenant, id)
	if errors.Is(err, invocation.ErrNotFound) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	_, rec, err := enforce.Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, op, Audience, true,
		[]enforce.Check{{ID: "tool", Role: registry.RoleTool, Action: action, Resource: alias2(registry.ToolNamespace, inv.Tool)}})
	if err != nil {
		return Result{}, mapEnforce(err)
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	err = s.d.Fence.Run(ctx, b, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, audit.Event{ID: newEventID(), Kind: audit.KindMutation, Tenant: rec.Tenant, DecisionID: rec.DecisionID,
			OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: strings.ToUpper(action), At: s.d.Now(),
			Targets: []audit.Target{{Type: "agent.tool", ID: registry.ToolOperationPrefix + inv.Tool}, {Type: "tool.invocation", ID: id}}})
	})
	switch {
	case errors.Is(err, invocation.ErrSelfResolution), errors.Is(err, invocation.ErrEvidence), errors.Is(err, invocation.ErrState):
		return Result{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	case err != nil:
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	inv, err = s.d.Invocations.Get(ctx, c.Tenant, id)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return result(inv), nil
}

func result(inv invocation.Invocation) Result {
	return Result{Invocation: inv.ID, State: string(inv.State), Receipt: inv.Receipt}
}

// event is the audit record of an invocation's step.
func event(rec signing.Record, id, outcome string, p planned) audit.Event {
	return audit.Event{ID: newEventID(), Kind: audit.KindMutation, Tenant: rec.Tenant, DecisionID: rec.DecisionID, OperationID: rec.OperationID,
		Actor: rec.Actor.ID, Outcome: outcome, At: rec.IssuedAt,
		Targets: []audit.Target{{Type: "agent.tool", ID: registry.ToolOperationPrefix + p.tool.ID, Version: fmt.Sprint(p.tool.Version)},
			{Type: "tool.invocation", ID: id, Digest: p.digest}}}
}

func mapEnforce(err error) error {
	var need *enforce.ApprovalRequired
	switch {
	case errors.As(err, &need):
		return err
	case errors.Is(err, enforce.ErrApprovalNotUsable):
		return err
	case errors.Is(err, enforce.ErrNotFound):
		return ErrNotFound
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

func isAuthorityChange(err error) bool {
	for _, e := range []error{fence.ErrIncarnation, fence.ErrEpoch, fence.ErrIdentity, fence.ErrDelegation, fence.ErrRecipientKey,
		fence.ErrResource, fence.ErrExpired} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// alias2 names a resource by alias.
func alias2(namespace, name string) decisionsvc.Alias {
	return decisionsvc.Alias{Namespace: namespace, Name: name}
}

// newEventID is a random audit event ID.
func newEventID() string { return cryptowire.NewUUID().String() }
