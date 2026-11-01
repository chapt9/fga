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
	"net/netip"
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
	// dispatch may take before another worker may reconcile it: the worker
	// sends nothing after it. Settle is how long after that a destination
	// may still receive a call sent in time; until then its "never
	// received" is not a failure (zero: Lease).
	Worker string
	Lease  time.Duration
	Settle time.Duration
	Now    func() time.Time
	Logger *slog.Logger
}

// sendMargin is how long before its lease ends a worker stops sending, so
// that its outcome is recorded while the lease holds.
const sendMargin = 2 * time.Second

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
	if d.Settle <= 0 {
		d.Settle = d.Lease
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
// token's subject, or an agent under a delegation; (2, 3) the tool,
// version and arguments are planned; (4) the decision role decides the
// tool's operation for the plan, which may need an approval, before any
// state is recorded for the call; (5) the dispatch commits in the
// decision's fence, with the reservation the decision obliges and the
// destination's transport exactly as the decision saw it; (6) the
// destination is called once under the invocation, within the worker's
// lease, and the outcome recorded with its audit event. A retry under the
// same idempotency key returns the invocation as it stands and never
// dispatches again (INV-003, INV-004).
func (s *Service) Invoke(ctx context.Context, c enforce.Caller, r Request) (Result, error) {
	p, err := s.plan(ctx, c.Tenant, r)
	if err != nil {
		return Result{}, err
	}
	// A caller the decision refuses leaves nothing behind: no invocation,
	// and no idempotency key taken from another (review v4 F07).
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
	inv, err := s.d.Invocations.Create(ctx, invocation.Invocation{Tenant: c.Tenant, IdempotencyKey: r.IdempotencyKey,
		OperationDigest: p.digest, Tool: p.tool.ID, ToolVersion: p.tool.Version, Arguments: p.args.Canonical(), Actor: c.Principal,
		Subject: c.Subject, Delegation: c.Delegation})
	switch {
	case errors.Is(err, invocation.ErrIdempotencyConflict):
		return Result{}, ErrConflict
	case err != nil:
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case inv.State != invocation.StatePrepared && inv.State != invocation.StateReserved:
		return result(inv), nil
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
	var dispatched invocation.Invocation
	var dest tools.Destination
	err = s.d.Fence.Run(ctx, b, nil, func(ctx context.Context, tx pgx.Tx) error {
		var raw []byte
		var err error
		if dest, raw, err = s.bind(ctx, tx, c.Tenant, p.tool); err != nil {
			return err
		}
		if dispatched, err = s.d.Invocations.DispatchTx(ctx, tx, c.Tenant, inv.ID, leased.FencingToken, raw); err != nil {
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
	case errors.Is(err, toolstore.ErrUnknownDestination):
		return Result{}, ErrNotFound
	case errors.Is(err, fence.ErrReplayed), errors.Is(err, fence.ErrApproval), errors.Is(err, errTransportChanged), errors.Is(err, errToolChanged),
		isAuthorityChange(err):
		return Result{}, ErrConflict
	case err != nil:
		return Result{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	res := s.send(ctx, dispatched, dest, connector.Call{Method: p.tool.Endpoint.Method, Path: p.tool.Endpoint.Path,
		Body: p.args.Canonical(), IdempotencyKey: inv.ID})
	outcome := map[connector.Outcome]invocation.State{connector.Succeeded: invocation.StateSucceeded,
		connector.Failed: invocation.StateFailed, connector.Unknown: invocation.StateUnknown}[res.Outcome]
	err = s.d.Invocations.Complete(ctx, c.Tenant, inv.ID, leased.FencingToken, outcome, res.Receipt, func(ctx context.Context, tx pgx.Tx) error {
		return s.d.Catalog.AppendTx(ctx, tx, event(rec, inv.ID, string(outcome), p))
	})
	if err != nil {
		// The call happened (or may have); a later reconciliation records
		// it, with its audit event (INV-003).
		s.d.Logger.Error("executor: recording an outcome", "invocation", inv.ID, "outcome", outcome, "error", err)
		return Result{Invocation: inv.ID, State: string(invocation.StateDispatching)}, nil
	}
	return Result{Invocation: inv.ID, State: string(outcome), Receipt: res.Receipt}, nil
}

// errTransportChanged is a destination whose transport is not the one its
// policy-visible resource records.
var errTransportChanged = errors.New("executor: the destination's transport changed")

// errToolChanged is a tool record that is not the one its policy-visible
// resource records.
var errToolChanged = errors.New("executor: the tool is not the one its resource records")

// binding is what a dispatch was authorized for, recorded with it: the
// destination's transport as it was in the dispatch's fence, and the
// tool's maximum hold age. Reconciliation asks that destination, never
// one registered since (review v4 F01, F03).
type binding struct {
	Destination    string   `json:"destination"`
	BaseURL        string   `json:"base_url"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	CredentialFile string   `json:"credential_file"`
	ReconcilePath  string   `json:"reconcile_path"`
	MaxHoldAge     string   `json:"max_hold_age"`
}

// bind checks in tx that the tool is the one its resource records, and
// reads the tool's destination, locked until the dispatch commits, and
// checks that its transport is the one the destination's resource
// records. Both resources are the ones the decision bound and the fence
// rechecks, so the tool definition and the transport used are the ones
// the decision saw (review v5 F02, review v4 F03).
func (s *Service) bind(ctx context.Context, tx pgx.Tx, tenant string, t tools.Tool) (tools.Destination, []byte, error) {
	tool, err := catalog.ResourceAttributesTx(ctx, tx, tenant, registry.ToolOperationPrefix+t.ID)
	if err != nil {
		return tools.Destination{}, nil, err
	}
	if tool[ToolDigestAttribute] != t.SchemaDigest() {
		return tools.Destination{}, nil, errToolChanged
	}
	d, err := toolstore.DestinationTx(ctx, tx, tenant, t.Destination)
	if err != nil {
		return tools.Destination{}, nil, err
	}
	attrs, err := catalog.ResourceAttributesTx(ctx, tx, tenant, registry.DestinationNamespace+":"+d.ID)
	if err != nil {
		return tools.Destination{}, nil, err
	}
	if attrs[TransportAttribute] != d.TransportDigest() {
		return tools.Destination{}, nil, errTransportChanged
	}
	b := binding{Destination: d.ID, BaseURL: d.BaseURL, CredentialFile: d.CredentialFile, ReconcilePath: d.ReconcilePath,
		MaxHoldAge: t.MaxHoldAge, AllowedCIDRs: []string{}}
	for _, p := range d.AllowedCIDRs {
		b.AllowedCIDRs = append(b.AllowedCIDRs, p.String())
	}
	raw, err := json.Marshal(b)
	return d, raw, err
}

// TransportAttribute is the destination resource's attribute that records
// its transport digest (tools.Destination.TransportDigest).
const TransportAttribute = "transport"

// ToolDigestAttribute is the tool resource's attribute that records the
// schema digest of its reviewed record (tools.Tool.SchemaDigest).
const ToolDigestAttribute = "schema_digest"

// bound returns the binding an invocation was dispatched with.
func bound(inv invocation.Invocation) (binding, tools.Destination, bool) {
	var b binding
	if len(inv.Binding) == 0 || json.Unmarshal(inv.Binding, &b) != nil {
		return binding{}, tools.Destination{}, false
	}
	d := tools.Destination{ID: b.Destination, BaseURL: b.BaseURL, CredentialFile: b.CredentialFile, ReconcilePath: b.ReconcilePath}
	for _, c := range b.AllowedCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return binding{}, tools.Destination{}, false
		}
		d.AllowedCIDRs = append(d.AllowedCIDRs, p)
	}
	return b, d, true
}

// send calls the destination only while the worker's lease holds, with a
// deadline at its end: after it, another worker may reconcile the call,
// and nothing this worker sends may arrive later than the deadline plus
// the destination's own handling (review v4 F02). A call with no time left
// is not sent.
func (s *Service) send(ctx context.Context, inv invocation.Invocation, d tools.Destination, call connector.Call) connector.Result {
	if inv.SendDeadline == nil {
		return connector.Result{Outcome: connector.Failed, Detail: "not sent: no send deadline"}
	}
	left := inv.SendDeadline.Sub(s.d.Now()) - sendMargin
	if left <= 0 {
		return connector.Result{Outcome: connector.Failed, Detail: "not sent: the worker's lease ends"}
	}
	ctx, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	return s.d.Connector.Do(ctx, d, call)
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
	// The caller who made it, or the user an agent made it for, sees it;
	// anyone else needs resolve on the tool.
	if !(inv.Actor == c.Principal && inv.Subject == c.Subject || c.Delegation == "" && inv.Subject == c.Principal) {
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
	// Neither the call's actor nor its subject settles it, whoever acts
	// for them (INV-006, INV-009); the store checks the actor itself.
	if c.Delegation != "" && (c.Subject == inv.Actor || c.Subject == inv.Subject) {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalid, invocation.ErrSelfResolution)
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

// Beginner begins a transaction, as a pgxpool.Pool does.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// RegisterDestination records a destination's transport and its
// policy-visible resource, with the transport's digest and attrs, in one
// transaction: a decision never sees one without the other (review v4
// F03).
func RegisterDestination(ctx context.Context, db Beginner, tenant string, d tools.Destination, attrs map[string]any) error {
	a := map[string]any{"name": d.ID}
	for k, v := range attrs {
		a[k] = v
	}
	a[TransportAttribute] = d.TransportDigest()
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if err := toolstore.PutDestinationTx(ctx, tx, tenant, d); err != nil {
			return err
		}
		return catalog.RegisterDestinationTx(ctx, tx, tenant, d.ID, a)
	})
}

// ReviewTool records that a tenant's tool, as stored, was reviewed, and
// registers it in the catalog with its version and schema digest, in one
// transaction: a record becomes usable only together with the resource
// policy sees for it, and dispatch requires the two to match (AGT-001,
// review v5 F02).
func ReviewTool(ctx context.Context, db Beginner, tenant, id string) (tools.Tool, error) {
	var t tools.Tool
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		var err error
		if t, err = toolstore.ReviewToolTx(ctx, tx, tenant, id); err != nil {
			return err
		}
		return catalog.RegisterToolTx(ctx, tx, tenant, t.ID, t.Operation(), map[string]any{"name": t.ID, "kind": "executor",
			"destination": t.Destination, "version": t.Version, ToolDigestAttribute: t.SchemaDigest()})
	})
	return t, err
}
