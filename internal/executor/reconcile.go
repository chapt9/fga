package executor

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/enforce"
	"fga/internal/invocation"
	"fga/internal/registry"
	"fga/internal/tools"
	"fga/internal/tools/connector"
)

// ToolInfo is a registered tool as a caller may see it.
type ToolInfo struct {
	Name        string         `json:"name"`
	Version     int            `json:"version"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// List returns the reviewed tools of the caller's tenant that the caller
// may discover (agent.tool.discover), with their argument schemas.
// Discovery shows a tool; only invoke lets it be called (AGT-002).
func (s *Service) List(ctx context.Context, c enforce.Caller) ([]ToolInfo, error) {
	all, err := s.d.Tools.ReviewedTools(ctx, c.Tenant)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := []ToolInfo{}
	for _, t := range all {
		_, _, err := enforce.Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, registry.OpToolDiscover, Audience, false,
			[]enforce.Check{{ID: "tool", Role: registry.RoleTool, Action: "discover", Resource: alias2(registry.ToolNamespace, t.ID)}})
		if err != nil {
			continue
		}
		out = append(out, ToolInfo{Name: t.ID, Version: t.Version, Description: t.Description, InputSchema: InputSchema(t)})
	}
	return out, nil
}

// InputSchema is the JSON Schema of a tool's arguments, as its strict
// parser accepts them.
func InputSchema(t tools.Tool) map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, a := range t.Arguments {
		var p map[string]any
		switch a.Type {
		case tools.ArgString:
			max := a.MaxLength
			if max == 0 {
				max = tools.DefaultMaxLength
			}
			p = map[string]any{"type": "string", "maxLength": max}
		case tools.ArgInteger:
			p = map[string]any{"type": "integer"}
		case tools.ArgMoney:
			p = map[string]any{"type": "object", "additionalProperties": false, "required": []string{"currency", "minor"},
				"properties": map[string]any{"currency": map[string]any{"type": "string", "pattern": "^[A-Z]{3}$"},
					"minor": map[string]any{"type": "integer", "minimum": 0}}}
		case tools.ArgEnum:
			p = map[string]any{"type": "string", "enum": a.Values}
		case tools.ArgResource:
			p = map[string]any{"type": "string", "description": "a " + a.ResourceType + " in namespace " + a.Namespace}
		}
		props[a.Name] = p
		if a.Required {
			required = append(required, a.Name)
		}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
}

// Reconcile runs one pass over invocations whose outcome is open, and
// reports how many it settled or escalated. It never dispatches again
// (INV-003), and asks only the destination each invocation was dispatched
// to, as it was then (review v4 F01):
//   - a DISPATCHING invocation whose worker's lease ran out is asked of
//     that destination by its idempotency key, where the destination
//     supports that, and recorded as reported, or UNKNOWN (INV-008);
//   - an UNKNOWN invocation is asked likewise, the least recently asked
//     first, and closed by the reported outcome as a recorded resolution
//     (INV-006, F06);
//   - an UNKNOWN invocation held beyond its tool's maximum hold age is
//     escalated once.
//
// A destination's "never received" is a failure only once the worker's
// send deadline and the settle time have passed: until then the call may
// still arrive (F02). Every change is recorded with its audit event (F08).
func (s *Service) Reconcile(ctx context.Context, limit int) (int, error) {
	n := 0
	stalled, err := s.d.Invocations.Stalled(ctx, limit)
	if err != nil {
		return n, err
	}
	for _, inv := range stalled {
		leased, err := s.d.Invocations.Acquire(ctx, inv.Tenant, inv.ID, s.d.Worker, s.d.Lease)
		if err != nil {
			continue
		}
		outcome := s.status(ctx, inv)
		if err := s.d.Invocations.Complete(ctx, inv.Tenant, inv.ID, leased.FencingToken, outcome, "reconciled",
			func(ctx context.Context, tx pgx.Tx) error {
				return s.d.Catalog.AppendTx(ctx, tx, s.event(inv, "RECONCILED_"+string(outcome)))
			}); err == nil {
			n++
		}
	}
	unknown, err := s.d.Invocations.Unknown(ctx, limit)
	if err != nil {
		return n, err
	}
	for _, inv := range unknown {
		if err := s.d.Invocations.Checked(ctx, inv.Tenant, inv.ID); err != nil {
			return n, err
		}
		if outcome := s.status(ctx, inv); outcome != invocation.StateUnknown {
			if err := s.d.Invocations.InTx(ctx, func(tx pgx.Tx) error {
				if err := s.d.Invocations.ResolveTx(ctx, tx, inv.Tenant, inv.ID, Reconciler, outcome,
					"the destination reported "+string(outcome)+" for the idempotency key"); err != nil {
					return err
				}
				return s.d.Catalog.AppendTx(ctx, tx, s.event(inv, "RESOLVED_"+string(outcome)))
			}); err == nil {
				n++
			}
			continue
		}
		b, _, ok := bound(inv)
		hold, err := time.ParseDuration(b.MaxHoldAge)
		if !ok || err != nil || inv.DispatchedAt == nil || s.d.Now().Sub(*inv.DispatchedAt) < hold {
			continue
		}
		escalated := false
		if err := s.d.Invocations.InTx(ctx, func(tx pgx.Tx) error {
			var err error
			if escalated, err = s.d.Invocations.EscalateTx(ctx, tx, inv.Tenant, inv.ID); err != nil || !escalated {
				return err
			}
			return s.d.Catalog.AppendTx(ctx, tx, s.event(inv, "ESCALATED"))
		}); err == nil && escalated {
			n++
		}
	}
	return n, nil
}

// Reconciler is the principal reconciliation records resolutions under.
const Reconciler = "system:reconciler"

// status asks the destination an invocation was dispatched to for its
// outcome by the idempotency key; without support, or on any doubt, it is
// UNKNOWN. A destination's report that the call failed is FAILED; its
// "never received" is FAILED only once nothing the worker sent can still
// arrive: after its send deadline and the settle time.
func (s *Service) status(ctx context.Context, inv invocation.Invocation) invocation.State {
	_, d, ok := bound(inv)
	if !ok {
		return invocation.StateUnknown
	}
	outcome, supported, err := s.d.Connector.Status(ctx, d, inv.ID)
	switch {
	case err != nil || !supported:
		return invocation.StateUnknown
	case outcome == connector.Succeeded:
		return invocation.StateSucceeded
	case outcome == connector.Failed:
		return invocation.StateFailed
	case outcome == connector.NotReceived && inv.SendDeadline != nil && !s.d.Now().Before(inv.SendDeadline.Add(s.d.Settle)):
		return invocation.StateFailed
	}
	return invocation.StateUnknown
}

// event is the audit record of a reconciliation step.
func (s *Service) event(inv invocation.Invocation, outcome string) audit.Event {
	return audit.Event{ID: newEventID(), Kind: audit.KindMutation, Tenant: inv.Tenant, Actor: inv.Actor, Outcome: outcome, At: s.d.Now(),
		Targets: []audit.Target{{Type: "agent.tool", ID: registry.ToolOperationPrefix + inv.Tool, Version: strconv.Itoa(inv.ToolVersion)},
			{Type: "tool.invocation", ID: inv.ID, Digest: inv.OperationDigest}}}
}
