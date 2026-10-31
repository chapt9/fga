package executor

import (
	"context"
	"fmt"
	"strconv"
	"time"

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
// (INV-003):
//   - a DISPATCHING invocation whose worker's lease ran out is asked of the
//     destination by its idempotency key, where the destination supports
//     that, and recorded as reported, or UNKNOWN (INV-008);
//   - an UNKNOWN invocation is asked likewise, and closed by the reported
//     outcome as a recorded resolution (INV-006);
//   - an UNKNOWN invocation held beyond its tool's maximum hold age is
//     escalated once, with an audit event.
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
		if err := s.d.Invocations.Complete(ctx, inv.Tenant, inv.ID, leased.FencingToken, outcome, "reconciled"); err == nil {
			n++
			s.audit(ctx, inv, "RECONCILED_"+string(outcome))
		}
	}
	unknown, err := s.d.Invocations.Unknown(ctx, limit)
	if err != nil {
		return n, err
	}
	for _, inv := range unknown {
		if outcome := s.status(ctx, inv); outcome != invocation.StateUnknown {
			if err := s.d.Invocations.Resolve(ctx, inv.Tenant, inv.ID, Reconciler, outcome,
				"the destination reported "+string(outcome)+" for the idempotency key"); err == nil {
				n++
				s.audit(ctx, inv, "RESOLVED_"+string(outcome))
			}
			continue
		}
		t, err := s.d.Tools.Tool(ctx, inv.Tenant, inv.Tool)
		hold, perr := time.ParseDuration(t.MaxHoldAge)
		if err != nil || perr != nil || inv.DispatchedAt == nil || s.d.Now().Sub(*inv.DispatchedAt) < hold {
			continue
		}
		if escalated, err := s.d.Invocations.Escalate(ctx, inv.Tenant, inv.ID); err == nil && escalated {
			n++
			s.audit(ctx, inv, "ESCALATED")
		}
	}
	return n, nil
}

// Reconciler is the principal reconciliation records resolutions under.
const Reconciler = "system:reconciler"

// status asks the destination for an invocation's outcome by its
// idempotency key; without support, or on any doubt, it is UNKNOWN. Only a
// destination with a reconcile path reports FAILED: an absent key there
// was never received.
func (s *Service) status(ctx context.Context, inv invocation.Invocation) invocation.State {
	t, err := s.d.Tools.Tool(ctx, inv.Tenant, inv.Tool)
	if err != nil {
		return invocation.StateUnknown
	}
	d, err := s.d.Tools.Destination(ctx, inv.Tenant, t.Destination)
	if err != nil {
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
	}
	return invocation.StateUnknown
}

func (s *Service) audit(ctx context.Context, inv invocation.Invocation, outcome string) {
	if err := s.d.Catalog.Append(ctx, audit.Event{ID: newEventID(), Kind: audit.KindMutation, Tenant: inv.Tenant, Actor: inv.Actor,
		Outcome: outcome, At: s.d.Now(), Targets: []audit.Target{{Type: "agent.tool", ID: registry.ToolOperationPrefix + inv.Tool,
			Version: strconv.Itoa(inv.ToolVersion)}, {Type: "tool.invocation", ID: inv.ID, Digest: inv.OperationDigest}}}); err != nil {
		s.d.Logger.Error("executor: audit", "invocation", inv.ID, "error", err)
	}
}
