// Package registry holds the canonical resource model: registered resource
// types and actions, canonical resources reached through protocol aliases,
// and operations mapped to the checks they need (specification 2.5,
// RES-001 to RES-008).
package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"fga/internal/decision"
	"fga/internal/policy"
	"fga/internal/policy/format"
)

// Errors returned by resolution and planning.
var (
	ErrUnknownAlias     = errors.New("unknown resource alias")
	ErrUnknownResource  = errors.New("unknown resource")
	ErrUnknownType      = errors.New("unregistered resource type")
	ErrUnknownOperation = errors.New("unregistered operation")
	ErrStale            = errors.New("resource changed since it was resolved")
)

// TypeDef registers a resource type, its canonical actions and the legacy
// action names that map to them (RES-003).
type TypeDef struct {
	Name          string
	Actions       []string
	ActionAliases map[string]string
}

// Types is the registry of resource types. It implements format.Schema.
type Types struct {
	actions map[string]map[string]bool
	aliases map[string]map[string]string
}

var _ format.Schema = (*Types)(nil)

// NewTypes builds a registry. An alias must name a registered action of its
// type and must not shadow one.
func NewTypes(defs []TypeDef) (*Types, error) {
	t := &Types{actions: map[string]map[string]bool{}, aliases: map[string]map[string]string{}}
	for _, d := range defs {
		if _, dup := t.actions[d.Name]; dup || d.Name == "" || len(d.Actions) == 0 {
			return nil, fmt.Errorf("registry: invalid or duplicate type %q", d.Name)
		}
		t.actions[d.Name] = map[string]bool{}
		for _, a := range d.Actions {
			t.actions[d.Name][a] = true
		}
		t.aliases[d.Name] = map[string]string{}
		for legacy, canonical := range d.ActionAliases {
			if !t.actions[d.Name][canonical] || t.actions[d.Name][legacy] {
				return nil, fmt.Errorf("registry: alias %q -> %q is invalid for %s", legacy, canonical, d.Name)
			}
			t.aliases[d.Name][legacy] = canonical
		}
	}
	return t, nil
}

// R1Types returns the resource types of release R1 (specification, "Resources, actions and canonical identity").
func R1Types() *Types {
	t, err := NewTypes([]TypeDef{
		{Name: "agent.tool", Actions: []string{"discover", "invoke", "configure", "approve", "resolve", "write-off"}},
		{Name: "network.destination", Actions: []string{"connect", "send"}},
		{Name: "business.record", Actions: []string{"read", "update", "approve", "export"}},
		{Name: "document.version", Actions: []string{"read-units", "raw-read", "discover"}},
		{Name: "document.text_unit", Actions: []string{"read", "use-in-model", "export-key"}},
		{Name: "document.derived", Actions: []string{"deliver", "declassify", "relabel"}},
		{Name: "text.entry", Actions: []string{"read", "use-in-model", "update"}},
		{Name: "storage.object", Actions: []string{"read", "stat", "discover", "new-version", "delete"},
			ActionAliases: map[string]string{"storage.object.read": "read"}},
		{Name: "storage.bucket", Actions: []string{"create-object", "list", "manage"}},
		{Name: "ai.model", Actions: []string{"submit", "configure"}},
		{Name: "platform.policy", Actions: []string{"propose", "test", "approve", "activate"}},
	})
	if err != nil {
		panic(err) // the table above is static; a failure is a programming error
	}
	return t
}

// HasResourceType implements format.Schema.
func (t *Types) HasResourceType(name string) bool { _, ok := t.actions[name]; return ok }

// HasAction implements format.Schema. Only canonical actions count.
func (t *Types) HasAction(resourceType, action string) bool { return t.actions[resourceType][action] }

// CanonicalAction maps an action name, canonical or legacy, to the
// canonical action. Policies are written against canonical actions only.
func (t *Types) CanonicalAction(resourceType, name string) (string, bool) {
	if t.actions[resourceType][name] {
		return name, true
	}
	canonical, ok := t.aliases[resourceType][name]
	return canonical, ok
}

// Resource is a canonical resource as read from the catalog. A resolved
// Resource is a snapshot: it is bound to the operation and revalidated, not
// re-resolved (RES-004).
type Resource struct {
	ID               string
	Tenant           string
	Type             string
	Scope            string
	Version          uint64
	Generation       uint64
	MetadataRevision uint64
	Attributes       map[string]any
}

// PolicyResource returns the resource as the policy engine sees it.
func (r Resource) PolicyResource() policy.Resource {
	return policy.Resource{Kind: r.Type, ID: r.ID, Scope: r.Scope, Attributes: r.Attributes}
}

// Alias names a resource in one protocol namespace, such as an HTTP path or
// an MCP URI (RES-002). Renaming changes the alias, not the resource (RES-005).
type Alias struct {
	Namespace string
	Name      string
}

// Catalog reads aliases and resources from authoritative state.
type Catalog interface {
	LookupAlias(ctx context.Context, tenant string, alias Alias) (resourceID string, err error)
	Get(ctx context.Context, tenant, id string) (Resource, error)
}

// Resolver resolves aliases to canonical resources.
type Resolver struct {
	catalog Catalog
	types   *Types
}

// NewResolver returns a Resolver over catalog.
func NewResolver(catalog Catalog, types *Types) *Resolver {
	return &Resolver{catalog: catalog, types: types}
}

// Resolve returns the canonical resource the alias names, as of now.
func (r *Resolver) Resolve(ctx context.Context, tenant string, alias Alias) (Resource, error) {
	id, err := r.catalog.LookupAlias(ctx, tenant, alias)
	if err != nil {
		return Resource{}, err
	}
	res, err := r.catalog.Get(ctx, tenant, id)
	if err != nil {
		return Resource{}, err
	}
	if !r.types.HasResourceType(res.Type) {
		return Resource{}, fmt.Errorf("%w: %s", ErrUnknownType, res.Type)
	}
	return res, nil
}

// Revalidate returns ErrStale if the resource's generation or metadata
// revision changed after bound was resolved (RES-004, DAT-003).
func (r *Resolver) Revalidate(ctx context.Context, bound Resource) error {
	current, err := r.catalog.Get(ctx, bound.Tenant, bound.ID)
	if err != nil {
		return err
	}
	if current.Generation != bound.Generation || current.MetadataRevision != bound.MetadataRevision {
		return ErrStale
	}
	return nil
}

// CheckSpec is one check an operation needs: an action on the resource bound
// to Role.
type CheckSpec struct {
	Role         string
	ResourceType string
	Action       string
}

// Operation is a registered protected operation (RES-001).
type Operation struct {
	Name   string
	Checks []CheckSpec
}

// Operations is the registry of operations.
type Operations struct {
	byName map[string]Operation
}

// NewOperations validates each operation against types: every check names a
// registered canonical action, and roles are unique within an operation.
func NewOperations(types *Types, ops []Operation) (*Operations, error) {
	o := &Operations{byName: map[string]Operation{}}
	for _, op := range ops {
		if _, dup := o.byName[op.Name]; dup || op.Name == "" || len(op.Checks) == 0 {
			return nil, fmt.Errorf("registry: invalid or duplicate operation %q", op.Name)
		}
		var roles []string
		for _, c := range op.Checks {
			if !types.HasAction(c.ResourceType, c.Action) {
				return nil, fmt.Errorf("registry: operation %q: %s %s is not registered", op.Name, c.ResourceType, c.Action)
			}
			if c.Role == "" || slices.Contains(roles, c.Role) {
				return nil, fmt.Errorf("registry: operation %q: invalid or duplicate role %q", op.Name, c.Role)
			}
			roles = append(roles, c.Role)
		}
		o.byName[op.Name] = op
	}
	return o, nil
}

// Plan returns the checks for one invocation of the named operation, in the
// registered order. Every role must be bound to a resource of the expected
// type, and no other bindings are accepted. An unregistered operation fails
// closed (RES-001); a compound operation yields one check per effect
// (RES-006).
func (o *Operations) Plan(name string, bound map[string]Resource) ([]decision.Check, error) {
	op, ok := o.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownOperation, name)
	}
	if len(bound) != len(op.Checks) {
		return nil, fmt.Errorf("registry: operation %q needs %d bound resources, got %d", name, len(op.Checks), len(bound))
	}
	checks := make([]decision.Check, 0, len(op.Checks))
	for _, c := range op.Checks {
		res, ok := bound[c.Role]
		if !ok {
			return nil, fmt.Errorf("registry: operation %q: no resource bound to %q", name, c.Role)
		}
		if res.Type != c.ResourceType {
			return nil, fmt.Errorf("registry: operation %q: %q is a %s, want %s", name, c.Role, res.Type, c.ResourceType)
		}
		checks = append(checks, decision.Check{ID: c.Role, Action: c.Action, Resource: res.PolicyResource()})
	}
	return checks, nil
}
