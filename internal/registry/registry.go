// Package registry holds the canonical resource model: registered resource
// types and actions, canonical resources reached through protocol aliases,
// and operations mapped to the checks they need (specification 2.5,
// RES-001 to RES-008).
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

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

// r1TypeDefs are the resource types of release R1 (specification 2.5,
// "Resources, actions and canonical identity"). Types of later phases are
// registered only when their service is enabled.
var r1TypeDefs = []TypeDef{
	// approve is the approver's authority on a resource (ruling 6); label
	// raises or sets a label, relabel lowers it (LAB-004); propose-label
	// stores an advisory classifier proposal (LAB-002), which under default
	// deny is an action like any other (ruling 7).
	{Name: "storage.bucket", Actions: []string{"create-object", "list", "manage", "approve"}},
	{Name: "storage.object", Actions: []string{"read", "stat", "discover", "read-history", "discover-history",
		"new-version", "delete", "delete-version", "share", "label", "relabel", "propose-label", "approve"},
		ActionAliases: map[string]string{"storage.object.read": "read"}},
	{Name: "document.version", Actions: []string{"read-units", "raw-read", "discover", "share", "export", "approve"}},
	{Name: "document.text_unit", Actions: []string{"read", "share", "use-in-model", "export-key", "label", "relabel", "propose-label", "approve"}},
	{Name: "text.entry", Actions: []string{"read", "use-in-model", "update"}},
	// new-version on derived outputs is our addition to the spec's table:
	// a derived output gets new versions, each with its own lineage.
	{Name: "document.derived", Actions: []string{"deliver", "declassify", "label", "relabel", "approve", "new-version"}},
	{Name: "crypto.recipient", Actions: []string{"enroll", "activate", "receive-key", "revoke", "discover"}},
	// Content-signing keys are looked up for verification; under default
	// deny (ruling 7) the lookup is a registered, policy-decided action.
	{Name: "crypto.signing-key", Actions: []string{"discover"}},
	{Name: "crypto.envelope", Actions: []string{"create", "release", "retire"}},
	{Name: "platform.policy", Actions: []string{"propose", "test", "approve", "activate"}},
}

// executorTypeDefs are the R2 types of the optional executor (feature
// executor). agent.tool also carries the approval and reconciliation
// actions that executor uses.
var executorTypeDefs = []TypeDef{
	{Name: "agent.tool", Actions: []string{"discover", "invoke", "configure", "approve", "resolve", "write-off"}},
	{Name: "network.destination", Actions: []string{"connect", "send"}},
	{Name: "business.record", Actions: []string{"read", "update", "approve", "export"}},
	{Name: "ai.model", Actions: []string{"submit", "configure"}},
}

// R1Types returns the resource types of release R1.
func R1Types() *Types { return mustTypes(r1TypeDefs) }

// ExecutorTypes returns the R1 types plus the types of the optional R2
// executor. Only roles that enable the executor use it.
func ExecutorTypes() *Types { return mustTypes(append(slices.Clone(r1TypeDefs), executorTypeDefs...)) }

func mustTypes(defs []TypeDef) *Types {
	t, err := NewTypes(defs)
	if err != nil {
		panic(err) // the tables above are static; a failure is a programming error
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

// PlannedPrefix starts the namespaces of planned resources: resources a
// fenced transition will create, such as the object of an upload intent.
// A planned resource has generation 0; the fence requires it to be absent
// until the transition creates it.
const PlannedPrefix = "planned."

// Planned-resource namespaces and the form of their names.
const (
	// PlannedObject: the upload intent ID.
	PlannedObject = "planned.object"
	// PlannedEnvelope: "<object>|<recipient fingerprint>|<envelope ID>",
	// where <object> is an object ID or "intent:<intent ID>".
	PlannedEnvelope = "planned.envelope"
	// PlannedRecipient: "<principal>|<recipient fingerprint>".
	PlannedRecipient = "planned.recipient"
	// PlannedDocumentVersion: the document intent ID. A unit intent's
	// object resolves under PlannedObject as a document.text_unit.
	PlannedDocumentVersion = "planned.document-version"
)

// Planner resolves planned resources from authoritative state, never from
// facts the caller supplies (ID-003, RES-009).
type Planner interface {
	Planned(ctx context.Context, tenant string, alias Alias) (Resource, error)
}

// ChangePrefix starts the namespaces of proposed changes to an existing
// resource. The resource resolves with its current binding (generation and
// metadata revision) and attributes, plus attributes describing the change
// that policies may condition on; the change itself is an argument of the
// operation, the rest is authoritative state.
const ChangePrefix = "change."

// ChangeLabel: "<resource ID>|<new label>". The resource gains new_label
// and floor (its collection's default label); the decision role adds the
// ranks (D-06).
const ChangeLabel = "change.label"

// Changer resolves proposed changes from authoritative state.
type Changer interface {
	Changed(ctx context.Context, tenant string, alias Alias) (Resource, error)
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

// Resolve returns the canonical resource the alias names, as of now. A
// planned namespace resolves through the catalog's Planner.
func (r *Resolver) Resolve(ctx context.Context, tenant string, alias Alias) (Resource, error) {
	if strings.HasPrefix(alias.Namespace, PlannedPrefix) {
		p, ok := r.catalog.(Planner)
		if !ok {
			return Resource{}, ErrUnknownAlias
		}
		res, err := p.Planned(ctx, tenant, alias)
		if err != nil {
			return Resource{}, err
		}
		if res.Generation != 0 || !r.types.HasResourceType(res.Type) {
			return Resource{}, fmt.Errorf("%w: planned %s", ErrUnknownType, res.Type)
		}
		return res, nil
	}
	if strings.HasPrefix(alias.Namespace, ChangePrefix) {
		c, ok := r.catalog.(Changer)
		if !ok {
			return Resource{}, ErrUnknownAlias
		}
		res, err := c.Changed(ctx, tenant, alias)
		if err != nil {
			return Resource{}, err
		}
		if res.Generation == 0 || !r.types.HasResourceType(res.Type) {
			return Resource{}, fmt.Errorf("%w: changed %s", ErrUnknownType, res.Type)
		}
		return res, nil
	}
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

// ResolveID returns the canonical resource of the given type and ID.
func (r *Resolver) ResolveID(ctx context.Context, tenant, typ, id string) (Resource, error) {
	res, err := r.catalog.Get(ctx, tenant, id)
	if err != nil {
		return Resource{}, err
	}
	if res.Type != typ {
		return Resource{}, ErrUnknownResource
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

// CheckKind says whose authority a check evaluates.
type CheckKind = decision.CheckKind

// Check kinds, as defined by the decision package.
const (
	KindOperation            = decision.KindOperation
	KindRecipientEligibility = decision.KindRecipientEligibility
)

// CheckSpec is one check an operation needs: an action on the resource bound
// to Role. A repeated role is needed once per item of a list, such as once
// per recipient envelope; it must appear at least once.
type CheckSpec struct {
	Role         string
	ResourceType string
	Action       string
	Kind         CheckKind
	Repeated     bool
	// Optional lets a request leave the role unfilled, for operations whose
	// checks depend on the data, such as lineage sources of three types.
	Optional bool
}

// CheckKind returns the check's kind, OPERATION when unset.
func (c CheckSpec) CheckKind() CheckKind { return c.kind() }

// kind returns the check's kind, OPERATION when unset.
func (c CheckSpec) kind() CheckKind {
	if c.Kind == "" {
		return KindOperation
	}
	return c.Kind
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
// registered canonical action and a known kind, and roles are unique within
// an operation.
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
			if k := c.kind(); k != KindOperation && k != KindRecipientEligibility {
				return nil, fmt.Errorf("registry: operation %q: unknown check kind %q", op.Name, c.Kind)
			}
			roles = append(roles, c.Role)
		}
		o.byName[op.Name] = op
	}
	return o, nil
}

// Spec returns the check registered for role.
func (op Operation) Spec(role string) (CheckSpec, bool) {
	for _, c := range op.Checks {
		if c.Role == role {
			return c, true
		}
	}
	return CheckSpec{}, false
}

// Lookup returns a registered operation.
func (o *Operations) Lookup(name string) (Operation, bool) {
	op, ok := o.byName[name]
	return op, ok
}

// Digest identifies the registry's content for release manifests (REL-001):
// operations by name, each with its checks in registered order.
func (o *Operations) Digest() string {
	h := sha256.New()
	h.Write([]byte("fga.operations/v1\n"))
	for _, name := range slices.Sorted(maps.Keys(o.byName)) {
		fmt.Fprintf(h, "op %s\n", name)
		for _, c := range o.byName[name].Checks {
			fmt.Fprintf(h, "check %s %s %s %s %t", c.Role, c.ResourceType, c.Action, c.kind(), c.Repeated)
			if c.Optional {
				h.Write([]byte(" optional"))
			}
			h.Write([]byte("\n"))
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Digest identifies the registered types, actions and aliases for release
// manifests (REL-001).
func (t *Types) Digest() string {
	h := sha256.New()
	h.Write([]byte("fga.types/v1\n"))
	for _, name := range slices.Sorted(maps.Keys(t.actions)) {
		fmt.Fprintf(h, "type %s\n", name)
		for _, a := range slices.Sorted(maps.Keys(t.actions[name])) {
			fmt.Fprintf(h, "action %s\n", a)
		}
		for _, legacy := range slices.Sorted(maps.Keys(t.aliases[name])) {
			fmt.Fprintf(h, "alias %s %s\n", legacy, t.aliases[name][legacy])
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
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
	for _, c := range op.Checks {
		if c.Repeated || c.Optional || c.kind() != KindOperation {
			return nil, fmt.Errorf("registry: operation %q has repeated or recipient checks; plan it by role", name)
		}
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
