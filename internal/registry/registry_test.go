package registry

import (
	"context"
	"errors"
	"testing"
)

var (
	unitAlias = Alias{Namespace: "mcp", Name: "doc://reports/q3#personnel"}
	unit      = Resource{ID: "u-1", Tenant: "t-acme", Type: "document.text_unit", Scope: "acme", Version: 7, Generation: 17, MetadataRevision: 2,
		Attributes: map[string]any{"state": "LIVE"}}
)

func catalogWithUnit() *MemoryCatalog {
	c := NewMemoryCatalog()
	c.Put(unit)
	c.SetAlias("t-acme", unitAlias, unit.ID)
	return c
}

func TestResolveAndRevalidate(t *testing.T) {
	ctx := context.Background()
	c := catalogWithUnit()
	r := NewResolver(c, R1Types())

	bound, err := r.Resolve(ctx, "t-acme", unitAlias)
	if err != nil || bound.ID != "u-1" || bound.Generation != 17 {
		t.Fatalf("Resolve = %+v, %v", bound, err)
	}
	if err := r.Revalidate(ctx, bound); err != nil {
		t.Fatalf("Revalidate of an unchanged resource: %v", err)
	}

	// V-051: a new version is published after resolution.
	newer := unit
	newer.Version, newer.Generation = 8, 18
	c.Put(newer)
	if err := r.Revalidate(ctx, bound); !errors.Is(err, ErrStale) {
		t.Fatalf("Revalidate after publication = %v, want %v", err, ErrStale)
	}

	// A metadata change (for example a label) is also a change (DAT-003).
	relabeled := newer
	relabeled.MetadataRevision = 3
	c.Put(relabeled)
	if err := r.Revalidate(ctx, newer); !errors.Is(err, ErrStale) {
		t.Fatalf("Revalidate after a metadata change = %v, want %v", err, ErrStale)
	}
}

func TestResolveFailures(t *testing.T) {
	ctx := context.Background()
	c := catalogWithUnit()
	c.Put(Resource{ID: "x-1", Tenant: "t-acme", Type: "storage.replica"})
	c.SetAlias("t-acme", Alias{"mcp", "replica"}, "x-1")
	r := NewResolver(c, R1Types())

	for name, tc := range map[string]struct {
		tenant string
		alias  Alias
		want   error
	}{
		"unknown alias":             {"t-acme", Alias{"mcp", "nope"}, ErrUnknownAlias},
		"alias of another tenant":   {"t-other", unitAlias, ErrUnknownAlias},
		"type not registered in R1": {"t-acme", Alias{"mcp", "replica"}, ErrUnknownType},
	} {
		if _, err := r.Resolve(ctx, tc.tenant, tc.alias); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
	}
}

// TestRenameKeepsPermissionIdentity covers V-056: the renamed alias resolves
// to the same resource, so the same policy applies.
func TestRenameKeepsPermissionIdentity(t *testing.T) {
	ctx := context.Background()
	c := catalogWithUnit()
	renamed := Alias{"mcp", "doc://reports/q3-final#personnel"}
	if err := c.Rename("t-acme", unitAlias, renamed); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(c, R1Types())
	got, err := r.Resolve(ctx, "t-acme", renamed)
	if err != nil || got.ID != unit.ID {
		t.Fatalf("Resolve(renamed) = %+v, %v; want resource %s", got, err, unit.ID)
	}
	if _, err := r.Resolve(ctx, "t-acme", unitAlias); !errors.Is(err, ErrUnknownAlias) {
		t.Errorf("old alias still resolves: %v", err)
	}
}

func TestCanonicalAction(t *testing.T) {
	types := R1Types()
	if a, ok := types.CanonicalAction("storage.object", "storage.object.read"); !ok || a != "read" {
		t.Errorf("legacy alias = %q, %v; want read (RES-003)", a, ok)
	}
	if !types.HasAction("storage.object", "read") || types.HasAction("storage.object", "storage.object.read") {
		t.Error("only canonical actions may appear in policies")
	}
	if _, err := NewTypes([]TypeDef{{Name: "x", Actions: []string{"read"}, ActionAliases: map[string]string{"read": "read"}}}); err == nil {
		t.Error("an alias that shadows a canonical action must be rejected")
	}
}

// TestPlanCompoundOperation covers RES-001 and RES-006 (V-035): a tool call
// needs separate checks for invoking the tool, reading its source and
// sending to its destination.
func TestPlanCompoundOperation(t *testing.T) {
	types := ExecutorTypes()
	ops, err := NewOperations(types, []Operation{{Name: "expense.submit", Checks: []CheckSpec{
		{Role: "source", ResourceType: "document.text_unit", Action: "read"},
		{Role: "tool", ResourceType: "agent.tool", Action: "invoke"},
		{Role: "destination", ResourceType: "network.destination", Action: "send"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tool := Resource{ID: "expense.submit", Tenant: "t-acme", Type: "agent.tool"}
	dest := Resource{ID: "expenses.example", Tenant: "t-acme", Type: "network.destination"}

	checks, err := ops.Plan("expense.submit", map[string]Resource{"source": unit, "tool": tool, "destination": dest})
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 3 || checks[0].Action != "read" || checks[1].Action != "invoke" || checks[2].Action != "send" {
		t.Fatalf("checks = %+v, want read, invoke, send", checks)
	}

	for name, tc := range map[string]struct {
		op    string
		bound map[string]Resource
	}{
		"unregistered operation": {"wire.transfer", map[string]Resource{"tool": tool}},
		"missing binding":        {"expense.submit", map[string]Resource{"source": unit, "tool": tool}},
		"wrong resource type":    {"expense.submit", map[string]Resource{"source": tool, "tool": tool, "destination": dest}},
		"extra binding":          {"expense.submit", map[string]Resource{"source": unit, "tool": tool, "destination": dest, "cc": dest}},
	} {
		if _, err := ops.Plan(tc.op, tc.bound); err == nil {
			t.Errorf("%s: Plan succeeded, want an error", name)
		}
	}
	if _, err := NewOperations(types, []Operation{{Name: "bad", Checks: []CheckSpec{{Role: "x", ResourceType: "agent.tool", Action: "delete"}}}}); err == nil {
		t.Error("an operation with an unregistered action must be rejected")
	}
}

// TestR1TypesExcludeLaterPhases covers the phase split of the resource
// table: R1 registers the crypto types and the storage history actions, and
// not the R2 executor types.
func TestR1TypesExcludeLaterPhases(t *testing.T) {
	r1, all := R1Types(), ExecutorTypes()
	for _, typ := range []string{"agent.tool", "network.destination", "business.record", "ai.model"} {
		if r1.HasResourceType(typ) || !all.HasResourceType(typ) {
			t.Errorf("%s: in R1 = %v, with executor = %v", typ, r1.HasResourceType(typ), all.HasResourceType(typ))
		}
	}
	for typ, actions := range map[string][]string{
		"storage.object":   {"read-history", "discover-history", "delete-version", "share"},
		"document.version": {"share", "export"},
		"crypto.recipient": {"enroll", "activate", "receive-key", "revoke"},
		"crypto.envelope":  {"create", "release", "retire"},
	} {
		for _, a := range actions {
			if !r1.HasAction(typ, a) {
				t.Errorf("R1 lacks %s %s", typ, a)
			}
		}
	}
}
