package gate

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"fga/internal/decision"
	"fga/internal/delegation"
	"fga/internal/identity"
	"fga/internal/policy"
	"fga/internal/registry"
)

var start = time.Unix(1_800_000_000, 0)

type capabilityTable map[[3]string]bool // actor, resource type, action

func (c capabilityTable) Allows(_ context.Context, _, actor, rt, action string) (bool, error) {
	return c[[3]string{actor, rt, action}], nil
}

type epochs map[string]uint64

func (e epochs) RequiredEpoch(_ context.Context, tenant string) (uint64, error) {
	return e[tenant], nil
}

type fixture struct {
	gate        *Gate
	identities  *identity.MemoryStore
	delegations *delegation.MemoryStore
	catalog     *registry.MemoryCatalog
	epochs      epochs
	clock       *time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{identities: identity.NewMemoryStore(), delegations: delegation.NewMemoryStore(),
		catalog: registry.NewMemoryCatalog(), epochs: epochs{"t-acme": 5}}
	now := start
	f.clock = &now
	f.identities.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 88, Roles: []string{"reviewer"},
		Attributes: map[string]any{"project_ids": []string{"p1"}}})
	f.identities.Put(identity.Identity{ID: "agent-7", Tenant: "t-acme", Revision: 12, Roles: []string{"agent"}})
	if err := f.delegations.Put(delegation.Delegation{ID: "dlg-5", Tenant: "t-acme", Actor: "agent-7", Subject: "user-42",
		Audience: "tools-gw-1", ExpiresAt: start.Add(time.Hour), Revision: 3,
		Grants: []delegation.Grant{{ResourceType: "document.text_unit", Actions: []string{"read"}}}}); err != nil {
		t.Fatal(err)
	}
	f.catalog.Put(registry.Resource{ID: "u-1", Tenant: "t-acme", Type: "document.text_unit", Generation: 17, MetadataRevision: 2})
	caps := capabilityTable{{"agent-7", "document.text_unit", "read"}: true, {"user-42", "document.text_unit", "read"}: true}
	g, err := New(Deps{Recipients: MemoryRecipients{}, Identities: f.identities, Delegations: f.delegations, Capabilities: caps,
		Resources: registry.NewResolver(f.catalog, registry.R1Types()), Epochs: f.epochs, Now: func() time.Time { return *f.clock }})
	if err != nil {
		t.Fatal(err)
	}
	f.gate = g
	return f
}

func delegatedBatch(action string) decision.Batch {
	return decision.Batch{
		Envelope: decision.Envelope{Tenant: "t-acme", Adapter: "tools-gw-1",
			Actor: decision.Ref{ID: "agent-7", Revision: 12}, Subject: decision.Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5"},
		Checks: []decision.Check{{ID: "c1", Action: action, Resource: policy.Resource{Kind: "document.text_unit", ID: "u-1"}}},
	}
}

func reason(err error) decision.Reason {
	var r *decision.Rejection
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// TestAdmitReturnsSubjectFromStore covers DLG-003 and V-020: the principal is
// the represented subject, with roles from the identity store; the batch
// cannot supply roles.
func TestAdmitReturnsSubjectFromStore(t *testing.T) {
	f := newFixture(t)
	adm, err := f.gate.Admit(context.Background(), delegatedBatch("read"))
	if err != nil {
		t.Fatal(err)
	}
	if p := adm.Principal; p.ID != "user-42" || !slices.Equal(p.Roles, []string{"reviewer"}) || adm.PrincipalRef.Revision != 88 {
		t.Fatalf("admission = %+v, want user-42 at revision 88 with stored roles", adm)
	}

	own := decision.Batch{Envelope: decision.Envelope{Tenant: "t-acme", Actor: decision.Ref{ID: "user-42", Revision: 88}},
		Checks: delegatedBatch("read").Checks}
	if adm, err := f.gate.Admit(context.Background(), own); err != nil || adm.Principal.ID != "user-42" {
		t.Fatalf("actor acting for itself: %+v, %v", adm, err)
	}
}

func TestAdmitRejections(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fixture)
		edit  func(*decision.Batch)
		want  decision.Reason
	}{
		{"missing tenant", nil, func(b *decision.Batch) { b.Envelope.Tenant = "" }, ReasonTenantMissing},
		{"subject without delegation", nil, func(b *decision.Batch) { b.Envelope.Delegation = "" }, ReasonSubjectMismatch},
		{"unknown actor", nil, func(b *decision.Batch) { b.Envelope.Actor.ID = "agent-x" }, ReasonIdentityUnknown},
		{"stale actor revision (V-027)", nil, func(b *decision.Batch) { b.Envelope.Actor.Revision = 11 }, ReasonIdentityStale},
		{"disabled subject", func(f *fixture) {
			f.identities.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 88, Disabled: true})
		}, nil, ReasonIdentityDisabled},
		{"expired delegation (V-021)", func(f *fixture) { *f.clock = start.Add(2 * time.Hour) }, nil, ReasonDelegationExpired},
		{"revoked delegation", func(f *fixture) { _ = f.delegations.Revoke("t-acme", "dlg-5") }, nil, ReasonDelegationRevoked},
		{"other executor (V-023)", nil, func(b *decision.Batch) { b.Envelope.Adapter = "tools-gw-2" }, ReasonDelegationAudience},
		{"action outside the delegation", nil, func(b *decision.Batch) { b.Checks[0].Action = "use-in-model" }, ReasonDelegationScope},
		{"actor lacks the capability (V-024)", func(f *fixture) {
			f.gate.capabilities = capabilityTable{}
		}, nil, ReasonActorCapability},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			b := delegatedBatch("read")
			if tt.edit != nil {
				tt.edit(&b)
			}
			_, err := f.gate.Admit(context.Background(), b)
			if got := reason(err); got != tt.want {
				t.Fatalf("Admit = %v, want rejection %s", err, tt.want)
			}
		})
	}
}

type failingIdentities struct{}

func (failingIdentities) Get(context.Context, string, string) (identity.Identity, error) {
	return identity.Identity{}, errors.New("database unreachable")
}

// TestAdmitStoreFailureIsNotARejection: an unavailable store means the
// service cannot decide (ERROR), not that the request was denied.
func TestAdmitStoreFailureIsNotARejection(t *testing.T) {
	f := newFixture(t)
	f.gate.identities = failingIdentities{}
	_, err := f.gate.Admit(context.Background(), delegatedBatch("read"))
	if err == nil || reason(err) != "" {
		t.Fatalf("Admit = %v, want a non-rejection error", err)
	}
}

// TestRecheck covers DEC-005 and DEC-006: a bound decision is rechecked
// against current state, and any change needs a new decision.
func TestRecheck(t *testing.T) {
	bound := registry.Resource{ID: "u-1", Tenant: "t-acme", Type: "document.text_unit", Generation: 17, MetadataRevision: 2}
	tests := []struct {
		name   string
		change func(*fixture)
		want   decision.Reason
	}{
		{"nothing changed", func(*fixture) {}, ""},
		{"past valid_until (V-086)", func(f *fixture) { *f.clock = start.Add(31 * time.Second) }, ReasonDecisionExpired},
		{"resource generation advanced (V-087)", func(f *fixture) {
			f.catalog.Put(registry.Resource{ID: "u-1", Tenant: "t-acme", Type: "document.text_unit", Generation: 18, MetadataRevision: 2})
		}, ReasonResourceChanged},
		{"delegation revision advanced (V-122)", func(f *fixture) {
			d, _ := f.delegations.Get(context.Background(), "t-acme", "dlg-5")
			d.Revision++
			_ = f.delegations.Put(d)
		}, ReasonDelegationChanged},
		{"subject identity changed", func(f *fixture) {
			f.identities.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 89})
		}, ReasonIdentityStale},
		{"required epoch passed the decision's", func(f *fixture) { f.epochs["t-acme"] = 6 }, ReasonPolicyEpochSuperseded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			b, err := f.gate.Bind(context.Background(), delegatedBatch("read").Envelope, []registry.Resource{bound}, nil, 5, 30*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			tt.change(f)
			if got := reason(f.gate.Recheck(context.Background(), b)); got != tt.want {
				t.Fatalf("Recheck reason = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBindValidUntil: valid_until is the earlier of the decision-age limit
// and the delegation's expiry (DEC-005).
func TestBindValidUntil(t *testing.T) {
	f := newFixture(t)
	env := delegatedBatch("read").Envelope
	short, _ := f.gate.Bind(context.Background(), env, nil, nil, 5, 30*time.Second)
	long, _ := f.gate.Bind(context.Background(), env, nil, nil, 5, 2*time.Hour)
	if !short.ValidUntil.Equal(start.Add(30*time.Second)) || !long.ValidUntil.Equal(start.Add(time.Hour)) {
		t.Fatalf("valid_until = %v and %v, want +30s and the delegation expiry +1h", short.ValidUntil, long.ValidUntil)
	}
	if !slices.Equal(short.DelegationChain, []delegation.Link{{ID: "dlg-5", Revision: 3}}) {
		t.Errorf("delegation chain = %v, want [dlg-5@3]", short.DelegationChain)
	}
}

// TestIdentityExpiry covers DEC-005: an expired identity is rejected at
// admission, and an identity's expiry bounds valid_until.
func TestIdentityExpiry(t *testing.T) {
	f := newFixture(t)
	f.identities.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 88, Roles: []string{"reviewer"},
		ExpiresAt: start.Add(10 * time.Second)})
	env := delegatedBatch("read").Envelope
	b, err := f.gate.Bind(context.Background(), env, nil, nil, 5, time.Minute)
	if err != nil || !b.ValidUntil.Equal(start.Add(10*time.Second)) {
		t.Fatalf("Bind = %v, %v; want valid until the subject's expiry", b.ValidUntil, err)
	}
	*f.clock = start.Add(10 * time.Second)
	if _, err := f.gate.Admit(context.Background(), delegatedBatch("read")); reason(err) != ReasonIdentityExpired {
		t.Fatalf("Admit at expiry = %v, want %s", err, ReasonIdentityExpired)
	}
}
