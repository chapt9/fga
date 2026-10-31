// Package gate validates the execution envelope before policy evaluation and
// rechecks a decision's bindings at admission and commit (specification
// 2.2, POL-003 step 1, ID-002, ID-004, DLG-001 to DLG-007, DEC-005, DEC-006).
package gate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"fga/internal/decision"
	"fga/internal/delegation"
	"fga/internal/identity"
	"fga/internal/policy"
	"fga/internal/registry"
)

// Reasons for rejecting an envelope or a recheck.
const (
	ReasonTenantMissing         decision.Reason = "TENANT_MISSING"
	ReasonSubjectMismatch       decision.Reason = "SUBJECT_WITHOUT_DELEGATION"
	ReasonIdentityUnknown       decision.Reason = "IDENTITY_UNKNOWN"
	ReasonIdentityStale         decision.Reason = "IDENTITY_STALE"
	ReasonIdentityDisabled      decision.Reason = "IDENTITY_DISABLED"
	ReasonIdentityExpired       decision.Reason = "IDENTITY_EXPIRED"
	ReasonDelegationUnknown     decision.Reason = "DELEGATION_UNKNOWN"
	ReasonDelegationExpired     decision.Reason = "DELEGATION_EXPIRED"
	ReasonDelegationRevoked     decision.Reason = "DELEGATION_REVOKED"
	ReasonDelegationInvalid     decision.Reason = "DELEGATION_INVALID"
	ReasonDelegationActor       decision.Reason = "DELEGATION_ACTOR_MISMATCH"
	ReasonDelegationSubject     decision.Reason = "DELEGATION_SUBJECT_MISMATCH"
	ReasonDelegationAudience    decision.Reason = "DELEGATION_AUDIENCE_MISMATCH"
	ReasonDelegationScope       decision.Reason = "DELEGATION_SCOPE"
	ReasonDelegationChanged     decision.Reason = "DELEGATION_CHANGED"
	ReasonActorCapability       decision.Reason = "ACTOR_CAPABILITY"
	ReasonDecisionExpired       decision.Reason = "DECISION_EXPIRED"
	ReasonResourceChanged       decision.Reason = "RESOURCE_CHANGED"
	ReasonPolicyEpochSuperseded decision.Reason = "POLICY_EPOCH_SUPERSEDED"
	ReasonRecipientUnknown      decision.Reason = "RECIPIENT_UNKNOWN"
	ReasonRecipientInactive     decision.Reason = "RECIPIENT_INACTIVE"
)

// ErrUnknownRecipient is returned for a fingerprint with no recipient key in
// the tenant.
var ErrUnknownRecipient = errors.New("unknown recipient key")

// RecipientKey is a recipient public key as recorded in authoritative state
// (RCP-001). Only an active key resolves a recipient check.
type RecipientKey struct {
	Tenant      string
	Fingerprint string
	Principal   string
	KeyVersion  uint64
	Revision    uint64
	Active      bool
}

// Recipients resolves recipient-key fingerprints (RES-009).
type Recipients interface {
	Recipient(ctx context.Context, tenant, fingerprint string) (RecipientKey, error)
}

// Capabilities reports what an actor may execute at all, whatever any
// subject permits (DLG-004).
type Capabilities interface {
	Allows(ctx context.Context, tenant, actor, resourceType, action string) (bool, error)
}

// Resources revalidates a bound resource (RES-004). registry.Resolver
// implements it.
type Resources interface {
	Revalidate(ctx context.Context, bound registry.Resource) error
}

// Epochs reports a tenant's required policy epoch (REL-003).
type Epochs interface {
	RequiredEpoch(ctx context.Context, tenant string) (uint64, error)
}

// Gate implements decision.Gate.
type Gate struct {
	identities   identity.Store
	delegations  delegation.Store
	capabilities Capabilities
	resources    Resources
	epochs       Epochs
	recipients   Recipients
	now          func() time.Time
}

var _ decision.Gate = (*Gate)(nil)

// Deps are the authoritative sources the gate reads.
type Deps struct {
	Identities   identity.Store
	Delegations  delegation.Store
	Capabilities Capabilities
	Resources    Resources
	Epochs       Epochs
	Recipients   Recipients
	Now          func() time.Time
}

// New returns a Gate. Every dependency is required.
func New(d Deps) (*Gate, error) {
	if d.Identities == nil || d.Delegations == nil || d.Capabilities == nil || d.Resources == nil || d.Epochs == nil ||
		d.Recipients == nil || d.Now == nil {
		return nil, errors.New("gate: every dependency is required")
	}
	return &Gate{identities: d.Identities, delegations: d.Delegations, capabilities: d.Capabilities,
		resources: d.Resources, epochs: d.Epochs, recipients: d.Recipients, now: d.Now}, nil
}

func reject(r decision.Reason) error { return &decision.Rejection{Reason: r} }

// Admit implements decision.Gate. The request principal is the subject when
// a delegation applies, otherwise the actor (DLG-003). Delegation scope and
// the actor's capability apply to operation checks; a recipient check is
// evaluated for the recipient its fingerprint resolves to, which must be an
// active key of an enabled identity (RES-009). Roles and attributes always
// come from the identity store.
func (g *Gate) Admit(ctx context.Context, b decision.Batch) (decision.Admission, error) {
	env := b.Envelope
	if env.Tenant == "" {
		return decision.Admission{}, reject(ReasonTenantMissing)
	}
	if (env.Delegation == "") != (env.Subject.ID == "") {
		return decision.Admission{}, reject(ReasonSubjectMismatch)
	}
	actor, err := g.current(ctx, env.Tenant, env.Actor)
	if err != nil {
		return decision.Admission{}, err
	}
	principal, principalRef := actor, env.Actor
	var chain delegation.Chain
	if env.Delegation != "" {
		if principal, err = g.current(ctx, env.Tenant, env.Subject); err != nil {
			return decision.Admission{}, err
		}
		principalRef = env.Subject
		if chain, err = g.chain(ctx, env); err != nil {
			return decision.Admission{}, err
		}
	}
	adm := decision.Admission{Principal: toPrincipal(principal), PrincipalRef: principalRef}
	for _, c := range b.Checks {
		if c.IsRecipient() {
			if _, done := adm.Recipients[c.PrincipalBinding]; done {
				continue
			}
			r, err := g.recipient(ctx, env.Tenant, c.PrincipalBinding)
			if err != nil {
				return decision.Admission{}, err
			}
			if adm.Recipients == nil {
				adm.Recipients = map[string]decision.Recipient{}
			}
			adm.Recipients[c.PrincipalBinding] = r
			continue
		}
		if chain != nil && !chain.Covers(c.Resource.Kind, c.Action) {
			return decision.Admission{}, reject(ReasonDelegationScope)
		}
		ok, err := g.capabilities.Allows(ctx, env.Tenant, env.Actor.ID, c.Resource.Kind, c.Action)
		if err != nil {
			return decision.Admission{}, fmt.Errorf("gate: actor capability: %w", err)
		}
		if !ok {
			return decision.Admission{}, reject(ReasonActorCapability)
		}
	}
	return adm, nil
}

func toPrincipal(id identity.Identity) policy.Principal {
	return policy.Principal{ID: id.ID, Roles: id.Roles, Attributes: id.Attributes}
}

// recipient resolves a fingerprint to an active key and its enabled,
// unexpired principal at the principal's current revision.
func (g *Gate) recipient(ctx context.Context, tenant, fingerprint string) (decision.Recipient, error) {
	key, err := g.recipients.Recipient(ctx, tenant, fingerprint)
	switch {
	case errors.Is(err, ErrUnknownRecipient):
		return decision.Recipient{}, reject(ReasonRecipientUnknown)
	case err != nil:
		return decision.Recipient{}, fmt.Errorf("gate: recipient: %w", err)
	case !key.Active:
		return decision.Recipient{}, reject(ReasonRecipientInactive)
	}
	id, err := g.identities.Get(ctx, tenant, key.Principal)
	switch {
	case errors.Is(err, identity.ErrUnknown):
		return decision.Recipient{}, reject(ReasonRecipientUnknown)
	case err != nil:
		return decision.Recipient{}, fmt.Errorf("gate: recipient identity: %w", err)
	case id.Disabled || id.ExpiredAt(g.now()):
		return decision.Recipient{}, reject(ReasonRecipientInactive)
	}
	return decision.Recipient{Principal: toPrincipal(id), Ref: decision.Ref{ID: id.ID, Revision: id.Revision},
		KeyVersion: key.KeyVersion, KeyRevision: key.Revision}, nil
}

// MemoryRecipients is an in-memory Recipients for tests and the
// development profile, keyed by tenant and fingerprint.
type MemoryRecipients map[[2]string]RecipientKey

// Recipient implements Recipients.
func (m MemoryRecipients) Recipient(_ context.Context, tenant, fingerprint string) (RecipientKey, error) {
	k, ok := m[[2]string{tenant, fingerprint}]
	if !ok {
		return RecipientKey{}, ErrUnknownRecipient
	}
	return k, nil
}

// current loads an identity and checks it is enabled and at the revision the
// request was built from (ID-004).
func (g *Gate) current(ctx context.Context, tenant string, ref decision.Ref) (identity.Identity, error) {
	id, err := g.identities.Get(ctx, tenant, ref.ID)
	switch {
	case errors.Is(err, identity.ErrUnknown):
		return identity.Identity{}, reject(ReasonIdentityUnknown)
	case err != nil:
		return identity.Identity{}, fmt.Errorf("gate: identity: %w", err)
	case id.Disabled:
		return identity.Identity{}, reject(ReasonIdentityDisabled)
	case id.ExpiredAt(g.now()):
		return identity.Identity{}, reject(ReasonIdentityExpired)
	case id.Revision != ref.Revision:
		return identity.Identity{}, reject(ReasonIdentityStale)
	}
	return id, nil
}

// chain resolves and admits the envelope's delegation.
func (g *Gate) chain(ctx context.Context, env decision.Envelope) (delegation.Chain, error) {
	chain, err := delegation.Resolve(ctx, g.delegations, env.Tenant, delegation.ID(env.Delegation), g.now())
	if err == nil {
		err = chain.Admit(env.Actor.ID, env.Subject.ID, env.Adapter)
	}
	if err == nil {
		return chain, nil
	}
	for target, reason := range map[error]decision.Reason{
		delegation.ErrNotFound:         ReasonDelegationUnknown,
		delegation.ErrExpired:          ReasonDelegationExpired,
		delegation.ErrRevoked:          ReasonDelegationRevoked,
		delegation.ErrTenantMismatch:   ReasonDelegationInvalid,
		delegation.ErrTooDeep:          ReasonDelegationInvalid,
		delegation.ErrCycle:            ReasonDelegationInvalid,
		delegation.ErrWidened:          ReasonDelegationInvalid,
		delegation.ErrActorMismatch:    ReasonDelegationActor,
		delegation.ErrSubjectMismatch:  ReasonDelegationSubject,
		delegation.ErrAudienceMismatch: ReasonDelegationAudience,
	} {
		if errors.Is(err, target) {
			return nil, reject(reason)
		}
	}
	return nil, fmt.Errorf("gate: delegation: %w", err)
}

// Binding is the authority an allowed decision was bound to. Enforcement
// points recheck it at read admission and immediately before a mutation's
// irreversible checkpoint (DEC-006).
type Binding struct {
	Envelope            decision.Envelope
	DelegationRevisions []uint64
	Resources           []registry.Resource
	PolicyEpoch         uint64
	ValidUntil          time.Time
}

// Bind records the authority behind an allowed decision. ValidUntil is the
// earliest of the decision-age limit, the actor's and subject's identity
// expiry and every delegation expiry (DEC-005).
func (g *Gate) Bind(ctx context.Context, env decision.Envelope, resources []registry.Resource, policyEpoch uint64, maxAge time.Duration) (Binding, error) {
	b := Binding{Envelope: env, Resources: slices.Clone(resources), PolicyEpoch: policyEpoch, ValidUntil: g.now().Add(maxAge)}
	refs := []decision.Ref{env.Actor}
	if env.Delegation != "" {
		refs = append(refs, env.Subject)
	}
	for _, ref := range refs {
		id, err := g.current(ctx, env.Tenant, ref)
		if err != nil {
			return Binding{}, err
		}
		if !id.ExpiresAt.IsZero() && id.ExpiresAt.Before(b.ValidUntil) {
			b.ValidUntil = id.ExpiresAt
		}
	}
	if env.Delegation != "" {
		chain, err := g.chain(ctx, env)
		if err != nil {
			return Binding{}, err
		}
		b.DelegationRevisions = chain.Revisions()
		for _, d := range chain {
			if d.ExpiresAt.Before(b.ValidUntil) {
				b.ValidUntil = d.ExpiresAt
			}
		}
	}
	return b, nil
}

// Recheck returns nil only if nothing the decision was bound to has changed:
// it is still valid, the identities and delegation chain are at the same
// revisions, every bound resource is unchanged and the tenant's required
// epoch has not passed the decision's (DEC-006). A mismatch needs a new
// decision.
func (g *Gate) Recheck(ctx context.Context, b Binding) error {
	if !g.now().Before(b.ValidUntil) {
		return reject(ReasonDecisionExpired)
	}
	env := b.Envelope
	if _, err := g.current(ctx, env.Tenant, env.Actor); err != nil {
		return err
	}
	if env.Delegation != "" {
		if _, err := g.current(ctx, env.Tenant, env.Subject); err != nil {
			return err
		}
		chain, err := g.chain(ctx, env)
		if err != nil {
			return err
		}
		if !slices.Equal(chain.Revisions(), b.DelegationRevisions) {
			return reject(ReasonDelegationChanged)
		}
	}
	for _, r := range b.Resources {
		err := g.resources.Revalidate(ctx, r)
		switch {
		case errors.Is(err, registry.ErrStale), errors.Is(err, registry.ErrUnknownResource):
			return reject(ReasonResourceChanged)
		case err != nil:
			return fmt.Errorf("gate: resource: %w", err)
		}
	}
	required, err := g.epochs.RequiredEpoch(ctx, env.Tenant)
	if err != nil {
		return fmt.Errorf("gate: required epoch: %w", err)
	}
	if required > b.PolicyEpoch {
		return reject(ReasonPolicyEpochSuperseded)
	}
	return nil
}
