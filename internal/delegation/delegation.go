// Package delegation resolves and checks delegation chains: an agent acting
// for a user carries both identities, and a delegation can only narrow its
// parent (specification 2.5, DLG-001 to DLG-007).
package delegation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// MaxDepth bounds a delegation chain, counting the leaf (DLG-002).
const MaxDepth = 4

// AllActions in a grant covers every action of its resource type.
const AllActions = "*"

// Errors returned when a chain cannot be used. Callers map them to stable
// reason codes.
var (
	ErrNotFound         = errors.New("delegation not found")
	ErrExpired          = errors.New("delegation expired")
	ErrRevoked          = errors.New("delegation revoked")
	ErrTenantMismatch   = errors.New("delegation belongs to another tenant")
	ErrTooDeep          = errors.New("delegation chain too deep")
	ErrCycle            = errors.New("delegation chain has a cycle")
	ErrWidened          = errors.New("delegation is wider than its parent")
	ErrActorMismatch    = errors.New("request actor is not the delegated actor")
	ErrSubjectMismatch  = errors.New("request subject is not the delegated subject")
	ErrAudienceMismatch = errors.New("delegation is not for this executor")
)

// ID identifies a delegation within a tenant.
type ID string

// Grant allows actions on one resource type.
type Grant struct {
	ResourceType string
	Actions      []string
}

// Delegation lets Actor exercise part of Subject's authority, presented only
// by Audience, until ExpiresAt (DLG-001).
type Delegation struct {
	ID        ID
	Tenant    string
	Actor     string
	Subject   string
	Audience  string
	Grants    []Grant
	ExpiresAt time.Time
	Parent    ID // empty for a delegation directly from the subject
	// Revision advances on every change, including revocation (DLG-005).
	Revision uint64
	Revoked  bool
}

// Store reads delegations from authoritative state. Get returns ErrNotFound
// for an unknown ID.
type Store interface {
	Get(ctx context.Context, tenant string, id ID) (Delegation, error)
}

// Chain is a delegation with its ancestors, leaf first, as resolved for one
// request.
type Chain []Delegation

// Leaf returns the delegation the request presented.
func (c Chain) Leaf() Delegation { return c[0] }

// Resolve loads the chain that starts at id and checks that every link is
// usable at now: same tenant, not revoked, not expired, no cycle, no deeper
// than MaxDepth and no wider than its parent. Revoking a parent therefore
// disables its children.
func Resolve(ctx context.Context, store Store, tenant string, id ID, now time.Time) (Chain, error) {
	var chain Chain
	seen := map[ID]bool{}
	for next := id; next != ""; {
		if seen[next] {
			return nil, ErrCycle
		}
		seen[next] = true
		if len(chain) == MaxDepth {
			return nil, ErrTooDeep
		}
		d, err := store.Get(ctx, tenant, next)
		if err != nil {
			return nil, err
		}
		switch {
		case d.Tenant != tenant:
			return nil, ErrTenantMismatch
		case d.Revoked:
			return nil, ErrRevoked
		case !now.Before(d.ExpiresAt):
			return nil, ErrExpired
		}
		if len(chain) > 0 {
			if err := ValidateChild(chain[len(chain)-1], d); err != nil {
				return nil, err
			}
		}
		chain = append(chain, d)
		next = d.Parent
	}
	return chain, nil
}

// ValidateChild checks that child narrows parent: same tenant and subject,
// expiring no later, and granting nothing the parent does not (DLG-002).
func ValidateChild(child, parent Delegation) error {
	switch {
	case child.Tenant != parent.Tenant:
		return ErrTenantMismatch
	case child.Subject != parent.Subject:
		return fmt.Errorf("%w: subject differs", ErrWidened)
	case child.ExpiresAt.After(parent.ExpiresAt):
		return fmt.Errorf("%w: expires after its parent", ErrWidened)
	}
	for _, g := range child.Grants {
		for _, a := range g.Actions {
			if !covers(parent.Grants, g.ResourceType, a) {
				return fmt.Errorf("%w: %s %s", ErrWidened, g.ResourceType, a)
			}
		}
	}
	return nil
}

// Admit checks that the request's actor, subject and presenting executor are
// the ones the leaf delegation names (DLG-001).
func (c Chain) Admit(actor, subject, audience string) error {
	leaf := c.Leaf()
	switch {
	case actor != leaf.Actor:
		return ErrActorMismatch
	case subject != leaf.Subject:
		return ErrSubjectMismatch
	case audience != leaf.Audience:
		return ErrAudienceMismatch
	}
	return nil
}

// Covers reports whether every link of the chain grants action on
// resourceType. The delegation ceiling is checked independently of business
// policy (DLG-004).
func (c Chain) Covers(resourceType, action string) bool {
	for _, d := range c {
		if !covers(d.Grants, resourceType, action) {
			return false
		}
	}
	return len(c) > 0
}

func covers(grants []Grant, resourceType, action string) bool {
	for _, g := range grants {
		if g.ResourceType == resourceType && (slices.Contains(g.Actions, action) || slices.Contains(g.Actions, AllActions)) {
			return true
		}
	}
	return false
}

// Revisions returns each link's revision, leaf first, for binding into a
// decision and rechecking at admission and commit (DEC-006).
func (c Chain) Revisions() []uint64 {
	revs := make([]uint64, len(c))
	for i, d := range c {
		revs[i] = d.Revision
	}
	return revs
}
