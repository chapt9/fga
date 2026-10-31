// Package identity holds verified identities as authoritative state: their
// revision, status, roles and attributes (specification 2.5, ID-002 to
// ID-004). Roles and attributes are never taken from a request.
package identity

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// ErrUnknown is returned for an identity that does not exist in a tenant.
var ErrUnknown = errors.New("unknown identity")

// Identity is a user, agent or service as recorded by the platform.
type Identity struct {
	ID     string
	Tenant string
	// Revision advances on every change to status, roles or attributes.
	Revision   uint64
	Disabled   bool
	Roles      []string
	Attributes map[string]any
}

// Store reads identities from authoritative state.
type Store interface {
	Get(ctx context.Context, tenant, id string) (Identity, error)
}

// MemoryStore is an in-memory Store for tests and the development profile.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[[2]string]Identity
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: map[[2]string]Identity{}}
}

// Get implements Store. The returned roles are a copy.
func (s *MemoryStore) Get(_ context.Context, tenant, id string) (Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.byID[[2]string{tenant, id}]
	if !ok {
		return Identity{}, ErrUnknown
	}
	i.Roles = slices.Clone(i.Roles)
	return i, nil
}

// Put stores an identity.
func (s *MemoryStore) Put(i Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[[2]string{i.Tenant, i.ID}] = i
}
