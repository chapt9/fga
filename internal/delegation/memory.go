package delegation

import (
	"context"
	"sync"
)

// MemoryStore is an in-memory Store for tests and the development profile.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[memoryKey]Delegation
}

type memoryKey struct {
	tenant string
	id     ID
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: map[memoryKey]Delegation{}}
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, tenant string, id ID) (Delegation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.byID[memoryKey{tenant, id}]
	if !ok {
		return Delegation{}, ErrNotFound
	}
	return d, nil
}

// Put stores d. A child is validated against its stored parent first.
func (s *MemoryStore) Put(d Delegation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Parent != "" {
		parent, ok := s.byID[memoryKey{d.Tenant, d.Parent}]
		if !ok {
			return ErrNotFound
		}
		if err := ValidateChild(d, parent); err != nil {
			return err
		}
	}
	s.byID[memoryKey{d.Tenant, d.ID}] = d
	return nil
}

// Revoke marks a delegation revoked and advances its revision.
func (s *MemoryStore) Revoke(tenant string, id ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := memoryKey{tenant, id}
	d, ok := s.byID[k]
	if !ok {
		return ErrNotFound
	}
	d.Revoked = true
	d.Revision++
	s.byID[k] = d
	return nil
}
