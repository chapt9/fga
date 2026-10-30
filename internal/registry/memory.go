package registry

import (
	"context"
	"sync"
)

// MemoryCatalog is an in-memory Catalog for tests and the development
// profile.
type MemoryCatalog struct {
	mu        sync.RWMutex
	resources map[tenantKey]Resource
	aliases   map[aliasKey]string
}

type tenantKey struct{ tenant, id string }

type aliasKey struct {
	tenant string
	alias  Alias
}

// NewMemoryCatalog returns an empty catalog.
func NewMemoryCatalog() *MemoryCatalog {
	return &MemoryCatalog{resources: map[tenantKey]Resource{}, aliases: map[aliasKey]string{}}
}

// LookupAlias implements Catalog.
func (c *MemoryCatalog) LookupAlias(_ context.Context, tenant string, alias Alias) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, ok := c.aliases[aliasKey{tenant, alias}]
	if !ok {
		return "", ErrUnknownAlias
	}
	return id, nil
}

// Get implements Catalog.
func (c *MemoryCatalog) Get(_ context.Context, tenant, id string) (Resource, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.resources[tenantKey{tenant, id}]
	if !ok {
		return Resource{}, ErrUnknownResource
	}
	return r, nil
}

// Put stores a resource.
func (c *MemoryCatalog) Put(r Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources[tenantKey{r.Tenant, r.ID}] = r
}

// SetAlias points alias at a resource of the same tenant.
func (c *MemoryCatalog) SetAlias(tenant string, alias Alias, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.aliases[aliasKey{tenant, alias}] = id
}

// Rename moves an alias to a new name. The resource and its permission
// identity do not change (RES-005).
func (c *MemoryCatalog) Rename(tenant string, from, to Alias) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.aliases[aliasKey{tenant, from}]
	if !ok {
		return ErrUnknownAlias
	}
	delete(c.aliases, aliasKey{tenant, from})
	c.aliases[aliasKey{tenant, to}] = id
	return nil
}
