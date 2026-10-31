// Package admission bounds the work each tenant can start (specification
// 2.5, AVL-006): concurrent requests and concurrent ciphertext streams per
// tenant, and concurrent requests overall. Overload is rejected at once
// rather than queued without bound, so a busy tenant cannot starve others
// and no rejection ever grants anything.
package admission

import (
	"errors"
	"sync"
)

// Limits are the bounds; every value must be positive.
type Limits struct {
	// TenantRequests bounds one tenant's concurrent requests, streams
	// included.
	TenantRequests int `json:"tenant_requests"`
	// TenantStreams bounds one tenant's concurrent ciphertext uploads and
	// downloads, and so the bytes it can have in flight.
	TenantStreams int `json:"tenant_streams"`
	// TotalRequests bounds all concurrent requests of the role.
	TotalRequests int `json:"total_requests"`
}

// DefaultLimits are the initial values (D-10 open; not measured).
var DefaultLimits = Limits{TenantRequests: 64, TenantStreams: 8, TotalRequests: 512}

// Validate reports whether every bound is positive.
func (l Limits) Validate() error {
	if l.TenantRequests <= 0 || l.TenantStreams <= 0 || l.TotalRequests <= 0 {
		return errors.New("admission: every limit must be positive")
	}
	return nil
}

// Limiter counts admitted work.
type Limiter struct {
	limits  Limits
	mu      sync.Mutex
	total   int
	tenants map[string]*count
}

type count struct{ requests, streams int }

// New returns a Limiter.
func New(l Limits) *Limiter { return &Limiter{limits: l, tenants: map[string]*count{}} }

// Acquire admits one request of tenant, a stream if stream is set. It
// returns a release function, or false when a bound is reached.
func (l *Limiter) Acquire(tenant string, stream bool) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.tenants[tenant]
	if c == nil {
		c = &count{}
		l.tenants[tenant] = c
	}
	if l.total >= l.limits.TotalRequests || c.requests >= l.limits.TenantRequests || (stream && c.streams >= l.limits.TenantStreams) {
		return nil, false
	}
	l.total++
	c.requests++
	if stream {
		c.streams++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			c.requests--
			if stream {
				c.streams--
			}
			if c.requests == 0 {
				delete(l.tenants, tenant)
			}
		})
	}, true
}
