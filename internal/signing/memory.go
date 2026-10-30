package signing

import (
	"context"
	"sync"
	"time"
)

// MemoryConsumption is an in-process Consumption for tests and the
// single-node development profile. It is not shared between processes.
type MemoryConsumption struct {
	mu       sync.Mutex
	consumed map[string]time.Time
}

// NewMemoryConsumption returns an empty consumption record.
func NewMemoryConsumption() *MemoryConsumption {
	return &MemoryConsumption{consumed: map[string]time.Time{}}
}

// Consume implements Consumption.
func (m *MemoryConsumption) Consume(_ context.Context, decisionID string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, done := m.consumed[decisionID]; done {
		return false, nil
	}
	m.consumed[decisionID] = until
	return true, nil
}
