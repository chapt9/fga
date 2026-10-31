// Package audit records mandatory audit events in an outbox that an exporter
// drains (specification 2.5, AUD-001 to AUD-003). An event that cannot be
// recorded stops the operation it describes; it is never dropped silently.
package audit

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

// ErrFull is returned when the outbox cannot take another event. Callers
// must refuse the operation rather than continue without evidence (AUD-002).
var ErrFull = errors.New("audit outbox is full")

// Kind distinguishes the events AUD-002 requires to be separate.
type Kind string

const (
	KindDecision            Kind = "decision"
	KindKeyRelease          Kind = "key_release"
	KindMutation            Kind = "mutation"
	KindApprovalConsumption Kind = "approval_consumption"
	KindExternalDelivery    Kind = "external_delivery"
	// KindReadAdmission is an admitted ciphertext read (CNT-008), and
	// KindEnvelopePublication the publication or retirement of a recipient
	// envelope (KEY-009). KindKeyRelease is an envelope delivery.
	KindReadAdmission       Kind = "read_admission"
	KindEnvelopePublication Kind = "envelope_publication"
)

// Target names the exact object, version and envelope an outcome event is
// about, by identifier and digest only (KEY-009, DSC-003).
type Target struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Version    string `json:"version,omitempty"`
	Recipient  string `json:"recipient,omitempty"`
	Envelope   string `json:"envelope,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Signer     string `json:"signer,omitempty"`
	Digest     string `json:"digest,omitempty"`
	// KEKVersion is the key-encryption key version a server-mode data key
	// was sealed or released under (SSE-003).
	KEKVersion uint32 `json:"kek_version,omitempty"`
}

// Check summarizes one check. It names resources and actions but carries no
// attribute values, labels or arguments (AUD-003).
type Check struct {
	ID           string `json:"id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Effect       string `json:"effect"`
	Reason       string `json:"reason,omitempty"`
}

// Event is one audit record. Decisions and outcomes are separate events
// joined by DecisionID and OperationID (AUD-001).
type Event struct {
	ID           string    `json:"id"`
	Kind         Kind      `json:"kind"`
	Tenant       string    `json:"tenant"`
	DecisionID   string    `json:"decision_id,omitempty"`
	OperationID  string    `json:"operation_id,omitempty"`
	Actor        string    `json:"actor"`
	Subject      string    `json:"subject,omitempty"`
	Delegation   string    `json:"delegation,omitempty"`
	Outcome      string    `json:"outcome"`
	Reason       string    `json:"reason,omitempty"`
	BundleDigest string    `json:"bundle_digest,omitempty"`
	PolicyEpoch  uint64    `json:"policy_epoch,omitempty"`
	Checks       []Check   `json:"checks,omitempty"`
	Targets      []Target  `json:"targets,omitempty"`
	At           time.Time `json:"at"`
}

// Outbox stores events until they are delivered. Append returns only after
// the event is recorded.
type Outbox interface {
	Append(ctx context.Context, e Event) error
	// Pending returns up to limit undelivered events, oldest first.
	Pending(ctx context.Context, limit int) ([]Event, error)
	// MarkDelivered is idempotent: marking an event twice, or an unknown
	// event, is not an error (AUD-003).
	MarkDelivered(ctx context.Context, ids []string) error
}

// MemoryOutbox is a bounded in-process Outbox for tests and the development
// profile. It is not durable across restarts.
type MemoryOutbox struct {
	mu       sync.Mutex
	capacity int
	events   []Event
	index    map[string]int
}

// NewMemoryOutbox returns an outbox that holds at most capacity undelivered
// events.
func NewMemoryOutbox(capacity int) *MemoryOutbox {
	return &MemoryOutbox{capacity: capacity, index: map[string]int{}}
}

// Append implements Outbox. Appending an event ID that is already pending is
// a no-op, so a retried append does not duplicate the record.
func (o *MemoryOutbox) Append(_ context.Context, e Event) error {
	if e.ID == "" {
		return errors.New("audit: event ID is required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, dup := o.index[e.ID]; dup {
		return nil
	}
	if len(o.events) >= o.capacity {
		return ErrFull
	}
	e.Checks = slices.Clone(e.Checks)
	o.index[e.ID] = len(o.events)
	o.events = append(o.events, e)
	return nil
}

// Pending implements Outbox.
func (o *MemoryOutbox) Pending(_ context.Context, limit int) ([]Event, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := min(limit, len(o.events))
	out := make([]Event, n)
	for i := range n {
		out[i] = o.events[i]
		out[i].Checks = slices.Clone(o.events[i].Checks)
	}
	return out, nil
}

// MarkDelivered implements Outbox.
func (o *MemoryOutbox) MarkDelivered(_ context.Context, ids []string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	kept := o.events[:0]
	for _, e := range o.events {
		if !drop[e.ID] {
			kept = append(kept, e)
		}
	}
	o.events = kept
	o.index = make(map[string]int, len(kept))
	for i, e := range kept {
		o.index[e.ID] = i
	}
	return nil
}

// Saturation reports the fraction of capacity in use, for the alarm that
// must fire before evidence can no longer be recorded (AUD-002).
func (o *MemoryOutbox) Saturation() float64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return float64(len(o.events)) / float64(o.capacity)
}
