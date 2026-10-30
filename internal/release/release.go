// Package release verifies, prepares and activates policy bundles, and
// serves decisions only from a snapshot that meets the tenant's required
// epoch (specification 2.2, REL-001 to REL-005).
package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"fga/internal/policy"
	"fga/internal/policy/engine"
	"fga/internal/policy/format"
)

// Errors returned by the manager.
var (
	ErrNoActiveSnapshot = errors.New("no active policy snapshot")
	ErrStaleEpoch       = errors.New("active snapshot is older than the required epoch")
	ErrUnknownSnapshot  = errors.New("request names a snapshot this instance does not hold")
)

// State is a step of activation (REL-002).
type State string

const (
	StateReceived State = "RECEIVED"
	StateVerified State = "VERIFIED"
	StatePrepared State = "PREPARED"
	StateReady    State = "READY"
	StateActive   State = "ACTIVE"
	StateRejected State = "REJECTED"
)

// Sentinel is a known request and its expected effect. Every sentinel must
// hold before a candidate becomes ready (REL-004).
type Sentinel struct {
	Name    string
	Set     policy.Set
	Request policy.Request // SnapshotDigest is filled in by the manager
	Want    policy.Effect
}

// Bundle is a signed policy release.
type Bundle struct {
	Epoch     uint64
	Documents map[string][]byte
	Sentinels []Sentinel
	KeyID     string
	Signature []byte
}

// Digest identifies the bundle's documents and sentinels.
func (b Bundle) Digest() (string, error) {
	h := sha256.New()
	h.Write([]byte("fga.bundle/v1\n"))
	names := make([]string, 0, len(b.Documents))
	for name := range b.Documents {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		doc := sha256.Sum256(b.Documents[name])
		fmt.Fprintf(h, "%s\n%x\n", name, doc)
	}
	sentinels, err := json.Marshal(b.Sentinels)
	if err != nil {
		return "", fmt.Errorf("release: encode sentinels: %w", err)
	}
	fmt.Fprintf(h, "sentinels\n%x\n", sha256.Sum256(sentinels))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// SigningBytes are the bytes a publisher signs: the epoch and the digest
// under a fixed domain prefix.
func SigningBytes(epoch uint64, digest string) []byte {
	b := []byte("fga.bundle.signature/v1\n")
	b = binary.BigEndian.AppendUint64(b, epoch)
	return append(b, digest...)
}

// Record is one activation state change.
type Record struct {
	Digest string
	Epoch  uint64
	State  State
	Error  string
	At     time.Time
}

// Snapshot is an activated, immutable bundle.
type Snapshot struct {
	Digest string
	Epoch  uint64
	Engine *engine.Engine
}

// EpochSource reports the authoritative required epoch for a tenant
// (REL-003).
type EpochSource interface {
	RequiredEpoch(ctx context.Context, tenant string) (uint64, error)
}

// Manager holds the active snapshot and the one it replaced. A batch that
// started on the replaced snapshot can finish on it (DEC-004); anything
// older is refused.
type Manager struct {
	publishers map[string]ed25519.PublicKey
	schema     format.Schema
	options    engine.Options
	epochs     EpochSource
	now        func() time.Time

	mu       sync.RWMutex
	active   *Snapshot
	previous *Snapshot
	history  []Record
}

// NewManager returns a manager that trusts the given publisher keys.
func NewManager(publishers map[string]ed25519.PublicKey, schema format.Schema, options engine.Options, epochs EpochSource, now func() time.Time) *Manager {
	return &Manager{publishers: publishers, schema: schema, options: options, epochs: epochs, now: now}
}

// Activate takes a candidate through verification, preparation and sentinel
// checks, then swaps it in. On any failure the candidate is rejected and the
// prior state is kept (REL-001).
func (m *Manager) Activate(ctx context.Context, b Bundle) error {
	digest, err := b.Digest()
	if err != nil {
		return err
	}
	m.record(digest, b.Epoch, StateReceived, nil)

	snap, err := m.prepare(ctx, b, digest)
	if err != nil {
		m.record(digest, b.Epoch, StateRejected, err)
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != nil && b.Epoch <= m.active.Epoch {
		err := fmt.Errorf("release: epoch %d is not above the active epoch %d; a rollback is a new release with a higher epoch", b.Epoch, m.active.Epoch)
		m.appendRecord(digest, b.Epoch, StateRejected, err)
		return err
	}
	m.previous, m.active = m.active, snap
	m.appendRecord(digest, b.Epoch, StateActive, nil)
	return nil
}

func (m *Manager) prepare(ctx context.Context, b Bundle, digest string) (*Snapshot, error) {
	key, ok := m.publishers[b.KeyID]
	if !ok || !ed25519.Verify(key, SigningBytes(b.Epoch, digest), b.Signature) {
		return nil, errors.New("release: bundle signature does not verify")
	}
	m.record(digest, b.Epoch, StateVerified, nil)

	docs := make([]format.Document, 0, len(b.Documents))
	for name, raw := range b.Documents {
		d, err := format.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("release: %s: %w", name, err)
		}
		docs = append(docs, d)
	}
	eng, err := engine.Compile(digest, docs, m.schema, m.options)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	m.record(digest, b.Epoch, StatePrepared, nil)

	for _, s := range b.Sentinels {
		got, err := evaluate(ctx, eng, digest, s)
		if err != nil {
			return nil, fmt.Errorf("release: sentinel %q: %w", s.Name, err)
		}
		if got != s.Want {
			return nil, fmt.Errorf("release: sentinel %q: got %v, want %v", s.Name, got, s.Want)
		}
	}
	m.record(digest, b.Epoch, StateReady, nil)
	return &Snapshot{Digest: digest, Epoch: b.Epoch, Engine: eng}, nil
}

func evaluate(ctx context.Context, eng *engine.Engine, digest string, s Sentinel) (policy.Effect, error) {
	req := s.Request
	req.SnapshotDigest, req.Set = digest, s.Set
	if len(req.Actions) != 1 {
		return policy.EffectUnknown, errors.New("a sentinel names exactly one action")
	}
	res, err := eng.Evaluate(ctx, req)
	if err != nil {
		return policy.EffectUnknown, err
	}
	return res.Actions[req.Actions[0]].Effect, nil
}

// Snapshot returns the active snapshot if it meets the tenant's required
// epoch. A node that cannot establish the epoch does not authorize from a
// stale bundle (REL-003).
func (m *Manager) Snapshot(ctx context.Context, tenant string) (*Snapshot, error) {
	required, err := m.epochs.RequiredEpoch(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("release: required epoch: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return nil, ErrNoActiveSnapshot
	}
	if m.active.Epoch < required {
		return nil, ErrStaleEpoch
	}
	return m.active, nil
}

// Evaluate implements policy.Evaluator by routing to the snapshot the request
// names: the active one or the one it replaced.
func (m *Manager) Evaluate(ctx context.Context, req policy.Request) (policy.Result, error) {
	m.mu.RLock()
	var eng *engine.Engine
	for _, s := range []*Snapshot{m.active, m.previous} {
		if s != nil && s.Digest == req.SnapshotDigest {
			eng = s.Engine
		}
	}
	m.mu.RUnlock()
	if eng == nil {
		return policy.Result{}, ErrUnknownSnapshot
	}
	return eng.Evaluate(ctx, req)
}

// Ready reports whether a snapshot is active. Readiness is never a grant;
// requests still check the required epoch (REL-006).
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active != nil
}

// History returns the activation records in order.
func (m *Manager) History() []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.history)
}

func (m *Manager) record(digest string, epoch uint64, state State, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendRecord(digest, epoch, state, err)
}

func (m *Manager) appendRecord(digest string, epoch uint64, state State, err error) {
	r := Record{Digest: digest, Epoch: epoch, State: state, At: m.now()}
	if err != nil {
		r.Error = err.Error()
	}
	m.history = append(m.history, r)
}

// Change is a sentinel whose effect differs between two snapshots.
type Change struct {
	Sentinel string
	Before   policy.Effect
	After    policy.Effect
}

// EffectChanges evaluates the sentinels against the active snapshot and a
// prepared candidate and lists every change, for the reviewer to acknowledge
// before activation (REL-005). It covers the sentinels only, not every
// principal.
func EffectChanges(ctx context.Context, active, candidate *Snapshot, sentinels []Sentinel) ([]Change, error) {
	var changes []Change
	for _, s := range sentinels {
		before, err := evaluate(ctx, active.Engine, active.Digest, s)
		if err != nil {
			return nil, err
		}
		after, err := evaluate(ctx, candidate.Engine, candidate.Digest, s)
		if err != nil {
			return nil, err
		}
		if before != after {
			changes = append(changes, Change{Sentinel: s.Name, Before: before, After: after})
		}
	}
	return changes, nil
}
