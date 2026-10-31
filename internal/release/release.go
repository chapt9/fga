// Package release verifies, prepares and activates policy bundles, and
// serves decisions only from a snapshot that meets the tenant's required
// epoch (specification 2.5, REL-001 to REL-005).
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

	"fga/internal/labels"
	"fga/internal/policy"
	"fga/internal/policy/engine"
	"fga/internal/policy/format"
	"fga/internal/signing"
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

// Format is the manifest format of a policy release.
const Format = "fga.release/v1"

// Info is the part of a release manifest beyond its documents, ceiling
// declaration and sentinels (REL-001). The build-dependent fields name the
// environment the release was validated against; an instance prepares only
// a release whose environment matches its own (POL-010).
type Info struct {
	Format   string `json:"format"`
	Audience string `json:"audience"`
	// Business names the documents of the business set.
	Business          []string `json:"business"`
	EvaluatorVersion  string   `json:"evaluator_version"`
	ExpressionLibrary string   `json:"expression_library"`
	Functions         string   `json:"functions"`
	CostLimit         uint64   `json:"cost_limit"`
	SchemaDigest      string   `json:"schema_digest"`
	OperationsDigest  string   `json:"operations_digest"`
	// LabelOrder lists labels from least to most restrictive. It is empty
	// with generation 0 until D-06 closes and labels are used (R1-C).
	LabelOrder      []string `json:"label_order"`
	LabelGeneration uint64   `json:"label_generation"`
	// TestEvidence references the conformance and sentinel evidence the
	// publisher reviewed (REL-005).
	TestEvidence string `json:"test_evidence"`
	// ObligationMapping, if set, is the release's explicit mapping from
	// policy outputs and prerequisites to platform obligations (POL-011).
	// Without it, outputs stay data and no decision carries an obligation.
	ObligationMapping *ObligationMapping `json:"obligation_mapping,omitempty"`
}

// ObligationMapping maps policy outputs and allow prerequisites to the
// obligations of signing.ObligationsV1 (POL-011, APR-007). It is part of
// the signed manifest, so only a publisher can change it.
type ObligationMapping struct {
	Version string `json:"version"`
	// Outputs maps an output name to the obligation type it becomes.
	Outputs map[string]string `json:"outputs,omitempty"`
	// Prerequisites maps an allow prerequisite to the obligation type it
	// becomes: the enforcing role then meets it instead of the decision
	// role resolving it first. Only a reservation can be mapped; an
	// approval is always resolved before a decision is signed.
	Prerequisites map[string]string `json:"prerequisites,omitempty"`
}

// check validates the mapping's structure.
func (m ObligationMapping) check() error {
	var errs []error
	if m.Version != signing.ObligationsV1 {
		errs = append(errs, fmt.Errorf("obligation_mapping.version must be %q", signing.ObligationsV1))
	}
	for out, t := range m.Outputs {
		if t != signing.MetadataProjection {
			errs = append(errs, fmt.Errorf("obligation_mapping: output %q maps to %q, which no output can become", out, t))
		}
	}
	for p, t := range m.Prerequisites {
		if p != policy.RequireReservation || t != signing.Reservation {
			errs = append(errs, fmt.Errorf("obligation_mapping: prerequisite %q cannot become %q", p, t))
		}
	}
	return errors.Join(errs...)
}

// checkOutputs validates the outputs a mapping turns into obligations: a
// metadata projection is a list of field names.
func (m ObligationMapping) checkOutputs(docs []format.Document) error {
	var errs []error
	for _, d := range docs {
		for _, r := range d.Rules {
			for name, v := range r.Outputs {
				if m.Outputs[name] != signing.MetadataProjection {
					continue
				}
				if list, ok := v.([]any); !ok || len(list) == 0 {
					errs = append(errs, fmt.Errorf("rule %q: output %q is a metadata projection, a non-empty list of field names", r.ID, name))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// Environment is what an instance checks a release against: its registry,
// its evaluator build and its limits.
type Environment struct {
	Schema           format.Schema
	SchemaDigest     string
	OperationsDigest string
	Audience         string
	// MaxCostLimit bounds the cost limit a release may select (DEC-009).
	MaxCostLimit uint64
}

// Stamp fills the build-dependent fields of info from the environment and
// this evaluator build. Publishing tools call it before signing.
func (e Environment) Stamp(info *Info) {
	info.Format = Format
	info.EvaluatorVersion, info.ExpressionLibrary, info.Functions = engine.EvaluatorVersion, engine.ExpressionLibrary, engine.Functions
	info.SchemaDigest, info.OperationsDigest = e.SchemaDigest, e.OperationsDigest
}

// check reports why info does not match the environment.
func (e Environment) check(info Info) error {
	var errs []error
	for _, f := range []struct{ name, got, want string }{
		{"format", info.Format, Format},
		{"audience", info.Audience, e.Audience},
		{"evaluator_version", info.EvaluatorVersion, engine.EvaluatorVersion},
		{"expression_library", info.ExpressionLibrary, engine.ExpressionLibrary},
		{"functions", info.Functions, engine.Functions},
		{"schema_digest", info.SchemaDigest, e.SchemaDigest},
		{"operations_digest", info.OperationsDigest, e.OperationsDigest},
	} {
		if f.got != f.want {
			errs = append(errs, fmt.Errorf("%s is %q, this instance requires %q", f.name, f.got, f.want))
		}
	}
	if info.CostLimit == 0 || info.CostLimit > e.MaxCostLimit {
		errs = append(errs, fmt.Errorf("cost_limit must be in (0, %d]", e.MaxCostLimit))
	}
	seen := map[string]bool{}
	for _, l := range info.LabelOrder {
		if l == "" || seen[l] {
			errs = append(errs, fmt.Errorf("label order has an empty or repeated label %q", l))
		}
		seen[l] = true
	}
	if (len(info.LabelOrder) == 0) != (info.LabelGeneration == 0) {
		errs = append(errs, errors.New("a label order needs a generation above 0, and only a label order has one"))
	}
	if info.ObligationMapping != nil {
		errs = append(errs, info.ObligationMapping.check())
	}
	return errors.Join(errs...)
}

// Bundle is a signed policy release.
type Bundle struct {
	Epoch     uint64
	Info      Info
	Documents map[string][]byte
	// Ceiling names the documents of the ceiling set. A release must declare
	// it, even when it is empty, so that a missing ceiling set is never
	// mistaken for an empty one (POL-007, V-153).
	Ceiling         []string
	CeilingDeclared bool
	Sentinels       []Sentinel
	KeyID           string
	Signature       []byte
}

// Digest identifies the bundle's documents and sentinels.
func (b Bundle) Digest() (string, error) {
	h := sha256.New()
	h.Write([]byte("fga.bundle/v2\n"))
	info, err := json.Marshal(b.Info)
	if err != nil {
		return "", fmt.Errorf("release: encode manifest: %w", err)
	}
	fmt.Fprintf(h, "manifest\n%x\n", sha256.Sum256(info))
	names := make([]string, 0, len(b.Documents))
	for name := range b.Documents {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		doc := sha256.Sum256(b.Documents[name])
		fmt.Fprintf(h, "%s\n%x\n", name, doc)
	}
	if b.CeilingDeclared {
		ceiling := slices.Sorted(slices.Values(b.Ceiling))
		fmt.Fprintf(h, "ceiling %d\n", len(ceiling))
		for _, name := range ceiling {
			fmt.Fprintf(h, "%s\n", name)
		}
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
	Info   Info
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
	env        Environment
	epochs     EpochSource
	now        func() time.Time

	mu       sync.RWMutex
	active   *Snapshot
	previous *Snapshot
	history  []Record
}

// NewManager returns a manager that trusts the given publisher keys and
// prepares releases for env.
func NewManager(publishers map[string]ed25519.PublicKey, env Environment, epochs EpochSource, now func() time.Time) *Manager {
	return &Manager{publishers: publishers, env: env, epochs: epochs, now: now}
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

	if err := m.env.check(b.Info); err != nil {
		return nil, fmt.Errorf("release: manifest: %w", err)
	}
	if !b.CeilingDeclared {
		return nil, errors.New("release: the manifest does not declare the ceiling set")
	}
	business := map[string]bool{}
	for _, name := range b.Info.Business {
		if _, ok := b.Documents[name]; !ok || business[name] {
			return nil, fmt.Errorf("release: business document %q is missing or listed twice", name)
		}
		business[name] = true
	}
	declared := map[string]bool{}
	for _, name := range b.Ceiling {
		if _, ok := b.Documents[name]; !ok || declared[name] {
			return nil, fmt.Errorf("release: ceiling document %q is missing or listed twice", name)
		}
		declared[name] = true
	}
	docs := make([]format.Document, 0, len(b.Documents))
	for name, raw := range b.Documents {
		d, err := format.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("release: %s: %w", name, err)
		}
		if (d.Set == format.SetCeiling) != declared[name] {
			return nil, fmt.Errorf("release: %s: a document is in the ceiling set exactly when the manifest declares it there", name)
		}
		if (d.Set == format.SetBusiness) != business[name] {
			return nil, fmt.Errorf("release: %s: a document is in the business set exactly when the manifest declares it there", name)
		}
		docs = append(docs, d)
	}
	if om := b.Info.ObligationMapping; om != nil {
		if err := om.checkOutputs(docs); err != nil {
			return nil, fmt.Errorf("release: %w", err)
		}
	}
	eng, err := engine.Compile(digest, docs, m.env.Schema, engine.Options{CostLimit: b.Info.CostLimit})
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	m.record(digest, b.Epoch, StatePrepared, nil)

	for _, s := range b.Sentinels {
		got, err := evaluate(ctx, eng, digest, b.Info.LabelOrder, s)
		if err != nil {
			return nil, fmt.Errorf("release: sentinel %q: %w", s.Name, err)
		}
		if got != s.Want {
			return nil, fmt.Errorf("release: sentinel %q: got %v, want %v", s.Name, got, s.Want)
		}
	}
	m.record(digest, b.Epoch, StateReady, nil)
	return &Snapshot{Digest: digest, Epoch: b.Epoch, Info: b.Info, Engine: eng}, nil
}

// evaluate decides a sentinel as the decision role would, with the label
// ranks the release's order gives.
func evaluate(ctx context.Context, eng *engine.Engine, digest string, order []string, s Sentinel) (policy.Effect, error) {
	req := s.Request
	req.SnapshotDigest, req.Set = digest, s.Set
	req.Principal, req.Resource = labels.Ranked(order, req.Principal, req.Resource)
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
		before, err := evaluate(ctx, active.Engine, active.Digest, active.Info.LabelOrder, s)
		if err != nil {
			return nil, err
		}
		after, err := evaluate(ctx, candidate.Engine, candidate.Digest, candidate.Info.LabelOrder, s)
		if err != nil {
			return nil, err
		}
		if before != after {
			changes = append(changes, Change{Sentinel: s.Name, Before: before, After: after})
		}
	}
	return changes, nil
}
