package release

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/policy"
	"fga/internal/policy/engine"
)

type testSchema map[string][]string

func (s testSchema) HasResourceType(t string) bool { _, ok := s[t]; return ok }
func (s testSchema) HasAction(t, a string) bool    { return slices.Contains(s[t], a) }

type fixedEpochs map[string]uint64

func (f fixedEpochs) RequiredEpoch(_ context.Context, tenant string) (uint64, error) {
	return f[tenant], nil
}

var (
	schema         = testSchema{"document.text_unit": {"read", "use-in-model"}}
	pub, priv, _   = ed25519.GenerateKey(nil)
	reviewersRead  = `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[{"id":"r","effect":"allow","actions":["read"],"roles":["reviewer"]}]}`
	nobodyReads    = `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[{"id":"r","effect":"deny","actions":["read"],"roles":["*"]}]}`
	brokenDocument = `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[{"id":"r","effect":"allow","actions":["read"],"roles":["reviewer"],"when":"principal.id =="}]}`
)

func reviewerSentinel(want policy.Effect) Sentinel {
	return Sentinel{Name: "reviewer reads", Set: policy.SetBusiness, Want: want, Request: policy.Request{
		Principal: policy.Principal{ID: "user-42", Roles: []string{"reviewer"}},
		Resource:  policy.Resource{Kind: "document.text_unit", ID: "u-1"},
		Actions:   []string{"read"},
	}}
}

var testEnv = Environment{Schema: schema, SchemaDigest: "sha256:test-schema", OperationsDigest: "sha256:test-ops",
	Audience: "fga-decision", MaxCostLimit: engine.DefaultOptions.CostLimit}

// testInfo is a manifest matching testEnv with the given business documents.
func testInfo(business ...string) Info {
	info := Info{Audience: "fga-decision", CostLimit: engine.DefaultOptions.CostLimit, Business: business}
	testEnv.Stamp(&info)
	return info
}

func signed(t *testing.T, epoch uint64, doc string, sentinels ...Sentinel) Bundle {
	t.Helper()
	b := Bundle{Epoch: epoch, Info: testInfo("units.json"), Documents: map[string][]byte{"units.json": []byte(doc)},
		CeilingDeclared: true, Sentinels: sentinels, KeyID: "publisher-1"}
	return resign(t, b)
}

func resign(t *testing.T, b Bundle) Bundle {
	t.Helper()
	digest, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(priv, SigningBytes(b.Epoch, digest))
	return b
}

func newManager(epochs fixedEpochs) *Manager {
	return NewManager(map[string]ed25519.PublicKey{"publisher-1": pub}, testEnv, epochs,
		func() time.Time { return time.Unix(1_800_000_000, 0) })
}

func states(m *Manager) []State {
	var s []State
	for _, r := range m.History() {
		s = append(s, r.State)
	}
	return s
}

func TestActivateRecordsEveryState(t *testing.T) {
	m := newManager(fixedEpochs{})
	if err := m.Activate(context.Background(), signed(t, 1, reviewersRead, reviewerSentinel(policy.EffectAllow))); err != nil {
		t.Fatal(err)
	}
	want := []State{StateReceived, StateVerified, StatePrepared, StateReady, StateActive}
	if got := states(m); !slices.Equal(got, want) {
		t.Fatalf("states = %v, want %v (REL-002)", got, want)
	}
	if !m.Ready() {
		t.Error("manager not ready after activation")
	}
}

// TestRejectedCandidateKeepsPriorState covers V-090 and the other ways a
// candidate fails: the prior snapshot stays active and the candidate is not
// acknowledged.
func TestRejectedCandidateKeepsPriorState(t *testing.T) {
	tampered := signed(t, 2, reviewersRead)
	tampered.Documents["units.json"] = []byte(nobodyReads)

	for name, tc := range map[string]struct {
		bundle  Bundle
		wantErr string
	}{
		"compile failure (V-090)": {signed(t, 2, brokenDocument), "rule"},
		"tampered document":       {tampered, "signature"},
		"unknown publisher":       {func() Bundle { b := signed(t, 2, reviewersRead); b.KeyID = "other"; return b }(), "signature"},
		"failing sentinel":        {signed(t, 2, nobodyReads, reviewerSentinel(policy.EffectAllow)), "sentinel"},
		"epoch not increasing":    {signed(t, 1, nobodyReads), "epoch"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newManager(fixedEpochs{})
			if err := m.Activate(context.Background(), signed(t, 1, reviewersRead)); err != nil {
				t.Fatal(err)
			}
			before, _ := m.Snapshot(context.Background(), "t-acme")

			err := m.Activate(context.Background(), tc.bundle)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Activate error = %v, want containing %q", err, tc.wantErr)
			}
			after, _ := m.Snapshot(context.Background(), "t-acme")
			if after != before {
				t.Error("a rejected candidate replaced the active snapshot")
			}
			if last := m.History()[len(m.History())-1]; last.State != StateRejected || last.Error == "" {
				t.Errorf("last record = %+v, want REJECTED with an error", last)
			}
		})
	}
}

// TestRollbackIsANewHigherEpoch covers V-093.
func TestRollbackIsANewHigherEpoch(t *testing.T) {
	m := newManager(fixedEpochs{})
	ctx := context.Background()
	for epoch, doc := range map[uint64]string{1: reviewersRead} {
		if err := m.Activate(ctx, signed(t, epoch, doc)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Activate(ctx, signed(t, 2, nobodyReads)); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(ctx, signed(t, 1, reviewersRead)); err == nil {
		t.Fatal("re-activating the old release under its old epoch must fail")
	}
	if err := m.Activate(ctx, signed(t, 3, reviewersRead)); err != nil {
		t.Fatalf("rollback as epoch 3: %v", err)
	}
	if s, _ := m.Snapshot(ctx, "t-acme"); s.Epoch != 3 {
		t.Errorf("active epoch = %d, want 3", s.Epoch)
	}
}

// TestSnapshotRequiresEpoch covers V-091: a node behind the tenant's required
// epoch refuses rather than deciding from a stale bundle.
func TestSnapshotRequiresEpoch(t *testing.T) {
	m := newManager(fixedEpochs{"t-acme": 2, "t-other": 1})
	ctx := context.Background()
	if _, err := m.Snapshot(ctx, "t-acme"); !errors.Is(err, ErrNoActiveSnapshot) {
		t.Fatalf("before activation: %v, want %v", err, ErrNoActiveSnapshot)
	}
	if err := m.Activate(ctx, signed(t, 1, reviewersRead)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Snapshot(ctx, "t-acme"); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("tenant requiring epoch 2: %v, want %v", err, ErrStaleEpoch)
	}
	if _, err := m.Snapshot(ctx, "t-other"); err != nil {
		t.Fatalf("tenant requiring epoch 1: %v", err)
	}
}

// TestBatchKeepsItsSnapshot covers V-092: a batch that started before an
// activation finishes on the snapshot it started with; an older snapshot is
// refused.
func TestBatchKeepsItsSnapshot(t *testing.T) {
	m := newManager(fixedEpochs{})
	ctx := context.Background()
	if err := m.Activate(ctx, signed(t, 1, reviewersRead)); err != nil {
		t.Fatal(err)
	}
	first, _ := m.Snapshot(ctx, "t-acme")
	req := reviewerSentinel(policy.EffectAllow).Request
	req.Set, req.SnapshotDigest = policy.SetBusiness, first.Digest

	if err := m.Activate(ctx, signed(t, 2, nobodyReads)); err != nil {
		t.Fatal(err)
	}
	res, err := m.Evaluate(ctx, req)
	if err != nil || res.Actions["read"].Effect != policy.EffectAllow {
		t.Fatalf("in-flight batch on the replaced snapshot = %v, %v; want ALLOW from that snapshot", res, err)
	}
	// A third, different release. (Republishing the first release's
	// documents would produce the first digest again.)
	if err := m.Activate(ctx, signed(t, 3, strings.Replace(reviewersRead, `"id":"r"`, `"id":"r3"`, 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Evaluate(ctx, req); !errors.Is(err, ErrUnknownSnapshot) {
		t.Fatalf("two activations later: %v, want %v", err, ErrUnknownSnapshot)
	}
}

// TestEffectChanges covers REL-005: the reviewer sees which sentinels change
// effect.
func TestEffectChanges(t *testing.T) {
	m := newManager(fixedEpochs{})
	ctx := context.Background()
	if err := m.Activate(ctx, signed(t, 1, reviewersRead)); err != nil {
		t.Fatal(err)
	}
	active, _ := m.Snapshot(ctx, "t-acme")
	cand := signed(t, 2, nobodyReads)
	digest, _ := cand.Digest()
	candidate, err := m.prepare(ctx, cand, digest)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := EffectChanges(ctx, active, candidate, []Sentinel{reviewerSentinel(policy.EffectAllow)})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Before != policy.EffectAllow || changes[0].After != policy.EffectDeny {
		t.Fatalf("changes = %+v, want reviewer read ALLOW -> DENY", changes)
	}
}

const draftCeiling = `{"format":"fga.policy/v1","set":"ceiling","resource":"document.text_unit","scope":"","rules":[{"id":"c","effect":"deny","actions":["read"],"roles":["*"],"when":"resource.attributes.state != 'LIVE'"}]}`

// TestCeilingDeclaration covers POL-007 and V-153: a release declares its
// ceiling set. An explicitly empty set passes every check; an omitted
// declaration, an undeclared ceiling document and a declared document that
// is missing or is not a ceiling document all reject.
func TestCeilingDeclaration(t *testing.T) {
	ctx := context.Background()
	withCeiling := func(declared bool, names ...string) Bundle {
		b := Bundle{Epoch: 1, Info: testInfo("units.json"), KeyID: "publisher-1", CeilingDeclared: declared, Ceiling: names,
			Documents: map[string][]byte{"units.json": []byte(reviewersRead), "ceiling.json": []byte(draftCeiling)}}
		return resign(t, b)
	}
	for name, tc := range map[string]struct {
		bundle  Bundle
		wantErr string
	}{
		"omitted declaration":       {resign(t, Bundle{Epoch: 1, Info: testInfo("units.json"), KeyID: "publisher-1", Documents: map[string][]byte{"units.json": []byte(reviewersRead)}}), "declare the ceiling set"},
		"undeclared ceiling":        {withCeiling(true), "ceiling set exactly"},
		"business declared ceiling": {withCeiling(true, "ceiling.json", "units.json"), "ceiling set exactly"},
		"missing ceiling document":  {withCeiling(true, "ceiling.json", "gone.json"), "missing"},
	} {
		if err := newManager(fixedEpochs{}).Activate(ctx, tc.bundle); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: Activate = %v, want an error containing %q", name, err, tc.wantErr)
		}
	}

	m := newManager(fixedEpochs{})
	if err := m.Activate(ctx, signed(t, 1, reviewersRead)); err != nil {
		t.Fatalf("explicitly empty ceiling set: %v", err)
	}
	snap, _ := m.Snapshot(ctx, "t-acme")
	req := reviewerSentinel(policy.EffectAllow).Request
	req.Set, req.SnapshotDigest = policy.SetCeiling, snap.Digest
	req.Resource.Attributes = map[string]any{"state": "DRAFT"}
	if res, err := m.Evaluate(ctx, req); err != nil || res.Actions["read"].Effect != policy.EffectAllow {
		t.Fatalf("empty ceiling set = %+v, %v; want PASS", res, err)
	}

	if err := m.Activate(ctx, resign(t, func() Bundle { b := withCeiling(true, "ceiling.json"); b.Epoch = 2; return b }())); err != nil {
		t.Fatalf("declared ceiling set: %v", err)
	}
	snap, _ = m.Snapshot(ctx, "t-acme")
	req.SnapshotDigest = snap.Digest
	if res, err := m.Evaluate(ctx, req); err != nil || res.Actions["read"].Effect != policy.EffectDeny {
		t.Fatalf("declared ceiling on a draft = %+v, %v; want DENY", res, err)
	}
}

// TestManifestEnvironment covers REL-001 and POL-010: an instance prepares a
// release only for its own audience, evaluator build, registry and limits,
// and every document is declared in exactly one set.
func TestManifestEnvironment(t *testing.T) {
	for name, edit := range map[string]func(*Info){
		"format":              func(i *Info) { i.Format = "fga.release/v0" },
		"audience":            func(i *Info) { i.Audience = "fga-storage" },
		"evaluator version":   func(i *Info) { i.EvaluatorVersion = "fga.evaluator/0" },
		"expression library":  func(i *Info) { i.ExpressionLibrary = "cel.dev/cel-go v0.1.0" },
		"functions":           func(i *Info) { i.Functions = "cel-extended/v1" },
		"schema digest":       func(i *Info) { i.SchemaDigest = "sha256:other" },
		"operations digest":   func(i *Info) { i.OperationsDigest = "sha256:other" },
		"cost limit above":    func(i *Info) { i.CostLimit = engine.DefaultOptions.CostLimit + 1 },
		"no cost limit":       func(i *Info) { i.CostLimit = 0 },
		"repeated label":      func(i *Info) { i.LabelOrder, i.LabelGeneration = []string{"internal", "internal"}, 1 },
		"labels without gen":  func(i *Info) { i.LabelOrder = []string{"internal"} },
		"undeclared business": func(i *Info) { i.Business = nil },
	} {
		b := signed(t, 1, reviewersRead)
		edit(&b.Info)
		b = resign(t, b)
		if err := newManager(fixedEpochs{}).Activate(context.Background(), b); err == nil {
			t.Errorf("%s: a mismatching manifest was activated", name)
		}
	}
	b := signed(t, 1, reviewersRead)
	b.Info.LabelOrder, b.Info.LabelGeneration = []string{"public", "internal", "confidential"}, 1
	m := newManager(fixedEpochs{})
	if err := m.Activate(context.Background(), resign(t, b)); err != nil {
		t.Fatalf("a valid label order: %v", err)
	}
	if snap, _ := m.Snapshot(context.Background(), "t-acme"); snap.Info.LabelGeneration != 1 || snap.Info.EvaluatorVersion != engine.EvaluatorVersion {
		t.Errorf("snapshot info = %+v", snap.Info)
	}

	// The manifest is part of the signed digest.
	tampered := signed(t, 1, reviewersRead)
	tampered.Info.TestEvidence = "edited after signing"
	if err := newManager(fixedEpochs{}).Activate(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("edited manifest: %v, want a signature failure", err)
	}
}
