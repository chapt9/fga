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

func signed(t *testing.T, epoch uint64, doc string, sentinels ...Sentinel) Bundle {
	t.Helper()
	b := Bundle{Epoch: epoch, Documents: map[string][]byte{"units.json": []byte(doc)}, Sentinels: sentinels, KeyID: "publisher-1"}
	digest, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(priv, SigningBytes(epoch, digest))
	return b
}

func newManager(epochs fixedEpochs) *Manager {
	return NewManager(map[string]ed25519.PublicKey{"publisher-1": pub}, schema, engine.DefaultOptions, epochs,
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
