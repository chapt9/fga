package decision

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"fga/internal/policy"
)

var (
	allow   = policy.ActionResult{Effect: policy.EffectAllow}
	deny    = policy.ActionResult{Effect: policy.EffectDeny}
	errored = policy.ActionResult{Effect: policy.EffectAllow, Errored: true}
)

// fakeEvaluator answers from a table keyed by policy set and action. An
// action missing from the table gets no result.
type fakeEvaluator struct {
	results map[policy.Set]map[string]policy.ActionResult
	err     error
	calls   []policy.Request
}

func (f *fakeEvaluator) Evaluate(_ context.Context, req policy.Request) (policy.Result, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return policy.Result{}, f.err
	}
	out := policy.Result{Actions: map[string]policy.ActionResult{}}
	for _, a := range req.Actions {
		if r, ok := f.results[req.Set][a]; ok {
			out.Actions[a] = r
		}
	}
	return out, nil
}

type gateFunc func(context.Context, Batch) (policy.Principal, error)

func (g gateFunc) Admit(ctx context.Context, b Batch) (policy.Principal, error) { return g(ctx, b) }

var reviewer = policy.Principal{ID: "user-42", Roles: []string{"reviewer"}}

var admitAll = gateFunc(func(context.Context, Batch) (policy.Principal, error) { return reviewer, nil })

func fixedClock(t time.Time, reads *int) func() time.Time {
	return func() time.Time {
		*reads++
		return t
	}
}

func newDecider(t *testing.T, gate Gate, ev policy.Evaluator) *Decider {
	t.Helper()
	var reads int
	d, err := NewDecider(gate, ev, fixedClock(time.Unix(1_800_000_000, 0), &reads))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func batch(actions ...string) Batch {
	b := Batch{SnapshotDigest: "sha256:bundle"}
	for i, a := range actions {
		b.Checks = append(b.Checks, Check{ID: "c" + string(rune('1'+i)), Action: a, Resource: policy.Resource{Kind: "document_unit", ID: "u-1"}})
	}
	return b
}

// TestCombinationOfCeilingAndBusinessSets covers one check through every
// ceiling and business result that changes the effective decision.
func TestCombinationOfCeilingAndBusinessSets(t *testing.T) {
	missing := (*policy.ActionResult)(nil)
	tests := []struct {
		name       string
		ceiling    *policy.ActionResult
		business   *policy.ActionResult
		wantEffect CheckEffect
		wantReason Reason
	}{
		{"business allow with no ceiling objection", &allow, &allow, CheckAllow, ""},
		// V-006, V-013: the business allow may come from a principal policy
		// or a tenant-scope policy; neither overrides the ceiling.
		{"business allow does not override a ceiling deny", &deny, &allow, CheckDeny, ReasonCeilingDeny},
		{"ceiling evaluation error denies (V-018)", &errored, &allow, CheckDeny, ReasonCeilingError},
		// A resource kind without a ceiling policy gets no ceiling result and
		// is denied rather than left unguarded.
		{"missing ceiling result denies", missing, &allow, CheckDeny, ReasonMissingResult},
		{"errored business rule denies (V-012)", &allow, &errored, CheckDeny, ReasonBusinessError},
		{"business deny (V-003)", &allow, &deny, CheckDeny, ReasonBusinessDeny},
		{"missing business result denies (DEC-004)", &allow, missing, CheckDeny, ReasonMissingResult},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &fakeEvaluator{results: map[policy.Set]map[string]policy.ActionResult{
				policy.SetCeiling: {}, policy.SetBusiness: {},
			}}
			if tt.ceiling != nil {
				ev.results[policy.SetCeiling]["read"] = *tt.ceiling
			}
			if tt.business != nil {
				ev.results[policy.SetBusiness]["read"] = *tt.business
			}
			got := newDecider(t, admitAll, ev).DecideBatch(context.Background(), batch("read"))

			r := got.Results[0]
			if r.Effect != tt.wantEffect || r.Reason != tt.wantReason {
				t.Fatalf("check = %v/%q, want %v/%q", r.Effect, r.Reason, tt.wantEffect, tt.wantReason)
			}
			wantOutcome := OutcomeDeny
			if tt.wantEffect == CheckAllow {
				wantOutcome = OutcomeAllow
			}
			if got.Outcome != wantOutcome {
				t.Fatalf("outcome = %v, want %v", got.Outcome, wantOutcome)
			}
			if tt.business != nil && r.Business != tt.business.Effect {
				t.Errorf("reported business effect = %v, want %v (DEC-003)", r.Business, tt.business.Effect)
			}
		})
	}
}

// TestBatchKeepsOrderAndOneClockRead covers V-007: a denied check does not
// change its peers, results keep request order, the compound outcome is a
// denial, and all evaluations share one time captured once (POL-008).
func TestBatchKeepsOrderAndOneClockRead(t *testing.T) {
	ev := &fakeEvaluator{results: map[policy.Set]map[string]policy.ActionResult{
		policy.SetCeiling:  {"read": allow, "export": allow, "stat": allow},
		policy.SetBusiness: {"read": allow, "export": deny, "stat": allow},
	}}
	var reads int
	d, err := NewDecider(admitAll, ev, fixedClock(time.Unix(1_800_000_000, 0), &reads))
	if err != nil {
		t.Fatal(err)
	}

	b := batch("read", "export", "stat")
	got := d.DecideBatch(context.Background(), b)

	want := []CheckEffect{CheckAllow, CheckDeny, CheckAllow}
	for i, r := range got.Results {
		if r.CheckID != b.Checks[i].ID || r.Effect != want[i] {
			t.Errorf("result %d = %s/%v, want %s/%v", i, r.CheckID, r.Effect, b.Checks[i].ID, want[i])
		}
	}
	if got.Outcome != OutcomeDeny || got.Reason != ReasonBusinessDeny {
		t.Errorf("outcome = %v/%q, want DENY/%q", got.Outcome, got.Reason, ReasonBusinessDeny)
	}
	if reads != 1 {
		t.Errorf("clock read %d times, want 1", reads)
	}
	if len(ev.calls) != 6 {
		t.Fatalf("evaluator called %d times, want 6 (ceiling and business per check)", len(ev.calls))
	}
	for _, c := range ev.calls {
		if c.Principal.ID != reviewer.ID {
			t.Errorf("request %v/%s evaluated principal %q, want the gate's principal", c.Set, c.Actions, c.Principal.ID)
		}
		if !c.Now.Equal(ev.calls[0].Now) || c.SnapshotDigest != "sha256:bundle" {
			t.Errorf("request %v/%s uses time %v and snapshot %q; want one time and one snapshot per batch", c.Set, c.Actions, c.Now, c.SnapshotDigest)
		}
	}
}

// TestNothingIsAllowedWhenEvaluationStops covers the paths where no policy
// result is available: the batch is malformed, the gate rejects or fails, the
// engine fails (V-015) or the caller cancels. None may produce an allow.
func TestNothingIsAllowedWhenEvaluationStops(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	allowAll := map[policy.Set]map[string]policy.ActionResult{
		policy.SetCeiling: {"read": allow}, policy.SetBusiness: {"read": allow},
	}
	duplicate := batch("read", "read")
	duplicate.Checks[1].ID = duplicate.Checks[0].ID

	tests := []struct {
		name        string
		ctx         context.Context
		gate        Gate
		engineErr   error
		batch       Batch
		wantOutcome Outcome
		wantReason  Reason
		wantCalls   bool
	}{
		{"empty batch", context.Background(), admitAll, nil, Batch{}, OutcomeDeny, ReasonEmptyBatch, false},
		{"duplicate check IDs", context.Background(), admitAll, nil, duplicate, OutcomeDeny, ReasonDuplicateCheckID, false},
		{"gate rejection", context.Background(), gateFunc(func(context.Context, Batch) (policy.Principal, error) {
			return policy.Principal{}, &Rejection{Reason: "DELEGATION_EXPIRED"}
		}), nil, batch("read"), OutcomeDeny, "DELEGATION_EXPIRED", false},
		{"gate failure", context.Background(), gateFunc(func(context.Context, Batch) (policy.Principal, error) {
			return policy.Principal{}, errors.New("catalog unreachable")
		}), nil, batch("read"), OutcomeError, ReasonGateUnavailable, false},
		{"engine failure (V-015)", context.Background(), admitAll, errors.New("cost limit exceeded"), batch("read"), OutcomeError, ReasonEngineUnavailable, true},
		{"cancelled request", cancelled, admitAll, nil, batch("read"), OutcomeError, ReasonCancelled, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &fakeEvaluator{results: allowAll, err: tt.engineErr}
			got := newDecider(t, tt.gate, ev).DecideBatch(tt.ctx, tt.batch)

			if got.Outcome != tt.wantOutcome || got.Reason != tt.wantReason {
				t.Fatalf("outcome = %v/%q, want %v/%q", got.Outcome, got.Reason, tt.wantOutcome, tt.wantReason)
			}
			for _, r := range got.Results {
				if r.Effect != CheckNotEvaluated {
					t.Errorf("check %s = %v, want not evaluated", r.CheckID, r.Effect)
				}
			}
			if called := len(ev.calls) > 0; called != tt.wantCalls {
				t.Errorf("evaluator called = %v, want %v", called, tt.wantCalls)
			}
		})
	}
}

func TestNewDeciderRequiresEveryDependency(t *testing.T) {
	ev := &fakeEvaluator{}
	now := time.Now
	for name, args := range map[string]struct {
		gate Gate
		ev   policy.Evaluator
		now  func() time.Time
	}{
		"no gate":      {nil, ev, now},
		"no evaluator": {admitAll, nil, now},
		"no clock":     {admitAll, ev, nil},
	} {
		if _, err := NewDecider(args.gate, args.ev, args.now); err == nil {
			t.Errorf("%s: NewDecider succeeded, want error", name)
		}
	}
}

// TestPrerequisitesBecomeNeedsOutcomes covers DEC-002 and APR-001: an allow
// that requires approval or a reservation is not an allow yet.
func TestPrerequisitesBecomeNeedsOutcomes(t *testing.T) {
	needs := func(r ...string) policy.ActionResult {
		return policy.ActionResult{Effect: policy.EffectAllow, Requires: r}
	}
	tests := []struct {
		name        string
		business    map[string]policy.ActionResult
		wantOutcome Outcome
		wantReq     []string
	}{
		{"approval", map[string]policy.ActionResult{"read": needs(policy.RequireApproval), "stat": allow}, OutcomeNeedsApproval, []string{"approval"}},
		{"reservation", map[string]policy.ActionResult{"read": needs(policy.RequireReservation), "stat": allow}, OutcomeNeedsReservation, []string{"reservation"}},
		{"both, approval first", map[string]policy.ActionResult{"read": needs(policy.RequireReservation), "stat": needs(policy.RequireApproval)},
			OutcomeNeedsApproval, []string{"approval", "reservation"}},
		{"a denied check still denies", map[string]policy.ActionResult{"read": needs(policy.RequireApproval), "stat": deny}, OutcomeDeny, []string{"approval"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &fakeEvaluator{results: map[policy.Set]map[string]policy.ActionResult{
				policy.SetCeiling: {"read": allow, "stat": allow}, policy.SetBusiness: tt.business}}
			got := newDecider(t, admitAll, ev).DecideBatch(context.Background(), batch("read", "stat"))
			if got.Outcome != tt.wantOutcome || !slices.Equal(got.Requires, tt.wantReq) {
				t.Fatalf("decision = %v %v, want %v %v", got.Outcome, got.Requires, tt.wantOutcome, tt.wantReq)
			}
		})
	}
}
