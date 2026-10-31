package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var issued = time.Unix(1_800_000_000, 0)

type keyring struct {
	mu   sync.Mutex
	keys map[string]Key
}

func (k *keyring) get() map[string]Key {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := map[string]Key{}
	for id, key := range k.keys {
		out[id] = key
	}
	return out
}

func (k *keyring) set(id string, key Key) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[id] = key
}

type fixture struct {
	signer *Signer
	keys   *keyring
	clock  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, err := NewSigner("dec-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{signer: s, clock: issued.Add(time.Second),
		keys: &keyring{keys: map[string]Key{"dec-1": {Public: pub, NotBefore: issued.Add(-time.Hour), NotAfter: issued.Add(time.Hour)}}}}
}

func (f *fixture) verifier(audience string, c Consumption) *Verifier {
	return NewVerifier(audience, f.keys.get, c, func() time.Time { return f.clock })
}

func record(singleUse bool) Record {
	return Record{
		DecisionID: "d-1", Audience: "storage", Tenant: "t-acme",
		RecoveryIncarnation: 1, Adapter: "storage-1",
		Actor: Ref{ID: "agent-7", Revision: 12}, Subject: Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5",
		DelegationChain: []Ref{{ID: "dlg-5", Revision: 3}}, Operation: "storage.object.read", OperationID: "op-1",
		OperationDigest: "sha256:op", BundleDigest: "sha256:bundle", PolicyEpoch: 5, EvaluatorVersion: "fga.evaluator/1", SingleUse: singleUse,
		Checks: []Check{{ID: "c1", Kind: "OPERATION", Principal: Ref{ID: "user-42", Revision: 88}, ResourceType: "storage.object",
			ResourceID: "o-1", Version: "v-1", Generation: 17, MetadataRevision: 2, Action: "read", BusinessEffect: "ALLOW", CeilingEffect: "PASS",
			Requires: []string{}}},
		IssuedAt: issued, ValidUntil: issued.Add(30 * time.Second),
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	f := newFixture(t)
	signed, err := f.signer.Sign(record(false))
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.verifier("storage", NewMemoryConsumption()).Verify(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if got.DecisionID != "d-1" || got.Checks[0].Generation != 17 || got.Version != RecordVersion {
		t.Fatalf("record = %+v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, *fixture) (Signed, string)
		want error
	}{
		{"audience of another role (V-025)", func(t *testing.T, f *fixture) (Signed, string) {
			return mustSign(t, f, record(false)), "keys"
		}, ErrAudience},
		{"tampered payload", func(t *testing.T, f *fixture) (Signed, string) {
			s := mustSign(t, f, record(false))
			s.Payload = bytes.Replace(s.Payload, []byte(`"generation":17`), []byte(`"generation":18`), 1)
			return s, "storage"
		}, ErrSignature},
		{"unknown key", func(t *testing.T, f *fixture) (Signed, string) {
			_, priv, _ := ed25519.GenerateKey(nil)
			other, _ := NewSigner("dec-x", priv)
			s, _ := other.Sign(record(false))
			return s, "storage"
		}, ErrUnknownKey},
		{"revoked key", func(t *testing.T, f *fixture) (Signed, string) {
			k := f.keys.get()["dec-1"]
			k.Revoked = true
			f.keys.set("dec-1", k)
			return mustSign(t, f, record(false)), "storage"
		}, ErrRevokedKey},
		{"issued after the key retired", func(t *testing.T, f *fixture) (Signed, string) {
			r := record(false)
			r.IssuedAt, r.ValidUntil = issued.Add(2*time.Hour), issued.Add(3*time.Hour)
			f.clock = r.IssuedAt
			return mustSign(t, f, r), "storage"
		}, ErrKeyValidity},
		{"expired (V-086)", func(t *testing.T, f *fixture) (Signed, string) {
			f.clock = issued.Add(30 * time.Second)
			return mustSign(t, f, record(false)), "storage"
		}, ErrExpired},
		{"issued in the future", func(t *testing.T, f *fixture) (Signed, string) {
			f.clock = issued.Add(-time.Minute)
			return mustSign(t, f, record(false)), "storage"
		}, ErrNotYetValid},
		{"signed record with an unknown field", func(t *testing.T, f *fixture) (Signed, string) {
			s := mustSign(t, f, record(false))
			payload := append(bytes.TrimSuffix(s.Payload, []byte("}")), []byte(`,"admin":true}`)...)
			resigned, err := f.signer.signBytes(payload)
			if err != nil {
				t.Fatal(err)
			}
			return resigned, "storage"
		}, ErrRecord},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			s, audience := tt.edit(t, f)
			if _, err := f.verifier(audience, NewMemoryConsumption()).Verify(context.Background(), s); !errors.Is(err, tt.want) {
				t.Fatalf("Verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

func mustSign(t *testing.T, f *fixture, r Record) Signed {
	t.Helper()
	s, err := f.signer.Sign(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSingleUseConsumedOnce covers V-026 and V-121: a single-use decision is
// accepted once, also when replicas present it at the same moment.
func TestSingleUseConsumedOnce(t *testing.T) {
	f := newFixture(t)
	s := mustSign(t, f, record(true))
	shared := NewMemoryConsumption()

	var accepted, replayed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.verifier("storage", shared).Verify(context.Background(), s)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrReplayed):
				replayed.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || replayed.Load() != 15 {
		t.Fatalf("accepted %d, replayed %d; want 1 and 15", accepted.Load(), replayed.Load())
	}
}

type failingConsumption struct{}

func (failingConsumption) Consume(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("catalog unreachable")
}

// TestSingleUseNeedsTheConsumptionStore: a replica that cannot record the
// consumption refuses the decision (DEC-011).
func TestSingleUseNeedsTheConsumptionStore(t *testing.T) {
	f := newFixture(t)
	if _, err := f.verifier("storage", failingConsumption{}).Verify(context.Background(), mustSign(t, f, record(true))); err == nil {
		t.Fatal("Verify succeeded without recording consumption")
	}
}

// TestRotationOverlap covers DEC-012: during rotation both keys verify; once
// the old key is retired, decisions it signed after retirement do not.
func TestRotationOverlap(t *testing.T) {
	f := newFixture(t)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	f.keys.set("dec-2", Key{Public: pub2, NotBefore: issued.Add(-time.Minute), NotAfter: issued.Add(24 * time.Hour)})
	next, _ := NewSigner("dec-2", priv2)

	v := f.verifier("storage", NewMemoryConsumption())
	oldSigned := mustSign(t, f, record(false))
	newSigned, _ := next.Sign(record(false))
	for name, s := range map[string]Signed{"old key": oldSigned, "new key": newSigned} {
		if _, err := v.Verify(context.Background(), s); err != nil {
			t.Errorf("%s during overlap: %v", name, err)
		}
	}
}

// TestTransmittedGrantIsBound covers V-141 and DEC-008: the verifier
// accepts the exact transmitted bytes, and removing or widening a check,
// adding an obligation or changing any other field after signing fails.
func TestTransmittedGrantIsBound(t *testing.T) {
	f := newFixture(t)
	signed, err := f.signer.Sign(record(false))
	if err != nil {
		t.Fatal(err)
	}
	v := f.verifier("storage", NewMemoryConsumption())
	rec, err := v.Verify(context.Background(), signed)
	if err != nil || rec.ObligationMappingVersion != NoObligations || rec.ResourceBindingsDigest != ResourceBindingsDigest(rec.Checks) {
		t.Fatalf("original grant: %+v, %v", rec, err)
	}
	alter := func(edit func(*Record)) Signed {
		r := rec
		r.Checks = slices.Clone(rec.Checks)
		edit(&r)
		payload, _ := json.Marshal(r)
		return Signed{Payload: payload, JWS: signed.JWS}
	}
	for name, edit := range map[string]func(*Record){
		"remove a check":    func(r *Record) { r.Checks = nil },
		"widen the action":  func(r *Record) { r.Checks[0].Action = "delete-version" },
		"other version":     func(r *Record) { r.Checks[0].Version = "v-2" },
		"add an obligation": func(r *Record) { r.Obligations = []Obligation{{Type: "redact", Version: 1}} },
		"older incarnation": func(r *Record) { r.RecoveryIncarnation = 0 },
	} {
		if _, err := v.Verify(context.Background(), alter(edit)); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: %v, want %v", name, err, ErrSignature)
		}
	}
}

// TestRecordContentRules covers DEC-002 and DEC-003 for correctly signed
// records: an obligation the enforcement point cannot apply, a check that
// is not an unconditional allow and an inconsistent check kind reject.
func TestRecordContentRules(t *testing.T) {
	f := newFixture(t)
	v := f.verifier("storage", NewMemoryConsumption())
	for name, tc := range map[string]struct {
		edit func(*Record)
		want error
	}{
		"obligation":         {func(r *Record) { r.Obligations = []Obligation{{Type: "watermark", Version: 1}} }, ErrObligation},
		"other mapping":      {func(r *Record) { r.ObligationMappingVersion = "fga.obligations/v9" }, ErrObligation},
		"business deny":      {func(r *Record) { r.Checks[0].BusinessEffect = "DENY" }, ErrRecord},
		"ceiling objection":  {func(r *Record) { r.Checks[0].CeilingEffect = "DENY" }, ErrRecord},
		"unmet prerequisite": {func(r *Record) { r.Checks[0].Requires = []string{"approval"} }, ErrRecord},
		"reservation": {func(r *Record) {
			r.Checks[0].Requires, r.Context.Approval = []string{"approval", "reservation"}, Ref{ID: "a-1", Revision: 2}
		}, ErrRecord},
		"bound approval": {func(r *Record) {
			r.Checks[0].Requires, r.Context.Approval = []string{"approval"}, Ref{ID: "a-1", Revision: 2}
		}, nil},
		"recipient w/o binding": {func(r *Record) { r.Checks[0].Kind = "RECIPIENT_ELIGIBILITY" }, ErrRecord},
		"no checks":             {func(r *Record) { r.Checks = nil }, ErrRecord},
	} {
		r := record(false)
		tc.edit(&r)
		signed, err := f.signer.Sign(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), signed); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
