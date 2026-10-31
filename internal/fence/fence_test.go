package fence

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/pgtest"
	"fga/internal/signing"
)

var now = time.Unix(1_800_000_000, 0).UTC()

func setup(t *testing.T) (*Fence, *catalog.Store, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Pool(t, catalog.Migrate)
	pgtest.Exec(t, pool,
		`INSERT INTO identities VALUES ('t-acme','user-42',88,false,'{reviewer}','{}'),('t-acme','agent-7',12,false,'{agent}','{}'),
		                               ('t-acme','user-77',5,false,'{reviewer}','{}')`,
		`INSERT INTO delegations VALUES ('t-acme','dlg-5','agent-7','user-42','storage-1','[]','2027-01-15 09:00:00+00',NULL,3,false)`,
		`INSERT INTO resources VALUES ('t-acme','o-1','storage.object','acme',1,17,2,'{}')`,
		`INSERT INTO recipient_keys (tenant, fingerprint, principal, public_key, suite, key_version, status, revision)
		 VALUES ('t-acme','sha256:77','user-77','\x00',1,1,'ACTIVE',3)`,
		`INSERT INTO tenant_epochs VALUES ('t-acme', 5)`,
		`CREATE TABLE effects (id text PRIMARY KEY)`)
	return New(pool, time.Second, func() time.Time { return now }), catalog.New(pool, 100), pool
}

// record is agent-7 acting for user-42, with a recipient check for user-77.
func record(id string) signing.Record {
	return signing.Record{DecisionID: id, Tenant: "t-acme", RecoveryIncarnation: 1, PolicyEpoch: 5, SingleUse: true,
		ValidUntil: now.Add(30 * time.Second), Actor: signing.Ref{ID: "agent-7", Revision: 12},
		Subject: signing.Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5", DelegationChain: []signing.Ref{{ID: "dlg-5", Revision: 3}},
		Checks: []signing.Check{
			{ID: "object", Kind: "OPERATION", Principal: signing.Ref{ID: "user-42", Revision: 88},
				ResourceType: "storage.object", ResourceID: "o-1", Generation: 17, MetadataRevision: 2},
			{ID: "recipient", Kind: "RECIPIENT_ELIGIBILITY", PrincipalBinding: "sha256:77", KeyRevision: 3,
				Principal: signing.Ref{ID: "user-77", Revision: 5}, ResourceType: "storage.object", ResourceID: "o-1", Generation: 17, MetadataRevision: 2},
			{ID: "planned", Kind: "OPERATION", Principal: signing.Ref{ID: "user-42", Revision: 88},
				ResourceType: "crypto.envelope", ResourceID: "e-new"},
		}}
}

func binding(t *testing.T, id string) Binding {
	t.Helper()
	b, err := FromRecord(record(id))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// effect is a protected transition: it inserts a row.
func effect(id string) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO effects VALUES ($1)`, id)
		return err
	}
}

func effects(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM effects`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFromRecord(t *testing.T) {
	b := binding(t, "d-1")
	if len(b.Identities) != 3 || b.Identities[0].ID != "agent-7" || len(b.Keys) != 1 || b.Keys[0] != (Ref{"sha256:77", 3}) ||
		len(b.Delegations) != 1 || len(b.Resources) != 2 || b.Resources[0].Type != "crypto.envelope" {
		t.Fatalf("binding = %+v", b)
	}
	conflicting := record("d-2")
	conflicting.Checks[1].Generation = 18
	if _, err := FromRecord(conflicting); err == nil {
		t.Error("a resource bound in two states must be rejected")
	}
}

// TestRunCommitsOnceAndConsumes covers DEC-011: the transition and the
// consumption commit together, and a replay neither consumes nor acts.
func TestRunCommitsOnceAndConsumes(t *testing.T) {
	f, _, pool := setup(t)
	ctx := context.Background()
	if err := f.Run(ctx, binding(t, "d-1"), []string{"o-1"}, effect("first")); err != nil {
		t.Fatal(err)
	}
	if err := f.Run(ctx, binding(t, "d-1"), nil, effect("replay")); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v, want %v", err, ErrReplayed)
	}
	if n := effects(t, pool); n != 1 {
		t.Fatalf("effects = %d, want 1", n)
	}
	var inc uint64
	_ = pool.QueryRow(ctx, `SELECT incarnation FROM consumed_decisions WHERE decision_id = 'd-1'`).Scan(&inc)
	if inc != 1 {
		t.Errorf("consumption incarnation = %d, want 1", inc)
	}
}

// TestEachFactIsRechecked covers DEC-006 and DAT-007 for every fact class:
// a change committed before the fence makes it fail without effect.
func TestEachFactIsRechecked(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*catalog.Store, *pgxpool.Pool) error
		want   error
	}{
		"subject disabled": {func(s *catalog.Store, _ *pgxpool.Pool) error {
			return s.DisableIdentity(context.Background(), "t-acme", "user-42")
		}, ErrIdentity},
		"recipient roles changed": {func(s *catalog.Store, _ *pgxpool.Pool) error {
			return s.TouchIdentity(context.Background(), "t-acme", "user-77")
		}, ErrIdentity},
		"delegation revoked": {func(s *catalog.Store, _ *pgxpool.Pool) error {
			return s.RevokeDelegation(context.Background(), "t-acme", "dlg-5")
		}, ErrDelegation},
		"recipient key revoked": {func(s *catalog.Store, _ *pgxpool.Pool) error {
			return s.RevokeRecipientKey(context.Background(), "t-acme", "sha256:77")
		}, ErrRecipientKey},
		"stricter release": {func(s *catalog.Store, _ *pgxpool.Pool) error { return s.RaiseEpoch(context.Background(), "t-acme", 6) }, ErrEpoch},
		"restore":          {func(s *catalog.Store, _ *pgxpool.Pool) error { return s.SetAdmission(context.Background(), true, 2) }, ErrIncarnation},
		"admission closed": {func(s *catalog.Store, _ *pgxpool.Pool) error { return s.SetAdmission(context.Background(), false, 0) }, ErrAdmissionClosed},
		"object overwritten": {func(_ *catalog.Store, p *pgxpool.Pool) error {
			_, err := p.Exec(context.Background(), `UPDATE resources SET generation = 18 WHERE id = 'o-1'`)
			return err
		}, ErrResource},
		"planned resource exists": {func(_ *catalog.Store, p *pgxpool.Pool) error {
			_, err := p.Exec(context.Background(), `INSERT INTO resources VALUES ('t-acme','e-new','crypto.envelope','acme',1,1,1,'{}')`)
			return err
		}, ErrResource},
	} {
		t.Run(name, func(t *testing.T) {
			f, s, pool := setup(t)
			if err := tc.change(s, pool); err != nil {
				t.Fatal(err)
			}
			if err := f.Run(context.Background(), binding(t, "d-1"), nil, effect("x")); !errors.Is(err, tc.want) {
				t.Fatalf("Run = %v, want %v", err, tc.want)
			}
			if effects(t, pool) != 0 {
				t.Error("a failed fence left an effect")
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	f, _, pool := setup(t)
	b := binding(t, "d-1")
	b.ValidUntil = now.Add(500 * time.Millisecond) // inside the one-second clock margin
	if err := f.Run(context.Background(), b, nil, effect("x")); !errors.Is(err, ErrExpired) {
		t.Fatalf("Run = %v, want %v", err, ErrExpired)
	}
	if effects(t, pool) != 0 {
		t.Error("an expired decision left an effect")
	}
}

// TestFenceOrdersAgainstRevocation covers DAT-007 and V-142's ordering: a
// revocation that arrives while a fence holds its locks waits for the fence
// to commit, and the next fence sees it.
func TestFenceOrdersAgainstRevocation(t *testing.T) {
	f, s, pool := setup(t)
	ctx := context.Background()
	inside, release := make(chan struct{}), make(chan struct{})
	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- f.Run(ctx, binding(t, "d-1"), nil, func(ctx context.Context, tx pgx.Tx) error {
			close(inside)
			<-release
			return effect("admitted")(ctx, tx)
		})
	}()
	<-inside
	var revoked atomic.Bool
	revokeDone := make(chan error, 1)
	go func() {
		err := s.DisableIdentity(ctx, "t-acme", "user-42")
		revoked.Store(true)
		revokeDone <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if revoked.Load() {
		t.Fatal("the revocation committed while the fence held its lock")
	}
	close(release)
	if err := <-fenceDone; err != nil {
		t.Fatalf("admitted fence: %v", err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatal(err)
	}
	if err := f.Run(ctx, binding(t, "d-2"), nil, effect("after")); !errors.Is(err, ErrIdentity) {
		t.Fatalf("fence after the revocation: %v, want %v", err, ErrIdentity)
	}
	if n := effects(t, pool); n != 1 {
		t.Fatalf("effects = %d, want only the admitted one", n)
	}
}

func TestCheckIsReadOnly(t *testing.T) {
	f, s, _ := setup(t)
	ctx := context.Background()
	if err := f.Check(ctx, binding(t, "d-1")); err != nil {
		t.Fatal(err)
	}
	if err := f.Check(ctx, binding(t, "d-1")); err != nil {
		t.Fatalf("Check consumed the decision: %v", err)
	}
	_ = s.RevokeRecipientKey(ctx, "t-acme", "sha256:77")
	if err := f.Check(ctx, binding(t, "d-1")); !errors.Is(err, ErrRecipientKey) {
		t.Fatalf("Check after revocation = %v", err)
	}
}
