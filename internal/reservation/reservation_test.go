package reservation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/pgtest"
	"fga/internal/tools"
)

func eur(minor int64) tools.Money { return tools.Money{Currency: "EUR", Minor: minor} }

func setup(t *testing.T, invocations ...string) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Pool(t, catalog.Migrate)
	pgtest.Invocations(t, pool, invocations...)
	return New(pool), pool
}

func budget(t *testing.T, pool *pgxpool.Pool) (reserved, spent int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `SELECT reserved_minor, spent_minor FROM budgets WHERE id = 'team-travel'`).
		Scan(&reserved, &spent); err != nil {
		t.Fatal(err)
	}
	return reserved, spent
}

func inTx(t *testing.T, pool *pgxpool.Pool, f func(ctx context.Context, tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := f(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TestConcurrentReservationsCannotOverspend covers V-041: two reservations
// of 600 against a limit of 1000 cannot both succeed.
func TestConcurrentReservationsCannotOverspend(t *testing.T) {
	s, pool := setup(t, "inv-1", "inv-2", "inv-3", "inv-4")
	errs := make([]error, 4)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Reserve(context.Background(), "t-acme", "team-travel", fmt.Sprintf("inv-%d", i+1), eur(60000))
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrInsufficient):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if reserved, _ := budget(t, pool); ok != 1 || reserved != 60000 {
		t.Fatalf("%d reservations succeeded with %d reserved, want 1 and 60000", ok, reserved)
	}
}

func TestReserveChecks(t *testing.T) {
	s, _ := setup(t, "inv-1")
	ctx := context.Background()
	if _, err := s.Reserve(ctx, "t-acme", "team-travel", "inv-1", tools.Money{Currency: "USD", Minor: 1}); !errors.Is(err, ErrCurrency) {
		t.Errorf("other currency: %v", err)
	}
	if _, err := s.Reserve(ctx, "t-acme", "no-such-budget", "inv-1", eur(1)); !errors.Is(err, ErrUnknownBudget) {
		t.Errorf("unknown budget: %v", err)
	}
	first, err := s.Reserve(ctx, "t-acme", "team-travel", "inv-1", eur(500))
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Reserve(ctx, "t-acme", "team-travel", "inv-1", eur(500))
	if err != nil || again.ID != first.ID {
		t.Fatalf("reserving again = %+v, %v; want the first reservation", again, err)
	}
}

func TestCommitReleaseAndWriteOff(t *testing.T) {
	s, pool := setup(t, "inv-1", "inv-2")
	ctx := context.Background()
	_, _ = s.Reserve(ctx, "t-acme", "team-travel", "inv-1", eur(300))
	_, _ = s.Reserve(ctx, "t-acme", "team-travel", "inv-2", eur(200))

	if err := inTx(t, pool, func(ctx context.Context, tx pgx.Tx) error { return CommitTx(ctx, tx, "t-acme", "inv-1") }); err != nil {
		t.Fatal(err)
	}
	if err := inTx(t, pool, func(ctx context.Context, tx pgx.Tx) error { return ReleaseTx(ctx, tx, "t-acme", "inv-2") }); err != nil {
		t.Fatal(err)
	}
	if reserved, spent := budget(t, pool); reserved != 0 || spent != 300 {
		t.Fatalf("budget reserved %d spent %d, want 0 and 300", reserved, spent)
	}
	if err := inTx(t, pool, func(ctx context.Context, tx pgx.Tx) error { return ReleaseTx(ctx, tx, "t-acme", "inv-1") }); !errors.Is(err, ErrWrongState) {
		t.Fatalf("releasing a committed reservation: %v", err)
	}
	if err := inTx(t, pool, func(ctx context.Context, tx pgx.Tx) error {
		return WriteOffTx(ctx, tx, "t-acme", "inv-1", "abandoned; vendor confirmed no charge")
	}); err != nil {
		t.Fatal(err)
	}
	if _, spent := budget(t, pool); spent != 0 {
		t.Fatalf("spent after write-off = %d, want 0", spent)
	}
	if r, _ := s.Get(ctx, "t-acme", "inv-1"); r.State != StateWrittenOff {
		t.Errorf("state = %s, want %s", r.State, StateWrittenOff)
	}
}
