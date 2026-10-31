// Package reservation holds budget reservations for invocations in
// PostgreSQL (specification 2.5, APR-004, APR-006, INV-007, INV-009,
// DAT-005). Amounts are integer minor units; a reservation cannot exceed
// its budget under any concurrency, because the budget row's own check
// constraint and a single conditional update decide it. Reservations are
// R2 (APR-004); this package belongs to the optional executor.
package reservation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/tools"
)

// Errors returned by the store.
var (
	ErrUnknownBudget = errors.New("unknown budget")
	ErrCurrency      = errors.New("amount is in another currency than the budget")
	ErrInsufficient  = errors.New("budget cannot cover the amount")
	ErrWrongState    = errors.New("reservation is not in the required state")
)

// State of a reservation.
type State string

const (
	StateHeld       State = "HELD"
	StateCommitted  State = "COMMITTED"
	StateReleased   State = "RELEASED"
	StateWrittenOff State = "WRITTEN_OFF"
)

// Reservation of part of a budget for one invocation.
type Reservation struct {
	ID          string
	Budget      string
	Invocation  string
	AmountMinor int64
	State       State
}

// Store is the reservations table.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a Store.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Reserve holds amount on a budget for an invocation. Reserving again for
// the same invocation returns the existing reservation and holds nothing
// more.
func (s *Store) Reserve(ctx context.Context, tenant, budget, invocation string, amount tools.Money) (Reservation, error) {
	if existing, err := s.Get(ctx, tenant, invocation); err == nil {
		return existing, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Reservation{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	tag, err := tx.Exec(ctx, `
		UPDATE budgets SET reserved_minor = reserved_minor + $4
		 WHERE tenant = $1 AND id = $2 AND currency = $3 AND reserved_minor + spent_minor + $4 <= limit_minor`,
		tenant, budget, amount.Currency, amount.Minor)
	if err != nil {
		return Reservation{}, err
	}
	if tag.RowsAffected() != 1 {
		return Reservation{}, s.whyNot(ctx, tenant, budget, amount)
	}
	r := Reservation{ID: newID(), Budget: budget, Invocation: invocation, AmountMinor: amount.Minor, State: StateHeld}
	if _, err := tx.Exec(ctx, `
		INSERT INTO reservations (tenant, id, budget, invocation, amount_minor, state) VALUES ($1, $2, $3, $4, $5, $6)`,
		tenant, r.ID, budget, invocation, amount.Minor, string(r.State)); err != nil {
		return Reservation{}, err
	}
	return r, tx.Commit(ctx)
}

func (s *Store) whyNot(ctx context.Context, tenant, budget string, amount tools.Money) error {
	var currency string
	err := s.pool.QueryRow(ctx, `SELECT currency FROM budgets WHERE tenant = $1 AND id = $2`, tenant, budget).Scan(&currency)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrUnknownBudget
	case err != nil:
		return err
	case currency != amount.Currency:
		return ErrCurrency
	default:
		return ErrInsufficient
	}
}

// Get returns the reservation of an invocation, or pgx.ErrNoRows.
func (s *Store) Get(ctx context.Context, tenant, invocation string) (Reservation, error) {
	r := Reservation{Invocation: invocation}
	var state string
	err := s.pool.QueryRow(ctx, `
		SELECT id, budget, amount_minor, state FROM reservations WHERE tenant = $1 AND invocation = $2`,
		tenant, invocation).Scan(&r.ID, &r.Budget, &r.AmountMinor, &state)
	r.State = State(state)
	return r, err
}

// CommitTx turns a held reservation into spending, inside the caller's
// transaction. An invocation without a reservation is left alone.
func CommitTx(ctx context.Context, tx pgx.Tx, tenant, invocation string) error {
	return move(ctx, tx, tenant, invocation, StateHeld, StateCommitted, "reserved_minor = reserved_minor - $3, spent_minor = spent_minor + $3", "")
}

// ReleaseTx returns a held reservation to the budget. Callers must only
// release when the external effect is known not to have happened (INV-007).
func ReleaseTx(ctx context.Context, tx pgx.Tx, tenant, invocation string) error {
	return move(ctx, tx, tenant, invocation, StateHeld, StateReleased, "reserved_minor = reserved_minor - $3", "")
}

// WriteOffTx removes committed spending of an abandoned invocation and
// records the accepted risk (INV-009).
func WriteOffTx(ctx context.Context, tx pgx.Tx, tenant, invocation, note string) error {
	return move(ctx, tx, tenant, invocation, StateCommitted, StateWrittenOff, "spent_minor = spent_minor - $3", note)
}

func move(ctx context.Context, tx pgx.Tx, tenant, invocation string, from, to State, budgetUpdate, note string) error {
	var id, budget, state string
	var amount int64
	err := tx.QueryRow(ctx, `
		SELECT id, budget, state, amount_minor FROM reservations WHERE tenant = $1 AND invocation = $2 FOR UPDATE`,
		tenant, invocation).Scan(&id, &budget, &state, &amount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if State(state) != from {
		return ErrWrongState
	}
	if _, err := tx.Exec(ctx, `UPDATE budgets SET `+budgetUpdate+` WHERE tenant = $1 AND id = $2`, tenant, budget, amount); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE reservations SET state = $3, note = $4 WHERE tenant = $1 AND id = $2`, tenant, id, string(to), note)
	return err
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b)
}
