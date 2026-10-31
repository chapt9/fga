// Package invocation is the durable state machine of tool invocations in
// PostgreSQL (specification 2.5, INV-001 to INV-009, APR-003, AGT-003 step
// 6). States move PREPARED -> RESERVED -> DISPATCHING -> SUCCEEDED, FAILED or
// UNKNOWN; UNKNOWN is closed only by a recorded resolution. Part of the
// optional R2 executor (feature executor).
package invocation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/approval"
	"fga/internal/reservation"
)

// State of an invocation.
type State string

const (
	StatePrepared    State = "PREPARED"
	StateReserved    State = "RESERVED"
	StateDispatching State = "DISPATCHING"
	StateSucceeded   State = "SUCCEEDED"
	StateFailed      State = "FAILED"
	StateUnknown     State = "UNKNOWN"
	StateAbandoned   State = "ABANDONED"
)

// Errors returned by the store.
var (
	ErrNotFound            = errors.New("invocation not found")
	ErrIdempotencyConflict = errors.New("idempotency key already used for a different operation")
	ErrLeased              = errors.New("another worker holds the invocation")
	ErrFenced              = errors.New("stale lease: another worker took over")
	ErrState               = errors.New("invocation is not in a state that allows this")
	ErrSelfResolution      = errors.New("the requester or acting agent cannot resolve or write off")
	ErrEvidence            = errors.New("a resolution needs evidence")
)

// Invocation is one prepared tool call.
type Invocation struct {
	Tenant          string
	ID              string
	IdempotencyKey  string
	OperationDigest string
	Tool            string
	ToolVersion     int
	Arguments       json.RawMessage
	Actor           string
	Subject         string
	Delegation      string
	State           State
	FencingToken    int64
	Receipt         string
	DispatchedAt    *time.Time
	Resolution      *Resolution
}

// Resolution records how an UNKNOWN outcome was closed (INV-006).
type Resolution struct {
	By       string    `json:"by"`
	Outcome  State     `json:"outcome"`
	Evidence string    `json:"evidence"`
	At       time.Time `json:"at"`
	WriteOff string    `json:"write_off,omitempty"`
}

// Store is the invocations table.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns a Store.
func New(pool *pgxpool.Pool, now func() time.Time) *Store { return &Store{pool: pool, now: now} }

const columns = `tenant, id, idempotency_key, operation_digest, tool, tool_version, arguments, actor, subject,
	delegation, state, fencing_token, receipt, dispatched_at, resolution`

func scan(row pgx.Row) (Invocation, error) {
	var inv Invocation
	var state string
	var resolution []byte
	err := row.Scan(&inv.Tenant, &inv.ID, &inv.IdempotencyKey, &inv.OperationDigest, &inv.Tool, &inv.ToolVersion,
		&inv.Arguments, &inv.Actor, &inv.Subject, &inv.Delegation, &state, &inv.FencingToken, &inv.Receipt,
		&inv.DispatchedAt, &resolution)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invocation{}, ErrNotFound
	}
	if err != nil {
		return Invocation{}, err
	}
	inv.State = State(state)
	if resolution != nil {
		inv.Resolution = &Resolution{}
		if err := json.Unmarshal(resolution, inv.Resolution); err != nil {
			return Invocation{}, err
		}
	}
	return inv, nil
}

// Create records a PREPARED invocation. Creating again with the same
// idempotency key returns the existing invocation if the operation and the
// actor are the same; a different operation, or another actor, under the
// same key is refused (INV-004), so a key never shows one actor's
// invocation to another.
func (s *Store) Create(ctx context.Context, inv Invocation) (Invocation, error) {
	inv.ID, inv.State = newID(), StatePrepared
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO invocations (tenant, id, idempotency_key, operation_digest, tool, tool_version, arguments, actor,
		                         subject, delegation, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (tenant, idempotency_key) DO NOTHING`,
		inv.Tenant, inv.ID, inv.IdempotencyKey, inv.OperationDigest, inv.Tool, inv.ToolVersion, inv.Arguments,
		inv.Actor, inv.Subject, inv.Delegation, string(inv.State))
	if err != nil {
		return Invocation{}, err
	}
	if tag.RowsAffected() == 1 {
		return s.Get(ctx, inv.Tenant, inv.ID)
	}
	existing, err := scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM invocations WHERE tenant = $1 AND idempotency_key = $2`,
		inv.Tenant, inv.IdempotencyKey))
	if err != nil {
		return Invocation{}, err
	}
	if existing.OperationDigest != inv.OperationDigest || existing.Actor != inv.Actor || existing.Subject != inv.Subject ||
		existing.Delegation != inv.Delegation {
		return Invocation{}, ErrIdempotencyConflict
	}
	return existing, nil
}

// Get returns an invocation.
func (s *Store) Get(ctx context.Context, tenant, id string) (Invocation, error) {
	return scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM invocations WHERE tenant = $1 AND id = $2`, tenant, id))
}

// MarkReserved records that the invocation's reservation is held.
func (s *Store) MarkReserved(ctx context.Context, tenant, id string) error {
	return s.transition(ctx, tenant, id, []State{StatePrepared, StateReserved}, StateReserved)
}

func (s *Store) transition(ctx context.Context, tenant, id string, from []State, to State) error {
	tag, err := s.pool.Exec(ctx, `UPDATE invocations SET state = $3, updated_at = $5
		WHERE tenant = $1 AND id = $2 AND state = ANY($4)`, tenant, id, string(to), statesOf(from), s.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrState
	}
	return nil
}

// Acquire gives owner the dispatch lease and a new fencing token. It fails
// while another worker's lease is live. An invocation found in DISPATCHING
// was abandoned by a worker: the new owner must reconcile it, never
// redispatch (INV-003).
func (s *Store) Acquire(ctx context.Context, tenant, id, owner string, lease time.Duration) (Invocation, error) {
	now := s.now()
	inv, err := scan(s.pool.QueryRow(ctx, `
		UPDATE invocations SET lease_owner = $3, lease_expires_at = $4, fencing_token = fencing_token + 1, updated_at = $5
		 WHERE tenant = $1 AND id = $2 AND state IN ('PREPARED', 'RESERVED', 'DISPATCHING')
		   AND (lease_expires_at IS NULL OR lease_expires_at <= $5)
		RETURNING `+columns, tenant, id, owner, now.Add(lease), now))
	if !errors.Is(err, ErrNotFound) {
		return inv, err
	}
	current, err := s.Get(ctx, tenant, id)
	if err != nil {
		return Invocation{}, err
	}
	if slices.Contains([]State{StatePrepared, StateReserved, StateDispatching}, current.State) {
		return Invocation{}, ErrLeased
	}
	return Invocation{}, ErrState
}

// locked loads the invocation for update and checks the caller's lease.
func (s *Store) locked(ctx context.Context, tx pgx.Tx, tenant, id string, token int64) (Invocation, error) {
	var leaseExpires *time.Time
	inv, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM invocations WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id))
	if err != nil {
		return Invocation{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT lease_expires_at FROM invocations WHERE tenant = $1 AND id = $2`, tenant, id).Scan(&leaseExpires); err != nil {
		return Invocation{}, err
	}
	if inv.FencingToken != token || leaseExpires == nil || !s.now().Before(*leaseExpires) {
		return Invocation{}, ErrFenced
	}
	return inv, nil
}

// BeginDispatch moves a leased invocation to DISPATCHING and, if an approval
// is named, consumes it in the same transaction (INV-002, APR-003).
func (s *Store) BeginDispatch(ctx context.Context, tenant, id string, token int64, approvalID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		inv, err := s.locked(ctx, tx, tenant, id, token)
		if err != nil {
			return err
		}
		if inv.State != StatePrepared && inv.State != StateReserved {
			return ErrState
		}
		now := s.now()
		if approvalID != "" {
			if err := approval.ConsumeTx(ctx, tx, tenant, approvalID, inv.OperationDigest, now); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE invocations SET state = 'DISPATCHING', dispatched_at = $3, updated_at = $3
			WHERE tenant = $1 AND id = $2`, tenant, id, now)
		return err
	})
}

// DispatchTx moves a leased invocation to DISPATCHING inside tx, the
// authority fence of its decision, which consumes the decision and the
// approval it binds in the same transaction (INV-002). It returns the
// invocation as it was.
func (s *Store) DispatchTx(ctx context.Context, tx pgx.Tx, tenant, id string, token int64) (Invocation, error) {
	inv, err := s.locked(ctx, tx, tenant, id, token)
	if err != nil {
		return Invocation{}, err
	}
	if inv.State != StatePrepared && inv.State != StateReserved {
		return Invocation{}, ErrState
	}
	_, err = tx.Exec(ctx, `UPDATE invocations SET state = 'DISPATCHING', dispatched_at = $3, updated_at = $3
		WHERE tenant = $1 AND id = $2`, tenant, id, s.now())
	return inv, err
}

// Complete records the dispatch outcome. SUCCEEDED commits the reservation,
// FAILED (the effect is known not to have happened) releases it, and
// UNKNOWN keeps it until resolution (INV-007).
func (s *Store) Complete(ctx context.Context, tenant, id string, token int64, outcome State, receipt string) error {
	if outcome != StateSucceeded && outcome != StateFailed && outcome != StateUnknown {
		return fmt.Errorf("invocation: %s is not a dispatch outcome", outcome)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		inv, err := s.locked(ctx, tx, tenant, id, token)
		if err != nil {
			return err
		}
		if inv.State != StateDispatching {
			return ErrState
		}
		if err := settle(ctx, tx, tenant, id, outcome); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE invocations SET state = $3, receipt = $4, lease_owner = '', lease_expires_at = NULL,
			updated_at = $5 WHERE tenant = $1 AND id = $2`, tenant, id, string(outcome), receipt, s.now())
		return err
	})
}

// settle applies an outcome to the reservation. ABANDONED keeps the charge
// (INV-009).
func settle(ctx context.Context, tx pgx.Tx, tenant, id string, outcome State) error {
	switch outcome {
	case StateSucceeded, StateAbandoned:
		return reservation.CommitTx(ctx, tx, tenant, id)
	case StateFailed:
		return reservation.ReleaseTx(ctx, tx, tenant, id)
	}
	return nil
}

// Resolve closes an UNKNOWN invocation as SUCCEEDED, FAILED (verified by
// evidence) or ABANDONED. The resolver must not be the requester or the
// acting agent (INV-006). ABANDONED keeps the reservation charged and
// prohibits redispatch (INV-009).
func (s *Store) Resolve(ctx context.Context, tenant, id, resolver string, outcome State, evidence string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return s.ResolveTx(ctx, tx, tenant, id, resolver, outcome, evidence) })
}

// ResolveTx is Resolve inside tx, such as the authority fence of the
// resolver's decision.
func (s *Store) ResolveTx(ctx context.Context, tx pgx.Tx, tenant, id, resolver string, outcome State, evidence string) error {
	if outcome != StateSucceeded && outcome != StateFailed && outcome != StateAbandoned {
		return fmt.Errorf("invocation: %s is not a resolution", outcome)
	}
	if evidence == "" {
		return ErrEvidence
	}
	inv, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM invocations WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id))
	if err != nil {
		return err
	}
	if inv.State != StateUnknown {
		return ErrState
	}
	if resolver == inv.Actor || resolver == inv.Subject {
		return ErrSelfResolution
	}
	if err := settle(ctx, tx, tenant, id, outcome); err != nil {
		return err
	}
	res, _ := json.Marshal(Resolution{By: resolver, Outcome: outcome, Evidence: evidence, At: s.now()})
	_, err = tx.Exec(ctx, `UPDATE invocations SET state = $3, resolution = $4, updated_at = $5 WHERE tenant = $1 AND id = $2`,
		tenant, id, string(outcome), res, s.now())
	return err
}

// WriteOff releases the charge of an ABANDONED invocation as an accepted
// risk, recorded with the principal and note (INV-009). It does not make
// the invocation dispatchable.
func (s *Store) WriteOff(ctx context.Context, tenant, id, principal, note string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return s.WriteOffTx(ctx, tx, tenant, id, principal, note) })
}

// WriteOffTx is WriteOff inside tx, such as the authority fence of the
// principal's decision.
func (s *Store) WriteOffTx(ctx context.Context, tx pgx.Tx, tenant, id, principal, note string) error {
	if note == "" {
		return ErrEvidence
	}
	inv, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM invocations WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id))
	if err != nil {
		return err
	}
	if inv.State != StateAbandoned {
		return ErrState
	}
	if principal == inv.Actor || principal == inv.Subject {
		return ErrSelfResolution
	}
	if err := reservation.WriteOffTx(ctx, tx, tenant, id, note); err != nil {
		return err
	}
	inv.Resolution.WriteOff = principal + ": " + note
	res, _ := json.Marshal(inv.Resolution)
	_, err = tx.Exec(ctx, `UPDATE invocations SET resolution = $3, updated_at = $4 WHERE tenant = $1 AND id = $2`,
		tenant, id, res, s.now())
	return err
}

// Stalled returns DISPATCHING invocations whose lease has expired: a worker
// stopped mid-dispatch and a replacement must reconcile them.
func (s *Store) Stalled(ctx context.Context, limit int) ([]Invocation, error) {
	return s.list(ctx, `state = 'DISPATCHING' AND lease_expires_at <= $2`, limit, s.now())
}

// Escalate marks an UNKNOWN invocation escalated (INV-006). It reports
// whether this call did so: an invocation is escalated once.
func (s *Store) Escalate(ctx context.Context, tenant, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE invocations SET escalated_at = $3, updated_at = $3
		WHERE tenant = $1 AND id = $2 AND state = 'UNKNOWN' AND escalated_at IS NULL`, tenant, id, s.now())
	return tag.RowsAffected() == 1, err
}

// Unknown returns UNKNOWN invocations, oldest dispatch first, for escalation
// by hold age (INV-006).
func (s *Store) Unknown(ctx context.Context, limit int) ([]Invocation, error) {
	return s.list(ctx, `state = 'UNKNOWN'`, limit)
}

// list runs a filtered query; $1 is the limit and args fill $2 onwards.
func (s *Store) list(ctx context.Context, where string, limit int, args ...any) ([]Invocation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM invocations WHERE `+where+` ORDER BY dispatched_at LIMIT $1`,
		append([]any{limit}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invocation
	for rows.Next() {
		inv, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func statesOf(states []State) []string {
	out := make([]string, len(states))
	for i, s := range states {
		out[i] = string(s)
	}
	return out
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b)
}
