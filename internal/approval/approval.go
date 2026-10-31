// Package approval stores approvals of prepared invocations in PostgreSQL
// (specification 2.5, APR-001 to APR-005). An approval is bound to one exact
// operation digest, cannot be given by the requester or the acting agent,
// expires, and is consumed exactly once at the dispatch checkpoint.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/tools"
)

// Errors returned by the store.
var (
	ErrNotFound     = errors.New("approval not found")
	ErrSelfApproval = errors.New("the requester or acting agent cannot approve")
	ErrNotPending   = errors.New("approval is no longer pending")
	ErrExpired      = errors.New("approval expired")
	ErrNotUsable    = errors.New("approval is not approved for this operation")
)

// State of an approval.
type State string

const (
	StatePending  State = "PENDING"
	StateApproved State = "APPROVED"
	StateRejected State = "REJECTED"
	StateConsumed State = "CONSUMED"
)

// Approval of one invocation.
type Approval struct {
	Tenant          string
	ID              string
	Invocation      string
	OperationDigest string
	Summary         tools.Summary
	// RequestedBy is the represented subject (or the actor acting for
	// itself); Actor is the executing agent. Neither may approve.
	RequestedBy string
	Actor       string
	State       State
	Approver    string
	ExpiresAt   time.Time
}

// Store is the approvals table.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns a Store.
func New(pool *pgxpool.Pool, now func() time.Time) *Store { return &Store{pool: pool, now: now} }

// Request records a pending approval and returns it with its ID.
func (s *Store) Request(ctx context.Context, a Approval) (Approval, error) {
	a.ID, a.State = newID(), StatePending
	summary, err := json.Marshal(a.Summary)
	if err != nil {
		return Approval{}, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO approvals (tenant, id, invocation, operation_digest, summary, requested_by, actor, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.Tenant, a.ID, a.Invocation, a.OperationDigest, summary, a.RequestedBy, a.Actor, string(a.State), a.ExpiresAt)
	return a, err
}

// Get returns an approval.
func (s *Store) Get(ctx context.Context, tenant, id string) (Approval, error) {
	a := Approval{Tenant: tenant, ID: id}
	var summary []byte
	var state string
	err := s.pool.QueryRow(ctx, `
		SELECT invocation, operation_digest, summary, requested_by, actor, state, approver, expires_at
		  FROM approvals WHERE tenant = $1 AND id = $2`, tenant, id).
		Scan(&a.Invocation, &a.OperationDigest, &summary, &a.RequestedBy, &a.Actor, &state, &a.Approver, &a.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, err
	}
	a.State = State(state)
	return a, json.Unmarshal(summary, &a.Summary)
}

// Decide approves or rejects a pending approval. The approver's authority is
// checked by the caller through the decision service; this store enforces
// that the approver is neither the requester nor the actor (APR-002).
func (s *Store) Decide(ctx context.Context, tenant, id, approver string, approve bool) error {
	state := StateRejected
	if approve {
		state = StateApproved
	}
	now := s.now()
	tag, err := s.pool.Exec(ctx, `
		UPDATE approvals SET state = $4, approver = $3, decided_at = $5
		 WHERE tenant = $1 AND id = $2 AND state = 'PENDING' AND expires_at > $5
		   AND requested_by <> $3 AND actor <> $3`, tenant, id, approver, string(state), now)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	a, err := s.Get(ctx, tenant, id)
	switch {
	case err != nil:
		return err
	case approver == a.RequestedBy || approver == a.Actor:
		return ErrSelfApproval
	case a.State != StatePending:
		return ErrNotPending
	default:
		return ErrExpired
	}
}

// Usable reports whether an approval is approved, unexpired and bound to
// operationDigest. A changed operation needs a new approval (V-030).
func (s *Store) Usable(ctx context.Context, tenant, id, operationDigest string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM approvals WHERE tenant = $1 AND id = $2 AND state = 'APPROVED'
		                AND operation_digest = $3 AND expires_at > $4)`, tenant, id, operationDigest, s.now()).Scan(&ok)
	return ok, err
}

// ConsumeTx consumes an approval inside the caller's dispatch transaction,
// so consumption and the invocation's ownership transition commit together
// (APR-003, INV-002). Only one transaction can consume it.
func ConsumeTx(ctx context.Context, tx pgx.Tx, tenant, id, operationDigest string, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE approvals SET state = 'CONSUMED', consumed_at = $4
		 WHERE tenant = $1 AND id = $2 AND state = 'APPROVED' AND operation_digest = $3 AND expires_at > $4`,
		tenant, id, operationDigest, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotUsable
	}
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b)
}
