// Package approval stores operation-bound approvals in PostgreSQL
// (specification 2.5, APR-001 to APR-005). An approval is bound to one exact
// operation instance and digest, cannot be given by the requester or the
// acting agent, expires, and is consumed exactly once, in the transaction of
// the protected operation's checkpoint. It shows the approver a summary
// rendered by the platform (opplan) and depends on no tool-execution code
// (MOD-004).
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/opplan"
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

// Approval of one operation instance.
type Approval struct {
	Tenant string
	ID     string
	// Operation is the operation the approval is for: a registered storage
	// operation, whose instance the digest identifies, or an executor
	// invocation ID.
	Operation       string
	OperationDigest string
	Summary         opplan.Summary
	// RequestedBy is the represented subject (or the actor acting for
	// itself); Actor is the executing agent. Neither may approve.
	RequestedBy string
	Actor       string
	State       State
	Approver    string
	ExpiresAt   time.Time
	// Revision advances on every state change; a decision that relies on
	// the approval binds it (DEC-008).
	Revision uint64
	// TargetType and TargetID name the resource an approver needs approve
	// on (ruling 6).
	TargetType string
	TargetID   string
	// PolicyEpoch and Bindings are the policy epoch and resource revisions
	// the approval was requested under; a change to either invalidates it
	// (APR-001).
	PolicyEpoch uint64
	Bindings    []Binding
}

// BoundTo reports whether the approval was requested under policy epoch
// and resource revisions bindings, as a request must be to use it.
func (a Approval) BoundTo(epoch uint64, bindings []Binding) bool {
	return a.PolicyEpoch == epoch && slices.Equal(a.Bindings, bindings)
}

// Binding is a resource revision an approval is bound to.
type Binding struct {
	Type             string `json:"type"`
	ID               string `json:"id"`
	Generation       uint64 `json:"generation"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

// Lifetime is how long a pending or approved approval stays usable.
const Lifetime = 24 * time.Hour

// Store is the approvals table.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns a Store.
func New(pool *pgxpool.Pool, now func() time.Time) *Store { return &Store{pool: pool, now: now} }

// Request records a pending approval and returns it with its ID.
func (s *Store) Request(ctx context.Context, a Approval) (Approval, error) {
	a.ID, a.State, a.Revision = newID(), StatePending, 1
	summary, err := json.Marshal(a.Summary)
	if err != nil {
		return Approval{}, err
	}
	if a.Bindings == nil {
		a.Bindings = []Binding{}
	}
	bindings, err := json.Marshal(a.Bindings)
	if err != nil {
		return Approval{}, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO approvals (tenant, id, operation, operation_digest, summary, requested_by, actor, state, expires_at,
		                       revision, target_type, target_id, policy_epoch, bindings, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, $11, $12, $13, $14)`,
		a.Tenant, a.ID, a.Operation, a.OperationDigest, summary, a.RequestedBy, a.Actor, string(a.State), a.ExpiresAt,
		a.TargetType, a.TargetID, a.PolicyEpoch, bindings, s.now())
	return a, err
}

// Open returns the pending, unexpired approval of the same requester,
// actor, operation and digest, requested under a's policy epoch and
// resource revisions, or records a new one, so that repeating a request
// does not pile up approvals. One requested before the policy or a bound
// resource changed could never be used, so it is not returned (review v5
// F11).
func (s *Store) Open(ctx context.Context, a Approval) (Approval, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+columns+` FROM approvals
		 WHERE tenant = $1 AND state = 'PENDING' AND expires_at > $2 AND operation = $3 AND operation_digest = $4
		   AND requested_by = $5 AND actor = $6
		 ORDER BY created_at`, a.Tenant, s.now(), a.Operation, a.OperationDigest, a.RequestedBy, a.Actor)
	if err != nil {
		return Approval{}, err
	}
	defer rows.Close()
	for rows.Next() {
		p := Approval{Tenant: a.Tenant}
		if err := scan(rows, &p); err != nil {
			return Approval{}, err
		}
		if p.BoundTo(a.PolicyEpoch, a.Bindings) {
			return p, nil
		}
	}
	if err := rows.Err(); err != nil {
		return Approval{}, err
	}
	rows.Close()
	return s.Request(ctx, a)
}

const columns = `id, operation, operation_digest, summary, requested_by, actor, state, approver, expires_at,
	revision, target_type, target_id, policy_epoch, bindings`

func scan(row pgx.Row, a *Approval) error {
	var summary, bindings []byte
	var state string
	if err := row.Scan(&a.ID, &a.Operation, &a.OperationDigest, &summary, &a.RequestedBy, &a.Actor, &state, &a.Approver, &a.ExpiresAt,
		&a.Revision, &a.TargetType, &a.TargetID, &a.PolicyEpoch, &bindings); err != nil {
		return err
	}
	a.State = State(state)
	if err := json.Unmarshal(bindings, &a.Bindings); err != nil {
		return err
	}
	return json.Unmarshal(summary, &a.Summary)
}

// Get returns an approval.
func (s *Store) Get(ctx context.Context, tenant, id string) (Approval, error) {
	a := Approval{Tenant: tenant}
	err := scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM approvals WHERE tenant = $1 AND id = $2`, tenant, id), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	return a, err
}

// Pending returns up to limit pending, unexpired approvals of a tenant
// that approver did not request and does not act in, oldest first, after
// the approval named by after (empty for the first page).
func (s *Store) Pending(ctx context.Context, tenant, approver, after string, limit int) ([]Approval, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+columns+` FROM approvals
		 WHERE tenant = $1 AND state = 'PENDING' AND expires_at > $2 AND requested_by <> $3 AND actor <> $3 AND id > $4
		 ORDER BY id LIMIT $5`, tenant, s.now(), approver, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a := Approval{Tenant: tenant}
		if err := scan(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Decide approves or rejects a pending approval. The approver's authority is
// checked by the caller through the decision service; this store enforces
// that the approver is neither the requester nor the actor (APR-002).
func (s *Store) Decide(ctx context.Context, tenant, id, approver string, approve bool) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return DecideTx(ctx, tx, tenant, id, approver, approve, s.now())
	})
}

// DecideTx is Decide inside the caller's transaction, so that an
// approver's fenced decision and the approval's transition commit
// together.
func DecideTx(ctx context.Context, tx pgx.Tx, tenant, id, approver string, approve bool, now time.Time) error {
	state := StateRejected
	if approve {
		state = StateApproved
	}
	tag, err := tx.Exec(ctx, `
		UPDATE approvals SET state = $4, approver = $3, decided_at = $5, revision = revision + 1
		 WHERE tenant = $1 AND id = $2 AND state = 'PENDING' AND expires_at > $5
		   AND requested_by <> $3 AND actor <> $3`, tenant, id, approver, string(state), now)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	a := Approval{Tenant: tenant}
	err = scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM approvals WHERE tenant = $1 AND id = $2`, tenant, id), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
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

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b)
}
