// Package fence is the authority fence of docs/design/authority-fence.md
// (specification 2.5, DAT-007, DEC-006, DEC-011, AVL-008): the final checks
// of a signed decision and the protected catalog transition it authorizes
// commit in one PostgreSQL transaction, ordered against every change to the
// facts checked.
//
// The fence locks each fact row the decision is bound to, in a fixed order,
// with a locking read. A concurrent change to one of those rows either
// commits first, and the fence then sees the new revision and rolls back, or
// waits until the fence has committed. Policy evaluation and network calls
// never run inside it.
package fence

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/signing"
)

// Errors of a failed fence. Each means the decision no longer matches
// authority and a new decision (or a rejection) is needed.
var (
	ErrAdmissionClosed = errors.New("fence: admission is closed for recovery")
	ErrIncarnation     = errors.New("fence: decision is from another recovery incarnation")
	ErrEpoch           = errors.New("fence: the required policy epoch has passed the decision's")
	ErrIdentity        = errors.New("fence: an identity changed, expired or was disabled")
	ErrDelegation      = errors.New("fence: a delegation changed, expired or was revoked")
	ErrRecipientKey    = errors.New("fence: a recipient key changed or is not active")
	ErrResource        = errors.New("fence: a bound resource changed")
	ErrExpired         = errors.New("fence: decision expired")
	ErrReplayed        = errors.New("fence: single-use decision already consumed")
	ErrApproval        = errors.New("fence: the approval changed, expired or was consumed")
)

// Ref names a row by ID at a revision.
type Ref struct {
	ID       string
	Revision uint64
}

// Resource is a bound resource. Generation 0 binds a planned resource,
// which must not exist yet (it is created by the fenced transition).
type Resource struct {
	Type             string
	ID               string
	Generation       uint64
	MetadataRevision uint64
}

// Binding is the authority a decision is bound to, as the fence rechecks
// it.
type Binding struct {
	DecisionID  string
	Tenant      string
	Incarnation uint64
	PolicyEpoch uint64
	ValidUntil  time.Time
	SingleUse   bool
	Identities  []Ref
	Delegations []Ref
	Keys        []Ref // recipient-key fingerprints and revisions
	Resources   []Resource
	// Approval is the approval the decision relied on, if any. It must
	// still be APPROVED at its revision, and Run consumes it (APR-002,
	// APR-003).
	Approval *Ref
}

// FromRecord returns the binding of a verified decision record: its actor,
// subject and every check principal; its delegation chain; every recipient
// key; and every bound resource.
func FromRecord(rec signing.Record) (Binding, error) {
	b := Binding{DecisionID: rec.DecisionID, Tenant: rec.Tenant, Incarnation: rec.RecoveryIncarnation,
		PolicyEpoch: rec.PolicyEpoch, ValidUntil: rec.ValidUntil, SingleUse: rec.SingleUse}
	ids := map[string]uint64{}
	keys := map[string]uint64{}
	resources := map[[2]string]Resource{}
	add := func(m map[string]uint64, id string, rev uint64) error {
		if old, ok := m[id]; ok && old != rev {
			return fmt.Errorf("fence: %s is bound at two revisions", id)
		}
		m[id] = rev
		return nil
	}
	refs := []signing.Ref{rec.Actor}
	if rec.Delegation != "" {
		refs = append(refs, rec.Subject)
	}
	for _, c := range rec.Checks {
		refs = append(refs, c.Principal)
		if c.PrincipalBinding != "" {
			if err := add(keys, c.PrincipalBinding, c.KeyRevision); err != nil {
				return Binding{}, err
			}
		}
		r := Resource{Type: c.ResourceType, ID: c.ResourceID, Generation: c.Generation, MetadataRevision: c.MetadataRevision}
		k := [2]string{r.Type, r.ID}
		if old, ok := resources[k]; ok && old != r {
			return Binding{}, fmt.Errorf("fence: %s %s is bound in two states", r.Type, r.ID)
		}
		resources[k] = r
	}
	for _, r := range refs {
		if r.ID == "" {
			return Binding{}, errors.New("fence: a bound identity has no ID")
		}
		if err := add(ids, r.ID, r.Revision); err != nil {
			return Binding{}, err
		}
	}
	if a := rec.Context.Approval; a.ID != "" {
		b.Approval = &Ref{ID: a.ID, Revision: a.Revision}
	}
	b.Identities = sortedRefs(ids)
	b.Keys = sortedRefs(keys)
	for _, d := range rec.DelegationChain {
		b.Delegations = append(b.Delegations, Ref(d))
	}
	slices.SortFunc(b.Delegations, func(x, y Ref) int { return cmp.Compare(x.ID, y.ID) })
	for _, r := range resources {
		b.Resources = append(b.Resources, r)
	}
	slices.SortFunc(b.Resources, func(x, y Resource) int {
		return cmp.Or(cmp.Compare(x.Type, y.Type), cmp.Compare(x.ID, y.ID))
	})
	return b, nil
}

func sortedRefs(m map[string]uint64) []Ref {
	out := make([]Ref, 0, len(m))
	for id, rev := range m {
		out = append(out, Ref{ID: id, Revision: rev})
	}
	slices.SortFunc(out, func(x, y Ref) int { return cmp.Compare(x.ID, y.ID) })
	return out
}

// Fence runs fenced transitions over one catalog.
type Fence struct {
	pool   *pgxpool.Pool
	margin time.Duration
	now    func() time.Time
}

// New returns a Fence. margin is the clock allowance subtracted from
// valid_until (POL-008).
func New(pool *pgxpool.Pool, margin time.Duration, now func() time.Time) *Fence {
	return &Fence{pool: pool, margin: margin, now: now}
}

// Run locks and rechecks b in the fixed order (steps 1 to 7), calls fn for
// the operation's own rows, consumes the approval the decision relied on
// and a single-use decision, checks the time once more and commits. mutate
// names the resources the operation changes; they are locked for update
// rather than share. Any failure rolls everything back.
func (f *Fence) Run(ctx context.Context, b Binding, mutate []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return f.RunAll(ctx, []Binding{b}, mutate, fn)
}

// RunAll is Run for an operation authorized by several decisions, such as
// a document publication whose checks are split into batches (DEC-009).
// Every decision's facts are checked together in the one lock order, and
// every decision is consumed in the same transaction, so the operation
// commits only if all of them still hold.
func (f *Fence) RunAll(ctx context.Context, bs []Binding, mutate []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	b, err := Merge(bs)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if err := f.check(ctx, tx, b, mutate, true); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if b.Approval != nil {
			tag, err := tx.Exec(ctx, `UPDATE approvals SET state = 'CONSUMED', consumed_at = $4, revision = revision + 1
			                           WHERE tenant = $1 AND id = $2 AND revision = $3 AND state = 'APPROVED'`,
				b.Tenant, b.Approval.ID, b.Approval.Revision, f.now())
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrApproval
			}
		}
		for _, d := range bs {
			if !d.SingleUse {
				continue
			}
			tag, err := tx.Exec(ctx, `INSERT INTO consumed_decisions (decision_id, valid_until, incarnation) VALUES ($1, $2, $3)
			                          ON CONFLICT DO NOTHING`, d.DecisionID, d.ValidUntil, d.Incarnation)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return ErrReplayed
			}
		}
		return f.checkTime(b)
	})
}

// Merge combines bindings of one operation into the binding the fence
// checks (and a read lease rechecks): same tenant and incarnation, the earliest expiry, the lowest
// policy epoch, and the union of every bound fact, which must agree where
// bindings share one. At most one approval may be bound.
func Merge(bs []Binding) (Binding, error) {
	if len(bs) == 0 {
		return Binding{}, errors.New("fence: no decision")
	}
	m := bs[0]
	m.Identities, m.Delegations, m.Keys, m.Resources = nil, nil, nil, nil
	ids, dels, keys := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	res := map[[2]string]Resource{}
	add := func(into map[string]uint64, refs []Ref) error {
		for _, r := range refs {
			if old, ok := into[r.ID]; ok && old != r.Revision {
				return fmt.Errorf("fence: %s is bound at two revisions", r.ID)
			}
			into[r.ID] = r.Revision
		}
		return nil
	}
	for i, b := range bs {
		if b.Tenant != m.Tenant || b.Incarnation != m.Incarnation {
			return Binding{}, errors.New("fence: decisions of one operation differ in tenant or incarnation")
		}
		if b.ValidUntil.Before(m.ValidUntil) {
			m.ValidUntil = b.ValidUntil
		}
		m.PolicyEpoch = min(m.PolicyEpoch, b.PolicyEpoch)
		if b.Approval != nil {
			if i > 0 && m.Approval != nil {
				return Binding{}, errors.New("fence: more than one approval is bound")
			}
			m.Approval = b.Approval
		}
		for _, err := range []error{add(ids, b.Identities), add(dels, b.Delegations), add(keys, b.Keys)} {
			if err != nil {
				return Binding{}, err
			}
		}
		for _, r := range b.Resources {
			k := [2]string{r.Type, r.ID}
			if old, ok := res[k]; ok && old != r {
				return Binding{}, fmt.Errorf("fence: %s %s is bound in two states", r.Type, r.ID)
			}
			res[k] = r
		}
	}
	m.Identities, m.Delegations, m.Keys = sortedRefs(ids), sortedRefs(dels), sortedRefs(keys)
	for _, r := range res {
		m.Resources = append(m.Resources, r)
	}
	slices.SortFunc(m.Resources, func(x, y Resource) int { return cmp.Or(cmp.Compare(x.Type, y.Type), cmp.Compare(x.ID, y.ID)) })
	return m, nil
}

// Check rechecks b without a transition, holding its locks only for the
// check. Stream leases use it to revalidate an admitted read (CNT-008).
func (f *Fence) Check(ctx context.Context, b Binding) error {
	return pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		return f.check(ctx, tx, b, nil, false)
	})
}

func (f *Fence) checkTime(b Binding) error {
	if !f.now().Add(f.margin).Before(b.ValidUntil) {
		return ErrExpired
	}
	return nil
}

// check runs steps 1 to 7 of the lock order; run says whether Run will
// consume the approval.
func (f *Fence) check(ctx context.Context, tx pgx.Tx, b Binding, mutate []string, run bool) error {
	if err := f.checkTime(b); err != nil {
		return err
	}
	now := f.now()

	// 1. Authority state.
	var incarnation uint64
	var open bool
	if err := tx.QueryRow(ctx, `SELECT incarnation, admission_open FROM authority_state WHERE id = 1 FOR SHARE`).Scan(&incarnation, &open); err != nil {
		return fmt.Errorf("fence: authority state: %w", err)
	}
	switch {
	case !open:
		return ErrAdmissionClosed
	case incarnation != b.Incarnation:
		return ErrIncarnation
	}

	// 2. Tenant epoch. A tenant without a row requires no epoch.
	var required uint64
	err := tx.QueryRow(ctx, `SELECT required_epoch FROM tenant_epochs WHERE tenant = $1 FOR SHARE`, b.Tenant).Scan(&required)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("fence: tenant epoch: %w", err)
	}
	if required > b.PolicyEpoch {
		return ErrEpoch
	}

	// 3. Identities.
	for _, r := range b.Identities {
		var rev uint64
		var disabled bool
		var expires *time.Time
		err := tx.QueryRow(ctx, `SELECT revision, disabled, expires_at FROM identities WHERE tenant = $1 AND id = $2 FOR SHARE`,
			b.Tenant, r.ID).Scan(&rev, &disabled, &expires)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (rev != r.Revision || disabled || expires != nil && !now.Before(*expires)) {
			return ErrIdentity
		}
		if err != nil {
			return fmt.Errorf("fence: identity: %w", err)
		}
	}

	// 4. Delegations.
	for _, r := range b.Delegations {
		var rev uint64
		var revoked bool
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT revision, revoked, expires_at FROM delegations WHERE tenant = $1 AND id = $2 FOR SHARE`,
			b.Tenant, r.ID).Scan(&rev, &revoked, &expires)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (rev != r.Revision || revoked || !now.Before(expires)) {
			return ErrDelegation
		}
		if err != nil {
			return fmt.Errorf("fence: delegation: %w", err)
		}
	}

	// 5. Recipient keys.
	for _, r := range b.Keys {
		var rev uint64
		var status string
		err := tx.QueryRow(ctx, `SELECT revision, status FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2 FOR SHARE`,
			b.Tenant, r.ID).Scan(&rev, &status)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (rev != r.Revision || status != "ACTIVE") {
			return ErrRecipientKey
		}
		if err != nil {
			return fmt.Errorf("fence: recipient key: %w", err)
		}
	}

	// 6. Resources: changed ones for update, the others for share. A
	// planned resource (generation 0) must still be absent.
	for _, r := range b.Resources {
		lock := "FOR SHARE"
		if slices.Contains(mutate, r.ID) {
			lock = "FOR UPDATE"
		}
		var gen, meta uint64
		err := tx.QueryRow(ctx, `SELECT generation, metadata_revision FROM resources WHERE tenant = $1 AND type = $2 AND id = $3 `+lock,
			b.Tenant, r.Type, r.ID).Scan(&gen, &meta)
		switch {
		case r.Generation == 0 && errors.Is(err, pgx.ErrNoRows):
			continue
		case r.Generation == 0 && err == nil, errors.Is(err, pgx.ErrNoRows):
			return ErrResource
		case err != nil:
			return fmt.Errorf("fence: resource: %w", err)
		case gen != r.Generation || meta != r.MetadataRevision:
			return ErrResource
		}
	}

	// 7. The approval the decision relied on, locked for update when Run
	// will consume it.
	if a := b.Approval; a != nil {
		lock := "FOR SHARE"
		if run {
			lock = "FOR UPDATE"
		}
		var state string
		var rev uint64
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT state, revision, expires_at FROM approvals WHERE tenant = $1 AND id = $2 `+lock, b.Tenant, a.ID).
			Scan(&state, &rev, &expires)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (state != "APPROVED" || rev != a.Revision || !now.Before(expires)) {
			return ErrApproval
		}
		if err != nil {
			return fmt.Errorf("fence: approval: %w", err)
		}
	}
	return nil
}
