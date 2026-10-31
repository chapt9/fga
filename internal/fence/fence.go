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

// Run locks and rechecks b in the fixed order, calls fn for the operation's
// own rows (step 7), consumes a single-use decision (step 8), checks the
// time once more and commits. mutate names the resources the operation
// changes; they are locked for update rather than share. Any failure rolls
// everything back.
func (f *Fence) Run(ctx context.Context, b Binding, mutate []string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if err := f.check(ctx, tx, b, mutate); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if b.SingleUse {
			tag, err := tx.Exec(ctx, `INSERT INTO consumed_decisions (decision_id, valid_until, incarnation) VALUES ($1, $2, $3)
			                          ON CONFLICT DO NOTHING`, b.DecisionID, b.ValidUntil, b.Incarnation)
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

// Check rechecks b without a transition, holding its locks only for the
// check. Stream leases use it to revalidate an admitted read (CNT-008).
func (f *Fence) Check(ctx context.Context, b Binding) error {
	return pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		return f.check(ctx, tx, b, nil)
	})
}

func (f *Fence) checkTime(b Binding) error {
	if !f.now().Add(f.margin).Before(b.ValidUntil) {
		return ErrExpired
	}
	return nil
}

// check runs steps 1 to 6 of the lock order.
func (f *Fence) check(ctx context.Context, tx pgx.Tx, b Binding, mutate []string) error {
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
	return nil
}
