package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/delegation"
)

// ErrNoRow is returned by a control change whose target does not exist.
var ErrNoRow = errors.New("catalog: no such row")

// Control changes to authority facts. Each updates one fact row and
// advances its revision, so a concurrent authority fence either waits for
// it or sees it (docs/design/authority-fence.md, "What changes a fenced
// fact"). They are administrative operations (ADM-002, ADM-003).

// DisableIdentity disables an identity.
func (s *Store) DisableIdentity(ctx context.Context, tenant, id string) error {
	return disableIdentity(ctx, s.pool, tenant, id)
}

func disableIdentity(ctx context.Context, q Querier, tenant, id string) error {
	return execOne(ctx, q, `UPDATE identities SET disabled = true, revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
}

// TouchIdentity advances an identity's revision, for changes to its roles,
// attributes or capabilities.
func (s *Store) TouchIdentity(ctx context.Context, tenant, id string) error {
	return s.exec1(ctx, `UPDATE identities SET revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
}

// RevokeDelegation revokes a delegation.
func (s *Store) RevokeDelegation(ctx context.Context, tenant, id string) error {
	return revokeDelegation(ctx, s.pool, tenant, id)
}

func revokeDelegation(ctx context.Context, q Querier, tenant, id string) error {
	return execOne(ctx, q, `UPDATE delegations SET revoked = true, revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
}

// RevokeRecipientKey revokes a recipient key and its resource record.
func (s *Store) RevokeRecipientKey(ctx context.Context, tenant, fingerprint string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE recipient_keys SET status = 'REVOKED', revision = revision + 1
		                           WHERE tenant = $1 AND fingerprint = $2 AND status <> 'REVOKED'`, tenant, fingerprint)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNoRow
		}
		_, err = tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"REVOKED"}'
		                        WHERE tenant = $1 AND type = 'crypto.recipient' AND id = $2`, tenant, fingerprint)
		return err
	})
}

// RaiseEpoch sets a tenant's required policy epoch, which only grows
// (REL-004).
func (s *Store) RaiseEpoch(ctx context.Context, tenant string, epoch uint64) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_epochs (tenant, required_epoch) VALUES ($1, $2)
		ON CONFLICT (tenant) DO UPDATE SET required_epoch = excluded.required_epoch
		 WHERE tenant_epochs.required_epoch < excluded.required_epoch`, tenant, epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("catalog: epoch %d is not above the required epoch", epoch)
	}
	return nil
}

// SetAdmission opens or closes admission and, when incarnation is not 0,
// moves to that recovery incarnation, which must be higher than the
// current one (AVL-008).
func (s *Store) SetAdmission(ctx context.Context, open bool, incarnation uint64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE authority_state SET admission_open = $1, incarnation = CASE WHEN $2 = 0 THEN incarnation ELSE $2 END,
		       changed_at = $3
		 WHERE id = 1 AND ($2 = 0 OR $2 > incarnation)`, open, incarnation, time.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("catalog: incarnation %d is not above the current one", incarnation)
	}
	return nil
}

func (s *Store) exec1(ctx context.Context, sql string, args ...any) error {
	return execOne(ctx, s.pool, sql, args...)
}

// execOne runs a statement that must change exactly one row.
func execOne(ctx context.Context, q Querier, sql string, args ...any) error {
	tag, err := q.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRow
	}
	return nil
}

// ErrDelegationExists is returned for a delegation ID already in use: a
// delegation is never changed, only revoked and replaced (DLG-005).
var ErrDelegationExists = errors.New("catalog: delegation exists")

// PutDelegation records a new delegation (DLG-001). It must name an actor
// other than its subject, an audience, at least one grant and a future
// expiry; a child must narrow its usable parent (DLG-002). Actor and
// subject must be known identities.
func (s *Store) PutDelegation(ctx context.Context, d delegation.Delegation, now time.Time) error {
	return s.putDelegation(ctx, s.pool, d, now)
}

func (s *Store) putDelegation(ctx context.Context, q Querier, d delegation.Delegation, now time.Time) error {
	switch {
	case d.ID == "" || len(d.ID) > 128 || d.Tenant == "" || d.Actor == "" || d.Subject == "" || d.Audience == "":
		return errors.New("catalog: a delegation needs an ID, tenant, actor, subject and audience")
	case d.Actor == d.Subject:
		return errors.New("catalog: a delegation's actor and subject differ")
	case len(d.Grants) == 0:
		return errors.New("catalog: a delegation grants at least one action")
	case !now.Before(d.ExpiresAt):
		return errors.New("catalog: a delegation expires in the future")
	}
	grants := make([]grantJSON, 0, len(d.Grants))
	for _, g := range d.Grants {
		if g.ResourceType == "" || len(g.Actions) == 0 {
			return errors.New("catalog: a grant names a resource type and actions")
		}
		grants = append(grants, grantJSON{ResourceType: g.ResourceType, Actions: g.Actions})
	}
	var parent *string
	if d.Parent != "" {
		chain, err := delegation.Resolve(ctx, s.Delegations(), d.Tenant, d.Parent, now)
		if err != nil {
			return fmt.Errorf("catalog: parent delegation: %w", err)
		}
		if len(chain) >= delegation.MaxDepth {
			return delegation.ErrTooDeep
		}
		if err := delegation.ValidateChild(d, chain.Leaf()); err != nil {
			return err
		}
		p := string(d.Parent)
		parent = &p
	}
	raw, err := json.Marshal(grants)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `INSERT INTO delegations (tenant, id, actor, subject, audience, grants, expires_at, parent, revision)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1) ON CONFLICT (tenant, id) DO NOTHING`,
		d.Tenant, string(d.ID), d.Actor, d.Subject, d.Audience, raw, d.ExpiresAt, parent)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrDelegationExists
	}
	return err
}
