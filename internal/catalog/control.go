package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNoRow is returned by a control change whose target does not exist.
var ErrNoRow = errors.New("catalog: no such row")

// Control changes to authority facts. Each updates one fact row and
// advances its revision, so a concurrent authority fence either waits for
// it or sees it (docs/design/authority-fence.md, "What changes a fenced
// fact"). They are administrative operations (ADM-002, ADM-003).

// DisableIdentity disables an identity.
func (s *Store) DisableIdentity(ctx context.Context, tenant, id string) error {
	return s.exec1(ctx, `UPDATE identities SET disabled = true, revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
}

// TouchIdentity advances an identity's revision, for changes to its roles,
// attributes or capabilities.
func (s *Store) TouchIdentity(ctx context.Context, tenant, id string) error {
	return s.exec1(ctx, `UPDATE identities SET revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
}

// RevokeDelegation revokes a delegation.
func (s *Store) RevokeDelegation(ctx context.Context, tenant, id string) error {
	return s.exec1(ctx, `UPDATE delegations SET revoked = true, revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, id)
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
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoRow
	}
	return nil
}
