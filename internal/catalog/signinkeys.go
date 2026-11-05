package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fga/internal/authn"
	"fga/internal/cryptowire"
)

// SignInKey is a registered sign-in key (migration 0033,
// docs/design/sign-in-keys.md): an Ed25519 public key its owner signs
// short access tokens with, a label naming where it is used, and limits
// below the account's rights.
type SignInKey struct {
	Fingerprint string          `json:"fingerprint"`
	Principal   string          `json:"principal"`
	Public      []byte          `json:"public_key"`
	Label       string          `json:"label"`
	Limits      authn.KeyLimits `json:"limits"`
	Status      string          `json:"status"`
	Revision    int64           `json:"revision"`
	CreatedAt   time.Time       `json:"created_at"`
	ChangedAt   time.Time       `json:"changed_at"`
}

// ErrSignInKeyExists means the key is already registered in the tenant,
// active or removed: a removed key is never registered again.
var ErrSignInKeyExists = errors.New("catalog: the sign-in key is already registered")

// ErrIdentityDisabled means the identity is disabled.
var ErrIdentityDisabled = errors.New("catalog: the identity is disabled")

// AddSignInKey registers public as an ACTIVE sign-in key of principal,
// which must be an enabled identity, and returns its fingerprint.
func (a *Admin) AddSignInKey(ctx context.Context, tenant, principal string, public []byte, label string, limits authn.KeyLimits) (string, error) {
	if !cryptowire.ValidEd25519PublicKey(public) {
		return "", errors.New("catalog: not a usable Ed25519 public key")
	}
	var disabled bool
	err := a.tx.QueryRow(ctx, `SELECT disabled FROM identities WHERE tenant = $1 AND id = $2 FOR SHARE`, tenant, principal).Scan(&disabled)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", ErrNoRow
	case err != nil:
		return "", err
	case disabled:
		return "", ErrIdentityDisabled
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		return "", err
	}
	fp := cryptowire.SignInKeyFingerprint(public).String()
	_, err = a.tx.Exec(ctx, `INSERT INTO sign_in_keys VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', 1, now(), now())`,
		tenant, fp, principal, public, label, raw)
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == "23505" {
		return "", ErrSignInKeyExists
	}
	return fp, err
}

// RemoveSignInKey removes principal's ACTIVE sign-in key, journaled first
// so that a restore takes it away again. It reports false when the key was
// removed already.
func (a *Admin) RemoveSignInKey(ctx context.Context, tenant, principal, fingerprint string) (bool, error) {
	var status string
	err := a.tx.QueryRow(ctx, `SELECT status FROM sign_in_keys WHERE tenant = $1 AND fingerprint = $2 AND principal = $3 FOR UPDATE`,
		tenant, fingerprint, principal).Scan(&status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, ErrNoRow
	case err != nil || status != "ACTIVE":
		return false, err
	}
	if err := a.Journal(ctx, a.journal.SignInKeyRemovedKind, tenant, fingerprint); err != nil {
		return false, err
	}
	_, err = a.tx.Exec(ctx, RemoveSignInKeySQL, tenant, fingerprint)
	return err == nil, err
}

// RemoveSignInKeySQL removes a sign-in key; reconcile runs it again for a
// journaled removal.
const RemoveSignInKeySQL = `UPDATE sign_in_keys SET status = 'REMOVED', revision = revision + 1, changed_at = now()
	 WHERE tenant = $1 AND fingerprint = $2 AND status <> 'REMOVED'`

// SignInKeys lists principal's sign-in keys, active and removed, oldest
// first.
func (s *Store) SignInKeys(ctx context.Context, tenant, principal string) ([]SignInKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT fingerprint, principal, public_key, label, limits, status, revision, created_at, changed_at
		  FROM sign_in_keys WHERE tenant = $1 AND principal = $2 ORDER BY created_at, fingerprint`, tenant, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SignInKey{}
	for rows.Next() {
		var k SignInKey
		var raw []byte
		if err := rows.Scan(&k.Fingerprint, &k.Principal, &k.Public, &k.Label, &raw, &k.Status, &k.Revision, &k.CreatedAt, &k.ChangedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &k.Limits); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ActiveSignInKey is the token check's lookup (authn.SignInKeys): the
// ACTIVE sign-in key with fingerprint of an enabled identity in tenant.
func (s *Store) ActiveSignInKey(ctx context.Context, tenant, fingerprint string) (authn.SignInKey, bool, error) {
	var k authn.SignInKey
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT k.principal, k.public_key, k.limits FROM sign_in_keys k
		  JOIN identities i ON i.tenant = k.tenant AND i.id = k.principal
		 WHERE k.tenant = $1 AND k.fingerprint = $2 AND k.status = 'ACTIVE' AND NOT i.disabled`, tenant, fingerprint).Scan(&k.Principal, &k.Public, &raw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return k, false, nil
	case err != nil:
		return k, false, err
	}
	if err := json.Unmarshal(raw, &k.Limits); err != nil {
		return k, false, err
	}
	k.Tenant = tenant
	return k, true, nil
}

// SignInKeyLookup returns s's ACTIVE sign-in keys as a token check's
// lookup, each bounded by timeout.
func (s *Store) SignInKeyLookup(timeout time.Duration) authn.SignInKeys {
	return func(tenant, fingerprint string) (authn.SignInKey, bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return s.ActiveSignInKey(ctx, tenant, fingerprint)
	}
}
