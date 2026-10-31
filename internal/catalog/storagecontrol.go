package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/cryptowire"
)

// Control operations for tenants, buckets, identities, capabilities and
// trusted key provisioning. They are administrative: the local
// administrator runs them through fga-admin (ADM-002, ADM-003), and tests
// use them to build state. None is reachable from an ordinary API request.

// BucketName is the form of a bucket name (native API design record).
var BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// EnsureTenant registers a tenant and returns its UUID, creating it on
// first use.
func (s *Store) EnsureTenant(ctx context.Context, tenant string) (cryptowire.UUID, error) {
	id := cryptowire.NewUUID()
	if _, err := s.pool.Exec(ctx, `INSERT INTO tenants (name, id) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, tenant, id); err != nil {
		return id, err
	}
	err := s.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE name = $1`, tenant).Scan(&id)
	return id, err
}

// Bucket is a bucket's protected defaults.
type Bucket struct {
	Name    string
	Scope   string
	Project string
	Label   string
}

// CreateBucket creates a bucket with its protected defaults, its
// storage.bucket resource and its native alias. Clients cannot set these
// (Table "Native storage operations", bucket administration).
func (s *Store) CreateBucket(ctx context.Context, tenant string, b Bucket) (cryptowire.UUID, error) {
	if !BucketName.MatchString(b.Name) {
		return cryptowire.UUID{}, fmt.Errorf("catalog: invalid bucket name %q", b.Name)
	}
	if _, err := s.EnsureTenant(ctx, tenant); err != nil {
		return cryptowire.UUID{}, err
	}
	id := cryptowire.NewUUID()
	attrs, _ := json.Marshal(map[string]any{"name": b.Name, "project": b.Project, "label": b.Label})
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO buckets (tenant, id, name, scope, default_project, default_label) VALUES ($1, $2, $3, $4, $5, $6)`,
			tenant, id, b.Name, b.Scope, b.Project, b.Label); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'storage.bucket', $3, 1, 1, 1, $4)`, tenant, id.String(), b.Scope, attrs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, 'native.bucket', $2, $3)`, tenant, b.Name, id.String())
		return err
	})
	return id, err
}

// PutIdentity creates an identity or replaces its roles and attributes,
// advancing its revision.
func (s *Store) PutIdentity(ctx context.Context, tenant, id string, roles []string, attrs map[string]any, expires *time.Time) error {
	if attrs == nil {
		attrs = map[string]any{}
	}
	if roles == nil {
		roles = []string{}
	}
	a, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO identities (tenant, id, revision, disabled, roles, attributes, expires_at) VALUES ($1, $2, 1, false, $3, $4, $5)
		ON CONFLICT (tenant, id) DO UPDATE SET roles = excluded.roles, attributes = excluded.attributes,
		       expires_at = excluded.expires_at, revision = identities.revision + 1`, tenant, id, roles, a, expires)
	return err
}

// GrantCapabilities lets an actor execute the given actions per resource
// type (DLG-004) and advances its identity revision.
func (s *Store) GrantCapabilities(ctx context.Context, tenant, actor string, actions map[string][]string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for typ, list := range actions {
			for _, a := range list {
				if _, err := tx.Exec(ctx, `INSERT INTO capabilities VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, tenant, actor, typ, a); err != nil {
					return err
				}
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE identities SET revision = revision + 1 WHERE tenant = $1 AND id = $2`, tenant, actor)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNoRow
		}
		return err
	})
}

// AddSigningKey provisions an ACTIVE content-signing key for principal by
// trusted provisioning (RCP-002) and returns its fingerprint.
func (s *Store) AddSigningKey(ctx context.Context, tenant, principal string, public []byte) (string, error) {
	if len(public) != 32 {
		return "", errors.New("catalog: an Ed25519 public key has 32 bytes")
	}
	fp := cryptowire.SigningKeyFingerprint(public).String()
	now := time.Now()
	attrs, _ := json.Marshal(map[string]any{"principal": principal, "status": "ACTIVE"})
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO signing_keys VALUES ($1, $2, $3, $4, 'ACTIVE', 1, $5, $5)`, tenant, fp, principal, public, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'crypto.signing-key', '', 1, 1, 1, $3)`, tenant, fp, attrs)
		return err
	})
	return fp, err
}

// SetSigningKeyStatus retires or marks compromised a content-signing key
// (RCP-011). A compromised key never becomes active again.
func (s *Store) SetSigningKeyStatus(ctx context.Context, tenant, fingerprint, status string) error {
	if status != "RETIRED" && status != "COMPROMISED" {
		return fmt.Errorf("catalog: status %q", status)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE signing_keys SET status = $3, revision = revision + 1, changed_at = now()
		                           WHERE tenant = $1 AND fingerprint = $2 AND status <> 'COMPROMISED' AND status <> $3`, tenant, fingerprint, status)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNoRow
		}
		_, err = tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || jsonb_build_object('status', $3::text)
		                        WHERE tenant = $1 AND type = 'crypto.signing-key' AND id = $2`, tenant, fingerprint, status)
		return err
	})
}

// AddRecipientKey provisions an ACTIVE recipient key for principal by
// trusted provisioning and returns its fingerprint and key version. Clients
// normally enroll through the keys role with a possession proof.
func (s *Store) AddRecipientKey(ctx context.Context, tenant, principal string, public []byte) (string, uint64, error) {
	if !cryptowire.ValidX25519PublicKey(public) {
		return "", 0, errors.New("catalog: not an X25519 public key")
	}
	fp := cryptowire.RecipientFingerprint(cryptowire.Suite1, public).String()
	var version uint64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(key_version), 0) + 1 FROM recipient_keys WHERE tenant = $1 AND principal = $2`,
			tenant, principal).Scan(&version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO recipient_keys (tenant, fingerprint, principal, public_key, suite, key_version, status, revision)
		                           VALUES ($1, $2, $3, $4, 1, $5, 'ACTIVE', 1)`, tenant, fp, principal, public, version); err != nil {
			return err
		}
		return InsertRecipientResource(ctx, tx, tenant, fp, principal)
	})
	return fp, version, err
}

// InsertRecipientResource records an active recipient key as a
// crypto.recipient resource, so policies and the fence can bind it.
func InsertRecipientResource(ctx context.Context, tx pgx.Tx, tenant, fingerprint, principal string) error {
	attrs, _ := json.Marshal(map[string]any{"principal": principal, "status": "ACTIVE"})
	_, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'crypto.recipient', '', 1, 1, 1, $3)`, tenant, fingerprint, attrs)
	return err
}
