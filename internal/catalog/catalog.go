// Package catalog is the PostgreSQL authority for the decision core. It
// implements the read stores of the identity, delegation, registry, gate,
// release and signing packages, and the audit outbox (specification 2.5,
// DAT-001 to DAT-004, DEC-011, AUD-002).
//
// Every query is scoped by tenant. Reads are plain consistent reads on the
// primary; there is no result cache (DAT-004).
package catalog

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/audit"
	"fga/internal/delegation"
	"fga/internal/identity"
	"fga/internal/registry"
	"fga/internal/signing"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the catalog over one connection pool.
type Store struct {
	pool           *pgxpool.Pool
	outboxCapacity int
}

var (
	_ identity.Store      = identityView{}
	_ delegation.Store    = delegationView{}
	_ registry.Catalog    = resourceView{}
	_ signing.Consumption = (*Store)(nil)
	_ audit.Outbox        = (*Store)(nil)
)

// The identity, delegation and registry stores each have a Get method with
// their own signature, so the catalog serves them through small views.
type (
	identityView   struct{ s *Store }
	delegationView struct{ s *Store }
	resourceView   struct{ s *Store }
)

// Identities returns the catalog as an identity.Store.
func (s *Store) Identities() identity.Store { return identityView{s} }

// Delegations returns the catalog as a delegation.Store.
func (s *Store) Delegations() delegation.Store { return delegationView{s} }

// Resources returns the catalog as a registry.Catalog.
func (s *Store) Resources() registry.Catalog { return resourceView{s} }

func (v identityView) Get(ctx context.Context, tenant, id string) (identity.Identity, error) {
	return v.s.GetIdentity(ctx, tenant, id)
}

func (v delegationView) Get(ctx context.Context, tenant string, id delegation.ID) (delegation.Delegation, error) {
	return v.s.GetDelegation(ctx, tenant, id)
}

func (v resourceView) Get(ctx context.Context, tenant, id string) (registry.Resource, error) {
	return v.s.GetResource(ctx, tenant, id)
}

func (v resourceView) LookupAlias(ctx context.Context, tenant string, alias registry.Alias) (string, error) {
	return v.s.LookupAlias(ctx, tenant, alias)
}

// New returns a Store. outboxCapacity bounds undelivered audit events.
func New(pool *pgxpool.Pool, outboxCapacity int) *Store {
	return &Store{pool: pool, outboxCapacity: outboxCapacity}
}

// Migrate applies the embedded migrations that have not been applied yet,
// in name order, each in its own transaction. Concurrent migrators are
// serialized by an advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, name := range names {
		if err := migrateOne(ctx, pool, name); err != nil {
			return fmt.Errorf("catalog: migration %s: %w", name, err)
		}
	}
	return nil
}

func migrateOne(ctx context.Context, pool *pgxpool.Pool, name string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7316)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var done bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&done); err != nil {
		return err
	}
	if done {
		return tx.Commit(ctx)
	}
	sql, err := migrations.ReadFile(name)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetIdentity reads one identity of a tenant.
func (s *Store) GetIdentity(ctx context.Context, tenant, id string) (identity.Identity, error) {
	i := identity.Identity{ID: id, Tenant: tenant}
	var expires *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT revision, disabled, expires_at, roles, attributes FROM identities WHERE tenant = $1 AND id = $2`,
		tenant, id).Scan(&i.Revision, &i.Disabled, &expires, &i.Roles, &i.Attributes)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Identity{}, identity.ErrUnknown
	}
	if expires != nil {
		i.ExpiresAt = *expires
	}
	return i, err
}

// grantJSON is the stored form of a delegation grant.
type grantJSON struct {
	ResourceType string   `json:"resource_type"`
	Actions      []string `json:"actions"`
}

// GetDelegation reads one delegation of a tenant.
func (s *Store) GetDelegation(ctx context.Context, tenant string, id delegation.ID) (delegation.Delegation, error) {
	d := delegation.Delegation{ID: id, Tenant: tenant}
	var grants []grantJSON
	var parent *string
	err := s.pool.QueryRow(ctx,
		`SELECT actor, subject, audience, grants, expires_at, parent, revision, revoked
		   FROM delegations WHERE tenant = $1 AND id = $2`, tenant, string(id)).
		Scan(&d.Actor, &d.Subject, &d.Audience, &grants, &d.ExpiresAt, &parent, &d.Revision, &d.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return delegation.Delegation{}, delegation.ErrNotFound
	}
	if err != nil {
		return delegation.Delegation{}, err
	}
	if parent != nil {
		d.Parent = delegation.ID(*parent)
	}
	for _, g := range grants {
		d.Grants = append(d.Grants, delegation.Grant{ResourceType: g.ResourceType, Actions: g.Actions})
	}
	return d, nil
}

// LookupAlias returns the resource an alias names in a tenant.
func (s *Store) LookupAlias(ctx context.Context, tenant string, alias registry.Alias) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT resource_id FROM aliases WHERE tenant = $1 AND namespace = $2 AND name = $3`,
		tenant, alias.Namespace, alias.Name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", registry.ErrUnknownAlias
	}
	return id, err
}

// GetResource reads one resource of a tenant.
func (s *Store) GetResource(ctx context.Context, tenant, id string) (registry.Resource, error) {
	r := registry.Resource{ID: id, Tenant: tenant}
	err := s.pool.QueryRow(ctx,
		`SELECT type, scope, version, generation, metadata_revision, attributes
		   FROM resources WHERE tenant = $1 AND id = $2`, tenant, id).
		Scan(&r.Type, &r.Scope, &r.Version, &r.Generation, &r.MetadataRevision, &r.Attributes)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	return r, err
}

// Allows implements gate.Capabilities.
func (s *Store) Allows(ctx context.Context, tenant, actor, resourceType, action string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM capabilities
		                 WHERE tenant = $1 AND actor = $2 AND resource_type = $3 AND action = $4)`,
		tenant, actor, resourceType, action).Scan(&ok)
	return ok, err
}

// RequiredEpoch implements release.EpochSource and gate.Epochs. A tenant
// without a row has no required epoch.
func (s *Store) RequiredEpoch(ctx context.Context, tenant string) (uint64, error) {
	var epoch uint64
	err := s.pool.QueryRow(ctx, `SELECT required_epoch FROM tenant_epochs WHERE tenant = $1`, tenant).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return epoch, err
}

// Consume implements signing.Consumption: the insert either creates the row
// or finds it, atomically, for every replica sharing the catalog.
func (s *Store) Consume(ctx context.Context, decisionID string, until time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO consumed_decisions (decision_id, valid_until) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		decisionID, until)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Append implements audit.Outbox. The capacity check and the insert are one
// statement; under concurrent appends the bound can be exceeded by at most
// the number of concurrent writers.
func (s *Store) Append(ctx context.Context, e audit.Event) error {
	if e.ID == "" {
		return errors.New("catalog: event ID is required")
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO audit_outbox (id, tenant, kind, event)
		 SELECT $1, $2, $3, $4
		  WHERE (SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL) < $5
		 ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Tenant, string(e.Kind), payload, s.outboxCapacity)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_outbox WHERE id = $1)`, e.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil // a retried append
	}
	return audit.ErrFull
}

// Pending implements audit.Outbox.
func (s *Store) Pending(ctx context.Context, limit int) ([]audit.Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event FROM audit_outbox WHERE delivered_at IS NULL ORDER BY seq LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (audit.Event, error) {
		var e audit.Event
		err := row.Scan(&e)
		return e, err
	})
}

// MarkDelivered implements audit.Outbox.
func (s *Store) MarkDelivered(ctx context.Context, ids []string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_outbox SET delivered_at = now() WHERE id = ANY($1) AND delivered_at IS NULL`, ids)
	return err
}
