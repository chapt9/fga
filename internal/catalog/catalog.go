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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/audit"
	"fga/internal/delegation"
	"fga/internal/gate"
	"fga/internal/identity"
	"fga/internal/registry"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the catalog over one connection pool.
type Store struct {
	pool           *pgxpool.Pool
	outboxCapacity int
	tenantCapacity int
}

var (
	_ identity.Store   = identityView{}
	_ delegation.Store = delegationView{}
	_ registry.Catalog = resourceView{}
	_ audit.Outbox     = (*Store)(nil)
	_ gate.Recipients  = (*Store)(nil)
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

// LimitTenants also bounds each tenant's undelivered audit events to n,
// so that one tenant cannot fill the outbox for every other (AUD-002,
// fga-audit F-07); 0 leaves the total bound only.
func (s *Store) LimitTenants(n int) *Store {
	s.tenantCapacity = n
	return s
}

// Migrate applies the core catalog migrations that have not been applied
// yet, in name order, each in its own transaction. Concurrent migrators are
// serialized by an advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return ApplyMigrations(ctx, pool, migrations, "migrations", "")
}

// ApplyMigrations applies the *.sql files of dir in fsys in name order,
// recording each under prefix + its path. An optional feature applies its
// own migrations this way after Migrate.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, dir, prefix string) error {
	names, err := fs.Glob(fsys, dir+"/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, name := range names {
		if err := migrateOne(ctx, pool, fsys, name, prefix+name); err != nil {
			return fmt.Errorf("catalog: migration %s: %w", prefix+name, err)
		}
	}
	return nil
}

func migrateOne(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, path, name string) error {
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
	sql, err := fs.ReadFile(fsys, path)
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
	if err != nil {
		return registry.Resource{}, err
	}
	if _, ok := registry.GrantableActions[r.Type]; ok {
		if r.Grants, err = resourceGrants(ctx, s.pool, tenant, id); err != nil {
			return registry.Resource{}, err
		}
	}
	return r, nil
}

// Recipient implements gate.Recipients.
func (s *Store) Recipient(ctx context.Context, tenant, fingerprint string) (gate.RecipientKey, error) {
	k := gate.RecipientKey{Tenant: tenant, Fingerprint: fingerprint}
	var status string
	err := s.pool.QueryRow(ctx,
		`SELECT principal, key_version, revision, status FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2`,
		tenant, fingerprint).Scan(&k.Principal, &k.KeyVersion, &k.Revision, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return gate.RecipientKey{}, gate.ErrUnknownRecipient
	}
	k.Active, k.Revoked = status == "ACTIVE", status == "REVOKED"
	return k, err
}

// AuthorityState implements decisionsvc.Authority: the current recovery
// incarnation and whether admission is open.
func (s *Store) AuthorityState(ctx context.Context) (uint64, bool, error) {
	var incarnation uint64
	var open bool
	err := s.pool.QueryRow(ctx, `SELECT incarnation, admission_open FROM authority_state WHERE id = 1`).Scan(&incarnation, &open)
	return incarnation, open, err
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

// RequiredEpoch implements release.EpochSource. A tenant
// without a row has no required epoch.
func (s *Store) RequiredEpoch(ctx context.Context, tenant string) (uint64, error) {
	var epoch uint64
	err := s.pool.QueryRow(ctx, `SELECT required_epoch FROM tenant_epochs WHERE tenant = $1`, tenant).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return epoch, err
}

// Append implements audit.Outbox.
func (s *Store) Append(ctx context.Context, e audit.Event) error {
	return appendEvent(ctx, s.pool, s.outboxCapacity, s.tenantCapacity, e)
}

// AppendTx appends an event inside the caller's transaction, so the event
// commits or rolls back with the outcome it records (AUD-002).
func (s *Store) AppendTx(ctx context.Context, tx pgx.Tx, e audit.Event) error {
	return appendEvent(ctx, tx, s.outboxCapacity, s.tenantCapacity, e)
}

// Querier is a connection pool or a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// appendEvent inserts e unless the outbox, or with a tenant bound the
// tenant's share of it, is full. The capacity checks and the insert are
// one statement; under concurrent appends a bound can be exceeded by at
// most the number of concurrent writers.
func appendEvent(ctx context.Context, q Querier, capacity, tenantCapacity int, e audit.Event) error {
	if e.ID == "" {
		return errors.New("catalog: event ID is required")
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx,
		`INSERT INTO audit_outbox (id, tenant, kind, event)
		 SELECT $1, $2, $3, $4
		  WHERE (SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL) < $5
		    AND ($6 = 0 OR (SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL AND tenant = $2) < $6)
		 ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Tenant, string(e.Kind), payload, capacity, tenantCapacity)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_outbox WHERE id = $1)`, e.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil // a retried append
	}
	return audit.ErrFull
}

// Pool returns the store's connection pool, for roles that run their own
// transactions over the catalog, such as the authority fence.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

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
