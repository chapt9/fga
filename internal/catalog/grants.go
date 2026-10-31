package catalog

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/registry"
)

// Share grants (specification 2.6.1, SHR-001 to SHR-003;
// docs/design/share-grants.md). A grant is an authority fact, never a
// permission by itself: the decision role shows the unexpired grants of a
// resource to policy as resource.attributes.shared_with, and only a rule
// that tests it turns a grant into an allow (default deny).

// MaxGrants bounds the unexpired grants of one resource, and with them
// the size of shared_with.
const MaxGrants = 100

// ShareGrant is a recorded share grant.
type ShareGrant struct {
	ID           string    `json:"grant_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Grantee      string    `json:"grantee"`
	Actions      []string  `json:"actions"`
	ExpiresAt    time.Time `json:"expires_at"`
	Grantor      string    `json:"grantor"`
	CreatedAt    time.Time `json:"created_at"`
}

// ErrGrantChanged means the grantee's grant on the resource changed
// between the operation's preparation and its commit.
var ErrGrantChanged = errors.New("catalog: the grant changed")

// resourceGrants returns the grants of a resource that were not removed,
// expired ones included, for the decision role.
func resourceGrants(ctx context.Context, q Querier, tenant, id string) ([]registry.Grant, error) {
	rows, err := q.Query(ctx, `SELECT grantee, actions, expires_at FROM share_grants
	                            WHERE tenant = $1 AND resource_id = $2 AND removed_at IS NULL ORDER BY grantee`, tenant, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (registry.Grant, error) {
		var g registry.Grant
		err := r.Scan(&g.Grantee, &g.Actions, &g.ExpiresAt)
		return g, err
	})
}

// ActiveGrant returns the ID of the grantee's grant on a resource that was
// not removed, or "" when there is none. Expired grants count: removing or
// replacing one is still a change.
func ActiveGrant(ctx context.Context, q Querier, tenant, resourceID, grantee string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM share_grants WHERE tenant = $1 AND resource_id = $2 AND grantee = $3 AND removed_at IS NULL`,
		tenant, resourceID, grantee).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// Grants returns the unexpired grants of a resource at now.
func Grants(ctx context.Context, q Querier, tenant, resourceID string, now time.Time) ([]ShareGrant, error) {
	rows, err := q.Query(ctx, `SELECT id::text, resource_type, resource_id, grantee, actions, expires_at, grantor, created_at
	                             FROM share_grants WHERE tenant = $1 AND resource_id = $2 AND removed_at IS NULL AND expires_at > $3
	                            ORDER BY grantee`, tenant, resourceID, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ShareGrant, error) {
		var g ShareGrant
		err := r.Scan(&g.ID, &g.ResourceType, &g.ResourceID, &g.Grantee, &g.Actions, &g.ExpiresAt, &g.Grantor, &g.CreatedAt)
		return g, err
	})
}

// RecordGrant stores g inside tx: the grantee's earlier grant on the
// resource, which must still be replaced (its ID, or "" for none), is
// removed by g.Grantor; grants of the resource that have expired are
// removed as expired; and the resource's metadata revision advances, so
// decisions bound to the earlier state fail (SHR-002). It returns the new
// metadata revision.
func RecordGrant(ctx context.Context, tx pgx.Tx, tenant string, g ShareGrant, replaced, decisionID string) (uint64, error) {
	current, err := lockGrant(ctx, tx, tenant, g.ResourceID, g.Grantee)
	if err != nil {
		return 0, err
	}
	if current != replaced {
		return 0, ErrGrantChanged
	}
	if current != "" {
		if _, err := tx.Exec(ctx, `UPDATE share_grants SET removed_at = $3, removed_by = $4 WHERE tenant = $1 AND id = $2::uuid`,
			tenant, current, g.CreatedAt, g.Grantor); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE share_grants SET removed_at = $3, removed_by = 'expired'
	                            WHERE tenant = $1 AND resource_id = $2 AND removed_at IS NULL AND expires_at <= $3`,
		tenant, g.ResourceID, g.CreatedAt); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM share_grants WHERE tenant = $1 AND resource_id = $2 AND removed_at IS NULL`,
		tenant, g.ResourceID).Scan(&n); err != nil {
		return 0, err
	}
	if n >= MaxGrants {
		return 0, ErrTooManyGrants
	}
	if _, err := tx.Exec(ctx, `INSERT INTO share_grants (tenant, id, resource_id, resource_type, grantee, actions, expires_at, grantor,
	                                                     decision_id, created_at)
	                           VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)`,
		tenant, g.ID, g.ResourceID, g.ResourceType, g.Grantee, g.Actions, g.ExpiresAt, g.Grantor, decisionID, g.CreatedAt); err != nil {
		return 0, err
	}
	return advanceGrants(ctx, tx, tenant, g.ResourceID)
}

// ErrTooManyGrants means a resource already has MaxGrants unexpired grants.
var ErrTooManyGrants = errors.New("catalog: too many share grants on the resource")

// RemoveGrant removes the grantee's grant id on a resource inside tx,
// which must still be its grant, and advances the resource's metadata
// revision (SHR-002). It returns the new metadata revision.
func RemoveGrant(ctx context.Context, tx pgx.Tx, tenant, resourceID, grantee, id, by string, at time.Time) (uint64, error) {
	current, err := lockGrant(ctx, tx, tenant, resourceID, grantee)
	if err != nil {
		return 0, err
	}
	if current != id || id == "" {
		return 0, ErrGrantChanged
	}
	if _, err := tx.Exec(ctx, `UPDATE share_grants SET removed_at = $3, removed_by = $4 WHERE tenant = $1 AND id = $2::uuid`,
		tenant, id, at, by); err != nil {
		return 0, err
	}
	return advanceGrants(ctx, tx, tenant, resourceID)
}

func lockGrant(ctx context.Context, tx pgx.Tx, tenant, resourceID, grantee string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM share_grants WHERE tenant = $1 AND resource_id = $2 AND grantee = $3 AND removed_at IS NULL
	                          FOR UPDATE`, tenant, resourceID, grantee).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func advanceGrants(ctx context.Context, tx pgx.Tx, tenant, resourceID string) (uint64, error) {
	var meta uint64
	err := tx.QueryRow(ctx, `UPDATE resources SET metadata_revision = metadata_revision + 1 WHERE tenant = $1 AND id = $2
	                          RETURNING metadata_revision`, tenant, resourceID).Scan(&meta)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, registry.ErrUnknownResource
	}
	return meta, err
}

// changedGrant resolves a proposed share grant: its resource as it is,
// with grantee, grantee_attributes, grant_actions and grant_expires_at
// added, so a rule can condition on whom and what is granted (SHR-001).
// An unknown or disabled grantee resolves with empty attributes; the
// commit rejects it.
func (v resourceView) changedGrant(ctx context.Context, tenant string, alias registry.Alias) (registry.Resource, error) {
	parts := strings.Split(alias.Name, "|")
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return registry.Resource{}, registry.ErrUnknownAlias
	}
	expires, err := time.Parse(time.RFC3339Nano, parts[3])
	if err != nil {
		return registry.Resource{}, registry.ErrUnknownAlias
	}
	r, err := v.s.GetResource(ctx, tenant, parts[0])
	if err != nil {
		return registry.Resource{}, err
	}
	if _, ok := registry.GrantableActions[r.Type]; !ok {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	granteeAttrs := map[string]any{}
	if i, err := v.s.GetIdentity(ctx, tenant, parts[1]); err == nil && !i.Disabled && i.Attributes != nil {
		granteeAttrs = i.Attributes
	}
	var actions []any
	for _, a := range strings.Split(parts[2], ",") {
		actions = append(actions, a)
	}
	attrs := make(map[string]any, len(r.Attributes)+4)
	for k, val := range r.Attributes {
		attrs[k] = val
	}
	attrs["grantee"], attrs["grantee_attributes"], attrs["grant_actions"] = parts[1], granteeAttrs, actions
	attrs["grant_expires_at"] = expires.UTC().Format(time.RFC3339)
	r.Attributes = attrs
	return r, nil
}
