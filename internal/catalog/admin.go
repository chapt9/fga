package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/delegation"
)

// Administrative changes to a tenant's directory: identities, their
// capabilities, delegations, buckets and MCP registration (ADM-001,
// ADM-002). Administer runs each with its audit event in one transaction
// (AUD-002). A change that takes access away is journaled before it is
// made and the journal's state recorded in the same transaction, so that a
// restore from an older backup cannot bring the access back: reconcile
// re-applies the Removal (AVL-008, review AMB-1).

// db is a connection pool or a transaction: a change written against it
// runs alone or inside an administrative transaction.
type db interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ErrNoJournal refuses a change that would take access away without a
// security journal to record it in.
var ErrNoJournal = errors.New("catalog: a change that takes access away needs the security journal")

// Removal is the access a directory change takes from one identity: roles,
// attribute values and capabilities. Reconcile re-applies removals only,
// never additions, so a restore loses access granted after the backup and
// keeps access removed after it.
type Removal struct {
	Identity     string              `json:"identity"`
	Roles        []string            `json:"roles,omitempty"`
	Attributes   map[string][]any    `json:"attributes,omitempty"`
	Capabilities map[string][]string `json:"capabilities,omitempty"`
}

// Empty reports whether r takes nothing away.
func (r Removal) Empty() bool {
	return len(r.Roles) == 0 && len(r.Attributes) == 0 && len(r.Capabilities) == 0
}

// Journal is how an administrative change reaches the security journal,
// which the catalog does not link: Append journals one entry and returns
// the journal's ID and chain values. The kinds name the entries of a
// Removal (journal.AccessRemoved), a disable (journal.IdentityDisabled)
// and a delegation revoke (journal.DelegationRevoked).
type Journal struct {
	Append       func(kind, tenant, subject string) (journalID string, chains []string, err error)
	RemovalKind  string
	DisabledKind string
	RevokedKind  string
}

// Admin makes administrative changes inside one transaction.
type Admin struct {
	tx      pgx.Tx
	s       *Store
	journal Journal
}

// Administer runs change and appends e in one transaction, so the change
// commits only together with its audit event.
func (s *Store) Administer(ctx context.Context, e audit.Event, j Journal, change func(*Admin) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := change(&Admin{tx: tx, s: s, journal: j}); err != nil {
			return err
		}
		return s.AppendTx(ctx, tx, e)
	})
}

// Journal journals an entry before the change it covers is made, and
// records the journal's state in the change's transaction (review
// finding 1). Without a journal the change is refused.
func (a *Admin) Journal(ctx context.Context, kind, tenant, subject string) error {
	if a.journal.Append == nil {
		return ErrNoJournal
	}
	id, chains, err := a.journal.Append(kind, tenant, subject)
	if err != nil {
		return err
	}
	return RecordJournal(ctx, a.tx, id, chains)
}

func (a *Admin) remove(ctx context.Context, tenant string, r Removal) error {
	if r.Empty() {
		return nil
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return a.Journal(ctx, a.journal.RemovalKind, tenant, string(raw))
}

// PutIdentity creates an identity or replaces its roles and attributes,
// advancing its revision. What a replacement takes away is journaled
// first.
func (a *Admin) PutIdentity(ctx context.Context, tenant, id string, roles []string, attrs map[string]any) error {
	if roles == nil {
		roles = []string{}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	if attrs == nil {
		raw = []byte("{}")
	}
	if err := ensureEpochRow(ctx, a.tx, tenant); err != nil {
		return err
	}
	var oldRoles []string
	var oldRaw []byte
	err = a.tx.QueryRow(ctx, `SELECT roles, attributes FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&oldRoles, &oldRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = a.tx.Exec(ctx, `INSERT INTO identities (tenant, id, revision, disabled, roles, attributes) VALUES ($1, $2, 1, false, $3, $4)`,
			tenant, id, roles, raw)
		return err
	}
	if err != nil {
		return err
	}
	// Both sides are compared as stored, through JSON, so numbers and
	// lists have one representation.
	var old, now map[string]any
	if err := json.Unmarshal(oldRaw, &old); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &now); err != nil {
		return err
	}
	r := Removal{Identity: id, Roles: without(oldRoles, roles), Attributes: removedValues(old, now)}
	if err := a.remove(ctx, tenant, r); err != nil {
		return err
	}
	_, err = a.tx.Exec(ctx, `UPDATE identities SET roles = $3, attributes = $4, revision = revision + 1 WHERE tenant = $1 AND id = $2`,
		tenant, id, roles, raw)
	return err
}

// DisableIdentity disables an identity, journaled first. The identity is
// locked before the journal's state is, the order every journaled change
// takes (audit F1). An unknown identity is refused and a disabled one left
// as it is, neither journaled, so a restore cannot disable an identity
// created later (audit F2).
func (a *Admin) DisableIdentity(ctx context.Context, tenant, id string) error {
	var disabled bool
	err := a.tx.QueryRow(ctx, `SELECT disabled FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&disabled)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNoRow
	case err != nil || disabled:
		return err
	}
	if err := a.Journal(ctx, a.journal.DisabledKind, tenant, id); err != nil {
		return err
	}
	return disableIdentity(ctx, a.tx, tenant, id)
}

// GrantCapabilities lets an actor execute actions per resource type.
func (a *Admin) GrantCapabilities(ctx context.Context, tenant, actor string, actions map[string][]string) error {
	return grantCapabilities(ctx, a.tx, tenant, actor, actions)
}

// RevokeCapabilities takes capabilities from an actor, journaling those it
// held first. It reports whether the actor held any of them.
func (a *Admin) RevokeCapabilities(ctx context.Context, tenant, actor string, actions map[string][]string) (bool, error) {
	var found bool
	err := a.tx.QueryRow(ctx, `SELECT true FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, actor).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoRow
	}
	if err != nil {
		return false, err
	}
	held, err := capabilitiesOf(ctx, a.tx, tenant, []string{actor})
	if err != nil {
		return false, err
	}
	r := Removal{Identity: actor, Capabilities: map[string][]string{}}
	for typ, list := range actions {
		for _, act := range list {
			if slices.Contains(held[actor][typ], act) && !slices.Contains(r.Capabilities[typ], act) {
				r.Capabilities[typ] = append(r.Capabilities[typ], act)
			}
		}
	}
	if r.Empty() {
		return false, nil
	}
	if err := a.remove(ctx, tenant, r); err != nil {
		return false, err
	}
	return true, applyRemoval(ctx, a.tx, tenant, r)
}

// PutDelegation records a new delegation (Store.PutDelegation).
func (a *Admin) PutDelegation(ctx context.Context, d delegation.Delegation, now time.Time) error {
	return a.s.putDelegation(ctx, a.tx, d, now)
}

// RevokeDelegation revokes a delegation, journaled first, as
// DisableIdentity disables an identity: locked first, an unknown one
// refused and a revoked one left as it is.
func (a *Admin) RevokeDelegation(ctx context.Context, tenant, id string) error {
	var revoked bool
	err := a.tx.QueryRow(ctx, `SELECT revoked FROM delegations WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&revoked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNoRow
	case err != nil || revoked:
		return err
	}
	if err := a.Journal(ctx, a.journal.RevokedKind, tenant, id); err != nil {
		return err
	}
	return revokeDelegation(ctx, a.tx, tenant, id)
}

// CreateBucket creates a bucket (Store.CreateBucket).
func (a *Admin) CreateBucket(ctx context.Context, tenant string, b Bucket) (cryptowire.UUID, error) {
	return createBucket(ctx, a.tx, tenant, b)
}

// EnableMCP registers the MCP tools for a tenant (Store.EnableMCP).
func (a *Admin) EnableMCP(ctx context.Context, tenant string) error {
	return enableMCP(ctx, a.tx, tenant)
}

// ApplyRemoval re-applies a journaled Removal: it takes away what r names
// and nothing else, and leaves alone what is already gone. Reconcile
// calls it after a restore.
func (s *Store) ApplyRemoval(ctx context.Context, tenant string, r Removal) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return applyRemoval(ctx, tx, tenant, r) })
}

func applyRemoval(ctx context.Context, q Querier, tenant string, r Removal) error {
	var roles []string
	var raw []byte
	err := q.QueryRow(ctx, `SELECT roles, attributes FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, r.Identity).Scan(&roles, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	attrs := map[string]any{}
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return err
	}
	kept := without(roles, r.Roles)
	changed := len(kept) != len(roles)
	for name, gone := range r.Attributes {
		cur, ok := attrs[name]
		if !ok {
			continue
		}
		if list, isList := cur.([]any); isList {
			rest := slices.DeleteFunc(slices.Clone(list), func(v any) bool { return containsJSON(gone, v) })
			if len(rest) != len(list) {
				attrs[name], changed = rest, true
			}
		} else if containsJSON(gone, cur) {
			// A changed scalar is removed rather than restored: a rule that
			// reads a missing attribute never matches.
			delete(attrs, name)
			changed = true
		}
	}
	for typ, acts := range r.Capabilities {
		tag, err := q.Exec(ctx, `DELETE FROM capabilities WHERE tenant = $1 AND actor = $2 AND resource_type = $3 AND action = ANY($4)`,
			tenant, r.Identity, typ, acts)
		if err != nil {
			return err
		}
		changed = changed || tag.RowsAffected() > 0
	}
	if !changed {
		return nil
	}
	if raw, err = json.Marshal(attrs); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE identities SET roles = $3, attributes = $4, revision = revision + 1 WHERE tenant = $1 AND id = $2`,
		tenant, r.Identity, kept, raw)
	return err
}

// without returns the elements of a that are not in b.
func without(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// removedValues lists, per attribute, the values that new no longer has:
// elements gone from a list, a list replaced by a scalar, a scalar changed
// or dropped.
func removedValues(old, new map[string]any) map[string][]any {
	out := map[string][]any{}
	for name, ov := range old {
		nv, kept := new[name]
		oldList, isList := ov.([]any)
		newList, newIsList := nv.([]any)
		switch {
		case isList && kept && newIsList:
			var gone []any
			for _, v := range oldList {
				if !containsJSON(newList, v) {
					gone = append(gone, v)
				}
			}
			if len(gone) > 0 {
				out[name] = gone
			}
		case isList:
			if len(oldList) > 0 {
				out[name] = oldList
			}
		case !kept || !equalJSON(ov, nv):
			out[name] = []any{ov}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func equalJSON(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

func containsJSON(list []any, v any) bool {
	return slices.ContainsFunc(list, func(x any) bool { return equalJSON(x, v) })
}

// IdentityRecord is an identity as the directory lists it.
type IdentityRecord struct {
	ID           string              `json:"id"`
	Roles        []string            `json:"roles"`
	Attributes   map[string]any      `json:"attributes"`
	Disabled     bool                `json:"disabled"`
	ExpiresAt    *time.Time          `json:"expires_at,omitempty"`
	Capabilities map[string][]string `json:"capabilities"`
}

// ListIdentities lists up to limit of a tenant's identities whose IDs sort
// after after, in ID order, with their capabilities.
func (s *Store) ListIdentities(ctx context.Context, tenant, after string, limit int) ([]IdentityRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, roles, attributes, disabled, expires_at FROM identities
	                                 WHERE tenant = $1 AND id > $2 ORDER BY id LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	out := []IdentityRecord{}
	var ids []string
	for rows.Next() {
		var r IdentityRecord
		var raw []byte
		if err := rows.Scan(&r.ID, &r.Roles, &raw, &r.Disabled, &r.ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &r.Attributes); err != nil {
			rows.Close()
			return nil, err
		}
		r.Capabilities = map[string][]string{}
		out = append(out, r)
		ids = append(ids, r.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	caps, err := capabilitiesOf(ctx, s.pool, tenant, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if c, ok := caps[out[i].ID]; ok {
			out[i].Capabilities = c
		}
	}
	return out, nil
}

// capabilitiesOf returns the capabilities of actors, by actor and type.
func capabilitiesOf(ctx context.Context, q Querier, tenant string, actors []string) (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{}
	if len(actors) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT actor, resource_type, action FROM capabilities WHERE tenant = $1 AND actor = ANY($2)
	                            ORDER BY actor, resource_type, action`, tenant, actors)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var actor, typ, act string
		if err := rows.Scan(&actor, &typ, &act); err != nil {
			return nil, err
		}
		if out[actor] == nil {
			out[actor] = map[string][]string{}
		}
		out[actor][typ] = append(out[actor][typ], act)
	}
	return out, rows.Err()
}

// DelegationRecord is a delegation as the directory lists it.
type DelegationRecord struct {
	ID        string              `json:"id"`
	Actor     string              `json:"actor"`
	Subject   string              `json:"subject"`
	Audience  string              `json:"audience"`
	Grants    map[string][]string `json:"grants"`
	ExpiresAt time.Time           `json:"expires_at"`
	Parent    string              `json:"parent,omitempty"`
	Revoked   bool                `json:"revoked"`
}

// ListDelegations lists up to limit of a tenant's delegations whose IDs
// sort after after, in ID order.
func (s *Store) ListDelegations(ctx context.Context, tenant, after string, limit int) ([]DelegationRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, actor, subject, audience, grants, expires_at, coalesce(parent, ''), revoked FROM delegations
	                                 WHERE tenant = $1 AND id > $2 ORDER BY id LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DelegationRecord{}
	for rows.Next() {
		var d DelegationRecord
		var raw []byte
		if err := rows.Scan(&d.ID, &d.Actor, &d.Subject, &d.Audience, &raw, &d.ExpiresAt, &d.Parent, &d.Revoked); err != nil {
			return nil, err
		}
		var grants []grantJSON
		if err := json.Unmarshal(raw, &grants); err != nil {
			return nil, err
		}
		d.Grants = map[string][]string{}
		for _, g := range grants {
			d.Grants[g.ResourceType] = g.Actions
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListBuckets lists up to limit of a tenant's buckets whose names sort
// after after, in name order.
func (s *Store) ListBuckets(ctx context.Context, tenant, after string, limit int) ([]Bucket, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, scope, default_project, default_label, encryption FROM buckets
	                                 WHERE tenant = $1 AND name > $2 ORDER BY name LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Name, &b.Scope, &b.Project, &b.Label, &b.Encryption); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// RecentEvents returns up to limit of a tenant's audit events still in the
// outbox, newest first: those not yet exported and those exported within
// the reclaim margin. The exported, signed chain is the audit record; this
// is a recent view of it for administrators.
func (s *Store) RecentEvents(ctx context.Context, tenant string, limit int) ([]audit.Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT event FROM audit_outbox WHERE tenant = $1 ORDER BY seq DESC LIMIT $2`, tenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []audit.Event{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e audit.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
