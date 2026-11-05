package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/delegation"
	"fga/internal/identity"
)

// Administrative changes to a tenant's directory: identities, their
// capabilities, delegations, buckets and MCP registration (ADM-001,
// ADM-002). Administer runs each with its audit event in one transaction
// (AUD-002). A change to an existing identity's roles or attributes, a
// change that takes capabilities away, a disable and a revoke are
// journaled before they are made and the journal's state recorded in the
// same transaction, so that a restore from an older backup cannot undo
// them: reconcile sets the IdentityState and re-applies the Removal
// (AVL-008, review AMB-1). Roles and attributes are recorded whole, since
// under deny rules adding a role can take access away and removing one can
// give it (review v5 F01).

// db is a connection pool or a transaction: a change written against it
// runs alone or inside an administrative transaction.
type db interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ErrNoJournal refuses a change that must be journaled when there is no
// security journal to record it in.
var ErrNoJournal = errors.New("catalog: this change needs the security journal")

// Removal is the capabilities a directory change takes from one identity.
// Reconcile re-applies removals only, never additions, so a restore loses
// capabilities granted after the backup and keeps those removed after it.
// Entries from before IdentityState also name roles and attribute values.
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

// IdentityState is the roles and attributes a directory change leaves an
// identity with. Reconcile sets them in journal order, so a restore keeps
// the last recorded state, whatever the policy makes of it.
type IdentityState struct {
	Identity   string         `json:"identity"`
	Roles      []string       `json:"roles"`
	Attributes map[string]any `json:"attributes"`
}

// Journal is how an administrative change reaches the security journal,
// which the catalog does not link: Append journals one entry and returns
// the journal's ID and chain values. The kinds name the entries of an
// IdentityState (journal.IdentitySet), a Removal (journal.AccessRemoved),
// a disable (journal.IdentityDisabled), a delegation revoke
// (journal.DelegationRevoked), a SourceState (journal.SourceSet) and a
// source's disable (journal.SourceDisabled).
type Journal struct {
	Append             func(kind, tenant, subject string) (journalID string, chains []string, err error)
	StateKind          string
	RemovalKind        string
	DisabledKind       string
	RevokedKind        string
	SourceSetKind      string
	SourceDisabledKind string
	// SignInKeyRemovedKind names a sign-in key's removal
	// (journal.SignInKeyRemoved).
	SignInKeyRemovedKind string
}

// Admin makes administrative changes inside one transaction.
type Admin struct {
	tx      pgx.Tx
	s       *Store
	journal Journal
	// stated names the identities whose state the transaction journaled,
	// and sourced the sources.
	stated, sourced []identityRef
}

type identityRef struct{ tenant, id string }

// restateTimeout bounds journaling an identity's committed state after a
// failed change, which runs even when the change's context was canceled.
const restateTimeout = 30 * time.Second

// Administer runs change and appends e in one transaction, so the change
// commits only together with its audit event. An IdentityState is
// journaled before its change commits; when the transaction then fails,
// the identity's committed state is journaled after it, so a restore does
// not set a state that never committed (review F1 of 2 November 2026). A
// SourceState is handled the same way, so a restore does not activate a
// version whose review never committed.
func (s *Store) Administer(ctx context.Context, e audit.Event, j Journal, change func(*Admin) error) error {
	a := &Admin{s: s, journal: j}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		a.tx = tx
		if err := change(a); err != nil {
			return err
		}
		return s.AppendTx(ctx, tx, e)
	})
	if err == nil || j.Append == nil {
		return err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restateTimeout)
	defer cancel()
	for _, r := range a.stated {
		if rerr := s.restate(rctx, j, r.tenant, r.id); rerr != nil {
			err = errors.Join(err, fmt.Errorf("catalog: journal the committed state of %s: %w", r.id, rerr))
		}
	}
	for _, r := range a.sourced {
		if rerr := s.restateSource(rctx, j, r.tenant, r.id); rerr != nil {
			err = errors.Join(err, fmt.Errorf("catalog: journal the committed state of source %s: %w", r.id, rerr))
		}
	}
	return err
}

// restate journals an identity's committed roles and attributes, read
// under its row lock, so that no other change's entry comes between.
// A crash between a change's entry and its commit still leaves the entry
// last.
func (s *Store) restate(ctx context.Context, j Journal, tenant, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var roles []string
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT roles, attributes FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&roles, &raw)
		if err != nil {
			return err
		}
		var attrs map[string]any
		if err := json.Unmarshal(raw, &attrs); err != nil {
			return err
		}
		state, err := json.Marshal(IdentityState{Identity: id, Roles: roles, Attributes: attrs})
		if err != nil {
			return err
		}
		return (&Admin{tx: tx, s: s, journal: j}).Journal(ctx, j.StateKind, tenant, string(state))
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
// advancing its revision. A replacement that changes them is journaled
// first with the state it leaves; a new identity is not, since a restore
// without it leaves the ID unknown, which has no access at all.
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
	if !slices.Equal(oldRoles, roles) || !reflect.DeepEqual(old, now) {
		state, err := json.Marshal(IdentityState{Identity: id, Roles: roles, Attributes: now})
		if err != nil {
			return err
		}
		a.stated = append(a.stated, identityRef{tenant, id})
		if err := a.Journal(ctx, a.journal.StateKind, tenant, string(state)); err != nil {
			return err
		}
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

// ApplyIdentityState sets a journaled IdentityState: the identity's roles
// and attributes become st's, advancing its revision if they change. An
// identity the catalog does not hold is left unknown. Reconcile calls it
// after a restore, in journal order.
func (s *Store) ApplyIdentityState(ctx context.Context, tenant string, st IdentityState) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var roles []string
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT roles, attributes FROM identities WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, st.Identity).Scan(&roles, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var attrs map[string]any
		if err := json.Unmarshal(raw, &attrs); err != nil {
			return err
		}
		if st.Roles == nil {
			st.Roles = []string{}
		}
		if st.Attributes == nil {
			st.Attributes = map[string]any{}
		}
		if slices.Equal(roles, st.Roles) && reflect.DeepEqual(attrs, st.Attributes) {
			return nil
		}
		if raw, err = json.Marshal(st.Attributes); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identities SET roles = $3, attributes = $4, revision = revision + 1 WHERE tenant = $1 AND id = $2`,
			tenant, st.Identity, st.Roles, raw)
		return err
	})
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

// IdentityRecordOf reads one identity as the directory lists it.
func (s *Store) IdentityRecordOf(ctx context.Context, tenant, id string) (IdentityRecord, error) {
	r := IdentityRecord{ID: id, Capabilities: map[string][]string{}}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT roles, attributes, disabled, expires_at FROM identities WHERE tenant = $1 AND id = $2`,
		tenant, id).Scan(&r.Roles, &raw, &r.Disabled, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityRecord{}, identity.ErrUnknown
	}
	if err != nil {
		return IdentityRecord{}, err
	}
	if err := json.Unmarshal(raw, &r.Attributes); err != nil {
		return IdentityRecord{}, err
	}
	caps, err := capabilitiesOf(ctx, s.pool, tenant, []string{id})
	if err != nil {
		return IdentityRecord{}, err
	}
	if c, ok := caps[id]; ok {
		r.Capabilities = c
	}
	return r, nil
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
	rows, err := s.pool.Query(ctx, `SELECT name, scope, default_project, default_label, encryption, coalesce(source, '') FROM buckets
	                                 WHERE tenant = $1 AND name > $2 ORDER BY name LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Name, &b.Scope, &b.Project, &b.Label, &b.Encryption, &b.Source); err != nil {
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
