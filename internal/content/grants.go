package content

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/journal"
	"fga/internal/opplan"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Share grants (specification 2.6.1, SHR-001 to SHR-003;
// docs/design/share-grants.md). A principal with share on a resource
// names a grantee of the same tenant, actions from the resource type's
// read set and an expiry. The grant is an authority fact: policy sees the
// unexpired grantees as resource.attributes.shared_with, and only a rule
// that tests it turns a grant into an allow. In server mode an honored
// grant is enough for the storage role to decrypt for the grantee; in
// client mode it only makes the grantee eligible as a recipient (SHR-003).

// Journal is the security journal (AVL-008).
type Journal interface {
	Append(kind, tenant, subject string) error
	// Binding is the journal's identity and the chain values of its
	// entries, which the catalog records with each journaled change.
	Binding() (id string, chains []string, err error)
}

// GrantTarget names the resource a grant is on, in a bucket: the bucket
// itself (no Key); the object or derived output at Key; or, for a
// document at Key, a document version (Version, or the current one) or
// one of its units or collection entries (Unit).
type GrantTarget struct {
	Bucket  string `json:"bucket"`
	Key     string `json:"key,omitempty"`
	Version string `json:"version,omitempty"`
	Unit    string `json:"unit,omitempty"`
}

// GrantRequest is a grant to record.
type GrantRequest struct {
	Grantee   string    `json:"grantee"`
	Actions   []string  `json:"actions"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GrantOutcome reports a recorded or removed grant.
type GrantOutcome struct {
	Grant            catalog.ShareGrant `json:"grant"`
	MetadataRevision uint64             `json:"metadata_revision"`
}

// grantTarget resolves t to the type and ID of its resource. It runs
// before the caller's share is decided, so a problem that depends on what
// the key holds answers like an absent target (review v3 F04).
func (s *Service) grantTarget(ctx context.Context, tenant string, t GrantTarget) (string, string, error) {
	if t.Key == "" && (t.Version != "" || t.Unit != "") {
		return "", "", ErrInvalid
	}
	b, err := s.bucketByName(ctx, tenant, t.Bucket)
	if err != nil {
		return "", "", err
	}
	if t.Key == "" {
		return "storage.bucket", b.ID.String(), nil
	}
	var id cryptowire.UUID
	var kind string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id, kind FROM objects WHERE tenant = $1 AND bucket = $2 AND key = $3`, tenant, b.ID, t.Key).
		Scan(&id, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	switch {
	case kind == "document" && t.Unit != "":
		d, m, err := s.unitTarget(ctx, Caller{Tenant: tenant}, t.Bucket, t.Key, t.Version, t.Unit)
		if err != nil {
			return "", "", err
		}
		return d.units.typ, m.entry.Unit, nil
	case kind == "document":
		d, err := s.documentVersion(ctx, tenant, t.Bucket, t.Key, t.Version)
		if err != nil {
			return "", "", err
		}
		return "document.version", d.id.String(), nil
	case t.Version != "" || t.Unit != "":
		// An object's or output's grant covers the resource, not a version.
		return "", "", ErrNotFound
	case kind == "derived":
		return "document.derived", id.String(), nil
	default:
		return "storage.object", id.String(), nil
	}
}

// actionName is the form of an action name.
var actionName = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)

// normalActions returns actions sorted and without duplicates, if each is
// an action name. Whether they fit the target's type is checked after the
// caller's share is decided (grantActionsFit).
func normalActions(actions []string) ([]string, error) {
	if len(actions) == 0 {
		return nil, ErrInvalid
	}
	out := slices.Clone(actions)
	slices.Sort(out)
	out = slices.Compact(out)
	for _, a := range out {
		if !actionName.MatchString(a) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}

// grantActionsFit checks that actions are from typ's read set (SHR-001).
func grantActionsFit(typ string, actions []string) error {
	allowed := registry.GrantableActions[typ]
	for _, a := range actions {
		if !slices.Contains(allowed, a) {
			return fmt.Errorf("%w: a grant on %s may name %s", ErrInvalid, typ, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// journalRemoval journals the removal of grant id before it is
// committed and returns the journal binding to record with it.
func (s *Service) journalRemoval(tenant, id string) (string, []string, error) {
	if s.d.Journal == nil {
		return "", nil, fmt.Errorf("%w: no security journal is configured", ErrUnavailable)
	}
	if err := s.d.Journal.Append(journal.GrantRemoved, tenant, id); err != nil {
		return "", nil, fmt.Errorf("%w: security journal: %v", ErrUnavailable, err)
	}
	journalID, chains, err := s.d.Journal.Binding()
	if err != nil {
		return "", nil, fmt.Errorf("%w: security journal: %v", ErrUnavailable, err)
	}
	return journalID, chains, nil
}

// RecordGrant records a share grant on t (SHR-001). It needs share on the
// resource; the decision sees the proposed grant (grantee, the grantee's
// attributes, grant_actions, grant_expires_at), so a policy may limit
// whom and what may be granted, or require an approval. The grantee must
// be a known, enabled principal of the tenant, the actions must come from
// the resource type's read set, and the expiry must not pass the
// grantor's own identity or delegation. A grant to the same grantee
// replaces the earlier one, whose removal is journaled. The resource's
// metadata revision advances (SHR-002).
func (s *Service) RecordGrant(ctx context.Context, c Caller, t GrantTarget, r GrantRequest) (GrantOutcome, error) {
	actions, err := normalActions(r.Actions)
	if err != nil {
		return GrantOutcome{}, err
	}
	typ, id, err := s.grantTarget(ctx, c.Tenant, t)
	if err != nil {
		return GrantOutcome{}, err
	}
	now := s.d.Now().UTC()
	expires := r.ExpiresAt.UTC().Truncate(time.Microsecond)
	if r.Grantee == "" || len(r.Grantee) > 256 || strings.Contains(r.Grantee, "|") || !now.Before(expires) {
		return GrantOutcome{}, ErrInvalid
	}
	// The decision sees the grantee as of this revision, and the commit
	// requires it still (review v2 finding 2); an unknown grantee is 0.
	var granteeRevision uint64
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT revision FROM identities WHERE tenant = $1 AND id = $2`, c.Tenant, r.Grantee).
		Scan(&granteeRevision); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return GrantOutcome{}, err
	}
	changes := map[string]string{"grantee": r.Grantee, "actions": strings.Join(actions, ","), "expires_at": expires.Format(time.RFC3339Nano)}
	rec, err := s.decidePlanned(ctx, c, registry.GrantOperation(typ, registry.GrantRecord),
		[]check{{id: "target", role: registry.RoleGrantTarget, action: "share",
			ref: planned(registry.ChangeGrant, id+"|"+r.Grantee+"|"+strconv.FormatUint(granteeRevision, 10)+"|"+changes["actions"]+"|"+
				changes["expires_at"])}},
		opplan.Summary{Action: "share", Targets: []opplan.Target{{Role: registry.RoleGrantTarget, Type: typ, ID: id}}, Changes: changes,
			Details: details(map[string]string{"bucket": t.Bucket, "key": t.Key, "version": t.Version, "unit": t.Unit})})
	if err != nil {
		return GrantOutcome{}, err
	}
	// Only a caller who may share the resource learns its type's read set.
	if err := grantActionsFit(typ, actions); err != nil {
		return GrantOutcome{}, err
	}
	replaced, err := catalog.ActiveGrant(ctx, s.d.Catalog.Pool(), c.Tenant, id, r.Grantee)
	if err != nil {
		return GrantOutcome{}, err
	}
	var journalID string
	var chains []string
	if replaced != "" {
		if journalID, chains, err = s.journalRemoval(c.Tenant, replaced); err != nil {
			return GrantOutcome{}, err
		}
	}
	g := catalog.ShareGrant{ID: cryptowire.NewUUID().String(), ResourceType: typ, ResourceID: id, Grantee: r.Grantee, Actions: actions,
		ExpiresAt: expires, Grantor: c.Represented(), CreatedAt: now}
	out := GrantOutcome{Grant: g}
	err = s.fenced(ctx, rec, []string{id}, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.grantHolds(ctx, tx, c.Tenant, rec, r.Grantee, granteeRevision, expires, now); err != nil {
			return err
		}
		meta, err := catalog.RecordGrant(ctx, tx, c.Tenant, g, replaced, rec.DecisionID)
		switch {
		case errors.Is(err, catalog.ErrGrantChanged):
			return fmt.Errorf("%w: the grantee's grant changed", ErrConflict)
		case errors.Is(err, catalog.ErrTooManyGrants):
			return fmt.Errorf("%w: the resource has %d unexpired grants", ErrInvalid, catalog.MaxGrants)
		case err != nil:
			return err
		}
		out.MetadataRevision = meta
		if journalID != "" {
			if err := catalog.RecordJournal(ctx, tx, journalID, chains); err != nil {
				return err
			}
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "SHARE_GRANT_RECORDED",
			audit.Target{Type: typ, ID: id, Generation: meta}, audit.Target{Type: "share.grant", ID: g.ID}))
	})
	if err != nil {
		return GrantOutcome{}, err
	}
	return out, nil
}

// grantHolds checks in the fence that the grantee is a known, enabled and
// unexpired principal of the tenant, still at the identity revision the
// decision saw (review v2 finding 2), and that expires does not pass the
// expiry of the grantor's identity, of the subject it acts for or of its
// delegation (SHR-001). The grantee's row is locked until the commit.
func (s *Service) grantHolds(ctx context.Context, tx pgx.Tx, tenant string, rec signing.Record, grantee string, revision uint64,
	expires, now time.Time) error {
	var disabled bool
	var until *time.Time
	var current uint64
	err := tx.QueryRow(ctx, `SELECT disabled, expires_at, revision FROM identities WHERE tenant = $1 AND id = $2 FOR SHARE`, tenant, grantee).
		Scan(&disabled, &until, &current)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (disabled || until != nil && !now.Before(*until)) {
		return fmt.Errorf("%w: the grantee is not a known, enabled principal of the tenant", ErrInvalid)
	}
	if err != nil {
		return err
	}
	if current != revision {
		return fmt.Errorf("%w: the grantee changed since the decision", ErrConflict)
	}
	for _, id := range []string{rec.Actor.ID, rec.Subject.ID} {
		if id == "" {
			continue
		}
		var until *time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM identities WHERE tenant = $1 AND id = $2`, tenant, id).Scan(&until); err != nil {
			return err
		}
		if until != nil && expires.After(*until) {
			return fmt.Errorf("%w: the grant would outlive the grantor", ErrInvalid)
		}
	}
	if rec.Delegation != "" {
		var until time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM delegations WHERE tenant = $1 AND id = $2`, tenant, rec.Delegation).Scan(&until); err != nil {
			return err
		}
		if expires.After(until) {
			return fmt.Errorf("%w: the grant would outlive the grantor's delegation", ErrInvalid)
		}
	}
	return nil
}

// RemoveGrant removes the grantee's grant on t (SHR-001). It needs share
// on the resource. The removal is journaled before it is committed, and
// the resource's metadata revision advances, so decisions, plans, key
// releases and stream leases bound to the grant end (SHR-002).
func (s *Service) RemoveGrant(ctx context.Context, c Caller, t GrantTarget, grantee string) (GrantOutcome, error) {
	typ, id, err := s.grantTarget(ctx, c.Tenant, t)
	if err != nil {
		return GrantOutcome{}, err
	}
	if grantee == "" {
		return GrantOutcome{}, ErrInvalid
	}
	rec, err := s.decidePlanned(ctx, c, registry.GrantOperation(typ, registry.GrantRemove),
		[]check{{id: "target", role: registry.RoleGrantTarget, action: "share", ref: canonical(typ, id)}},
		opplan.Summary{Action: "share", Targets: []opplan.Target{{Role: registry.RoleGrantTarget, Type: typ, ID: id}},
			Changes: map[string]string{"removed_grantee": grantee},
			Details: details(map[string]string{"bucket": t.Bucket, "key": t.Key, "version": t.Version, "unit": t.Unit})})
	if err != nil {
		return GrantOutcome{}, err
	}
	grantID, err := catalog.ActiveGrant(ctx, s.d.Catalog.Pool(), c.Tenant, id, grantee)
	if err != nil {
		return GrantOutcome{}, err
	}
	if grantID == "" {
		return GrantOutcome{}, ErrNotFound
	}
	journalID, chains, err := s.journalRemoval(c.Tenant, grantID)
	if err != nil {
		return GrantOutcome{}, err
	}
	out := GrantOutcome{Grant: catalog.ShareGrant{ID: grantID, ResourceType: typ, ResourceID: id, Grantee: grantee}}
	err = s.fenced(ctx, rec, []string{id}, func(ctx context.Context, tx pgx.Tx) error {
		meta, err := catalog.RemoveGrant(ctx, tx, c.Tenant, id, grantee, grantID, c.Represented(), s.d.Now())
		if errors.Is(err, catalog.ErrGrantChanged) {
			return fmt.Errorf("%w: the grantee's grant changed", ErrConflict)
		}
		if err != nil {
			return err
		}
		out.MetadataRevision = meta
		if err := catalog.RecordJournal(ctx, tx, journalID, chains); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "SHARE_GRANT_REMOVED",
			audit.Target{Type: typ, ID: id, Generation: meta}, audit.Target{Type: "share.grant", ID: grantID}))
	})
	if err != nil {
		return GrantOutcome{}, err
	}
	return out, nil
}

// ListGrants returns the unexpired grants on t to a caller with share on
// the resource.
func (s *Service) ListGrants(ctx context.Context, c Caller, t GrantTarget) ([]catalog.ShareGrant, error) {
	typ, id, err := s.grantTarget(ctx, c.Tenant, t)
	if err != nil {
		return nil, err
	}
	_, rec, err := s.decide(ctx, c, registry.GrantOperation(typ, registry.GrantList), Audience, false,
		[]check{{id: "target", role: registry.RoleGrantTarget, action: "share", ref: canonical(typ, id)}})
	if err != nil {
		return nil, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return nil, err
	}
	grants, err := catalog.Grants(ctx, s.d.Catalog.Pool(), c.Tenant, id, s.d.Now())
	if err != nil {
		return nil, err
	}
	if grants == nil {
		grants = []catalog.ShareGrant{}
	}
	return grants, nil
}
