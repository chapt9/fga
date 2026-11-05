// Package adminops makes the administrative changes to a tenant's
// directory (identities, their capabilities, delegations, buckets, MCP
// registration) for fga-admin's commands and for its admin API alike, so
// that each is made one way: checked, in one transaction with its audit
// event (AUD-002), and journaled first when a restore must not undo it,
// so that a restore cannot bring access back or roll a change of roles
// back (ADM-002, AVL-008, review AMB-1, review v5 F01).
// Bootstrap and recovery operations stay with fga-admin's commands
// (ADM-003).
package adminops

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/delegation"
	"fga/internal/journal"
	"fga/internal/registry"
)

// ErrInvalid marks a request the directory does not take: a malformed
// identifier, an unknown resource type or action, an unknown preset.
var ErrInvalid = errors.New("adminops: invalid request")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Presets are the capability sets granted by name.
var Presets = map[string]map[string][]string{
	// storage is the capability set of an ordinary storage user (DLG-004).
	"storage": {
		"storage.bucket": {"create-object", "list", "share"},
		"storage.object": {"read", "stat", "discover", "read-history", "discover-history", "new-version", "delete", "delete-version", "share",
			"label", "relabel", "propose-label", "export"},
		"crypto.envelope":    {"create", "release", "retire"},
		"document.version":   {"read-units", "raw-read", "discover", "share", "export"},
		"document.text_unit": {"read", "share", "label", "relabel", "propose-label", "export-key"},
		"document.derived":   {"deliver", "declassify", "label", "relabel", "new-version", "share"},
		"text.entry":         {"read", "use-in-model", "update", "share"},
		"crypto.recipient":   {"enroll", "activate", "receive-key", "revoke", "discover"},
		"crypto.signing-key": {"discover", "enroll", "activate", "retire"},
		"agent.tool":         {"discover", "invoke"},
	},
	// source is the capability set of a system posting server-mode
	// readings to a source (docs/design/mcp-data-tools.md, ING-012):
	// posting, and no upload; policies say to which sources.
	"source": {
		"storage.bucket": {"post-reading"},
		"storage.object": {"post-reading"},
	},
	// source-client adds what a client-mode posting system needs: sharing
	// its readings with the recipients its source names (ING-011) and its
	// own content-signing key for the manifests it signs.
	"source-client": {
		"storage.bucket":     {"post-reading"},
		"storage.object":     {"post-reading"},
		"document.version":   {"share"},
		"document.text_unit": {"share"},
		"crypto.envelope":    {"create"},
		"crypto.signing-key": {"discover", "enroll", "activate", "retire"},
	},
	// approver lets an actor decide approvals (ruling 6); policies still
	// say on which resources.
	"approver": {
		"storage.bucket":     {"approve"},
		"storage.object":     {"approve"},
		"document.text_unit": {"approve"},
		"document.derived":   {"approve"},
		"document.version":   {"approve"},
		"text.entry":         {"approve"},
		"crypto.envelope":    {"approve"},
		"crypto.recipient":   {"approve"},
		"crypto.signing-key": {"approve"},
		"agent.tool":         {"approve"},
	},
}

// Who names the administrator a change is made for, and how the change
// arrived, for its audit event.
type Who struct {
	Actor string // the administrator's token subject, or "operator" at the command line
	Via   string // "cli", or "console " and the console's client identity
}

// Ops makes administrative changes.
type Ops struct {
	Store *catalog.Store
	// Journal opens the security journal. A change it must record (a
	// change to an existing identity, a revoke, a disable) is refused
	// without it.
	Journal func() (*journal.Journal, error)
	Now     func() time.Time
	// AllowSelfReview lets the author of a source's draft review it. Only
	// the local administrator's tool sets it (ADM-003); through the admin
	// API another administrator reviews (D-G).
	AllowSelfReview bool
}

func (o Ops) event(tenant string, who Who, change, typ, id string) audit.Event {
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: audit.KindAdministration, Tenant: tenant, Actor: who.Actor,
		Outcome: change, Reason: "via " + who.Via, Targets: []audit.Target{{Type: typ, ID: id}}, At: o.Now().UTC()}
}

func (o Ops) journal() catalog.Journal {
	return catalog.Journal{StateKind: journal.IdentitySet, RemovalKind: journal.AccessRemoved, DisabledKind: journal.IdentityDisabled,
		RevokedKind: journal.DelegationRevoked, SourceSetKind: journal.SourceSet, SourceDisabledKind: journal.SourceDisabled,
		SignInKeyRemovedKind: journal.SignInKeyRemoved,
		Append: func(kind, tenant, subject string) (string, []string, error) {
			if o.Journal == nil {
				return "", nil, catalog.ErrNoJournal
			}
			j, err := o.Journal()
			if err != nil {
				return "", nil, fmt.Errorf("%w: %v", catalog.ErrNoJournal, err)
			}
			// A journal that cannot record the change is unavailable to
			// it, as a missing one is (audit F5).
			if err := j.Append(kind, tenant, subject); err != nil {
				return "", nil, fmt.Errorf("%w: %w", catalog.ErrNoJournal, err)
			}
			js, err := j.State()
			if err != nil {
				return "", nil, fmt.Errorf("%w: %w", catalog.ErrNoJournal, err)
			}
			return js.ID, js.Chains, nil
		}}
}

// An identifier names an identity, delegation or role. It is printable,
// has no spaces or slashes, and is at most 256 bytes: token subjects of
// identity providers fit (D-04).
var identifier = regexp.MustCompile(`^[^\s/\x00-\x1f\x7f]{1,256}$`)

func checkID(what, id string) error {
	if !identifier.MatchString(id) {
		return invalid("%s %q: use 1 to 256 printable characters without spaces or slashes", what, id)
	}
	return nil
}

// PutIdentity creates an identity or replaces its roles and attributes.
func (o Ops) PutIdentity(ctx context.Context, who Who, tenant, id string, roles []string, attrs map[string]any) error {
	if err := checkID("identity", id); err != nil {
		return err
	}
	for _, r := range roles {
		if err := checkID("role", r); err != nil {
			return err
		}
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "identity.put", "identity", id), o.journal(), func(a *catalog.Admin) error {
		return a.PutIdentity(ctx, tenant, id, roles, attrs)
	})
}

// DisableIdentity disables an identity, journaled first. It is final: an
// identity is not enabled again. Unless confirmUnreadable, it is refused
// with a *catalog.LastReaderError when the identity is the last reader of
// some client-mode files, before anything is journaled.
func (o Ops) DisableIdentity(ctx context.Context, who Who, tenant, id string, confirmUnreadable bool) error {
	if err := checkID("identity", id); err != nil {
		return err
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "identity.disable", "identity", id), o.journal(), func(a *catalog.Admin) error {
		if err := a.CheckLastReaders(ctx, tenant, id, "", confirmUnreadable); err != nil {
			return err
		}
		return a.DisableIdentity(ctx, tenant, id)
	})
}

// Capabilities resolves a preset or an explicit set of actions per
// resource type into capabilities, each type and action known to the
// registry.
func Capabilities(preset string, actions map[string][]string) (map[string][]string, error) {
	switch {
	case preset != "" && len(actions) > 0:
		return nil, invalid("give a preset or capabilities, not both")
	case preset != "":
		p, ok := Presets[preset]
		if !ok {
			return nil, invalid("unknown preset %q", preset)
		}
		return maps.Clone(p), nil
	case len(actions) == 0:
		return nil, invalid("no capabilities given")
	}
	types := registry.CoreTypes()
	for typ, list := range actions {
		if !types.HasResourceType(typ) {
			return nil, invalid("unknown resource type %q", typ)
		}
		if len(list) == 0 {
			return nil, invalid("%s: no actions given", typ)
		}
		for _, a := range list {
			if !types.HasAction(typ, a) {
				return nil, invalid("%s has no action %q", typ, a)
			}
		}
	}
	return actions, nil
}

// Grant lets an actor execute the given actions per resource type.
func (o Ops) Grant(ctx context.Context, who Who, tenant, actor string, actions map[string][]string) error {
	if err := checkID("identity", actor); err != nil {
		return err
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "capabilities.grant", "identity", actor), o.journal(), func(a *catalog.Admin) error {
		return a.GrantCapabilities(ctx, tenant, actor, actions)
	})
}

// Revoke takes capabilities from an actor, journaling those it held. It
// reports whether the actor held any of them.
func (o Ops) Revoke(ctx context.Context, who Who, tenant, actor string, actions map[string][]string) (bool, error) {
	if err := checkID("identity", actor); err != nil {
		return false, err
	}
	var held bool
	err := o.Store.Administer(ctx, o.event(tenant, who, "capabilities.revoke", "identity", actor), o.journal(), func(a *catalog.Admin) error {
		var err error
		held, err = a.RevokeCapabilities(ctx, tenant, actor, actions)
		return err
	})
	return held, err
}

// ParseGrants reads delegation grants written as 'type:a,b;type:c', with *
// for every action of a type.
func ParseGrants(list string) ([]delegation.Grant, error) {
	m := map[string][]string{}
	for _, part := range strings.Split(list, ";") {
		typ, acts, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			return nil, invalid("%q is not resource-type:actions", part)
		}
		// A type given without actions stays, so Grants refuses it rather
		// than drop it unnoticed (audit F7).
		if _, seen := m[typ]; !seen {
			m[typ] = nil
		}
		for _, a := range strings.Split(acts, ",") {
			if a = strings.TrimSpace(a); a != "" {
				m[typ] = append(m[typ], a)
			}
		}
	}
	return Grants(m)
}

// Grants turns actions per resource type into delegation grants, each type
// and action known to the registry or * for all of a type's actions.
func Grants(m map[string][]string) ([]delegation.Grant, error) {
	types := registry.CoreTypes()
	var out []delegation.Grant
	for _, typ := range slices.Sorted(maps.Keys(m)) {
		if !types.HasResourceType(typ) {
			return nil, invalid("unknown resource type %q", typ)
		}
		g := delegation.Grant{ResourceType: typ, Actions: m[typ]}
		if len(g.Actions) == 0 {
			return nil, invalid("%s: no actions given", typ)
		}
		for _, a := range g.Actions {
			if a != delegation.AllActions && !types.HasAction(typ, a) {
				return nil, invalid("%s has no action %q", typ, a)
			}
		}
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil, invalid("a delegation grants at least one action")
	}
	return out, nil
}

// AddDelegation records a new delegation (DLG-001).
func (o Ops) AddDelegation(ctx context.Context, who Who, d delegation.Delegation) error {
	for what, id := range map[string]string{"delegation": string(d.ID), "actor": d.Actor, "subject": d.Subject, "audience": d.Audience} {
		if err := checkID(what, id); err != nil {
			return err
		}
	}
	switch {
	case d.Actor == d.Subject:
		return invalid("a delegation's actor and subject differ")
	case !o.Now().Before(d.ExpiresAt):
		return invalid("a delegation expires in the future")
	case len(d.Grants) == 0:
		return invalid("a delegation grants at least one action")
	}
	return o.Store.Administer(ctx, o.event(d.Tenant, who, "delegation.add", "delegation", string(d.ID)), o.journal(), func(a *catalog.Admin) error {
		return a.PutDelegation(ctx, d, o.Now())
	})
}

// RevokeDelegation revokes a delegation, journaled first.
func (o Ops) RevokeDelegation(ctx context.Context, who Who, tenant, id string) error {
	if err := checkID("delegation", id); err != nil {
		return err
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "delegation.revoke", "delegation", id), o.journal(), func(a *catalog.Admin) error {
		return a.RevokeDelegation(ctx, tenant, id)
	})
}

// CreateBucket creates a bucket with its protected defaults.
func (o Ops) CreateBucket(ctx context.Context, who Who, tenant string, b catalog.Bucket) (cryptowire.UUID, error) {
	if !catalog.BucketName.MatchString(b.Name) {
		return cryptowire.UUID{}, invalid("bucket name %q", b.Name)
	}
	if !catalog.EncryptionMode(b.Encryption) {
		return cryptowire.UUID{}, invalid("encryption mode %q: server or client", b.Encryption)
	}
	var id cryptowire.UUID
	err := o.Store.Administer(ctx, o.event(tenant, who, "bucket.create", "storage.bucket", b.Name), o.journal(), func(a *catalog.Admin) error {
		var err error
		id, err = a.CreateBucket(ctx, tenant, b)
		return err
	})
	return id, err
}

// EnableMCP registers the MCP tools for a tenant (MCP-003).
func (o Ops) EnableMCP(ctx context.Context, who Who, tenant string) error {
	return o.Store.Administer(ctx, o.event(tenant, who, "mcp.enable", "tenant", tenant), o.journal(), func(a *catalog.Admin) error {
		return a.EnableMCP(ctx, tenant)
	})
}
