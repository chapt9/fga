package content_test

import (
	"errors"
	"io"
	"maps"
	"strings"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/delegation"
	"fga/internal/r1test"
	"fga/internal/registry"
)

// historyPolicies are the fixture's policies, with the members of a
// project also allowed raw-read and export on its document versions and
// export-key on its units, so that only history separates a member from
// the owner on every disclosure route.
func historyPolicies(extra map[string]string) map[string]string {
	policies := maps.Clone(r1test.Policies)
	add := func(file, rule string) {
		policies[file] = strings.Replace(policies[file], `"rules":[`, `"rules":[`+rule+",", 1)
	}
	add("documents.json", `{"id":"members-take-versions","effect":"allow","actions":["raw-read","export"],"roles":["member"],
	  "when":"resource.attributes.project in principal.attributes.projects"}`)
	add("units.json", `{"id":"members-export-units","effect":"allow","actions":["export-key"],"roles":["member"],
	  "when":"resource.attributes.project in principal.attributes.projects"}`)
	for file, rule := range extra {
		add(file, rule)
	}
	return policies
}

// putText publishes text, with an original, as a new version of key in the
// server-mode bucket vault.
func putText(t *testing.T, st *r1test.Stack, c content.Caller, key, idem, text string) content.DocumentPublished {
	t.Helper()
	p, err := st.Content.PutDocumentText(ctx, c, content.TextRequest{Bucket: "vault", Key: key, IdempotencyKey: idem,
		Original: strings.NewReader("the original of " + text)}, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func drain(s *content.Stream, err error) error {
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = io.ReadAll(s)
	return err
}

// TestDocumentHistoryChecks covers DOC-009 on each disclosure route of a
// superseded document version, in both modes: a member without
// read-history gets the current version on every route and nothing of the
// superseded one, while a member who may read history, and the owner, get
// both.
func TestDocumentHistoryChecks(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: historyPolicies(nil)})
	st.ModeBucket("vault", "p1", "internal", "server")
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	ada := st.Client("ada", []string{"member", "auditor"}, "p1")
	alice.Pin(bob)
	alice.Pin(ada)
	bob.Pin(alice)
	ada.Pin(alice)

	v1 := putText(t, st, alice.Caller, "notes", "n-1", "Old notes.")
	putText(t, st, alice.Caller, "notes", "n-2", "New notes.")
	up, err := alice.PrepareDocumentWithOriginal("reports", "plan", []string{"Old plan."}, []byte("old original"), alice, bob, ada)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := alice.FinalizeDocument(up)
	if err != nil {
		t.Fatal(err)
	}
	if up, err = alice.PrepareDocumentWithOriginal("reports", "plan", []string{"New plan."}, []byte("new original"), alice, bob, ada); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	units := func(bucket, key, version string) []string { return st.UnitIDs(alice.Caller, bucket, key, version) }
	recipient := func(c *r1test.Client) string { return c.Recipient.Fingerprint().String() }

	type route func(c *r1test.Client, version string, units []string) error
	server := map[string]route{
		"unit listing": func(c *r1test.Client, v string, _ []string) error {
			_, err := st.Content.ListUnits(ctx, c.Caller, "vault", "notes", v, 100, "")
			return err
		},
		"unit selection": func(c *r1test.Client, v string, u []string) error {
			_, err := st.Content.SelectUnits(ctx, c.Caller, "vault", "notes", v, u)
			return err
		},
		"manifest": func(c *r1test.Client, v string, _ []string) error {
			_, _, err := st.Content.Manifest(ctx, c.Caller, "vault", "notes", v)
			return err
		},
		"unit plaintext": func(c *r1test.Client, v string, u []string) error {
			_, err := readUnitPlain(st, c.Caller, "vault", "notes", v, u[0])
			return err
		},
		"plaintext export": func(c *r1test.Client, v string, u []string) error {
			_, err := st.Content.ExportUnitsPlain(ctx, c.Caller, "vault", "notes", v, u)
			return err
		},
		"original plaintext": func(c *r1test.Client, v string, _ []string) error {
			return drain(st.Content.ReadOriginalPlain(ctx, c.Caller, "vault", "notes", v))
		},
	}
	client := map[string]route{
		"unit ciphertext": func(c *r1test.Client, v string, u []string) error {
			return drain(st.Content.ReadUnitCiphertext(ctx, c.Caller, "reports", "plan", v, u[0]))
		},
		"unit package": func(c *r1test.Client, v string, u []string) error {
			_, err := st.Content.UnitPackage(ctx, c.Caller, "reports", "plan", v, u[0], recipient(c))
			return err
		},
		"original package": func(c *r1test.Client, v string, _ []string) error {
			_, err := st.Content.OriginalPackage(ctx, c.Caller, "reports", "plan", v, recipient(c))
			return err
		},
		"original ciphertext": func(c *r1test.Client, v string, _ []string) error {
			return drain(st.Content.ReadOriginal(ctx, c.Caller, "reports", "plan", v))
		},
	}
	for mode, routes := range map[string]struct {
		routes          map[string]route
		bucket, key, v1 string
	}{"server": {server, "vault", "notes", v1.DocumentVersion}, "client": {client, "reports", "plan", c1.DocumentVersion}} {
		old, current := units(routes.bucket, routes.key, routes.v1), units(routes.bucket, routes.key, "")
		if len(old) != 1 || len(current) != 1 || old[0] == current[0] {
			t.Fatalf("%s: units %v and %v", mode, old, current)
		}
		for name, r := range routes.routes {
			if err := r(bob, "", current); err != nil {
				t.Errorf("%s %s: a member reads the current version: %v", mode, name, err)
			}
			if err := r(bob, routes.v1, old); !errors.Is(err, content.ErrNotFound) {
				t.Errorf("%s %s: a member without read-history reads the superseded version: %v", mode, name, err)
			}
			for _, c := range []*r1test.Client{ada, alice} {
				if err := r(c, routes.v1, old); err != nil {
					t.Errorf("%s %s: %s reads the superseded version: %v", mode, name, c.Caller.Principal, err)
				}
			}
		}
	}
	// The export of a superseded version to a recipient goes through the
	// keys role's envelope release under the history twin.
	old := units("reports", "plan", c1.DocumentVersion)
	if _, err := st.Content.ExportUnits(ctx, alice.Caller, "reports", "plan", c1.DocumentVersion, old, recipient(alice)); err != nil {
		t.Errorf("the owner exports the superseded version: %v", err)
	}
	if _, err := st.Content.ExportUnits(ctx, bob.Caller, "reports", "plan", c1.DocumentVersion, old, recipient(bob)); !errors.Is(err, content.ErrNotFound) {
		t.Errorf("a member without read-history exports the superseded version: %v", err)
	}
}

// TestKeysReleaseHistory covers DOC-009 when a newer version arrives
// mid-read: a reader decided for the current version loses it, in the
// storage role's admission and in the keys role's release alike, while a
// reader of history keeps reading the superseded version: its history check
// holds for every version of the document.
func TestKeysReleaseHistory(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: historyPolicies(nil)})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	ada := st.Client("ada", []string{"member", "auditor"}, "p1")
	putText(t, st, alice.Caller, "notes", "n-1", "First.")
	n := 1
	publishAfter := func(op string) {
		st.AfterDecide = func(req decisionsvc.Request) {
			if req.Operation == op {
				st.AfterDecide = nil
				n++
				*st.Clock = st.Clock.Add(time.Second) // within a decision's age
				putText(t, st, alice.Caller, "notes", "n-"+string(rune('0'+n)), "Next.")
			}
		}
	}
	read := func(c *r1test.Client, version string) error {
		u := st.UnitIDs(alice.Caller, "vault", "notes", version)
		_, err := readUnitPlain(st, c.Caller, "vault", "notes", version, u[0])
		return err
	}
	publishAfter(registry.OpDocReadUnit)
	if err := read(bob, ""); !errors.Is(err, content.ErrConflict) {
		t.Errorf("the storage role admitted a read of a version superseded after its decision: %v", err)
	}
	publishAfter(registry.OpKeyReleaseUnit)
	if err := read(bob, ""); !errors.Is(err, content.ErrNotFound) {
		t.Errorf("the keys role released a key of a version superseded after its decision: %v", err)
	}
	u := st.UnitIDs(alice.Caller, "vault", "notes", "")
	publishAfter(registry.OpDocSelectUnits)
	if _, err := st.Content.SelectUnits(ctx, bob.Caller, "vault", "notes", "", u); !errors.Is(err, content.ErrConflict) {
		t.Errorf("a selection of a version superseded after its decision: %v", err)
	}
	if st.AfterDecide != nil {
		t.Fatal("a hook did not run")
	}
	if err := read(bob, ""); err != nil {
		t.Fatalf("without a newer version the current one reads: %v", err)
	}
	var first string
	if err := st.Pool.QueryRow(ctx, `SELECT v.id::text FROM document_versions v JOIN objects o ON o.id = v.document
	                                 WHERE o.key = 'notes' ORDER BY v.created_at LIMIT 1`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{registry.HistoryOp(registry.OpDocReadUnit), registry.HistoryOp(registry.OpKeyReleaseUnit)} {
		publishAfter(op)
		if err := read(ada, first); err != nil {
			t.Errorf("a reader of history loses a superseded version to a newer one after %s: %v", op, err)
		}
		if st.AfterDecide != nil {
			t.Fatalf("the hook for %s did not run", op)
		}
	}
}

// TestDocumentVersionListing covers DOC-010 and DOC-011: versions newest
// first with their publication time; superseded entries only with
// discover-history, left out without a count otherwise; a continuation
// bound to its caller; and a listing that starts again when the head
// moves.
func TestDocumentVersionListing(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: historyPolicies(nil)})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	carl := st.Client("carl", []string{"member"}, "p2")
	var ids []string
	for i, text := range []string{"One.", "Two.", "Three."} {
		*st.Clock = st.Clock.Add(time.Minute)
		ids = append(ids, putText(t, st, alice.Caller, "notes", "n-"+string(rune('1'+i)), text).DocumentVersion)
	}
	list := func(c *r1test.Client, limit int, continuation string) (content.DocumentVersionPage, error) {
		return st.Content.ListDocumentVersions(ctx, c.Caller, "vault", "notes", limit, continuation)
	}
	versions := func(p content.DocumentVersionPage) []string {
		var out []string
		for _, v := range p.Versions {
			out = append(out, v.DocumentVersion)
			if v.PublishedAt == "" {
				t.Errorf("version %s has no published_at", v.DocumentVersion)
			}
			if v.Current != (v.DocumentVersion == ids[len(ids)-1]) {
				t.Errorf("version %s: current = %t", v.DocumentVersion, v.Current)
			}
		}
		return out
	}
	page, err := list(alice, 0, "")
	if err != nil || strings.Join(versions(page), ",") != strings.Join([]string{ids[2], ids[1], ids[0]}, ",") || page.Continuation != "" {
		t.Fatalf("the owner lists %v %q, %v", versions(page), page.Continuation, err)
	}
	if page, err := list(bob, 0, ""); err != nil || len(page.Versions) != 1 || page.Versions[0].DocumentVersion != ids[2] {
		t.Fatalf("a member without discover-history lists %+v, %v", page, err)
	}
	if _, err := list(carl, 0, ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member of another project lists the versions: %v", err)
	}
	first, err := list(alice, 2, "")
	if err != nil || len(first.Versions) != 2 || first.Continuation == "" {
		t.Fatalf("the first page %+v, %v", first, err)
	}
	if second, err := list(alice, 2, first.Continuation); err != nil || len(second.Versions) != 1 || second.Versions[0].DocumentVersion != ids[0] ||
		second.Continuation != "" {
		t.Fatalf("the second page %+v, %v", second, err)
	}
	if _, err := list(bob, 2, first.Continuation); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("another caller's continuation: %v", err)
	}
	st.AfterDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpDocDiscover {
			st.AfterDecide = nil
			*st.Clock = st.Clock.Add(time.Second) // within a decision's age
			ids = append(ids, putText(t, st, alice.Caller, "notes", "n-4", "Four.").DocumentVersion)
		}
	}
	if page, err := list(alice, 0, ""); err != nil || len(page.Versions) != 4 || page.Versions[0].DocumentVersion != ids[3] {
		t.Fatalf("a listing across a new version: %v, %v", versions(page), err)
	}
}

// TestPublishedAtCondition covers DOC-011: a rule can bound history by the
// server's published_at, here from a fixed date on, and a version without
// published_at meets no guarded condition. A window relative to request.now
// is refused by the engine, which bounds a decision's validity only by
// timestamp literals (POL-008).
func TestPublishedAtCondition(t *testing.T) {
	cutoff := r1test.Now.Add(time.Hour).UTC().Format(time.RFC3339)
	since := `has(resource.attributes.published_at) && timestamp(resource.attributes.published_at) >= timestamp('` + cutoff + `') && ` +
		`resource.attributes.project in principal.attributes.projects`
	st := r1test.NewWith(t, r1test.Options{Policies: historyPolicies(map[string]string{
		"documents.json": `{"id":"viewers-since","effect":"allow","actions":["read-units","discover"],"roles":["viewer"],"when":"` + since + `"}`,
		"units.json": `{"id":"viewers-read-units","effect":"allow","actions":["read"],"roles":["viewer"],
		  "when":"resource.attributes.project in principal.attributes.projects"}`,
	})})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.User("vic", []string{"viewer"}, "p1")
	putText(t, st, alice.Caller, "notes", "n-1", "Before.")
	early := st.UnitIDs(alice.Caller, "vault", "notes", "")[0]
	if _, err := readUnitPlain(st, st.Caller("vic"), "vault", "notes", "", early); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a viewer reads a version published before the date: %v", err)
	}
	*st.Clock = st.Clock.Add(2 * time.Hour)
	p := putText(t, st, st.CallerFor("alice", content.Audience), "notes", "n-2", "After.")
	late := st.UnitIDs(st.CallerFor("alice", content.Audience), "vault", "notes", "")[0]
	if _, err := readUnitPlain(st, st.Caller("vic"), "vault", "notes", "", late); err != nil {
		t.Fatalf("a viewer reads a version published after the date: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE resources SET attributes = attributes - 'published_at' WHERE id = $1`, p.DocumentVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := readUnitPlain(st, st.Caller("vic"), "vault", "notes", "", late); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a viewer reads a version without published_at: %v", err)
	}
}

// TestDelegationWithoutHistory covers DOC-009 under a delegation: an agent
// whose delegation leaves out read-history reads only the current version,
// while the person it acts for reads history.
func TestDelegationWithoutHistory(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: historyPolicies(nil)})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.User("agent-1", []string{"agent"})
	v1 := putText(t, st, alice.Caller, "notes", "n-1", "Old.")
	putText(t, st, alice.Caller, "notes", "n-2", "New.")
	if err := st.Catalog.PutDelegation(ctx, delegation.Delegation{ID: "dlg-1", Tenant: r1test.Tenant, Actor: "agent-1", Subject: "alice",
		Audience: r1test.StorageAdapter, ExpiresAt: st.Clock.Add(time.Hour), Grants: []delegation.Grant{
			{ResourceType: "document.version", Actions: []string{"read-units", "discover"}},
			{ResourceType: "document.text_unit", Actions: []string{"read"}},
		}}, *st.Clock); err != nil {
		t.Fatal(err)
	}
	agent := st.Caller("agent-1")
	agent.Subject, agent.Delegation = "alice", "dlg-1"
	old, current := st.UnitIDs(alice.Caller, "vault", "notes", v1.DocumentVersion), st.UnitIDs(alice.Caller, "vault", "notes", "")
	if _, err := readUnitPlain(st, agent, "vault", "notes", "", current[0]); err != nil {
		t.Fatalf("the agent reads the current version: %v", err)
	}
	if _, err := readUnitPlain(st, agent, "vault", "notes", v1.DocumentVersion, old[0]); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("the agent reads history its delegation leaves out: %v", err)
	}
	if _, err := readUnitPlain(st, alice.Caller, "vault", "notes", v1.DocumentVersion, old[0]); err != nil {
		t.Fatalf("the person reads history: %v", err)
	}
}
