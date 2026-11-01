package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/delegation"
	"fga/internal/pgtest"
)

// recordingJournal records the entries administrative changes journal.
type recordingJournal struct{ kinds, subjects []string }

func (j *recordingJournal) journal() Journal {
	return Journal{RemovalKind: "access-removed", Append: func(kind, _, subject string) (string, []string, error) {
		j.kinds = append(j.kinds, kind)
		j.subjects = append(j.subjects, subject)
		chains := make([]string, len(j.subjects))
		for i := range chains {
			chains[i] = fmt.Sprintf("chain-%d", i+1)
		}
		return "journal-1", chains, nil
	}}
}

func (j *recordingJournal) removal(t *testing.T, i int) Removal {
	t.Helper()
	var r Removal
	if err := json.Unmarshal([]byte(j.subjects[i]), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func adminEvent() audit.Event {
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: audit.KindAdministration, Tenant: "t-acme", Actor: "root", Outcome: "test", At: now}
}

func adminStore(t *testing.T) *Store {
	t.Helper()
	return New(pgtest.Pool(t, Migrate), 1000)
}

func countEvents(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_outbox WHERE kind = 'administration'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRemovedValues(t *testing.T) {
	old := map[string]any{"projects": []any{"p1", "p2"}, "dept": "sales", "level": 3.0, "tags": []any{"a"}, "gone": "x", "same": "y", "none": []any{}}
	now := map[string]any{"projects": []any{"p2", "p3"}, "dept": "ops", "level": 3.0, "tags": "a", "same": "y"}
	want := map[string][]any{"projects": {"p1"}, "dept": {"sales"}, "tags": {"a"}, "gone": {"x"}}
	if got := removedValues(old, now); !reflect.DeepEqual(got, want) {
		t.Fatalf("removed = %v, want %v", got, want)
	}
	if got := removedValues(map[string]any{"projects": []any{"p1"}}, map[string]any{"projects": []any{"p1", "p2"}, "dept": "new"}); got != nil {
		t.Fatalf("an addition removed %v", got)
	}
}

// TestAdministerJournalsRemovals covers review AMB-1: a replacement that
// takes a role or an attribute value away is journaled before it is made,
// with the journal's state recorded in its transaction, and every change
// commits with its audit event; additions are not journaled.
func TestAdministerJournalsRemovals(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	var j recordingJournal
	put := func(roles []string, attrs map[string]any) {
		t.Helper()
		if err := s.Administer(ctx, adminEvent(), j.journal(), func(a *Admin) error {
			return a.PutIdentity(ctx, "t-acme", "lena", roles, attrs)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put([]string{"member"}, map[string]any{"projects": []any{"p1"}})
	put([]string{"member", "lead"}, map[string]any{"projects": []any{"p1", "p2"}, "dept": "sales"})
	if len(j.subjects) != 0 {
		t.Fatalf("additions were journaled: %v", j.subjects)
	}
	put([]string{"member"}, map[string]any{"projects": []any{"p2"}})
	if len(j.subjects) != 1 || j.kinds[0] != "access-removed" {
		t.Fatalf("journal = %v %v", j.kinds, j.subjects)
	}
	want := Removal{Identity: "lena", Roles: []string{"lead"}, Attributes: map[string][]any{"projects": {"p1"}, "dept": {"sales"}}}
	if got := j.removal(t, 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("removal = %+v, want %+v", got, want)
	}
	var bound string
	var entries int
	if err := s.pool.QueryRow(ctx, `SELECT journal_id, entries FROM journal_state`).Scan(&bound, &entries); err != nil || bound != "journal-1" || entries != 1 {
		t.Fatalf("journal state = %q %d, %v", bound, entries, err)
	}
	if n := countEvents(t, s); n != 3 {
		t.Fatalf("%d administration events, want 3", n)
	}
}

// TestRemovalNeedsJournal: without a security journal, a change that
// takes access away is refused and nothing of it commits, its audit event
// included; one that only adds is made.
func TestRemovalNeedsJournal(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	put := func(roles []string) error {
		return s.Administer(ctx, adminEvent(), Journal{}, func(a *Admin) error { return a.PutIdentity(ctx, "t-acme", "lena", roles, nil) })
	}
	if err := put([]string{"member", "lead"}); err != nil {
		t.Fatal(err)
	}
	if err := put([]string{"member"}); !errors.Is(err, ErrNoJournal) {
		t.Fatalf("removal without a journal: %v", err)
	}
	ids, err := s.ListIdentities(ctx, "t-acme", "", 10)
	if err != nil || len(ids) != 1 || !slices.Contains(ids[0].Roles, "lead") {
		t.Fatalf("identities = %+v, %v", ids, err)
	}
	if n := countEvents(t, s); n != 1 {
		t.Fatalf("%d administration events, want the addition's only", n)
	}
}

func TestRevokeCapabilities(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	var j recordingJournal
	admin := func(change func(a *Admin) error) error { return s.Administer(ctx, adminEvent(), j.journal(), change) }
	if err := admin(func(a *Admin) error {
		if err := a.PutIdentity(ctx, "t-acme", "bob", []string{"member"}, nil); err != nil {
			return err
		}
		return a.GrantCapabilities(ctx, "t-acme", "bob", map[string][]string{"storage.object": {"read", "stat"}})
	}); err != nil {
		t.Fatal(err)
	}
	revoke := func(actor string, caps map[string][]string) (bool, error) {
		var held bool
		err := admin(func(a *Admin) error {
			var err error
			held, err = a.RevokeCapabilities(ctx, "t-acme", actor, caps)
			return err
		})
		return held, err
	}
	held, err := revoke("bob", map[string][]string{"storage.object": {"read", "delete"}, "storage.bucket": {"list"}})
	if err != nil || !held {
		t.Fatalf("revoke = %v, %v", held, err)
	}
	want := Removal{Identity: "bob", Capabilities: map[string][]string{"storage.object": {"read"}}}
	if len(j.subjects) != 1 || !reflect.DeepEqual(j.removal(t, 0), want) {
		t.Fatalf("journal = %v, want only what bob held", j.subjects)
	}
	ids, _ := s.ListIdentities(ctx, "t-acme", "", 10)
	if got := ids[0].Capabilities["storage.object"]; !reflect.DeepEqual(got, []string{"stat"}) {
		t.Fatalf("capabilities left = %v", got)
	}
	if held, err := revoke("bob", map[string][]string{"storage.object": {"read"}}); err != nil || held || len(j.subjects) != 1 {
		t.Fatalf("revoking what bob no longer holds: %v, %v, journal %d", held, err, len(j.subjects))
	}
	if _, err := revoke("nobody", map[string][]string{"storage.object": {"read"}}); !errors.Is(err, ErrNoRow) {
		t.Fatalf("revoke from an unknown identity: %v", err)
	}
}

// TestApplyRemoval covers the replay of a journaled removal: it takes away
// what it names, leaves later values alone, and is idempotent.
func TestApplyRemoval(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	for _, stmt := range []string{
		`INSERT INTO identities (tenant, id, revision, roles, attributes) VALUES
		   ('t-acme', 'lena', 1, '{member,lead}', '{"projects":["p1","p2"],"dept":"sales","level":2}')`,
		`INSERT INTO capabilities VALUES ('t-acme', 'lena', 'storage.object', 'read'), ('t-acme', 'lena', 'storage.object', 'stat')`,
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	r := Removal{Identity: "lena", Roles: []string{"lead"}, Attributes: map[string][]any{"projects": {"p1"}, "dept": {"sales"}},
		Capabilities: map[string][]string{"storage.object": {"read"}}}
	if err := s.ApplyRemoval(ctx, "t-acme", r); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ListIdentities(ctx, "t-acme", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	got := ids[0]
	if !reflect.DeepEqual(got.Roles, []string{"member"}) || !reflect.DeepEqual(got.Attributes, map[string]any{"projects": []any{"p2"}, "level": 2.0}) ||
		!reflect.DeepEqual(got.Capabilities, map[string][]string{"storage.object": {"stat"}}) {
		t.Fatalf("after the removal: %+v", got)
	}
	revision := func() (n int64) {
		_ = s.pool.QueryRow(ctx, `SELECT revision FROM identities WHERE id = 'lena'`).Scan(&n)
		return n
	}
	before := revision()
	if err := s.ApplyRemoval(ctx, "t-acme", r); err != nil || revision() != before {
		t.Fatalf("a second replay changed the identity: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE identities SET attributes = attributes || '{"dept":"ops"}'`); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyRemoval(ctx, "t-acme", r); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.ListIdentities(ctx, "t-acme", "", 10); ids[0].Attributes["dept"] != "ops" {
		t.Fatalf("a value set after the removal was taken: %v", ids[0].Attributes)
	}
	if err := s.ApplyRemoval(ctx, "t-acme", Removal{Identity: "gone", Roles: []string{"lead"}}); err != nil {
		t.Fatalf("removal from a missing identity: %v", err)
	}
}

func TestDirectoryListings(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	err := s.Administer(ctx, adminEvent(), Journal{}, func(a *Admin) error {
		for _, id := range []string{"carl", "alice", "bob"} {
			if err := a.PutIdentity(ctx, "t-acme", id, []string{"member"}, map[string]any{"projects": []any{"p1"}}); err != nil {
				return err
			}
		}
		if err := a.PutIdentity(ctx, "t-other", "eve", nil, nil); err != nil {
			return err
		}
		if err := a.GrantCapabilities(ctx, "t-acme", "bob", map[string][]string{"storage.bucket": {"list"}}); err != nil {
			return err
		}
		if err := a.PutDelegation(ctx, delegation.Delegation{ID: "dlg-1", Tenant: "t-acme", Actor: "carl", Subject: "bob", Audience: "mcp",
			Grants: []delegation.Grant{{ResourceType: "storage.object", Actions: []string{"read"}}}, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
			return err
		}
		for _, name := range []string{"shared", "reports"} {
			if _, err := a.CreateBucket(ctx, "t-acme", Bucket{Name: name, Project: "p1", Label: "internal", Encryption: "server"}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ListIdentities(ctx, "t-acme", "", 2)
	if err != nil || len(first) != 2 || first[0].ID != "alice" || first[1].ID != "bob" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	if !reflect.DeepEqual(first[1].Capabilities, map[string][]string{"storage.bucket": {"list"}}) || len(first[0].Capabilities) != 0 {
		t.Fatalf("capabilities = %v, %v", first[0].Capabilities, first[1].Capabilities)
	}
	if rest, err := s.ListIdentities(ctx, "t-acme", "bob", 2); err != nil || len(rest) != 1 || rest[0].ID != "carl" {
		t.Fatalf("second page = %+v, %v", rest, err)
	}
	ds, err := s.ListDelegations(ctx, "t-acme", "", 10)
	if err != nil || len(ds) != 1 || ds[0].Actor != "carl" || !reflect.DeepEqual(ds[0].Grants, map[string][]string{"storage.object": {"read"}}) {
		t.Fatalf("delegations = %+v, %v", ds, err)
	}
	bs, err := s.ListBuckets(ctx, "t-acme", "", 10)
	if err != nil || len(bs) != 2 || bs[0].Name != "reports" || bs[1].Encryption != "server" {
		t.Fatalf("buckets = %+v, %v", bs, err)
	}
	if err := s.Append(ctx, audit.Event{ID: "later", Kind: audit.KindDecision, Tenant: "t-acme", At: now}); err != nil {
		t.Fatal(err)
	}
	events, err := s.RecentEvents(ctx, "t-acme", 2)
	if err != nil || len(events) != 2 || events[0].ID != "later" || events[1].Kind != audit.KindAdministration {
		t.Fatalf("events = %+v, %v", events, err)
	}
}
