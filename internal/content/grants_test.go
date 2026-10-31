package content_test

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/journal"
	"fga/internal/r1test"
)

// grantPolicies are the fixture policies with rules that honor share
// grants of read and stat on objects (SHR-002), and a ceiling that keeps
// restricted objects from principals without the cleared role (V-175).
func grantPolicies() map[string]string {
	p := maps.Clone(r1test.Policies)
	p["objects.json"] = strings.TrimSuffix(p["objects.json"], "]}") + `,
	  {"id":"grantees-read","effect":"allow","actions":["read"],"roles":["*"],"when":"principal.id in resource.attributes.shared_with.read"},
	  {"id":"grantees-stat","effect":"allow","actions":["stat"],"roles":["*"],"when":"principal.id in resource.attributes.shared_with.stat"}]}`
	p["ceiling-objects.json"] = `{"format":"fga.policy/v1","set":"ceiling","resource":"storage.object","scope":"","rules":[
	  {"id":"restricted-needs-clearance","effect":"deny","actions":["read"],"roles":["*"],
	   "when":"resource.attributes.label == \"restricted\" && !(\"cleared\" in principal.roles)"}]}`
	return p
}

func grant(st *r1test.Stack, c content.Caller, t content.GrantTarget, grantee string, d time.Duration, actions ...string) (content.GrantOutcome, error) {
	return st.Content.RecordGrant(ctx, c, t, content.GrantRequest{Grantee: grantee, Actions: actions, ExpiresAt: st.Clock.Add(d)})
}

// TestGrantDefaultDeny covers V-171: without a rule that tests
// shared_with, a recorded grant allows nothing.
func TestGrantDefaultDeny(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p2")
	if _, err := putPlain(st, alice.Caller, "vault", "plan.txt", "", []byte("the plan")); err != nil {
		t.Fatal(err)
	}
	if _, err := grant(st, alice.Caller, content.GrantTarget{Bucket: "vault", Key: "plan.txt"}, "bob", time.Hour, "read"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPlain(st, bob.Caller, "vault", "plan.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob with a grant no rule honors: %v", err)
	}
}

// TestGrants covers SHR-001, SHR-002 and SHR-003 in server mode: V-172 to
// V-177, a grant ending a stream at its expiry (TH-29), replacement and
// listing, and journaled removals (AVL-008).
func TestGrants(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: grantPolicies()})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p2")
	carol := st.Client("carol", []string{"member"}, "p1")
	plan := content.GrantTarget{Bucket: "vault", Key: "plan.txt"}
	if _, err := putPlain(st, alice.Caller, "vault", "plan.txt", "", []byte("the plan")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPlain(st, bob.Caller, "vault", "plan.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob before a grant: %v", err)
	}

	// V-176: carol may read alice's object but not share it.
	if _, err := grant(st, carol.Caller, plan, "bob", time.Hour, "read"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a grant without share: %v", err)
	}
	// V-177: another tenant's principal, an action outside the read set,
	// or an expiry that has passed.
	if _, err := st.Catalog.EnsureTenant(ctx, "t-other"); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.PutIdentity(ctx, "t-other", "olga", []string{"member"}, map[string]any{"projects": []string{"p1"}}, nil); err != nil {
		t.Fatal(err)
	}
	for name, try := range map[string]func() error{
		"another tenant's principal": func() error { _, err := grant(st, alice.Caller, plan, "olga", time.Hour, "read"); return err },
		"delete":                     func() error { _, err := grant(st, alice.Caller, plan, "bob", time.Hour, "read", "delete"); return err },
		"an expiry that has passed":  func() error { _, err := grant(st, alice.Caller, plan, "bob", -time.Minute, "read"); return err },
		"a version of an object": func() error {
			_, err := st.Content.RecordGrant(ctx, alice.Caller, content.GrantTarget{Bucket: "vault", Key: "plan.txt", Version: "x"},
				content.GrantRequest{Grantee: "bob", Actions: []string{"read"}, ExpiresAt: st.Clock.Add(time.Hour)})
			return err
		},
	} {
		if err := try(); !errors.Is(err, content.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// V-172: an honored grant is enough for the storage role to decrypt.
	out, err := grant(st, alice.Caller, plan, "bob", time.Hour, "stat", "read", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Grant.Actions, []string{"read", "stat"}) || out.Grant.ResourceType != "storage.object" {
		t.Fatalf("grant: %+v", out.Grant)
	}
	if got, _, err := readPlain(st, bob.Caller, "vault", "plan.txt", ""); err != nil || string(got) != "the plan" {
		t.Fatalf("bob with an honored grant: %q %v", got, err)
	}
	if gs, err := st.Content.ListGrants(ctx, alice.Caller, plan); err != nil || len(gs) != 1 || gs[0].Grantee != "bob" {
		t.Fatalf("alice lists the grants: %+v %v", gs, err)
	}
	if _, err := st.Content.ListGrants(ctx, bob.Caller, plan); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob lists the grants: %v", err)
	}

	// V-175: an honored grant does not lift a ceiling.
	if _, err := st.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "secret.txt", IdempotencyKey: "secret",
		Label: "restricted"}, 6, strings.NewReader("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := grant(st, alice.Caller, content.GrantTarget{Bucket: "vault", Key: "secret.txt"}, "bob", time.Hour, "read"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPlain(st, bob.Caller, "vault", "secret.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob above his clearance: %v", err)
	}

	// V-174: removing the grant ends bob's stream at its next lease check,
	// and the removal is journaled before it is committed.
	big := bytes.Repeat([]byte("x"), 3<<20)
	if _, err := putPlain(st, alice.Caller, "vault", "big.bin", "", big); err != nil {
		t.Fatal(err)
	}
	bigTarget := content.GrantTarget{Bucket: "vault", Key: "big.bin"}
	bigGrant, err := grant(st, alice.Caller, bigTarget, "bob", time.Hour, "read")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := st.Content.ReadObject(ctx, bob.Caller, "vault", "big.bin", "")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.RemoveGrant(ctx, alice.Caller, bigTarget, "bob"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * r1test.LeaseCheckEvery)
	if _, err := io.ReadAll(stream); !errors.Is(err, content.ErrLease) {
		t.Fatalf("bob's stream after the removal: %v", err)
	}
	stream.Close()
	if _, _, err := readPlain(st, bob.Caller, "vault", "big.bin", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob after the removal: %v", err)
	}
	if _, err := st.Content.RemoveGrant(ctx, alice.Caller, bigTarget, "bob"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("removing it again: %v", err)
	}

	// Replacing bob's grant on plan.txt with one expiring in ten minutes
	// journals the earlier grant's removal. V-173 and TH-29: a stream bob
	// opened under it ends at its expiry, and afterwards it is gone.
	replaced, err := grant(st, alice.Caller, plan, "bob", 10*time.Minute, "read")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := st.Journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var removed []string
	for _, e := range entries {
		if e.Kind == journal.GrantRemoved {
			removed = append(removed, e.Subject)
		}
	}
	// The fixture clock stands still, so the journal's order among them is
	// its random tie-break.
	want := []string{bigGrant.Grant.ID, out.Grant.ID}
	slices.Sort(removed)
	slices.Sort(want)
	if !slices.Equal(removed, want) {
		t.Fatalf("journaled removals %v, want %v", removed, want)
	}
	stream, err = st.Content.ReadObject(ctx, bob.Caller, "vault", "plan.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, buf[:2]); err != nil {
		t.Fatal(err)
	}
	*st.Clock = replaced.Grant.ExpiresAt
	if _, err := stream.Read(buf); !errors.Is(err, content.ErrLease) {
		t.Fatalf("bob's stream at the grant's expiry: %v", err)
	}
	stream.Close()
	bob.Caller = st.Caller("bob")
	if _, _, err := readPlain(st, bob.Caller, "vault", "plan.txt", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob after the expiry: %v", err)
	}
	alice.Caller = st.Caller("alice")
	if gs, err := st.Content.ListGrants(ctx, alice.Caller, plan); err != nil || len(gs) != 0 {
		t.Fatalf("grants after the expiry: %+v %v", gs, err)
	}
}

// TestGrantOutlivingGrantor covers SHR-001: a grant cannot outlive the
// grantor's identity.
func TestGrantOutlivingGrantor(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: grantPolicies()})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.Client("bob", []string{"member"}, "p2")
	if _, err := putPlain(st, alice.Caller, "vault", "plan.txt", "", []byte("the plan")); err != nil {
		t.Fatal(err)
	}
	until := st.Clock.Add(time.Hour)
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "alice", []string{"member"}, map[string]any{"projects": []string{"p1"}}, &until); err != nil {
		t.Fatal(err)
	}
	alice.Caller = st.Caller("alice")
	plan := content.GrantTarget{Bucket: "vault", Key: "plan.txt"}
	if _, err := grant(st, alice.Caller, plan, "bob", 2*time.Hour, "read"); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a grant beyond the grantor's expiry: %v", err)
	}
	if _, err := grant(st, alice.Caller, plan, "bob", 30*time.Minute, "read"); err != nil {
		t.Fatalf("a grant within it: %v", err)
	}
}

// TestGrantClientMode covers V-178 (SHR-003): in client mode an honored
// grant makes the grantee eligible as a recipient but supplies no key.
func TestGrantClientMode(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: grantPolicies()})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p2")
	alice.Pin(bob)
	bob.Pin(alice)
	if _, err := alice.Put("reports", "doc", []byte("client-encrypted")); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Share("reports", "doc", "", bob, 1); err == nil {
		t.Fatal("alice shared with bob, who may not read")
	}
	if _, err := grant(st, alice.Caller, content.GrantTarget{Bucket: "reports", Key: "doc"}, "bob", time.Hour, "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Get("reports", "doc", ""); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob with a grant but no envelope: %v", err)
	}
	if _, err := alice.Share("reports", "doc", "", bob, 1); err != nil {
		t.Fatalf("alice shares with an eligible bob: %v", err)
	}
	if got, err := bob.Get("reports", "doc", ""); err != nil || string(got) != "client-encrypted" {
		t.Fatalf("bob with a grant and an envelope: %q %v", got, err)
	}
}

// TestGrantTargets covers the grant targets and read sets of SHR-001
// (specification 2.6.1): a bucket, a document version, a unit, a
// collection entry and a derived output each take their own actions.
func TestGrantTargets(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member", "lead"}, "p1")
	st.Client("bob", []string{"member"}, "p2")
	src, err := putPlain(st, alice.Caller, "vault", "data.csv", "", []byte("a,b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "notes.md", IdempotencyKey: "n"},
		[]byte("One.\n\nTwo.")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "chat", IdempotencyKey: "c",
		Collection: true}, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	units, err := st.Content.ListUnits(ctx, alice.Caller, "vault", "notes.md", "", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := st.Content.ListUnits(ctx, alice.Caller, "vault", "chat", "", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "out.txt", IdempotencyKey: "o"},
		[]cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: src.Object, Version: src.Version}}, -1, strings.NewReader("derived")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		target   content.GrantTarget
		typ      string
		good     string
		bad      string
		shareErr error
	}{
		{content.GrantTarget{Bucket: "vault"}, "storage.bucket", "list", "read", nil},
		{content.GrantTarget{Bucket: "vault", Key: "notes.md"}, "document.version", "read-units", "read", nil},
		{content.GrantTarget{Bucket: "vault", Key: "notes.md", Unit: units.Units[1].Unit}, "document.text_unit", "read", "read-units", nil},
		{content.GrantTarget{Bucket: "vault", Key: "chat", Unit: entries.Units[0].Unit}, "text.entry", "read", "update", nil},
		{content.GrantTarget{Bucket: "vault", Key: "out.txt"}, "document.derived", "deliver", "read", nil},
	} {
		if _, err := grant(st, alice.Caller, c.target, "bob", time.Hour, c.bad); !errors.Is(err, content.ErrInvalid) {
			t.Errorf("%s with %s: %v", c.typ, c.bad, err)
		}
		out, err := grant(st, alice.Caller, c.target, "bob", time.Hour, c.good)
		if err != nil {
			t.Errorf("%s with %s: %v", c.typ, c.good, err)
			continue
		}
		if out.Grant.ResourceType != c.typ {
			t.Errorf("%+v resolved to %s, want %s", c.target, out.Grant.ResourceType, c.typ)
		}
	}
}
