package adminops

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"fga/internal/catalog"
	"fga/internal/delegation"
	"fga/internal/journal"
	"fga/internal/r1test"
)

func TestCapabilities(t *testing.T) {
	got, err := Capabilities("approver", nil)
	if err != nil || !reflect.DeepEqual(got["storage.object"], []string{"approve"}) {
		t.Fatalf("approver = %v, %v", got, err)
	}
	got["storage.object"] = nil
	if Presets["approver"]["storage.object"] == nil {
		t.Fatal("a caller changed the preset")
	}
	if _, err := Capabilities("", map[string][]string{"storage.object": {"read", "stat"}}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		preset  string
		actions map[string][]string
	}{
		"nothing":            {},
		"both":               {"storage", map[string][]string{"storage.object": {"read"}}},
		"an unknown preset":  {preset: "everything"},
		"an unknown type":    {actions: map[string][]string{"storage.vault": {"read"}}},
		"an unknown action":  {actions: map[string][]string{"storage.object": {"fly"}}},
		"a type, no actions": {actions: map[string][]string{"storage.object": {}}},
	} {
		if _, err := Capabilities(c.preset, c.actions); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseGrants(t *testing.T) {
	got, err := ParseGrants("storage.object:read, stat; agent.tool:*")
	want := []delegation.Grant{{ResourceType: "agent.tool", Actions: []string{"*"}}, {ResourceType: "storage.object", Actions: []string{"read", "stat"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("grants = %+v, %v", got, err)
	}
	// A type given without actions, or an unknown one, is refused even
	// beside a valid part, never dropped (audit F7).
	for _, bad := range []string{"", "storage.object", "storage.object:", "storage.vault:read", "storage.object:fly",
		"storage.object:read;storage.bucket:", "storage.object:read;bogus:", "bogus:"} {
		if _, err := ParseGrants(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestCheckID(t *testing.T) {
	for _, ok := range []string{"alice", "agent-7", "auth0|5f8a", "user@example.com", "00u1ab2C3D"} {
		if err := checkID("identity", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a/b", "tab\there", string(make([]byte, 257))} {
		if err := checkID("identity", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestDisableAndRevokeLockTheTargetFirst covers audit F1: a disable or a
// delegation revoke locks its target before it takes the journal's state,
// as a role change and the authority fence do. Here another transaction
// holds the target, then needs the journal's state; with the opposite
// order the two deadlock.
func TestDisableAndRevokeLockTheTargetFirst(t *testing.T) {
	st := r1test.New(t)
	ctx := context.Background()
	ops := Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil }, Now: func() time.Time { return *st.Clock }}
	who := Who{Actor: "root", Via: "test"}
	for _, id := range []string{"ann", "ben"} {
		if err := ops.PutIdentity(ctx, who, r1test.Tenant, id, []string{"member", "lead"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// A journaled change commits the journal's state row.
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "ann", []string{"member"}, nil); err != nil {
		t.Fatal(err)
	}
	d := delegation.Delegation{ID: "dlg-1", Tenant: r1test.Tenant, Actor: "ben", Subject: "ann", Audience: "fga-storage",
		Grants: []delegation.Grant{{ResourceType: "storage.object", Actions: []string{"read"}}}, ExpiresAt: st.Clock.Add(time.Hour)}
	if err := ops.AddDelegation(ctx, who, d); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		lock   string
		change func() error
	}{
		"disable": {`SELECT 1 FROM identities WHERE tenant = $1 AND id = 'ann' FOR UPDATE`,
			func() error { return ops.DisableIdentity(ctx, who, r1test.Tenant, "ann", false) }},
		"revoke a delegation": {`SELECT 1 FROM delegations WHERE tenant = $1 AND id = 'dlg-1' FOR UPDATE`,
			func() error { return ops.RevokeDelegation(ctx, who, r1test.Tenant, "dlg-1") }},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := st.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var pid int
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, c.lock, r1test.Tenant); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.change() }()
			for waited := 0; ; waited++ {
				var blocked int
				if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, pid).
					Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked > 0 {
					break
				}
				if waited == 500 {
					t.Fatal("the change never waited for the target")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM journal_state WHERE id = 1 FOR UPDATE`); err != nil {
				t.Fatalf("the other transaction: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("the change: %v", err)
			}
		})
	}
}

// TestDisableNeedsConfirmation covers the owner's safeguard of 1 November
// 2026 (safeguard 2): disabling the only person who can open some
// client-mode files is refused, with the number of such files per bucket
// and no file names, until it is confirmed; nothing is journaled or
// changed by the refusal. A person whose files others can open too is
// disabled at once, and then those others may become last readers.
func TestDisableNeedsConfirmation(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	st.Bucket("other", "p1")
	ctx := context.Background()
	ops := Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil }, Now: func() time.Time { return *st.Clock }}
	who := Who{Actor: "root", Via: "test"}
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	for key, to := range map[string][]*r1test.Client{"solo.bin": {alice}, "shared.bin": {alice, bob}} {
		if _, err := alice.Put("reports", key, []byte(key), to...); err != nil {
			t.Fatal(err)
		}
	}
	up, err := alice.PrepareDocument("other", "notes.md", []string{"one", "two"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	unreadable := func(principal, fingerprint string) []catalog.Unreadable {
		t.Helper()
		u, err := catalog.LastReaders(ctx, st.Pool, r1test.Tenant, principal, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	want := []catalog.Unreadable{{Bucket: "other", Files: 1}, {Bucket: "reports", Files: 1}}
	if got := unreadable("alice", ""); !reflect.DeepEqual(got, want) {
		t.Fatalf("alice is the last reader of %+v, want %+v", got, want)
	}
	if got := unreadable("", alice.Recipient.Fingerprint().String()); !reflect.DeepEqual(got, want) {
		t.Fatalf("alice's key is the last reader of %+v, want %+v", got, want)
	}
	if got := unreadable("bob", ""); len(got) != 0 {
		t.Fatalf("bob is the last reader of %+v", got)
	}

	entries := func() int {
		t.Helper()
		es, err := st.Journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		return len(es)
	}
	before := entries()
	err = ops.DisableIdentity(ctx, who, r1test.Tenant, "alice", false)
	var last *catalog.LastReaderError
	if !errors.As(err, &last) || !reflect.DeepEqual(last.Unreadable, want) || strings.Contains(err.Error(), "solo") || strings.Contains(err.Error(), "notes") {
		t.Fatalf("disabling the last reader: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM identities WHERE id = 'alice' AND disabled`); n != 0 || entries() != before {
		t.Fatal("a refused disable changed something")
	}
	if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "bob", false); err != nil {
		t.Fatalf("disabling a reader others can stand in for: %v", err)
	}
	if got := unreadable("alice", ""); !reflect.DeepEqual(got, []catalog.Unreadable{{Bucket: "other", Files: 1}, {Bucket: "reports", Files: 2}}) {
		t.Fatalf("with bob disabled, alice is the last reader of %+v", got)
	}
	if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "alice", true); err != nil {
		t.Fatalf("a confirmed disable: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM identities WHERE id = 'alice' AND disabled`); n != 1 {
		t.Fatal("the confirmed disable did not disable alice")
	}
}
