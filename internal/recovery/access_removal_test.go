package recovery_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/audit"
	"fga/internal/backupcrypt"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

// TestRestoreKeepsTheLastRecordedState covers review v5 F01: reconcile
// gives each identity the roles and attributes its last journaled change
// left, in journal order. Inferring the effect of a change from what it
// removed was wrong under deny rules: adding contractor, which the example
// policy denies reading, takes access away, and removing it gives access.
// Capabilities taken away after the backup stay taken away.
func TestRestoreKeepsTheLastRecordedState(t *testing.T) {
	st := r1test.New(t)
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	who := adminops.Who{Actor: "root", Via: "test"}
	put := func(id string, roles []string, attrs map[string]any) {
		t.Helper()
		if err := ops.PutIdentity(ctx, who, r1test.Tenant, id, roles, attrs); err != nil {
			t.Fatal(err)
		}
	}
	put("lena", []string{"member", "lead"}, map[string]any{"projects": []any{"p1", "p2"}})
	if err := ops.Grant(ctx, who, r1test.Tenant, "lena", adminops.Presets["approver"]); err != nil {
		t.Fatal(err)
	}
	put("carl", []string{"member"}, nil)
	// dana loses contractor and is given it back, both before the backup.
	put("dana", []string{"member", "contractor"}, nil)
	put("dana", []string{"member"}, nil)
	put("dana", []string{"member", "contractor"}, nil)
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}

	// After the backup: lena loses lead and project p2 and becomes an
	// auditor, and approving objects is revoked; carl becomes a contractor.
	put("lena", []string{"member", "auditor"}, map[string]any{"projects": []any{"p1"}})
	if held, err := ops.Revoke(ctx, who, r1test.Tenant, "lena", map[string][]string{"storage.object": {"approve"}}); err != nil || !held {
		t.Fatalf("revoke = %v, %v", held, err)
	}
	put("carl", []string{"member", "contractor"}, nil)
	// erin is created after the backup; the restore leaves erin unknown.
	put("erin", []string{"member"}, nil)
	put("erin", []string{"member", "lead"}, nil)

	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if got := identityOf(t, st, "lena"); !slices.Contains(got.Roles, "lead") || !slices.Contains(got.Capabilities["storage.object"], "approve") {
		t.Fatalf("after the restore %+v; the test needs the backup's state", got)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][]string{"lena": {"member", "auditor"}, "carl": {"member", "contractor"}, "dana": {"member", "contractor"}} {
		if got := identityOf(t, st, id).Roles; !reflect.DeepEqual(got, want) {
			t.Errorf("%s's roles after reconcile = %v, want %v, the last recorded", id, got, want)
		}
	}
	ids, err := st.Catalog.ListIdentities(ctx, r1test.Tenant, "", 100)
	if err != nil || slices.ContainsFunc(ids, func(r catalog.IdentityRecord) bool { return r.ID == "erin" }) {
		t.Errorf("after reconcile erin, created after the backup, is known (%v)", err)
	}
	got := identityOf(t, st, "lena")
	if !reflect.DeepEqual(got.Attributes["projects"], []any{"p1"}) {
		t.Errorf("projects after reconcile = %v", got.Attributes["projects"])
	}
	if slices.Contains(got.Capabilities["storage.object"], "approve") || !slices.Contains(got.Capabilities["storage.bucket"], "approve") {
		t.Errorf("capabilities after reconcile = %v", got.Capabilities)
	}
}

// TestRefusedChangesAreNotReplayed covers audit F2: disabling an unknown
// identity or revoking an unknown delegation is refused without a journal
// entry, and disabling an identity twice journals it once. Otherwise a
// restore would disable an identity created after the refusal.
func TestRefusedChangesAreNotReplayed(t *testing.T) {
	st := r1test.New(t)
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	who := adminops.Who{Actor: "root", Via: "test"}
	entries := func() int {
		t.Helper()
		es, err := st.Journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		return len(es)
	}
	before := entries()
	if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "eve", false); !errors.Is(err, catalog.ErrNoRow) {
		t.Fatalf("disable an unknown identity: %v", err)
	}
	if err := ops.RevokeDelegation(ctx, who, r1test.Tenant, "dlg-none"); !errors.Is(err, catalog.ErrNoRow) {
		t.Fatalf("revoke an unknown delegation: %v", err)
	}
	if n := entries(); n != before {
		t.Fatalf("refused changes journaled %d entries", n-before)
	}
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "carl", []string{"member"}, nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "carl", false); err != nil {
			t.Fatal(err)
		}
	}
	if n := entries(); n != before+1 {
		t.Fatalf("disabling twice journaled %d entries, want 1", n-before)
	}

	// eve is created after the refused disable, and is in the backup.
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "eve", []string{"member"}, nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	if eve := identityOf(t, st, "eve"); eve.Disabled {
		t.Fatal("the restore disabled eve, created after a refused disable")
	}
}

// TestFailedChangesAreNotReplayed covers review F1 of 2 November 2026: an
// identity change is journaled before its transaction commits, so a change
// that then fails, here on a full audit outbox, leaves its entry. The
// identity's committed state is journaled after it, so a restore does not
// give the identity roles it never had.
func TestFailedChangesAreNotReplayed(t *testing.T) {
	st := r1test.New(t)
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	who := adminops.Who{Actor: "root", Via: "test"}
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "lena", []string{"member", "lead"}, nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "lena", []string{"member"}, nil); err != nil {
		t.Fatal(err)
	}
	full := ops
	full.Store = catalog.New(st.Pool, 1)
	if err := full.PutIdentity(ctx, who, r1test.Tenant, "lena", []string{"member", "admin"}, nil); !errors.Is(err, audit.ErrFull) {
		t.Fatalf("a change on a full outbox: %v", err)
	}
	if got := identityOf(t, st, "lena").Roles; !slices.Equal(got, []string{"member"}) {
		t.Fatalf("lena's roles after the failed change = %v", got)
	}
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	if got := identityOf(t, st, "lena").Roles; !slices.Equal(got, []string{"member"}) {
		t.Fatalf("lena's roles after reconcile = %v, want [member], the last committed", got)
	}
}

func identityOf(t *testing.T, st *r1test.Stack, id string) catalog.IdentityRecord {
	t.Helper()
	ids, err := st.Catalog.ListIdentities(ctx, r1test.Tenant, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range ids {
		if rec.ID == id {
			return rec
		}
	}
	t.Fatalf("%s is missing", id)
	return catalog.IdentityRecord{}
}
