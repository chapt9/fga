package recovery_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/backupcrypt"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

// TestRestoreKeepsAccessRemoval covers review AMB-1: roles, attribute
// values and capabilities an administrator took away after a backup stay
// taken away once the restored catalog is reconciled, and access granted
// after the backup is not brought back by the replay.
func TestRestoreKeepsAccessRemoval(t *testing.T) {
	st := r1test.New(t)
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	who := adminops.Who{Actor: "root", Via: "test"}
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "lena", []string{"member", "lead"}, map[string]any{"projects": []any{"p1", "p2"}}); err != nil {
		t.Fatal(err)
	}
	if err := ops.Grant(ctx, who, r1test.Tenant, "lena", adminops.Presets["approver"]); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}

	// After the backup: lead and project p2 are taken away and auditor is
	// added; approving objects is revoked.
	if err := ops.PutIdentity(ctx, who, r1test.Tenant, "lena", []string{"member", "auditor"}, map[string]any{"projects": []any{"p1"}}); err != nil {
		t.Fatal(err)
	}
	if held, err := ops.Revoke(ctx, who, r1test.Tenant, "lena", map[string][]string{"storage.object": {"approve"}}); err != nil || !held {
		t.Fatalf("revoke = %v, %v", held, err)
	}

	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	lena := func() catalog.IdentityRecord {
		ids, err := st.Catalog.ListIdentities(ctx, r1test.Tenant, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if id.ID == "lena" {
				return id
			}
		}
		t.Fatal("lena is missing")
		return catalog.IdentityRecord{}
	}
	if got := lena(); !slices.Contains(got.Roles, "lead") || !slices.Contains(got.Capabilities["storage.object"], "approve") {
		t.Fatalf("after the restore %+v; the test needs the backup's state", got)
	}
	rep, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal)
	if err != nil || rep.Replayed != 2 {
		t.Fatalf("reconcile = %+v, %v", rep, err)
	}
	got := lena()
	if !reflect.DeepEqual(got.Roles, []string{"member"}) {
		t.Fatalf("roles after reconcile = %v, want lead removed and auditor, added after the backup, not restored", got.Roles)
	}
	if !reflect.DeepEqual(got.Attributes["projects"], []any{"p1"}) {
		t.Fatalf("projects after reconcile = %v", got.Attributes["projects"])
	}
	if slices.Contains(got.Capabilities["storage.object"], "approve") || !slices.Contains(got.Capabilities["storage.bucket"], "approve") {
		t.Fatalf("capabilities after reconcile = %v", got.Capabilities)
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
	if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "eve"); !errors.Is(err, catalog.ErrNoRow) {
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
		if err := ops.DisableIdentity(ctx, who, r1test.Tenant, "carl"); err != nil {
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
