package recovery_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/backupcrypt"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/recovery"
	"fga/internal/sources"
)

func sourceRecord(t *testing.T, id, label string) sources.Definition {
	t.Helper()
	d, err := sources.Parse([]byte(`{"format":"fga.source/v1","id":"` + id + `","owner":"team-greenhouse",
	 "key":{"mode":"fixed","prefix":"station"},
	 "groups":[{"name":"climate","label":"` + label + `","fields":["/temperature"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestRestoreKeepsSourceReviews covers ING-008: after a restore, reconcile
// makes each source's last reviewed version active again, written from
// the journal when the backup lacks it, and keeps a source disabled after
// the backup disabled; a source added after the backup stays unknown.
func TestRestoreKeepsSourceReviews(t *testing.T) {
	st := r1test.New(t)
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	root, rita := adminops.Who{Actor: "root", Via: "test"}, adminops.Who{Actor: "rita", Via: "test"}
	if err := ops.PutIdentity(ctx, root, r1test.Tenant, "team-greenhouse", nil, nil); err != nil {
		t.Fatal(err)
	}
	addAndReview := func(id string) {
		t.Helper()
		v, err := ops.AddSource(ctx, root, r1test.Tenant, catalog.Bucket{Name: id, Project: "greenhouse", Label: "internal", Encryption: "server"},
			sourceRecord(t, id, "internal"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ops.ReviewSource(ctx, rita, r1test.Tenant, id, v.Version, v.Digest); err != nil {
			t.Fatal(err)
		}
	}
	addAndReview("climate")
	addAndReview("orchard")
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, backupKey(t), backupcrypt.Scheme); err != nil {
		t.Fatal(err)
	}

	// After the backup: climate's group becomes confidential in a reviewed
	// version 2, orchard is disabled, and late is added.
	v2, err := ops.PutSource(ctx, root, r1test.Tenant, sourceRecord(t, "climate", "confidential"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ReviewSource(ctx, rita, r1test.Tenant, "climate", v2.Version, v2.Digest); err != nil {
		t.Fatal(err)
	}
	if err := ops.DisableSource(ctx, root, r1test.Tenant, "orchard"); err != nil {
		t.Fatal(err)
	}
	addAndReview("late")

	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, backupKey(t)); err != nil {
		t.Fatal(err)
	}
	if src, err := st.Catalog.Source(ctx, r1test.Tenant, "climate"); err != nil || src.Active.Version != 1 || src.Draft != nil {
		t.Fatalf("after the restore %+v %v; the test needs the backup's state", src, err)
	}
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	climate, err := st.Catalog.Source(ctx, r1test.Tenant, "climate")
	if err != nil || climate.Active == nil || climate.Active.Version != 2 || climate.Active.Digest != v2.Digest ||
		string(climate.Active.Definition) != string(v2.Definition) || climate.Active.Reviewer != "rita" {
		t.Fatalf("climate after reconcile %+v %v", climate, err)
	}
	if def, err := sources.Parse(climate.Active.Definition); err != nil || def.Groups[0].Label != "confidential" {
		t.Fatalf("climate's active record %+v %v", def, err)
	}
	if orchard, err := st.Catalog.Source(ctx, r1test.Tenant, "orchard"); err != nil || !orchard.Disabled {
		t.Fatalf("orchard after reconcile %+v %v", orchard, err)
	}
	if _, err := st.Catalog.Source(ctx, r1test.Tenant, "late"); !errors.Is(err, catalog.ErrNoRow) {
		t.Fatalf("a source added after the backup: %v", err)
	}
}
