package adminops

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/jsonunits"
	"fga/internal/r1test"
	"fga/internal/sources"
)

const sourceRecord = `{"format":"fga.source/v1","id":"greenhouse-climate","owner":"team-greenhouse",
 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/humidity","/sensor"]},
           {"name":"location","label":"restricted","fields":["/gps"]}]}`

func record(t *testing.T, edit func(*sources.Definition)) sources.Definition {
	t.Helper()
	d, err := sources.Parse([]byte(sourceRecord))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&d)
	}
	return d
}

func outcomes(t *testing.T, st *r1test.Stack) []string {
	t.Helper()
	events, err := st.Catalog.RecentEvents(context.Background(), r1test.Tenant, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range slices.Backward(events) {
		if strings.HasPrefix(e.Outcome, "source.") {
			out = append(out, e.Outcome+" by "+e.Actor)
		}
	}
	return out
}

// TestSources covers ING-001, ING-006, ING-008 and D-G through the
// administrative operations: a record is checked against the bucket's
// mode, the tenant's identities and the active label order when it is
// added, put and reviewed; another administrator reviews, naming the
// draft's version and digest, except at the local administrator's tool;
// a review and a disable are journaled; every change is audited.
func TestSources(t *testing.T) {
	st := r1test.New(t)
	ctx := context.Background()
	ops := Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil }, Now: func() time.Time { return *st.Clock }}
	root, rita := Who{Actor: "root", Via: "test"}, Who{Actor: "rita", Via: "test"}
	for _, id := range []string{"team-greenhouse", "lena", "facility-1"} {
		if err := ops.PutIdentity(ctx, root, r1test.Tenant, id, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	bucket := catalog.Bucket{Name: "greenhouse-climate", Project: "greenhouse", Label: "internal", Encryption: "server"}

	for name, c := range map[string]struct {
		bucket catalog.Bucket
		def    sources.Definition
	}{
		"an unknown owner": {bucket, record(t, func(d *sources.Definition) { d.Owner = "nobody" })},
		"a label below the bucket's": {catalog.Bucket{Name: "greenhouse-climate", Project: "greenhouse", Label: "confidential", Encryption: "server"},
			record(t, nil)},
		"a label not in the order":  {bucket, record(t, func(d *sources.Definition) { d.Groups[0].Label = "secret" })},
		"recipients in server mode": {bucket, record(t, func(d *sources.Definition) { d.Groups[0].Recipients = []string{"lena"} })},
		"a bad bucket name":         {catalog.Bucket{Name: "GH", Label: "internal", Encryption: "server"}, record(t, nil)},
		"an unknown recipient": {catalog.Bucket{Name: "greenhouse-climate", Label: "internal", Encryption: "client"},
			record(t, func(d *sources.Definition) {
				d.Groups[0].Recipients, d.Groups[1].Recipients = []string{"lena"}, []string{"ghost"}
			})},
	} {
		if _, err := ops.AddSource(ctx, root, r1test.Tenant, c.bucket, c.def); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if list, _ := st.Catalog.ListSources(ctx, r1test.Tenant, "", 10); len(list) != 0 {
		t.Fatalf("a refused source was stored: %+v", list)
	}

	v1, err := ops.AddSource(ctx, root, r1test.Tenant, bucket, record(t, nil))
	if err != nil || v1.Version != 1 || v1.State != "DRAFT" {
		t.Fatalf("add = %+v, %v", v1, err)
	}
	if _, err := ops.AddSource(ctx, root, r1test.Tenant, bucket, record(t, nil)); err == nil {
		t.Fatal("a source was added twice")
	}

	// Trying a sample stores nothing and names the refused field.
	r, err := ops.TrySource(ctx, r1test.Tenant, "greenhouse-climate", 0, []byte(`{"sensor":"gh-north-1","temperature":21.5}`), "")
	if err != nil || r.Key != "sensor/gh-north-1" || len(r.Units) != 2 {
		t.Fatalf("try = %+v, %v", r, err)
	}
	var refused *jsonunits.ReadingError
	if _, err := ops.TrySource(ctx, r1test.Tenant, "greenhouse-climate", 0, []byte(`{"sensor":"a","pin":"1234"}`), ""); !errors.As(err, &refused) ||
		refused.Pointer != "/pin" {
		t.Fatalf("try an unlisted member: %v", err)
	}

	entries := func() []string {
		t.Helper()
		es, err := st.Journal.Entries()
		if err != nil {
			t.Fatal(err)
		}
		var kinds []string
		for _, e := range es {
			if strings.HasPrefix(e.Kind, "source-") {
				kinds = append(kinds, e.Kind)
			}
		}
		return kinds
	}
	if _, err := ops.ReviewSource(ctx, root, r1test.Tenant, "greenhouse-climate", 1, v1.Digest); !errors.Is(err, catalog.ErrSelfReview) {
		t.Fatalf("the author reviews: %v", err)
	}
	if _, err := ops.ReviewSource(ctx, rita, r1test.Tenant, "greenhouse-climate", 1, "0000"); !errors.Is(err, catalog.ErrSourceConflict) {
		t.Fatalf("another digest: %v", err)
	}
	if got := entries(); len(got) != 0 {
		t.Fatalf("refused reviews journaled %v", got)
	}
	if v, err := ops.ReviewSource(ctx, rita, r1test.Tenant, "greenhouse-climate", 1, v1.Digest); err != nil || v.State != "ACTIVE" {
		t.Fatalf("review = %+v, %v", v, err)
	}

	// A draft rita wrote is reviewed by root; the local administrator's
	// tool may review its own.
	v2, err := ops.PutSource(ctx, rita, r1test.Tenant, record(t, func(d *sources.Definition) { d.Groups[1].Label = "confidential" }))
	if err != nil || v2.Version != 2 {
		t.Fatalf("put = %+v, %v", v2, err)
	}
	if _, err := ops.ReviewSource(ctx, root, r1test.Tenant, "greenhouse-climate", 2, v2.Digest); err != nil {
		t.Fatal(err)
	}
	cli := ops
	cli.AllowSelfReview = true
	operator := Who{Actor: "operator", Via: "cli"}
	v3, err := cli.PutSource(ctx, operator, r1test.Tenant, record(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.ReviewSource(ctx, operator, r1test.Tenant, "greenhouse-climate", 3, v3.Digest); err != nil {
		t.Fatal(err)
	}

	// A draft is checked again at review: its owner was disabled since.
	v4, err := ops.PutSource(ctx, root, r1test.Tenant, record(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.DisableIdentity(ctx, root, r1test.Tenant, "team-greenhouse", false); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ReviewSource(ctx, rita, r1test.Tenant, "greenhouse-climate", 4, v4.Digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a review after the owner's disable: %v", err)
	}

	if err := ops.DisableSource(ctx, rita, r1test.Tenant, "greenhouse-climate"); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.PutSource(ctx, root, r1test.Tenant, record(t, func(d *sources.Definition) { d.Owner = "lena" })); !errors.Is(err, catalog.ErrSourceDisabled) {
		t.Fatalf("a draft for a disabled source: %v", err)
	}
	if got, want := entries(), []string{"source-set", "source-set", "source-set", "source-disabled"}; !slices.Equal(got, want) {
		t.Fatalf("journal %v, want %v", got, want)
	}
	want := []string{"source.add by root", "source.review by rita", "source.put by rita", "source.review by root",
		"source.put by operator", "source.review by operator", "source.put by root", "source.disable by rita"}
	if got := outcomes(t, st); !slices.Equal(got, want) {
		t.Fatalf("audit\n got %v\nwant %v", got, want)
	}

	// A client-mode source names enabled recipients for every group.
	clientBucket := catalog.Bucket{Name: "greenhouse-private", Project: "greenhouse", Label: "internal", Encryption: "client"}
	if err := ops.PutIdentity(ctx, root, r1test.Tenant, "team-2", nil, nil); err != nil {
		t.Fatal(err)
	}
	client := record(t, func(d *sources.Definition) {
		d.ID, d.Owner = "greenhouse-private", "team-2"
		d.Groups[0].Recipients, d.Groups[1].Recipients = []string{"lena"}, []string{"facility-1", "lena"}
	})
	if _, err := ops.AddSource(ctx, root, r1test.Tenant, clientBucket, client); err != nil {
		t.Fatal(err)
	}
	src, err := st.Catalog.Source(ctx, r1test.Tenant, "greenhouse-private")
	if err != nil || src.Encryption != "client" || src.Draft == nil {
		t.Fatalf("client source %+v %v", src, err)
	}
}
