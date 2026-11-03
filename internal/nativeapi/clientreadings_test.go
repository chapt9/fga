package nativeapi_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/admission"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/sources"
	"fga/sdk/go/client"
	"fga/sdk/go/crypto"
)

// TestClientReadingsHTTP covers client-mode readings end to end with the
// SDK (ING-009 to ING-011): a posting system splits and encrypts a reading,
// each group's recipients open exactly their groups, a member who is no
// recipient gets nothing, and fga holds no value. The envelopes must be for
// exactly the active keys of each group's recipients, a key the posting
// system did not pin is refused on the client, and a recipient whom policy
// refuses refuses the post.
func TestClientReadingsHTTP(t *testing.T) {
	d, _, lena, alice, bob, sensor := privateReadings(t, nil)
	ctx := context.Background()
	st := d.st
	poster := d.client(t, sensor)
	post := func(src, id, idem string) error {
		_, err := poster.PostReading(ctx, src, []byte(`{"sensor":"`+id+`","temperature":21.7351,"humidity":58.4127}`), "", idem)
		return err
	}
	if err := post("greenhouse-private", "gh-p1", "r-1"); err != nil {
		t.Fatal(err)
	}
	read := func(c *r1test.Client) (string, error) {
		var b bytes.Buffer
		_, err := d.client(t, c).GetDocument(ctx, "greenhouse-private", "sensor/gh-p1", "", &b)
		return b.String(), err
	}
	if text, err := read(lena); err != nil || !strings.Contains(text, "21.7351") || !strings.Contains(text, "58.4127") {
		t.Fatalf("the owner, a recipient of both groups, reads %q, %v", text, err)
	}
	if text, err := read(alice); err != nil || !strings.Contains(text, "21.7351") || strings.Contains(text, "58.4127") {
		t.Fatalf("a recipient of temperature only reads %q, %v", text, err)
	}
	if text, err := read(bob); err == nil || strings.Contains(text, "21.7351") {
		t.Fatalf("a member who is no recipient reads %q, %v", text, err)
	}

	// fga holds no value: not in the catalog, the blobs or the journal.
	for _, value := range []string{"21.7351", "58.4127"} {
		rows, err := st.Pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()`)
		if err != nil {
			t.Fatal(err)
		}
		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			tables = append(tables, name)
		}
		rows.Close()
		for _, table := range tables {
			if n := st.Count(`SELECT count(*) FROM "`+table+`" x WHERE x::text LIKE $1`, "%"+value+"%"); n != 0 {
				t.Errorf("table %s holds the value %s", table, value)
			}
		}
		for _, dir := range []string{st.BlobDir, st.JournalDir} {
			if err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
				if err != nil || e.IsDir() {
					return err
				}
				b, err := os.ReadFile(path)
				if err == nil && bytes.Contains(b, []byte(value)) {
					t.Errorf("%s holds the value %s", path, value)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A recipient's key that arrives after the layout was read, here at the
	// begin, is missing from the envelopes: the post is refused, and posting
	// again with the new layout is refused on the client until the key is
	// pinned.
	key, err := crypto.NewRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	st.AfterDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpReadingBeginVersion {
			st.AfterDecide = nil
			if fp, _, err = st.Catalog.AddRecipientKey(ctx, r1test.Tenant, "alice", key.PublicKey()); err != nil {
				t.Error(err)
			}
		}
	}
	var refused *client.Error
	if err := post("greenhouse-private", "gh-p1", "r-2"); !errors.As(err, &refused) || refused.Status != http.StatusConflict {
		t.Fatalf("envelopes missing a recipient's active key: %v", err)
	}
	if err := post("greenhouse-private", "gh-p1", "r-3"); !errors.Is(err, crypto.ErrUntrusted) {
		t.Fatalf("a recipient key the posting system did not pin: %v", err)
	}
	// A key revoked after the layout was read is one too many.
	sensor.Trust.Recipients[mustDigest(t, fp)] = key.PublicKey()
	st.AfterDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpReadingBeginVersion {
			st.AfterDecide = nil
			if err := st.Catalog.RevokeRecipientKey(ctx, r1test.Tenant, fp); err != nil {
				t.Error(err)
			}
		}
	}
	if err := post("greenhouse-private", "gh-p1", "r-4"); err == nil {
		t.Fatal("envelopes for a revoked key were accepted")
	}
	if err := post("greenhouse-private", "gh-p1", "r-5"); err != nil {
		t.Fatalf("a post with the current layout: %v", err)
	}

	// A recipient whom policy refuses, here a member of another project,
	// refuses the post: nobody silently misses a reading.
	if err := post("orchard-private", "or-1", "o-1"); err == nil {
		t.Fatal("a reading was published with a recipient that policy refuses")
	}
	if n := st.Count(`SELECT count(*) FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
	                   WHERE b.name = 'orchard-private' AND o.current_document_version IS NOT NULL`); n != 0 {
		t.Fatalf("the refused reading left %d published documents", n)
	}
}

// privateReadings deploys two client-mode sources posted by sensor-7, in
// project greenhouse: greenhouse-private, whose temperature group lena and
// alice receive and whose restricted humidity group lena only, and
// orchard-private, which names carl of another project. extra adds rules
// by policy file.
func privateReadings(t *testing.T, extra map[string]string) (d *deployment, ops adminops.Ops, lena, alice, bob, sensor *r1test.Client) {
	t.Helper()
	policies := maps.Clone(r1test.Policies)
	own := `has(resource.attributes.source) && has(principal.attributes.sources) && resource.attributes.source in principal.attributes.sources`
	rules := map[string]string{
		"buckets.json":   `{"id":"sources-post-readings","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"` + own + `"}`,
		"objects.json":   `{"id":"sources-post-reading-versions","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"` + own + `"}`,
		"documents.json": `{"id":"sources-share-readings","effect":"allow","actions":["share"],"roles":["source"],"when":"` + own + `"}`,
		"units.json":     `{"id":"sources-share-reading-units","effect":"allow","actions":["share"],"roles":["source"],"when":"` + own + `"}`,
	}
	for _, m := range []map[string]string{rules, extra} {
		for file, rule := range m {
			policies[file] = strings.Replace(policies[file], `"rules":[`, `"rules":[`+rule+",", 1)
		}
	}
	d = deployFull(t, admission.DefaultLimits, r1test.Options{Policies: policies})
	ctx := context.Background()
	st := d.st
	lena = st.Client("lena", []string{"member"}, "greenhouse")
	alice = st.Client("alice", []string{"member"}, "greenhouse")
	bob = st.Client("bob", []string{"member"}, "greenhouse")
	carl := st.Client("carl", []string{"member"}, "orchards")
	sensor = st.Client("sensor-7", []string{"source"})
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "sensor-7", []string{"source"},
		map[string]any{"sources": []string{"greenhouse-private", "orchard-private"}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*r1test.Client{lena, alice, carl} {
		sensor.Pin(c)
		c.Pin(sensor)
	}
	bob.Pin(sensor)
	ops = adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	source := func(id, project, groups string) {
		t.Helper()
		def, err := sources.Parse([]byte(`{"format":"fga.source/v1","id":"` + id + `","owner":"lena",
		 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},"groups":[` + groups + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		v, err := ops.AddSource(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant,
			catalog.Bucket{Name: id, Project: project, Label: "internal", Encryption: "client"}, def)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ops.ReviewSource(ctx, adminops.Who{Actor: "rita", Via: "test"}, r1test.Tenant, id, v.Version, v.Digest); err != nil {
			t.Fatal(err)
		}
	}
	source("greenhouse-private", "greenhouse", `{"name":"temperature","label":"internal","fields":["/sensor","/temperature"],"recipients":["lena","alice"]},
	 {"name":"humidity","label":"restricted","fields":["/humidity"],"recipients":["lena"]}`)
	source("orchard-private", "greenhouse", `{"name":"all","label":"internal","fields":["/sensor","/temperature"],"recipients":["lena","carl"]}`)
	return d, ops, lena, alice, bob, sensor
}

func mustDigest(t *testing.T, s string) cryptowire.Digest {
	t.Helper()
	d, err := cryptowire.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
