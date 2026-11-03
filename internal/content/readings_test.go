package content_test

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/sources"
	"fga/sdk/go/crypto"
)

// readingPolicies are the fixture's policies with the example bundle's
// rules for posting systems and a rule letting facility staff read the
// location group of their projects' readings.
func readingPolicies() map[string]string {
	policies := maps.Clone(r1test.Policies)
	add := func(file, rule string) {
		policies[file] = strings.Replace(policies[file], `"rules":[`, `"rules":[`+rule+",", 1)
	}
	own := `has(resource.attributes.source) && has(principal.attributes.sources) && resource.attributes.source in principal.attributes.sources`
	add("buckets.json", `{"id":"sources-post-readings","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"`+own+`"}`)
	add("objects.json", `{"id":"sources-post-reading-versions","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"`+own+`"}`)
	add("units.json", `{"id":"facility-reads-location","effect":"allow","actions":["read"],"roles":["facility"],
	  "when":"has(resource.attributes.group) && resource.attributes.group == 'location' && resource.attributes.project in principal.attributes.projects"}`)
	return policies
}

const climateRecord = `{"format":"fga.source/v1","id":"%s","owner":"team-greenhouse",
 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/humidity","/sensor"]},
           {"name":"location","label":"restricted","fields":["/gps"]}]}`

type readings struct {
	st     *r1test.Stack
	ops    adminops.Ops
	sensor content.Caller
}

// newReadings builds a stack with an owner, a posting system for the
// source greenhouse-climate, and that source added and reviewed.
func newReadings(t *testing.T) *readings {
	t.Helper()
	st := r1test.NewWith(t, r1test.Options{Policies: readingPolicies()})
	r := &readings{st: st, ops: adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}}
	st.User("team-greenhouse", []string{"member"}, "greenhouse")
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "sensor-7", []string{"source"},
		map[string]any{"sources": []string{"greenhouse-climate"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.GrantCapabilities(ctx, r1test.Tenant, "sensor-7", adminops.Presets["source"]); err != nil {
		t.Fatal(err)
	}
	r.sensor = st.Caller("sensor-7")
	r.source(t, "greenhouse-climate", true)
	return r
}

// source adds a server-mode source with its bucket and, if reviewed, makes
// its draft active.
func (r *readings) source(t *testing.T, id string, reviewed bool) {
	t.Helper()
	def, err := sources.Parse([]byte(strings.Replace(climateRecord, "%s", id, 1)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.ops.AddSource(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant,
		catalog.Bucket{Name: id, Project: "greenhouse", Label: "internal", Encryption: "server"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if reviewed {
		if _, err := r.ops.ReviewSource(ctx, adminops.Who{Actor: "rita", Via: "test"}, r1test.Tenant, id, v.Version, v.Digest); err != nil {
			t.Fatal(err)
		}
	}
}

func (r *readings) post(c content.Caller, source, idem, payload string) (content.ReadingPublished, error) {
	return r.st.Content.PutReading(ctx, c, content.ReadingRequest{Source: source, IdempotencyKey: idem}, []byte(payload))
}

func (r *readings) attributes(t *testing.T, sql string, args ...any) []map[string]any {
	t.Helper()
	rows, err := r.st.Pool.Query(ctx, sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var a map[string]any
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

const northReading = `{"sensor":"gh-north-1","temperature":21.5,"humidity":40,"gps":{"lat":48.1,"lon":11.5}}`

// TestSourceIngest covers ING-002 to ING-006 in server mode: a reading
// becomes a version of the document at the key its source derives, one
// unit per group with the group's label, attributes and manifest profile,
// owned by the source's owner; the posting system needs no label right;
// a retry under the same idempotency key is the same version, one with
// another reading is refused.
func TestSourceIngest(t *testing.T) {
	r := newReadings(t)
	p, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading)
	if err != nil || p.Key != "sensor/gh-north-1" || p.Units != 2 {
		t.Fatalf("post = %+v, %v", p, err)
	}
	doc := r.attributes(t, `SELECT r.attributes FROM objects o JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
	                        WHERE o.tenant = $1 AND o.key = 'sensor/gh-north-1' AND o.kind = 'document'`, r1test.Tenant)
	if len(doc) != 1 || doc[0]["owner"] != "team-greenhouse" || doc[0]["source"] != "greenhouse-climate" || doc[0]["source_version"] != nil {
		t.Fatalf("document attributes %v", doc)
	}
	version := r.attributes(t, `SELECT attributes FROM resources WHERE tenant = $1 AND id = $2`, r1test.Tenant, p.DocumentVersion)
	if len(version) != 1 || version[0]["source"] != "greenhouse-climate" || version[0]["source_version"] != 1.0 || version[0]["owner"] != "team-greenhouse" {
		t.Fatalf("version attributes %v", version)
	}
	units := r.attributes(t, `SELECT r.attributes FROM document_units u JOIN resources r ON r.tenant = u.tenant AND r.id = u.unit::text
	                          WHERE u.tenant = $1 AND u.document_version = $2 ORDER BY u.position`, r1test.Tenant, p.DocumentVersion)
	if len(units) != 2 || units[0]["group"] != "climate" || units[0]["label"] != "internal" || units[1]["group"] != "location" ||
		units[1]["label"] != "restricted" || units[1]["source"] != "greenhouse-climate" || units[1]["owner"] != "team-greenhouse" {
		t.Fatalf("unit attributes %v", units)
	}
	var norm, extraction string
	if err := r.st.Pool.QueryRow(ctx, `SELECT normalization_version, extraction_version FROM document_versions WHERE tenant = $1 AND id = $2`,
		r1test.Tenant, p.DocumentVersion).Scan(&norm, &extraction); err != nil || norm != "fga.json/groups-v1" ||
		extraction != "fga.source/v1:greenhouse-climate:1" {
		t.Fatalf("manifest versions %q %q %v", norm, extraction, err)
	}

	again, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading)
	if err != nil || again.DocumentVersion != p.DocumentVersion {
		t.Fatalf("a retry = %+v, %v", again, err)
	}
	if _, err := r.post(r.sensor, "greenhouse-climate", "r-1", `{"sensor":"gh-south-2","temperature":19}`); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("another reading under the same idempotency key: %v", err)
	}
	next, err := r.post(r.sensor, "greenhouse-climate", "r-2", `{"sensor":"gh-north-1","temperature":22}`)
	if err != nil || next.Document != p.Document || next.DocumentVersion == p.DocumentVersion || next.Generation != p.Generation+1 {
		t.Fatalf("the next reading = %+v, %v", next, err)
	}
}

// TestSourceGroupsSeparate covers the design's property P1: a group's
// values reach only callers allowed to read its unit, on every read
// route. Members of the project read the climate group and never the
// restricted location group; facility staff read both; the source's
// owner reads both; the posting system and members of other projects
// read nothing.
func TestSourceGroupsSeparate(t *testing.T) {
	r := newReadings(t)
	if _, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading); err != nil {
		t.Fatal(err)
	}
	st := r.st
	mia := st.User("mia", []string{"member"}, "greenhouse")
	fay := st.User("fay", []string{"member", "facility"}, "greenhouse")
	olaf := st.User("olaf", []string{"member"}, "orchards")
	owner := st.Caller("team-greenhouse")
	const bucket, key = "greenhouse-climate", "sensor/gh-north-1"
	all := st.UnitIDs(owner, bucket, key, "")
	if len(all) != 2 {
		t.Fatalf("the owner sees %v", all)
	}
	climate, location := all[0], all[1]
	visible := func(c content.Caller) []string {
		t.Helper()
		page, err := st.Content.ListUnits(ctx, c, bucket, key, "", 100, "")
		if err != nil {
			return nil
		}
		var ids []string
		for _, u := range page.Units {
			ids = append(ids, u.Unit)
		}
		return ids
	}
	for name, c := range map[string]struct {
		caller content.Caller
		want   []string
	}{
		"a member":          {mia, []string{climate}},
		"facility staff":    {fay, []string{climate, location}},
		"the owner":         {owner, []string{climate, location}},
		"the poster":        {r.sensor, nil},
		"another project's": {olaf, nil},
	} {
		if got := visible(c.caller); !slices.Equal(got, c.want) {
			t.Errorf("%s lists %v, want %v", name, got, c.want)
		}
	}
	text, err := readUnitPlain(st, mia, bucket, key, "", climate)
	if err != nil {
		t.Fatal(err)
	}
	var unit struct {
		Group  string         `json:"group"`
		Fields map[string]any `json:"fields"`
	}
	if err := json.Unmarshal([]byte(text), &unit); err != nil || unit.Group != "climate" || unit.Fields["/temperature"] != 21.5 ||
		unit.Fields["/gps"] != nil {
		t.Fatalf("the climate unit %q %v", text, err)
	}
	// Every route that would carry the location group refuses a member.
	if _, err := readUnitPlain(st, mia, bucket, key, "", location); err == nil {
		t.Error("a member read the location unit")
	}
	if _, err := st.Content.SelectUnits(ctx, mia, bucket, key, "", []string{climate, location}); err == nil {
		t.Error("a member selected the location unit")
	}
	if _, _, err := st.Content.Manifest(ctx, mia, bucket, key, ""); err == nil {
		t.Error("a member read the manifest of every unit")
	}
	if _, err := st.Content.ExportUnitsPlain(ctx, mia, bucket, key, "", []string{location}); err == nil {
		t.Error("a member exported the location unit")
	}
	if _, err := st.Content.ReadOriginalPlain(ctx, owner, bucket, key, ""); err == nil {
		t.Error("a reading has an original file")
	}
	if text, err := readUnitPlain(st, fay, bucket, key, "", location); err != nil || !strings.Contains(text, `"/gps":{"lat":48.1,"lon":11.5}`) {
		t.Fatalf("facility staff read the location unit: %q %v", text, err)
	}
}

// TestSourceIdentityLimits covers ING-002, ING-003 and ING-012: a posting
// system posts only to its own sources and uploads nothing, and nobody
// writes a source's bucket through another route, not even a member
// allowed to create objects in the bucket's project.
func TestSourceIdentityLimits(t *testing.T) {
	r := newReadings(t)
	r.source(t, "orchard", true)
	st := r.st
	if _, err := r.post(r.sensor, "orchard", "o-1", northReading); err == nil {
		t.Fatal("a system posted to a source it does not serve")
	}
	if n := st.Count(`SELECT count(*) FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket WHERE b.name = 'orchard'`); n != 0 {
		t.Fatalf("the refused reading left %d objects", n)
	}
	// The right to post is no right to upload: the decision refuses the
	// posting system before the bucket's source is looked at.
	if _, err := st.Content.PutDocumentText(ctx, r.sensor, content.TextRequest{Bucket: "greenhouse-climate", Key: "notes", IdempotencyKey: "t-sensor"},
		[]byte("a note")); !errors.Is(err, content.ErrNotFound) {
		t.Errorf("the posting system writes text into its source's bucket: %v", err)
	}
	mia := st.User("mia", []string{"member"}, "greenhouse")
	if _, err := st.Content.PutDocumentText(ctx, mia, content.TextRequest{Bucket: "greenhouse-climate", Key: "notes", IdempotencyKey: "t-mia"},
		[]byte("a note")); !errors.Is(err, content.ErrSourceBucket) {
		t.Errorf("a member writes text into the source's bucket: %v", err)
	}
	if _, err := st.Content.PutObject(ctx, mia, content.BeginRequest{Bucket: "greenhouse-climate", Key: "blob", IdempotencyKey: "o-1"}, 4,
		strings.NewReader("data")); !errors.Is(err, content.ErrSourceBucket) {
		t.Errorf("a member puts an object into the source's bucket: %v", err)
	}
}

// TestPostingNeedsItsOwnRight is the regression test of the first open
// point of stop 2's demo check (ING-012): a post is decided as
// post-reading, so a member whose rules let them upload in the bucket's
// project, and the readings' owner, whose rules let them add versions,
// post nothing, though both hold every capability. Before, a member posted
// a reading under a new key that looked like the device's.
func TestPostingNeedsItsOwnRight(t *testing.T) {
	r := newReadings(t)
	if _, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading); err != nil {
		t.Fatal(err)
	}
	st := r.st
	mia := st.User("mia", []string{"member"}, "greenhouse")
	owner := st.Caller("team-greenhouse")
	for name, c := range map[string]struct {
		caller  content.Caller
		payload string
	}{
		"a member under a new key":         {mia, `{"sensor":"made-up","temperature":99}`},
		"a member under the device's key":  {mia, `{"sensor":"gh-north-1","temperature":99}`},
		"the owner under a new key":        {owner, `{"sensor":"owner-made","temperature":99}`},
		"the owner under the device's key": {owner, `{"sensor":"gh-north-1","temperature":99}`},
	} {
		if _, err := r.post(c.caller, "greenhouse-climate", "m-"+name, c.payload); !errors.Is(err, content.ErrNotFound) {
			t.Errorf("%s posts: %v", name, err)
		}
	}
	if n := st.Count(`SELECT count(*) FROM document_versions v JOIN objects o ON o.tenant = v.tenant AND o.id = v.document
	                   JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket WHERE b.source IS NOT NULL`); n != 1 {
		t.Fatalf("%d reading versions, want only the device's", n)
	}
}

// TestSourceRefusals: an unknown or disabled source, or one with no
// reviewed version, takes no reading; a reading the profile refuses, or
// whose key is not one, is invalid, and its refusal names no value.
func TestSourceRefusals(t *testing.T) {
	r := newReadings(t)
	r.source(t, "unreviewed", false)
	for name, c := range map[string]struct {
		source, payload string
		want            error
	}{
		"an unknown source":         {"nowhere", northReading, content.ErrNotFound},
		"a source not yet reviewed": {"unreviewed", northReading, content.ErrNotFound},
		"a member in no group":      {"greenhouse-climate", `{"sensor":"gh-north-1","pin":"1234"}`, content.ErrInvalid},
		"a key not matching":        {"greenhouse-climate", `{"sensor":"North 1"}`, content.ErrInvalid},
		"not an object":             {"greenhouse-climate", `[1]`, content.ErrInvalid},
	} {
		_, err := r.post(r.sensor, c.source, "x-"+name, c.payload)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), "1234") || strings.Contains(err.Error(), "North 1")) {
			t.Errorf("%s: the refusal quotes a value: %v", name, err)
		}
	}
	if err := r.ops.DisableSource(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant, "greenhouse-climate"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.post(r.sensor, "greenhouse-climate", "after", northReading); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a reading of a disabled source: %v", err)
	}
}

// TestClientReadingBegin covers ING-010 at the begin of a client-mode
// reading: the layout answers each group's recipient keys to a caller who
// may post; the declaration follows the active version's key rule and
// groups, and names that version; a server-mode source refuses the route
// after authorization; and a caller who may not post learns nothing.
func TestClientReadingBegin(t *testing.T) {
	r := newReadings(t)
	st := r.st
	owner, err := crypto.NewRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	fp, _, err := st.Catalog.AddRecipientKey(ctx, r1test.Tenant, "team-greenhouse", owner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	def, err := sources.Parse([]byte(`{"format":"fga.source/v1","id":"vault","owner":"team-greenhouse",
	 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
	 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/sensor"],"recipients":["team-greenhouse"]},
	           {"name":"location","label":"restricted","fields":["/gps"],"recipients":["team-greenhouse","mia"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	mia := st.User("mia", []string{"member"}, "greenhouse")
	v, err := r.ops.AddSource(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant,
		catalog.Bucket{Name: "vault", Project: "greenhouse", Label: "internal", Encryption: "client"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ops.ReviewSource(ctx, adminops.Who{Actor: "rita", Via: "test"}, r1test.Tenant, "vault", v.Version, v.Digest); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "sensor-7", []string{"source"},
		map[string]any{"sources": []string{"greenhouse-climate", "vault"}}, nil); err != nil {
		t.Fatal(err)
	}
	sensor := st.Caller("sensor-7")
	l, err := st.Content.SourceLayout(ctx, sensor, "vault")
	if err != nil || l.Version != 1 || l.Encryption != "client" || len(l.Recipients) != 2 || len(l.Recipients[0]) != 1 ||
		l.Recipients[0][0].Fingerprint != fp || len(l.Recipients[1]) != 1 {
		t.Fatalf("the layout %+v, %v", l, err)
	}
	if _, err := st.Content.SourceLayout(ctx, mia, "vault"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a member who may not post reads the layout: %v", err)
	}
	ok := content.ReadingBeginRequest{Source: "vault", SourceVersion: 1, Key: "sensor/gh-1", IdempotencyKey: "b-1",
		Fields: [][]string{{"/sensor", "/temperature"}, {}}}
	in, err := st.Content.BeginReading(ctx, sensor, ok)
	if err != nil || len(in.Units) != 2 {
		t.Fatalf("a client-mode begin: %+v, %v", in, err)
	}
	for name, c := range map[string]struct {
		caller content.Caller
		change func(*content.ReadingBeginRequest)
		want   error
	}{
		"another version":          {sensor, func(r *content.ReadingBeginRequest) { r.SourceVersion = 2 }, content.ErrConflict},
		"a key outside the rule":   {sensor, func(r *content.ReadingBeginRequest) { r.Key = "gh-1" }, content.ErrInvalid},
		"a field of another group": {sensor, func(r *content.ReadingBeginRequest) { r.Fields = [][]string{{"/gps"}, {}} }, content.ErrInvalid},
		"a group missing":          {sensor, func(r *content.ReadingBeginRequest) { r.Fields = r.Fields[:1] }, content.ErrInvalid},
		"a server-mode source": {sensor, func(r *content.ReadingBeginRequest) {
			r.Source, r.Fields = "greenhouse-climate", [][]string{{"/sensor"}, {}}
		}, content.ErrEncryptionMode},
		"a member who may not post": {mia, func(*content.ReadingBeginRequest) {}, content.ErrNotFound},
	} {
		req := ok
		req.IdempotencyKey = "b-" + name
		c.change(&req)
		if _, err := st.Content.BeginReading(ctx, c.caller, req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
