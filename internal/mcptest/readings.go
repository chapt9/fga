package mcptest

import (
	"context"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/datatools"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/sources"
	"fga/sdk/go/client"
)

// ReadingPolicies are the fixture's policies with the example bundle's
// rules for posting systems and for members using their projects' data
// tools (docs/design/mcp-data-tools.md).
func ReadingPolicies() map[string]string {
	policies := maps.Clone(r1test.Policies)
	own := `has(resource.attributes.source) && has(principal.attributes.sources) && resource.attributes.source in principal.attributes.sources`
	for file, rule := range map[string]string{
		"buckets.json":   `{"id":"sources-post-readings","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"` + own + `"}`,
		"objects.json":   `{"id":"sources-post-reading-versions","effect":"allow","actions":["post-reading"],"roles":["source"],"when":"` + own + `"}`,
		"documents.json": `{"id":"sources-share-readings","effect":"allow","actions":["share"],"roles":["source"],"when":"` + own + `"}`,
		"units.json":     `{"id":"sources-share-reading-units","effect":"allow","actions":["share"],"roles":["source"],"when":"` + own + `"}`,
		"tools.json": `{"id":"members-use-data-tools","effect":"allow","actions":["discover","invoke"],"roles":["member"],
		  "when":"resource.attributes.kind == \"data\" && resource.attributes.project in principal.attributes.projects"}`,
	} {
		policies[file] = strings.Replace(policies[file], `"rules":[`, `"rules":[`+rule+",", 1)
	}
	return policies
}

// Reading is the payload Readings posts to both sources.
const Reading = `{"sensor":"gh-1","temperature":21.75,"humidity":58.5}`

// Readings adds two sources of project p1 owned by alice that sensor-7
// posts to, a latest data tool over each that skips unreadable fields, and
// one Reading of each at key sensor/gh-1: climate in server mode, read by
// read_climate, whose humidity group is restricted; and private in client
// mode, read by private_climate, whose temperature group alice and bob
// receive and whose humidity group alice only. The deployment's policies
// must be ReadingPolicies. It enables MCP.
func Readings(t *testing.T, d *Deployment, alice, bob *r1test.Client) {
	t.Helper()
	ctx := context.Background()
	st := d.St
	sensor := st.Client("sensor-7", []string{"source"})
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "sensor-7", []string{"source"},
		map[string]any{"sources": []string{"climate", "private"}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*r1test.Client{alice, bob} {
		sensor.Pin(c)
		c.Pin(sensor)
	}
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	root, rita := adminops.Who{Actor: "root", Via: "test"}, adminops.Who{Actor: "rita", Via: "test"}
	add := func(mode, id, groups, outputs string) {
		t.Helper()
		def, err := sources.Parse([]byte(`{"format":"fga.source/v1","id":"` + id + `","owner":"alice",
		 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},"groups":[` + groups + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		v, err := ops.AddSource(ctx, root, r1test.Tenant, catalog.Bucket{Name: id, Project: "p1", Label: "internal", Encryption: mode}, def)
		if err == nil {
			_, err = ops.ReviewSource(ctx, rita, r1test.Tenant, id, v.Version, v.Digest)
		}
		if err != nil {
			t.Fatal(err)
		}
		tool, err := datatools.Parse([]byte(`{"format":"fga.data-tool/v1","name":"` + map[string]string{"server": "read_climate", "client": "private_climate"}[mode] +
			`","description":"Latest climate of one sensor.","source":"` + id + `","operation":"latest","on_unreadable":"skip_fields",
			 "arguments":[{"name":"sensor","type":"string"}],"select":{"argument":"sensor"},"outputs":[` + outputs + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		tv, err := ops.AddDataTool(ctx, root, r1test.Tenant, tool)
		if err == nil {
			_, err = ops.ReviewDataTool(ctx, root, r1test.Tenant, tool.Name, tv.Version, tv.Digest)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	outputs := func(first, second string) string {
		return `{"name":"temperature","group":"` + first + `","field":"/temperature","type":"number"},
		        {"name":"humidity","group":"` + second + `","field":"/humidity","type":"number"}`
	}
	add("server", "climate", `{"name":"climate","label":"internal","fields":["/sensor","/temperature"]},
	 {"name":"humidity","label":"restricted","fields":["/humidity"]}`, outputs("climate", "humidity"))
	add("client", "private", `{"name":"temperature","label":"internal","fields":["/sensor","/temperature"],"recipients":["alice","bob"]},
	 {"name":"humidity","label":"internal","fields":["/humidity"],"recipients":["alice"]}`, outputs("temperature", "humidity"))
	if _, err := st.Content.PutReading(ctx, sensor.Caller, content.ReadingRequest{Source: "climate", IdempotencyKey: "c-1"}, []byte(Reading)); err != nil {
		t.Fatal(err)
	}
	poster := &client.Client{StorageURL: d.Storage.URL, HTTP: http.DefaultClient, StorageToken: sensor.Caller.Token, Recipient: sensor.Recipient,
		KeyVersion: sensor.KeyVersion, Signer: sensor.Signer, Trust: sensor.Trust, TempDir: t.TempDir(), Now: func() time.Time { return *st.Clock }}
	if _, err := poster.PostReading(ctx, "private", []byte(Reading), "", "p-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
}
