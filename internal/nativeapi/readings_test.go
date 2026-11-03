package nativeapi_test

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/admission"
	"fga/internal/catalog"
	"fga/internal/httpapi"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/sources"
)

// TestReadingsHTTP covers the readings route (ING-002): a posting system
// posts JSON and gets the reading's key and version; a retry under the
// same Idempotency-Key is the same version; the route takes JSON only and
// at most 1 MiB; another route into the source's bucket answers 409
// SOURCE_BUCKET; and no MCP decision opens the route.
func TestReadingsHTTP(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	own := `has(resource.attributes.source) && has(principal.attributes.sources) && resource.attributes.source in principal.attributes.sources`
	for file, rule := range map[string]string{
		"buckets.json": `{"id":"sources-create-readings","effect":"allow","actions":["create-object"],"roles":["source"],"when":"` + own + `"}`,
		"objects.json": `{"id":"sources-version-readings","effect":"allow","actions":["new-version"],"roles":["source"],"when":"` + own + `"}`,
	} {
		policies[file] = strings.Replace(policies[file], `"rules":[`, `"rules":[`+rule+",", 1)
	}
	d := deployFull(t, admission.DefaultLimits, r1test.Options{Policies: policies})
	ctx := context.Background()
	st := d.st
	st.User("team-greenhouse", []string{"member"}, "greenhouse")
	mia := st.User("mia", []string{"member"}, "greenhouse")
	if err := st.Catalog.PutIdentity(ctx, r1test.Tenant, "sensor-7", []string{"source"},
		map[string]any{"sources": []string{"greenhouse-climate"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.GrantCapabilities(ctx, r1test.Tenant, "sensor-7", adminops.Presets["source"]); err != nil {
		t.Fatal(err)
	}
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil },
		Now: func() time.Time { return *st.Clock }}
	def, err := sources.Parse([]byte(`{"format":"fga.source/v1","id":"greenhouse-climate","owner":"team-greenhouse",
	 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
	 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/sensor"]},{"name":"location","label":"restricted","fields":["/gps"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	v, err := ops.AddSource(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant,
		catalog.Bucket{Name: "greenhouse-climate", Project: "greenhouse", Label: "internal", Encryption: "server"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ReviewSource(ctx, adminops.Who{Actor: "rita", Via: "test"}, r1test.Tenant, "greenhouse-climate", v.Version, v.Digest); err != nil {
		t.Fatal(err)
	}

	call := func(method, path, contentType, body string, header map[string]string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, d.storage.URL+path, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	sensor := map[string]string{"Authorization": "Bearer " + st.Caller("sensor-7").Token}
	reading := `{"sensor":"gh-north-1","temperature":21.5,"gps":{"lat":48.1}}`
	code, out := call("POST", "/v1/sources/greenhouse-climate/readings", "application/json", reading, sensor)
	if code != http.StatusOK || out["key"] != "sensor/gh-north-1" || out["document_version_id"] == "" || out["units"] != 2.0 {
		t.Fatalf("post = %d %v", code, out)
	}
	retry := maps.Clone(sensor)
	retry["Idempotency-Key"] = "reading-17"
	_, first := call("POST", "/v1/sources/greenhouse-climate/readings", "application/json", reading, retry)
	code, again := call("POST", "/v1/sources/greenhouse-climate/readings", "application/json", reading, retry)
	if code != http.StatusOK || first["document_version_id"] == nil || again["document_version_id"] != first["document_version_id"] {
		t.Fatalf("a retry = %d %v, first %v", code, again, first)
	}
	for name, c := range map[string]struct {
		path, contentType, body string
		want                    int
		code                    string
	}{
		"not JSON":          {"/v1/sources/greenhouse-climate/readings", "text/plain", reading, http.StatusBadRequest, httpapi.CodeInvalid},
		"too large":         {"/v1/sources/greenhouse-climate/readings", "application/json", `{"sensor":"` + strings.Repeat("a", 1<<20) + `"}`, http.StatusRequestEntityTooLarge, httpapi.CodeTooLarge},
		"an unknown source": {"/v1/sources/orchard/readings", "application/json", reading, http.StatusNotFound, httpapi.CodeNotFound},
		"a refused reading": {"/v1/sources/greenhouse-climate/readings", "application/json", `{"sensor":"gh-north-1","pin":"1"}`, http.StatusBadRequest, httpapi.CodeInvalid},
	} {
		if code, out := call("POST", c.path, c.contentType, c.body, sensor); code != c.want || out["error"] != c.code {
			t.Errorf("%s: %d %v, want %d %s", name, code, out, c.want, c.code)
		}
	}

	// A member allowed to create objects in the bucket's project still
	// cannot write the source's bucket through another route.
	text := "a note"
	code, out = call("POST", "/v1/buckets/greenhouse-climate/documents/text?key=notes", "text/plain", text,
		map[string]string{"Authorization": "Bearer " + mia.Token, "Content-Length": strconv.Itoa(len(text))})
	if code != http.StatusConflict || out["error"] != httpapi.CodeSourceBucket {
		t.Fatalf("text into the source's bucket: %d %v", code, out)
	}

	// No MCP decision opens the readings route (P3): the gateway takes it
	// for no tool, so the call has no caller.
	if err := st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	mcpToken, err := st.Issuer.Issue("mia", r1test.Tenant, r1test.MCPAudience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signed, ok := mcpDecision(t, d, r1test.MCPAdapter, "mia", "documents.read", mcpToken, registry.OpMCPInvoke)
	if !ok {
		t.Fatal("no MCP decision for mia")
	}
	code, _ = call("POST", "/v1/sources/greenhouse-climate/readings", "application/json", reading,
		map[string]string{"X-Test-Workload": r1test.MCPAdapter, httpapi.DecisionHeader: signed.Evidence()})
	if code != http.StatusUnauthorized {
		t.Fatalf("an MCP decision posts a reading: %d", code)
	}
}
