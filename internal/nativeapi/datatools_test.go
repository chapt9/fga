package nativeapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/cryptowire"
	"fga/internal/datatools"
	"fga/internal/httpapi"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/sdk/go/client"
)

// TestDataToolsHTTP covers DTL-009 with the SDK over HTTP: a call over
// client-mode readings answers only the caller's own packages, with no
// plaintext and never cached; the caller's client opens and projects them
// into the server-mode answer; a recipient of fewer groups gets fewer
// fields; a member who is no recipient, and a caller naming another's key,
// get nothing.
func TestDataToolsHTTP(t *testing.T) {
	d, ops, lena, alice, bob, sensor := privateReadings(t, map[string]string{"tools.json": `{"id":"members-use-data-tools","effect":"allow",
	  "actions":["discover","invoke"],"roles":["member"],
	  "when":"resource.attributes.kind == \"data\" && resource.attributes.project in principal.attributes.projects"}`})
	ctx := context.Background()
	if _, err := d.client(t, sensor).PostReading(ctx, "greenhouse-private", []byte(`{"sensor":"gh-p1","temperature":21.7351,"humidity":58.4127}`),
		"", "r-1"); err != nil {
		t.Fatal(err)
	}
	def, err := datatools.Parse([]byte(`{"format":"fga.data-tool/v1","name":"private_climate","description":"Climate of a private sensor.",
	 "source":"greenhouse-private","operation":"latest","arguments":[{"name":"sensor","type":"string"}],"select":{"argument":"sensor"},
	 "on_unreadable":"skip_fields","outputs":[{"name":"temperature","group":"temperature","field":"/temperature","type":"number"},
	 {"name":"humidity","group":"humidity","field":"/humidity","type":"number"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	who := adminops.Who{Actor: "root", Via: "test"}
	v, err := ops.AddDataTool(ctx, who, r1test.Tenant, def)
	if err == nil {
		_, err = ops.ReviewDataTool(ctx, who, r1test.Tenant, "private_climate", v.Version, v.Digest)
	}
	if err != nil {
		t.Fatal(err)
	}
	args := json.RawMessage(`{"sensor":"gh-p1"}`)
	reading := func(c *r1test.Client) (map[string]any, error) {
		raw, err := d.client(t, c).CallDataTool(ctx, "private_climate", args, 0)
		if err != nil {
			return nil, err
		}
		var a struct {
			Reading map[string]any `json:"reading"`
		}
		return a.Reading, json.Unmarshal(raw, &a)
	}
	if got, err := reading(lena); err != nil || got["temperature"] != 21.7351 || got["humidity"] != 58.4127 || len(got) != 2 {
		t.Fatalf("a recipient of both groups: %v, %v", got, err)
	}
	if got, err := reading(alice); err != nil || got["temperature"] != 21.7351 || len(got) != 1 {
		t.Fatalf("a recipient of one group: %v, %v", got, err)
	}
	var refused *client.Error
	if _, err := reading(bob); !errors.As(err, &refused) || refused.Status != http.StatusNotFound {
		t.Fatalf("a member who is no recipient: %v", err)
	}
	if tools, err := d.client(t, alice).ListDataTools(ctx); err != nil || len(tools) != 1 || tools[0].Encryption != "client" {
		t.Fatalf("listing %+v, %v", tools, err)
	}

	// On the wire: only the caller's envelope, no value, not cached; another
	// person's key gets nothing.
	raw := func(c *r1test.Client, recipient cryptowire.Digest) (*http.Response, []byte) {
		body := `{"arguments":{"sensor":"gh-p1"},"recipient":"` + recipient.String() + `"}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.storage.URL+"/v1/data-tools/private_climate/call", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+c.Caller.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := raw(alice, alice.Recipient.Fingerprint())
	var a struct {
		Encrypted bool `json:"encrypted"`
		Packages  []struct {
			Envelope struct {
				Context []byte `json:"context"`
			} `json:"envelope"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &a); err != nil || resp.StatusCode != http.StatusOK || !a.Encrypted || len(a.Packages) != 1 ||
		resp.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "21.7351") ||
		!strings.Contains(string(body), `"envelope_id"`) || !strings.Contains(string(body), `"receipt_signature"`) {
		t.Fatalf("the raw answer %d %s: %s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
	if ec, err := cryptowire.ParseEnvelopeContext(a.Packages[0].Envelope.Context); err != nil || ec.Recipient != alice.Recipient.Fingerprint() {
		t.Fatalf("the envelope is for %v: %v", ec.Recipient, err)
	}
	if resp, _ := raw(alice, lena.Recipient.Fingerprint()); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a call naming another person's key: %d", resp.StatusCode)
	}

	// MCP-009: a gateway decision on a data tool opens that tool's call
	// route only, and data.list the listing only.
	if err := d.st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	mcpToken, err := d.st.Issuer.Issue("alice", r1test.Tenant, r1test.MCPAudience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	decision := func(tool string) string {
		signed, ok := mcpDecision(t, d, r1test.MCPAdapter, "alice", tool, mcpToken, registry.OpMCPInvoke)
		if !ok {
			t.Fatalf("no decision for %s", tool)
		}
		return signed.Evidence()
	}
	gateway := func(evidence, method, path string) int {
		body := `{"arguments":{"sensor":"gh-p1"},"recipient":"` + alice.Recipient.Fingerprint().String() + `"}`
		req, _ := http.NewRequestWithContext(ctx, method, d.storage.URL+path, strings.NewReader(body))
		req.Header.Set("X-Test-Workload", r1test.MCPAdapter)
		req.Header.Set(httpapi.DecisionHeader, evidence)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	tool, list, read := decision("private_climate"), decision("data.list"), decision("documents.read")
	for name, c := range map[string]struct {
		evidence, method, path string
		want                   int
	}{
		"the tool's call":                   {tool, http.MethodPost, "/v1/data-tools/private_climate/call", http.StatusOK},
		"the listing under data.list":       {list, http.MethodGet, "/v1/data-tools", http.StatusOK},
		"another data tool's call":          {tool, http.MethodPost, "/v1/data-tools/other_climate/call", http.StatusUnauthorized},
		"the listing under a data tool":     {tool, http.MethodGet, "/v1/data-tools", http.StatusUnauthorized},
		"a call under data.list":            {list, http.MethodPost, "/v1/data-tools/private_climate/call", http.StatusUnauthorized},
		"a call under documents.read":       {read, http.MethodPost, "/v1/data-tools/private_climate/call", http.StatusUnauthorized},
		"a preview":                         {tool, http.MethodPost, "/v1/data-tools/preview", http.StatusUnauthorized},
		"ingestion":                         {tool, http.MethodPost, "/v1/sources/greenhouse-private/readings/begin", http.StatusUnauthorized},
		"a document read under a data tool": {tool, http.MethodGet, "/v1/buckets/greenhouse-private/document/units?key=sensor/gh-p1", http.StatusUnauthorized},
	} {
		if got := gateway(c.evidence, c.method, c.path); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
}
