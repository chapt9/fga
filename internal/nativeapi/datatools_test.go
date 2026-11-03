package nativeapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"fga/internal/adminops"
	"fga/internal/cryptowire"
	"fga/internal/datatools"
	"fga/internal/r1test"
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
		resp.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "21.7351") {
		t.Fatalf("the raw answer %d %s: %s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
	if ec, err := cryptowire.ParseEnvelopeContext(a.Packages[0].Envelope.Context); err != nil || ec.Recipient != alice.Recipient.Fingerprint() {
		t.Fatalf("the envelope is for %v: %v", ec.Recipient, err)
	}
	if resp, _ := raw(alice, lena.Recipient.Fingerprint()); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a call naming another person's key: %d", resp.StatusCode)
	}
}
