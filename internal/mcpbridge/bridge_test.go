package mcpbridge_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/mcpbridge"
	"fga/internal/mcpsvc"
	"fga/internal/mcptest"
	"fga/internal/mcpwire"
	"fga/internal/r1test"
)

var ctx = context.Background()

// bridgeFor starts user's bridge to the deployment, with status as every
// signer's status, and connects a test application to it in memory.
func bridgeFor(t *testing.T, d *mcptest.Deployment, user string, c *r1test.Client, status string) (*mcpbridge.Bridge, *mcp.ClientSession) {
	t.Helper()
	return bridgeTo(t, d.MCP.URL+"/mcp", &http.Client{Transport: mcptest.Bearer(d.Token(t, user))}, c, status)
}

// bridgeTo starts c's bridge to the MCP endpoint upstream and connects a
// test application to it in memory.
func bridgeTo(t *testing.T, upstream string, hc *http.Client, c *r1test.Client, status string) (*mcpbridge.Bridge, *mcp.ClientSession) {
	t.Helper()
	b, err := mcpbridge.New(ctx, mcpbridge.Deps{UpstreamURL: upstream, HTTP: hc,
		Key: c.Recipient, Trust: c.Trust, SignerStatus: func(context.Context, cryptowire.Digest) (string, error) { return status, nil },
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	appSide, bridgeSide := mcp.NewInMemoryTransports()
	if _, err := b.Server().Connect(ctx, bridgeSide, nil); err != nil {
		t.Fatal(err)
	}
	app, err := mcp.NewClient(&mcp.Implementation{Name: "app", Version: "1"}, nil).Connect(ctx, appSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return b, app
}

func text(t *testing.T, res *mcp.CallToolResult, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if res.IsError {
		t.Fatalf("tool error: %s", b.String())
	}
	return b.String()
}

// TestBridge covers MCP-005 and T-10 for the local bridge: the application
// that launched it reads client-mode objects and documents as plaintext,
// opened with the user's own key; server-mode content passes through
// unchanged; an export made for another recipient passes through unopened;
// a user without an envelope gets nothing.
func TestBridge(t *testing.T) {
	d := mcptest.Deploy(t, mcpsvc.DefaultLimits, nil)
	alice, bob, plain, _ := mcptest.ClientFixture(t, d)
	d.St.ModeBucket("vault", "p1", "internal", "server")
	if _, err := d.St.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "plan.txt", IdempotencyKey: "o1"},
		8, strings.NewReader("the plan")); err != nil {
		t.Fatal(err)
	}
	_, app := bridgeFor(t, d, "bob", bob, "ACTIVE")

	tools, err := app.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 4 {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	for _, tool := range tools.Tools {
		if tool.OutputSchema != nil {
			t.Errorf("%s keeps the MCP role's output schema", tool.Name)
		}
	}
	res, err := app.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fga://reports/plan.bin"})
	if err != nil || len(res.Contents) != 1 || res.Contents[0].MIMEType != "text/plain" || res.Contents[0].Text != string(plain) {
		t.Fatalf("the client-mode object through the bridge: %v", err)
	}
	read, err := app.CallTool(ctx, &mcp.CallToolParams{Name: mcpsvc.ToolReadDocument, Arguments: map[string]any{"bucket": "reports", "key": "q3.md"}})
	if got := text(t, read, err); got != strings.Join(mcptest.Paragraphs, "\n\n") {
		t.Fatalf("the client-mode document through the bridge: %q", got)
	}
	var opened mcpbridge.Opened
	raw, _ := json.Marshal(read.StructuredContent)
	if err := json.Unmarshal(raw, &opened); err != nil || len(opened.Units) != 3 || opened.Units[1].Text != mcptest.Paragraphs[1] {
		t.Fatalf("structured units: %+v %v", opened, err)
	}
	res, err = app.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fga://vault/plan.txt"})
	if err != nil || res.Contents[0].Text != "the plan" {
		t.Fatalf("server-mode content through the bridge: %+v %v", res, err)
	}

	// alice exports for bob: her bridge cannot open it and passes it on.
	_, aliceApp := bridgeFor(t, d, "alice", alice, "ACTIVE")
	x, err := aliceApp.CallTool(ctx, &mcp.CallToolParams{Name: mcpsvc.ToolExport,
		Arguments: map[string]any{"bucket": "reports", "key": "plan.bin", "recipient": bob.Recipient.Fingerprint().String()}})
	text(t, x, err)
	raw, _ = json.Marshal(x.StructuredContent)
	if !strings.Contains(string(raw), `"package"`) || strings.Contains(string(raw), "client-mode secret") {
		t.Fatalf("an export for another recipient was opened: %.200s", raw)
	}

	// dave is a member with no envelope: nothing to open.
	dave := d.St.Client("dave", []string{"member"}, "p1")
	_, daveApp := bridgeFor(t, d, "dave", dave, "ACTIVE")
	if _, err := daveApp.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fga://reports/plan.bin"}); err == nil {
		t.Fatal("a user without an envelope read the object")
	}
}

// TestOpenRefusesBadPackages covers CRY-006 and RCP-011 at the bridge: a
// package opens completely or not at all. Altered, truncated or swapped
// ciphertext, a descriptor of another version, a package for another
// recipient, an untrusted or compromised signer each fail verification,
// and nothing is returned.
func TestOpenRefusesBadPackages(t *testing.T) {
	d := mcptest.Deploy(t, mcpsvc.DefaultLimits, nil)
	alice, bob, plain, _ := mcptest.ClientFixture(t, d)
	s, err := d.Connect(t, "bob", bob.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	obj := packageOf(t, s, "fga://reports/plan.bin")
	doc := packageOf(t, s, "fga://reports/q3.md")
	b, _ := bridgeFor(t, d, "bob", bob, "ACTIVE")
	if o, err := b.Open(ctx, obj, ""); err != nil || !bytes.Equal(o.Object, plain) {
		t.Fatalf("the intact object: %v", err)
	}
	if o, err := b.Open(ctx, doc, ""); err != nil || len(o.Units) != 3 {
		t.Fatalf("the intact document: %v", err)
	}

	flip := func(b64 string, i int) string {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		raw[i] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	truncate := func(b64 string) string {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		return base64.StdEncoding.EncodeToString(raw[:len(raw)-1])
	}
	cases := map[string]func() (*mcpwire.Package, string){
		"altered object ciphertext": func() (*mcpwire.Package, string) {
			p := clone(obj)
			p.Object.Ciphertext = flip(p.Object.Ciphertext, 100)
			return p, ""
		},
		"truncated object ciphertext": func() (*mcpwire.Package, string) {
			p := clone(obj)
			p.Object.Ciphertext = truncate(p.Object.Ciphertext)
			return p, ""
		},
		"altered unit ciphertext": func() (*mcpwire.Package, string) {
			p := clone(doc)
			p.Units[1].Ciphertext = flip(p.Units[1].Ciphertext, 3)
			return p, ""
		},
		"swapped unit ciphertexts": func() (*mcpwire.Package, string) {
			p := clone(doc)
			p.Units[0].Ciphertext, p.Units[1].Ciphertext = p.Units[1].Ciphertext, p.Units[0].Ciphertext
			return p, ""
		},
		"a unit claimed as another": func() (*mcpwire.Package, string) {
			p := clone(doc)
			p.Units[0].Unit = p.Units[1].Unit
			return p, ""
		},
		"another object version claimed": func() (*mcpwire.Package, string) {
			p := clone(obj)
			p.Object.Version = "00000000-0000-4000-8000-000000000000"
			return p, ""
		},
		"another version asked for": func() (*mcpwire.Package, string) { return clone(doc), "00000000-0000-4000-8000-000000000000" },
		"another recipient": func() (*mcpwire.Package, string) {
			p := clone(obj)
			p.Recipient = alice.Recipient.Fingerprint().String()
			return p, ""
		},
	}
	for name, c := range cases {
		p, version := c()
		if o, err := b.Open(ctx, p, version); !errors.Is(err, mcpbridge.ErrVerify) || o.Object != nil || o.Units != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The units asked for, each once, and no other (review v5 F09).
	ids := []string{doc.Units[0].Unit, doc.Units[1].Unit, doc.Units[2].Unit}
	if o, err := b.Open(ctx, doc, "", ids[2], ids[0], ids[1]); err != nil || len(o.Units) != 3 {
		t.Fatalf("every unit asked for: %v", err)
	}
	onlyB, twice := clone(doc), clone(doc)
	onlyB.Units = onlyB.Units[1:2]
	twice.Units[1] = twice.Units[0]
	for name, c := range map[string]struct {
		p     *mcpwire.Package
		units []string
	}{
		"a unit not asked for":     {doc, ids[:2]},
		"a unit asked for missing": {onlyB, ids[:2]},
		"a unit twice":             {twice, nil},
		"units asked of an object": {obj, ids[:1]},
	} {
		if o, err := b.Open(ctx, c.p, "", c.units...); !errors.Is(err, mcpbridge.ErrVerify) || o.Object != nil || o.Units != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	compromised, _ := bridgeFor(t, d, "bob", bob, "COMPROMISED")
	if _, err := compromised.Open(ctx, obj, ""); !errors.Is(err, mcpbridge.ErrVerify) {
		t.Errorf("a compromised signer: %v", err)
	}
	untrusting, err := mcpbridge.New(ctx, mcpbridge.Deps{UpstreamURL: d.MCP.URL + "/mcp", HTTP: &http.Client{Transport: mcptest.Bearer(d.Token(t, "bob"))},
		Key: bob.Recipient, Trust: &r1test.Trust{}, SignerStatus: func(context.Context, cryptowire.Digest) (string, error) { return "ACTIVE", nil },
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusting.Close()
	if _, err := untrusting.Open(ctx, doc, ""); !errors.Is(err, mcpbridge.ErrVerify) {
		t.Errorf("an untrusted signer: %v", err)
	}
}

// TestBridgeBindsRequestedUnits covers review v5 F09: a package opens
// only as the units the application asked for. An upstream that answers a
// request for unit A with a correctly signed package of unit B of the same
// version, or with fewer units than asked for, gets an error and no
// plaintext, by resource and by tool.
func TestBridgeBindsRequestedUnits(t *testing.T) {
	d := mcptest.Deploy(t, mcpsvc.DefaultLimits, nil)
	_, bob, _, _ := mcptest.ClientFixture(t, d)
	s, err := d.Connect(t, "bob", bob.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	doc := packageOf(t, s, "fga://reports/q3.md")
	a, b := doc.Units[0].Unit, doc.Units[1].Unit
	onlyB := clone(doc)
	onlyB.Units = onlyB.Units[1:2]
	_, app := bridgeTo(t, substituting(t, onlyB), &http.Client{}, bob, "ACTIVE")

	resource := func(units ...string) (string, error) {
		uri := "fga://reports/q3.md"
		if len(units) == 1 {
			uri += "?unit=" + units[0]
		}
		res, err := app.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			return "", err
		}
		return res.Contents[0].Text, nil
	}
	tool := func(units ...string) (string, error) {
		res, err := app.CallTool(ctx, &mcp.CallToolParams{Name: mcpsvc.ToolReadDocument,
			Arguments: map[string]any{"bucket": "reports", "key": "q3.md", "units": units}})
		if err != nil {
			return "", err
		}
		if res.IsError {
			return "", errors.New("tool error")
		}
		return res.Content[0].(*mcp.TextContent).Text, nil
	}
	for name, read := range map[string]func(...string) (string, error){"resource": resource, "tool": tool} {
		if got, err := read(a); err == nil {
			t.Errorf("%s: unit A answered with unit B's text %q", name, got)
		}
		if got, err := read(b); err != nil || got != mcptest.Paragraphs[1] {
			t.Errorf("%s: unit B asked and given: %q %v", name, got, err)
		}
	}
	if got, err := tool(a, b); err == nil {
		t.Errorf("tool: units A and B answered with B alone: %q", got)
	}
}

// substituting starts a stand-in for the MCP role that answers every read,
// by resource or by tool, with pkg, whatever was asked for.
func substituting(t *testing.T, pkg *mcpwire.Package) string {
	t.Helper()
	raw, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "fga-mcp", Version: "test"}, nil)
	srv.AddResourceTemplate(&mcp.ResourceTemplate{Name: "fga", URITemplate: "fga://{bucket}/{+key}"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: mcpwire.MIMEType, Text: string(raw)}}}, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: mcpsvc.ToolReadDocument}, func(context.Context, *mcp.CallToolRequest, map[string]any) (*mcp.CallToolResult, map[string]any, error) {
		return nil, map[string]any{"package": pkg}, nil
	})
	h := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(h.Close)
	return h.URL
}

func packageOf(t *testing.T, s *mcp.ClientSession, uri string) *mcpwire.Package {
	t.Helper()
	res, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil || len(res.Contents) != 1 || res.Contents[0].MIMEType != mcpwire.MIMEType {
		t.Fatalf("%s: %+v %v", uri, res, err)
	}
	var p mcpwire.Package
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func clone(p *mcpwire.Package) *mcpwire.Package {
	b, _ := json.Marshal(p)
	var c mcpwire.Package
	_ = json.Unmarshal(b, &c)
	return &c
}
