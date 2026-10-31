package mcpsvc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/mcpsvc"
	"fga/internal/mcptest"
	"fga/internal/mcpwire"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/sdk/go/crypto"
)

var ctx = context.Background()

func deploy(t *testing.T) *mcptest.Deployment { return mcptest.Deploy(t, mcpsvc.DefaultLimits, nil) }

// connect opens a session for user: a generic MCP client, or with a
// recipient fingerprint one that declares the encrypted-package
// capability.
func connect(t *testing.T, d *mcptest.Deployment, user, recipient string) *mcp.ClientSession {
	t.Helper()
	s, err := d.Connect(t, user, recipient)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// stateful opens a session at the newest protocol version that has them.
func stateful(t *testing.T, d *mcptest.Deployment, user string) *mcp.ClientSession {
	t.Helper()
	s, err := d.ConnectWith(t, mcptest.Conn{User: user, Protocol: mcptest.Stateful})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func toolNames(t *testing.T, s *mcp.ClientSession) []string {
	t.Helper()
	res, err := s.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.CacheScope != "private" {
		t.Errorf("tools/list cache scope %q", res.CacheScope)
	}
	var out []string
	for _, tool := range res.Tools {
		out = append(out, tool.Name)
	}
	slices.Sort(out)
	return out
}

// call calls a tool; a tool error comes back as an error.
func call(s *mcp.ClientSession, tool string, args any, out any) (string, error) {
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", err
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	if res.IsError {
		return "", errors.New(text.String())
	}
	if out != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			return "", err
		}
	}
	return text.String(), nil
}

func readResource(s *mcp.ClientSession, uri string) (string, error) {
	res, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		return "", err
	}
	if len(res.Contents) != 1 {
		return "", errors.New("not one content")
	}
	if res.CacheScope != "private" {
		return "", errors.New("cache scope " + res.CacheScope)
	}
	return res.Contents[0].Text, nil
}

func resourceNotFound(err error) bool {
	var e *jsonrpc.Error
	return errors.As(err, &e) && e.Code == mcp.CodeResourceNotFound
}

// nativeUnit reads a unit's plaintext over the native API with the user's
// own storage token, as any client does.
func nativeUnit(t *testing.T, d *mcptest.Deployment, c *r1test.Client, bucket, key, unit string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, d.Storage.URL+"/v1/buckets/"+bucket+"/document/unit/content?"+
		url.Values{"key": {key}, "unit": {unit}}.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+c.Caller.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("native unit read: %d %s", resp.StatusCode, b)
	}
	return string(b)
}

const notes = "First paragraph.\n\nSecond paragraph, restricted later.\n\nThird paragraph.\n"

// TestMCPReads covers MCP-003 and MCP-005 for a generic MCP client:
// server-mode content comes back as plaintext through the native read
// routes, and so the storage role's checks; a document read returns only
// the units the user may read (V-169); and the native API, resources/read
// and the read tool return the same unit under the same storage decision
// (V-002, V-050).
func TestMCPReads(t *testing.T) {
	d := deploy(t)
	st := d.St
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := st.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "plan.txt", IdempotencyKey: "o1"},
		8, strings.NewReader("the plan")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "d1"},
		[]byte(notes)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "log", IdempotencyKey: "c1",
		Collection: true}, []byte("entry one\n\nentry two")); err != nil {
		t.Fatal(err)
	}
	units := st.UnitIDs(alice.Caller, "vault", "q3/notes.md", "")
	s := connect(t, d, "bob", "")

	// Before the tenant enables MCP there are no tools and no reads.
	if names := toolNames(t, s); len(names) != 0 {
		t.Fatalf("tools before MCP was enabled: %v", names)
	}
	if _, err := readResource(s, "fga://vault/plan.txt"); err == nil {
		t.Fatal("a read before MCP was enabled")
	}
	if err := st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	if names := toolNames(t, s); !slices.Equal(names, []string{mcpsvc.ToolExport, mcpsvc.ToolReadDocument, mcpsvc.ToolSearch, mcpsvc.ToolReadText}) {
		t.Fatalf("tools: %v", names)
	}

	if got, err := readResource(s, "fga://vault/plan.txt"); err != nil || got != "the plan" {
		t.Fatalf("the object: %q %v", got, err)
	}
	if got, err := readResource(s, "fga://vault/q3/notes.md"); err != nil || got != strings.TrimSpace(strings.ReplaceAll(notes, "restricted later", "restricted later")) {
		t.Fatalf("the document: %q %v", got, err)
	}

	// V-169: with the second unit out of bob's reach, he reads the other
	// two, and nothing of the second: no text and no ID.
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "vault", "q3/notes.md", "", units[1], "restricted"); err != nil {
		t.Fatal(err)
	}
	var out mcpsvc.ReadOutput
	text, err := call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, &out)
	if err != nil || text != "First paragraph.\n\nThird paragraph." || len(out.Units) != 2 || out.Units[0].Unit != units[0] || out.Units[1].Unit != units[2] {
		t.Fatalf("bob's read: %q %+v %v", text, out, err)
	}
	if got, err := readResource(s, "fga://vault/q3/notes.md"); err != nil || got != "First paragraph.\n\nThird paragraph." {
		t.Fatalf("bob's resource read: %q %v", got, err)
	}
	if _, err := readResource(s, "fga://vault/q3/notes.md?unit="+units[1]); !resourceNotFound(err) {
		t.Fatalf("bob reads the restricted unit: %v", err)
	}
	if _, err := call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md", "units": []string{units[0], units[1]}}, nil); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("bob selects the restricted unit: %v", err)
	}
	a := connect(t, d, "alice", "")
	if text, err := call(a, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil); err != nil ||
		!strings.Contains(text, "Second paragraph") {
		t.Fatalf("the owner's read: %q %v", text, err)
	}

	// V-002, V-050: one unit through the native API, resources/read and the
	// read tool: the same text, and the storage role's decision for it has
	// the same operation and checks each time.
	var mu sync.Mutex
	var seen []decisionsvc.Request
	st.AfterDecide = func(r decisionsvc.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r)
	}
	last := func() decisionsvc.Request {
		mu.Lock()
		defer mu.Unlock()
		r := seen[len(seen)-1]
		seen = nil
		return r
	}
	native := nativeUnit(t, d, bob, "vault", "q3/notes.md", units[2])
	nativeDecision := last()
	viaResource, err := readResource(s, "fga://vault/q3/notes.md?unit="+units[2])
	resourceDecision := last()
	if err != nil {
		t.Fatal(err)
	}
	viaTool, err := call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md", "units": []string{units[2]}}, nil)
	toolDecision := last()
	if err != nil {
		t.Fatal(err)
	}
	if native != "Third paragraph." || viaResource != native || viaTool != native {
		t.Fatalf("native %q, resources/read %q, tool %q", native, viaResource, viaTool)
	}
	for name, r := range map[string]decisionsvc.Request{"resources/read": resourceDecision, "the tool": toolDecision} {
		if r.Operation != nativeDecision.Operation || r.Actor.ID != "bob" || !slices.EqualFunc(r.Checks, nativeDecision.Checks,
			func(a, b decisionsvc.Check) bool {
				return a.Role == b.Role && a.Action == b.Action && a.Resource == b.Resource
			}) {
			t.Errorf("%s decided %+v, the native read %+v", name, r, nativeDecision)
		}
	}
	st.AfterDecide = nil

	// documents.read and text.read each read their own kind only.
	if text, err := call(s, mcpsvc.ToolReadText, map[string]any{"bucket": "vault", "key": "log"}, nil); err != nil || text != "entry one\n\nentry two" {
		t.Fatalf("text.read: %q %v", text, err)
	}
	if _, err := call(s, mcpsvc.ToolReadText, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil); err == nil {
		t.Fatal("text.read read a document")
	}
	if _, err := call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "log"}, nil); err == nil {
		t.Fatal("documents.read read a collection")
	}

	// documents.search: catalog metadata only.
	var found mcpsvc.SearchOutput
	if _, err := call(s, mcpsvc.ToolSearch, map[string]any{"bucket": "vault", "prefix": "q3/"}, &found); err != nil ||
		len(found.Results) != 1 || found.Results[0].URI != "fga://vault/q3/notes.md" {
		t.Fatalf("search: %+v %v", found, err)
	}

	// resources/list goes through the configured buckets; a bucket the
	// user may not list is passed over.
	var uris []string
	cursor := ""
	for range 10 {
		res, err := s.ListResources(ctx, &mcp.ListResourcesParams{Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res.Resources {
			uris = append(uris, r.URI)
		}
		if cursor = res.NextCursor; cursor == "" {
			break
		}
	}
	if !slices.Equal(uris, []string{"fga://vault/plan.txt", "fga://vault/log", "fga://vault/q3/notes.md"}) {
		t.Fatalf("resources: %v", uris)
	}
	if _, err := s.ListResources(ctx, &mcp.ListResourcesParams{Cursor: "bm90IGEgY3Vyc29y"}); err == nil {
		t.Fatal("a forged cursor was accepted")
	}
}

// TestMCPNoPermissionFromTools covers MCP-003 and MCP-002: a tool
// permission authorizes no content, and content permission no tool. A
// member of another project may use every tool and still reads nothing of
// p1; a user without the tool permissions sees no tools and calls none.
func TestMCPNoPermissionFromTools(t *testing.T) {
	d := deploy(t)
	st := d.St
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	st.Client("carol", []string{"member"}, "p2")
	st.Client("guest", []string{"guest"}, "p1")
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "d1"},
		[]byte(notes)); err != nil {
		t.Fatal(err)
	}
	if err := st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	carol := connect(t, d, "carol", "")
	if names := toolNames(t, carol); len(names) != 4 {
		t.Fatalf("carol's tools: %v", names)
	}
	if _, err := call(carol, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("carol reads p1's document: %v", err)
	}
	if _, err := readResource(carol, "fga://vault/q3/notes.md"); !resourceNotFound(err) {
		t.Fatalf("carol's resource read: %v", err)
	}
	var found mcpsvc.SearchOutput
	if _, err := call(carol, mcpsvc.ToolSearch, map[string]any{"bucket": "vault"}, &found); err == nil && len(found.Results) > 0 {
		t.Fatalf("carol finds %+v", found)
	}
	if res, err := carol.ListResources(ctx, nil); err != nil || len(res.Resources) != 0 {
		t.Fatalf("carol lists %v, %v", res, err)
	}

	guest := connect(t, d, "guest", "")
	if names := toolNames(t, guest); len(names) != 0 {
		t.Fatalf("the guest's tools: %v", names)
	}
	if _, err := call(guest, mcpsvc.ToolReadDocument, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil); err == nil ||
		!strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("the guest calls a tool: %v", err)
	}
}

// TestMCPSessions covers MCP-007 and V-115: a session is bound to the user
// whose token opened it; another user's token, a token for another
// audience or none is refused, and the session ID alone is no authority.
func TestMCPSessions(t *testing.T) {
	d := deploy(t)
	d.St.ModeBucket("vault", "p1", "internal", "server")
	d.St.Client("alice", []string{"member"}, "p1")
	d.St.Client("bob", []string{"member"}, "p1")
	if err := d.St.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	s := stateful(t, d, "alice")
	if s.ID() == "" {
		t.Fatal("no session ID")
	}
	storageToken, err := d.St.Issuer.Issue("alice", r1test.Tenant, content.Audience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	post := func(token string) int {
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`
		req, _ := http.NewRequest(http.MethodPost, d.MCP.URL+"/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Session-Id", s.ID())
		req.Header.Set("Mcp-Protocol-Version", s.InitializeResult().ProtocolVersion)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(d.Token(t, "alice")); code != http.StatusOK {
		t.Fatalf("alice in her session: %d", code)
	}
	for name, c := range map[string]struct {
		token string
		want  int
	}{
		"bob's token in alice's session (V-115)": {d.Token(t, "bob"), http.StatusForbidden},
		"alice's token for the storage role":     {storageToken, http.StatusUnauthorized},
		"no token":                               {"", http.StatusUnauthorized},
	} {
		if code := post(c.token); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
}

// serverDocument publishes a server-mode document of alice's that bob,
// of the same project, may read, and enables MCP for the tenant.
func serverDocument(t *testing.T, d *mcptest.Deployment) {
	t.Helper()
	d.St.ModeBucket("vault", "p1", "internal", "server")
	alice := d.St.Client("alice", []string{"member"}, "p1")
	d.St.Client("bob", []string{"member"}, "p1")
	d.St.Client("carol", []string{"member"}, "p1")
	if _, err := d.St.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "d1"},
		[]byte(notes)); err != nil {
		t.Fatal(err)
	}
	if err := d.St.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
}

// TestMCPPanicContained covers fault isolation in the MCP role: a panic
// while serving one request fails that request only. The SDK runs
// handlers in its own goroutines, so without the role's guard the panic
// would end the process and every user's session.
func TestMCPPanicContained(t *testing.T) {
	var panicking atomic.Bool
	d := mcptest.Deploy(t, mcpsvc.DefaultLimits, func(string) {
		if panicking.Load() {
			panic("a broken decision client")
		}
	})
	serverDocument(t, d)
	alice, bob := connect(t, d, "alice", ""), connect(t, d, "bob", "")
	read := map[string]any{"bucket": "vault", "key": "q3/notes.md"}

	panicking.Store(true)
	if _, err := call(alice, mcpsvc.ToolReadDocument, read, nil); err == nil || strings.Contains(err.Error(), "broken") {
		t.Fatalf("a panicking call: %v", err)
	}
	if _, err := readResource(alice, "fga://vault/q3/notes.md"); err == nil {
		t.Fatal("a panicking resource read succeeded")
	}
	if _, err := alice.ListTools(ctx, nil); err == nil {
		t.Fatal("a panicking tools/list succeeded")
	}
	panicking.Store(false)
	for name, s := range map[string]*mcp.ClientSession{"alice": alice, "bob": bob} {
		if text, err := call(s, mcpsvc.ToolReadDocument, read, nil); err != nil || !strings.HasPrefix(text, "First paragraph.") {
			t.Fatalf("%s after the panics: %q %v", name, text, err)
		}
	}
}

// TestMCPLimits covers the MCP role's load bounds: open sessions and
// concurrent calls are bounded per user and in total, a request over a
// bound is refused at once, and closing a session frees its place.
func TestMCPLimits(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	d := mcptest.Deploy(t, mcpsvc.Limits{MaxBytes: 1 << 20, MaxUnits: 100, UserRequests: 1, TotalRequests: 2, UserSessions: 2, TotalSessions: 3},
		func(body string) {
			if strings.Contains(body, `"actor":{"id":"alice"`) && strings.Contains(body, `"name":"documents.read"`) {
				entered <- struct{}{}
				<-proceed
			}
		})
	serverDocument(t, d)
	a1, a2 := stateful(t, d, "alice"), stateful(t, d, "alice")
	if _, err := d.ConnectWith(t, mcptest.Conn{User: "alice", Protocol: mcptest.Stateful}); err == nil {
		t.Fatal("alice opened a third session")
	}
	b := stateful(t, d, "bob")
	if _, err := d.ConnectWith(t, mcptest.Conn{User: "carol", Protocol: mcptest.Stateful}); err == nil {
		t.Fatal("a session over the total")
	}

	// alice's call holds her one call slot; her next call is refused,
	// bob's goes ahead.
	read := map[string]any{"bucket": "vault", "key": "q3/notes.md"}
	done := make(chan error, 1)
	go func() {
		_, err := call(a1, mcpsvc.ToolReadDocument, read, nil)
		done <- err
	}()
	<-entered
	if _, err := call(a2, mcpsvc.ToolReadDocument, read, nil); err == nil {
		t.Fatal("alice's second concurrent call was admitted")
	}
	if _, err := call(b, mcpsvc.ToolReadDocument, read, nil); err != nil {
		t.Fatalf("bob's call: %v", err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatalf("alice's held call: %v", err)
	}

	// Closing a session frees its place.
	if err := a2.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := d.ConnectWith(t, mcptest.Conn{User: "alice", Protocol: mcptest.Stateful}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a closed session still counts")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestGatewayRevision covers the decision role's side of the MCP role
// having no identity store: for a configured gateway's own MCP
// operations on the user's token, a request naming revision 0 is decided
// at the user's current revision; any other adapter or operation must
// name the revision (ID-004).
func TestGatewayRevision(t *testing.T) {
	d := deploy(t)
	serverDocument(t, d)
	var bucket string
	if err := d.St.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'vault'`).Scan(&bucket); err != nil {
		t.Fatal(err)
	}
	tool := decisionsvc.Alias{Namespace: registry.MCPToolNamespace, Name: mcpsvc.ToolSearch}
	decide := func(adapter, audience, op string, check decisionsvc.Check) string {
		token, err := d.St.Issuer.Issue("bob", r1test.Tenant, audience, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		resp := d.St.Decisions.Decide(ctx, adapter, decisionsvc.Request{RequestID: "r-" + adapter + op, Tenant: r1test.Tenant,
			Operation: op, OperationID: "o-" + adapter + op, Audience: content.Audience, Actor: decisionsvc.Ref{ID: "bob"}, Evidence: token,
			Checks: []decisionsvc.Check{check}})
		return resp.Outcome + " " + resp.Reason
	}
	invoke := decisionsvc.Check{ID: "tool", Role: registry.RoleTool, Action: "invoke", Resource: tool}
	for _, c := range []struct {
		name, adapter, audience, op string
		check                       decisionsvc.Check
		want                        string
	}{
		{"the gateway's invoke", r1test.MCPAdapter, r1test.MCPAudience, registry.OpMCPInvoke, invoke, "ALLOW "},
		{"the gateway's discover", r1test.MCPAdapter, r1test.MCPAudience, registry.OpMCPDiscover,
			decisionsvc.Check{ID: "tool", Role: registry.RoleTool, Action: "discover", Resource: tool}, "ALLOW "},
		{"another adapter's MCP operation", r1test.StorageAdapter, content.Audience, registry.OpMCPInvoke, invoke, "DENY IDENTITY_STALE"},
		{"the gateway's other operation", r1test.MCPAdapter, r1test.MCPAudience, registry.OpListBucket,
			decisionsvc.Check{ID: "bucket", Role: registry.RoleBucket, Action: "list", Resource: decisionsvc.Alias{Type: "storage.bucket", ID: bucket}},
			"DENY IDENTITY_STALE"},
	} {
		if got := decide(c.adapter, c.audience, c.op, c.check); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func envelopeOf(t *testing.T, d mcpwire.Delivery) crypto.Envelope {
	return crypto.Envelope{Context: unb64(t, d.Envelope.Context), Ciphertext: unb64(t, d.Envelope.Ciphertext), Signature: d.Envelope.Signature}
}

// openObject verifies and decrypts an object package with c's key, as a
// compatible client does.
func openObject(t *testing.T, c *r1test.Client, p *mcpwire.Package) ([]byte, error) {
	t.Helper()
	if p == nil || p.Object == nil {
		t.Fatalf("no object package: %+v", p)
	}
	var out bytes.Buffer
	err := crypto.Decrypt(&out, bytes.NewReader(unb64(t, p.Object.Ciphertext)), crypto.Package{Descriptor: unb64(t, p.Object.Descriptor),
		DescriptorSignature: p.Object.DescriptorSignature, Envelope: envelopeOf(t, p.Object.Delivery)}, c.Recipient, c.Trust)
	return out.Bytes(), err
}

// openUnits decrypts every unit of a package with c's key.
func openUnits(t *testing.T, c *r1test.Client, p *mcpwire.Package) []string {
	t.Helper()
	if p == nil {
		t.Fatal("no package")
	}
	var out []string
	for _, u := range p.Units {
		var b bytes.Buffer
		if _, err := crypto.DecryptUnit(&b, bytes.NewReader(unb64(t, u.Ciphertext)), crypto.UnitPackage{Descriptor: unb64(t, u.Descriptor),
			DescriptorSignature: u.DescriptorSignature, Envelope: envelopeOf(t, u.Delivery)}, c.Recipient, c.Trust); err != nil {
			t.Fatalf("unit %s: %v", u.Unit, err)
		}
		out = append(out, b.String())
	}
	return out
}

// TestMCPClientMode covers MCP-005 for client-mode content: a generic MCP
// client gets an explicit capability error and no plaintext (V-170); a
// client that declares the encrypted-package capability gets the exact
// packages a native client downloads, which it decrypts with its own key,
// while the MCP role sees only ciphertext; units the user may not read are
// left out of the package without a trace.
func TestMCPClientMode(t *testing.T) {
	d := deploy(t)
	_, bob, plain, units := mcptest.ClientFixture(t, d)
	secret := "client-mode secret"

	generic := connect(t, d, "bob", "")
	if _, err := readResource(generic, "fga://reports/plan.bin"); err == nil || !strings.Contains(err.Error(), "client-mode") ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("a generic client reads a client-mode object (V-170): %v", err)
	}
	if _, err := call(generic, mcpsvc.ToolReadDocument, map[string]any{"bucket": "reports", "key": "q3.md"}, nil); err == nil ||
		!strings.Contains(err.Error(), "client-mode") {
		t.Fatalf("a generic client reads a client-mode document: %v", err)
	}

	s := connect(t, d, "bob", bob.Recipient.Fingerprint().String())
	res, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fga://reports/plan.bin"})
	if err != nil || len(res.Contents) != 1 || res.Contents[0].MIMEType != mcpwire.MIMEType {
		t.Fatalf("the object for a capable client: %+v %v", res, err)
	}
	if strings.Contains(res.Contents[0].Text, secret) {
		t.Fatal("plaintext in the MCP response")
	}
	var pkg mcpwire.Package
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &pkg); err != nil || pkg.Profile != mcpwire.Profile ||
		pkg.Recipient != bob.Recipient.Fingerprint().String() {
		t.Fatalf("package %+v, %v", pkg, err)
	}
	if got, err := openObject(t, bob, &pkg); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("bob opens the object: %v", err)
	}
	// An older client declares the capability under experimental, in a
	// session; it is served alike.
	older, err := d.ConnectWith(t, mcptest.Conn{User: "bob", Recipient: bob.Recipient.Fingerprint().String(), LegacyCapability: true,
		Protocol: mcptest.Stateful})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := older.ReadResource(ctx, &mcp.ReadResourceParams{URI: "fga://reports/plan.bin"}); err != nil ||
		len(res.Contents) != 1 || res.Contents[0].MIMEType != mcpwire.MIMEType {
		t.Fatalf("the object for an older capable client: %+v %v", res, err)
	}

	var out mcpsvc.ReadOutput
	text, err := call(s, mcpsvc.ToolReadDocument, map[string]any{"bucket": "reports", "key": "q3.md"}, &out)
	if err != nil || !strings.Contains(text, "Client-mode content") || len(out.Units) != 0 {
		t.Fatalf("the document for a capable client: %q %+v %v", text, out, err)
	}
	if got := openUnits(t, bob, out.Package); !slices.Equal(got, mcptest.Paragraphs) {
		t.Fatalf("bob's units: %q", got)
	}

	// A unit out of bob's reach is left out of the package, ID and all.
	alice := d.St.Client("alice", []string{"member"}, "p1")
	if _, err := d.St.Content.SetUnitLabel(ctx, alice.Caller, "reports", "q3.md", "", units[1], "restricted"); err != nil {
		t.Fatal(err)
	}
	res2, err := s.CallTool(ctx, &mcp.CallToolParams{Name: mcpsvc.ToolReadDocument, Arguments: map[string]any{"bucket": "reports", "key": "q3.md"}})
	if err != nil || res2.IsError {
		t.Fatalf("after the label change: %+v %v", res2, err)
	}
	raw, _ := json.Marshal(res2)
	if strings.Contains(string(raw), units[1]) {
		t.Fatal("the restricted unit's ID is in the response")
	}
	b, _ := json.Marshal(res2.StructuredContent)
	out = mcpsvc.ReadOutput{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if got := openUnits(t, bob, out.Package); !slices.Equal(got, []string{mcptest.Paragraphs[0], mcptest.Paragraphs[2]}) {
		t.Fatalf("bob's units after the label change: %q", got)
	}
	if _, err := readResource(s, "fga://reports/q3.md?unit="+units[1]); !resourceNotFound(err) {
		t.Fatalf("bob reads the restricted unit: %v", err)
	}

	carol := connect(t, d, "carol", bob.Recipient.Fingerprint().String())
	if _, err := call(carol, mcpsvc.ToolReadDocument, map[string]any{"bucket": "reports", "key": "q3.md"}, nil); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("carol, of another project: %v", err)
	}
}

// TestMCPExport covers documents.export in both modes (the compound export
// operation, MCP-005): server mode returns the plaintext of a complete
// export, client mode the ciphertext and the recipient's existing
// envelopes, which only that recipient opens; export needs its own
// permission, and a recipient without an envelope gets nothing.
func TestMCPExport(t *testing.T) {
	d := deploy(t)
	alice, bob, plain, _ := mcptest.ClientFixture(t, d)
	d.St.ModeBucket("vault", "p1", "internal", "server")
	if _, err := d.St.Content.PutObject(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "plan.txt", IdempotencyKey: "o1"},
		8, strings.NewReader("the plan")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.St.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "d1"},
		[]byte(notes)); err != nil {
		t.Fatal(err)
	}
	a := connect(t, d, "alice", "")

	// Server mode.
	var x mcpsvc.ExportOutput
	if text, err := call(a, mcpsvc.ToolExport, map[string]any{"bucket": "vault", "key": "plan.txt"}, &x); err != nil || text != "the plan" ||
		string(unb64(t, x.Object)) != "the plan" {
		t.Fatalf("server-mode object export: %q %+v %v", text, x, err)
	}
	x = mcpsvc.ExportOutput{}
	if text, err := call(a, mcpsvc.ToolExport, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, &x); err != nil ||
		text != strings.TrimSpace(notes) || len(x.Units) != 3 {
		t.Fatalf("server-mode document export: %q %+v %v", text, x, err)
	}
	b := connect(t, d, "bob", "")
	if _, err := call(b, mcpsvc.ToolExport, map[string]any{"bucket": "vault", "key": "q3/notes.md"}, nil); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("bob may read but not export: %v", err)
	}

	// Client mode: alice exports for bob, who already has envelopes.
	if _, err := call(a, mcpsvc.ToolExport, map[string]any{"bucket": "reports", "key": "plan.bin"}, nil); err == nil ||
		!strings.Contains(err.Error(), "needs a recipient") {
		t.Fatalf("a client-mode export without a recipient: %v", err)
	}
	forBob := map[string]any{"bucket": "reports", "key": "plan.bin", "recipient": bob.Recipient.Fingerprint().String()}
	x = mcpsvc.ExportOutput{}
	if _, err := call(a, mcpsvc.ToolExport, forBob, &x); err != nil {
		t.Fatal(err)
	}
	if got, err := openObject(t, bob, x.Package); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("bob opens alice's export: %v", err)
	}
	if _, err := openObject(t, alice, x.Package); err == nil {
		t.Fatal("alice opened an export made for bob")
	}
	forBob["key"] = "q3.md"
	x = mcpsvc.ExportOutput{}
	if _, err := call(a, mcpsvc.ToolExport, forBob, &x); err != nil {
		t.Fatal(err)
	}
	if got := openUnits(t, bob, x.Package); !slices.Equal(got, mcptest.Paragraphs) {
		t.Fatalf("bob's units of the export: %q", got)
	}
	carol := d.St.Client("carol", []string{"member"}, "p2")
	if _, err := call(a, mcpsvc.ToolExport, map[string]any{"bucket": "reports", "key": "plan.bin",
		"recipient": carol.Recipient.Fingerprint().String()}, nil); err == nil {
		t.Fatal("an export for a recipient without an envelope")
	}
}

// TestMCPTransport covers the MCP transport and authorization rules the
// role follows: a client of protocol 2026-07-28 is served without a
// session and an earlier one in a session; the protected resource
// metadata (RFC 9728) names the endpoint and its authorization servers,
// and a request without a token is pointed to it; a browser request from
// an origin not allowed is refused before its token is looked at.
func TestMCPTransport(t *testing.T) {
	const public = "https://mcp.example/mcp"
	d := mcptest.DeployWith(t, mcptest.Options{Limits: mcpsvc.DefaultLimits, Edit: func(deps *mcpsvc.Deps) {
		deps.PublicURL, deps.AuthorizationServers = public, []string{"https://idp.example"}
		deps.AllowedOrigins = []string{"https://app.example"}
	}})
	serverDocument(t, d)
	if s := connect(t, d, "alice", ""); s.InitializeResult().ProtocolVersion != "2026-07-28" || s.ID() != "" {
		t.Fatalf("the newest protocol: %q, session %q", s.InitializeResult().ProtocolVersion, s.ID())
	}
	if s := stateful(t, d, "alice"); s.InitializeResult().ProtocolVersion != mcptest.Stateful || s.ID() == "" {
		t.Fatalf("a protocol with sessions: %q, session %q", s.InitializeResult().ProtocolVersion, s.ID())
	}

	resp, err := http.Get(d.MCP.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	err = json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || meta.Resource != public || !slices.Equal(meta.AuthorizationServers, []string{"https://idp.example"}) {
		t.Fatalf("metadata: %d %+v %v", resp.StatusCode, meta, err)
	}

	post := func(origin, token string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, d.MCP.URL+"/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize",`+
			`"params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := post("", ""); r.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(r.Header.Get("WWW-Authenticate"), `resource_metadata="https://mcp.example/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("no token: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	token := d.Token(t, "alice")
	if r := post("http://rebound.example", token); r.StatusCode != http.StatusForbidden {
		t.Fatalf("another origin: %d", r.StatusCode)
	}
	if r := post("https://app.example", token); r.StatusCode != http.StatusOK {
		t.Fatalf("the allowed origin: %d", r.StatusCode)
	}
}
