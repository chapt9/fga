package mcpsvc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/admission"
	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/httpapi"
	"fga/internal/mcpsvc"
	"fga/internal/nativeapi"
	"fga/internal/r1test"
	"fga/internal/registry"
)

var ctx = context.Background()

// deployment is a decision role and a storage role over HTTP, as in
// production, and the MCP role calling both as its workload (mcp-1).
type deployment struct {
	st      *r1test.Stack
	storage *httptest.Server
	mcp     *httptest.Server
}

func deploy(t *testing.T) *deployment { return deployWith(t, mcpsvc.DefaultLimits, nil) }

// deployWith deploys with limits; beforeDecision, if set, runs in the
// MCP role's goroutine before each of its decision requests is sent.
func deployWith(t *testing.T, limits mcpsvc.Limits, beforeDecision func(body string)) *deployment {
	t.Helper()
	st := r1test.New(t)
	workloadOf := func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Workload"), nil }
	decision := httptest.NewServer(st.Decisions.Handler(workloadOf))
	t.Cleanup(decision.Close)
	gw := &httpapi.Gateway{AdapterOf: workloadOf, Adapters: map[string]bool{r1test.MCPAdapter: true}, Operation: registry.OpMCPInvoke,
		Verifier: st.Verifier(content.Audience)}
	storage := httptest.NewServer(nativeapi.StorageWith(st.Content, st.Tokens, func() bool { return true },
		admission.New(admission.DefaultLimits), gw))
	t.Cleanup(storage.Close)
	asMCP := &http.Client{Transport: workload{r1test.MCPAdapter}}
	toDecision := asMCP
	if beforeDecision != nil {
		toDecision = &http.Client{Transport: hooked{workload{r1test.MCPAdapter}, beforeDecision}}
	}
	svc, err := mcpsvc.New(mcpsvc.Deps{Tokens: st.Tokens, Audience: r1test.MCPAudience, StorageAudience: content.Audience,
		Decision: mcpsvc.Peer{URL: decision.URL, HTTP: toDecision}, Storage: mcpsvc.Peer{URL: storage.URL, HTTP: asMCP},
		Buckets: []string{"vault", "other"}, Limits: limits, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)
	return &deployment{st: st, storage: storage, mcp: srv}
}

type workload struct{ name string }

func (w workload) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Workload", w.name)
	return http.DefaultTransport.RoundTrip(r)
}

// hooked runs before on each request's body, then sends it.
type hooked struct {
	next   http.RoundTripper
	before func(body string)
}

func (h hooked) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	h.before(string(b))
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(b))
	return h.next.RoundTrip(r)
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// mcpToken issues a user's token for the MCP role.
func (d *deployment) mcpToken(t *testing.T, user string) string {
	t.Helper()
	tok, err := d.st.Issuer.Issue(user, r1test.Tenant, r1test.MCPAudience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// connect opens an MCP session for user, as a generic MCP client.
func (d *deployment) connect(t *testing.T, user string) *mcp.ClientSession {
	t.Helper()
	s, err := d.tryConnect(t, user)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (d *deployment) tryConnect(t *testing.T, user string) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	s, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: d.mcp.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{d.mcpToken(t, user)}}, MaxRetries: -1}, nil)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
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
func (d *deployment) nativeUnit(t *testing.T, c *r1test.Client, bucket, key, unit string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, d.storage.URL+"/v1/buckets/"+bucket+"/document/unit/content?"+
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

// unitIDs lists the units a caller sees in a document.
func unitIDs(t *testing.T, st *r1test.Stack, c *r1test.Client, bucket, key string) []string {
	t.Helper()
	page, err := st.Content.ListUnits(ctx, c.Caller, bucket, key, "", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, u := range page.Units {
		out = append(out, u.Unit)
	}
	return out
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
	st := d.st
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
	units := unitIDs(t, st, alice, "vault", "q3/notes.md")
	s := d.connect(t, "bob")

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
	if names := toolNames(t, s); !slices.Equal(names, []string{mcpsvc.ToolReadDocument, mcpsvc.ToolSearch, mcpsvc.ToolReadText}) {
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
	a := d.connect(t, "alice")
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
	native := d.nativeUnit(t, bob, "vault", "q3/notes.md", units[2])
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
	st := d.st
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
	carol := d.connect(t, "carol")
	if names := toolNames(t, carol); len(names) != 3 {
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

	guest := d.connect(t, "guest")
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
	d.st.ModeBucket("vault", "p1", "internal", "server")
	d.st.Client("alice", []string{"member"}, "p1")
	d.st.Client("bob", []string{"member"}, "p1")
	if err := d.st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	s := d.connect(t, "alice")
	if s.ID() == "" {
		t.Fatal("no session ID")
	}
	storageToken, err := d.st.Issuer.Issue("alice", r1test.Tenant, content.Audience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	post := func(token string) int {
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`
		req, _ := http.NewRequest(http.MethodPost, d.mcp.URL+"/mcp", bytes.NewBufferString(body))
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
	if code := post(d.mcpToken(t, "alice")); code != http.StatusOK {
		t.Fatalf("alice in her session: %d", code)
	}
	for name, c := range map[string]struct {
		token string
		want  int
	}{
		"bob's token in alice's session (V-115)": {d.mcpToken(t, "bob"), http.StatusForbidden},
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
func serverDocument(t *testing.T, d *deployment) {
	t.Helper()
	d.st.ModeBucket("vault", "p1", "internal", "server")
	alice := d.st.Client("alice", []string{"member"}, "p1")
	d.st.Client("bob", []string{"member"}, "p1")
	d.st.Client("carol", []string{"member"}, "p1")
	if _, err := d.st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "q3/notes.md", IdempotencyKey: "d1"},
		[]byte(notes)); err != nil {
		t.Fatal(err)
	}
	if err := d.st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
}

// TestMCPPanicContained covers fault isolation in the MCP role: a panic
// while serving one request fails that request only. The SDK runs
// handlers in its own goroutines, so without the role's guard the panic
// would end the process and every user's session.
func TestMCPPanicContained(t *testing.T) {
	var panicking atomic.Bool
	d := deployWith(t, mcpsvc.DefaultLimits, func(string) {
		if panicking.Load() {
			panic("a broken decision client")
		}
	})
	serverDocument(t, d)
	alice, bob := d.connect(t, "alice"), d.connect(t, "bob")
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
	d := deployWith(t, mcpsvc.Limits{MaxBytes: 1 << 20, MaxUnits: 100, UserRequests: 1, TotalRequests: 2, UserSessions: 2, TotalSessions: 3},
		func(body string) {
			if strings.Contains(body, `"actor":{"id":"alice"`) && strings.Contains(body, `"name":"documents.read"`) {
				entered <- struct{}{}
				<-proceed
			}
		})
	serverDocument(t, d)
	a1, a2 := d.connect(t, "alice"), d.connect(t, "alice")
	if _, err := d.tryConnect(t, "alice"); err == nil {
		t.Fatal("alice opened a third session")
	}
	b := d.connect(t, "bob")
	if _, err := d.tryConnect(t, "carol"); err == nil {
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
		if _, err := d.tryConnect(t, "alice"); err == nil {
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
	if err := d.st.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'vault'`).Scan(&bucket); err != nil {
		t.Fatal(err)
	}
	tool := decisionsvc.Alias{Namespace: registry.MCPToolNamespace, Name: mcpsvc.ToolSearch}
	decide := func(adapter, audience, op string, check decisionsvc.Check) string {
		token, err := d.st.Issuer.Issue("bob", r1test.Tenant, audience, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		resp := d.st.Decisions.Decide(ctx, adapter, decisionsvc.Request{RequestID: "r-" + adapter + op, Tenant: r1test.Tenant,
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
