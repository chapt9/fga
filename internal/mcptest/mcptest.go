// Package mcptest deploys the MCP role for tests, as in production: a
// decision role and a storage role over HTTP, optionally the tools role,
// and the MCP role calling them as its workload (mcp-1), over the r1test
// stack. The MCP role's own tests and the bridge's use it. Test code only;
// no role links it.
package mcptest

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/admission"
	"fga/internal/content"
	"fga/internal/executor"
	"fga/internal/httpapi"
	"fga/internal/mcpsvc"
	"fga/internal/mcpwire"
	"fga/internal/nativeapi"
	"fga/internal/r1test"
	"fga/internal/registry"
)

// Deployment is the deployed stack.
type Deployment struct {
	St      *r1test.Stack
	Storage *httptest.Server
	// MCP serves the MCP role's handler; its endpoint is MCP.URL + "/mcp".
	MCP *httptest.Server
}

// Options shape a deployment.
type Options struct {
	Limits mcpsvc.Limits
	// BeforeDecision, if set, runs in the MCP role's goroutine before each
	// of its decision requests is sent, with the request body.
	BeforeDecision func(body string)
	// Stack makes the r1test stack.
	Stack r1test.Options
	// Tools, if set, returns the tools role over the stack, which the MCP
	// role then reaches over HTTP as its gateway.
	Tools func(st *r1test.Stack) *executor.Service
}

// Deploy deploys with limits. beforeDecision, if set, runs in the MCP
// role's goroutine before each of its decision requests is sent, with the
// request body.
func Deploy(t *testing.T, limits mcpsvc.Limits, beforeDecision func(body string)) *Deployment {
	t.Helper()
	return DeployWith(t, Options{Limits: limits, BeforeDecision: beforeDecision})
}

// DeployWith deploys as o says.
func DeployWith(t *testing.T, o Options) *Deployment {
	t.Helper()
	st := r1test.NewWith(t, o.Stack)
	limits, beforeDecision := o.Limits, o.BeforeDecision
	workloadOf := func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Workload"), nil }
	decision := httptest.NewServer(st.Decisions.Handler(workloadOf))
	t.Cleanup(decision.Close)
	gw := &httpapi.Gateway{AdapterOf: workloadOf, Adapters: map[string]bool{r1test.MCPAdapter: true}, Operation: registry.OpMCPInvoke,
		Verifier: st.Verifier(content.Audience)}
	storage := httptest.NewServer(nativeapi.StorageWith(st.Content, st.Tokens, func() bool { return true },
		admission.New(admission.DefaultLimits), gw))
	t.Cleanup(storage.Close)
	asMCP := &http.Client{Transport: Workload(r1test.MCPAdapter)}
	toDecision := asMCP
	if beforeDecision != nil {
		toDecision = &http.Client{Transport: hooked{Workload(r1test.MCPAdapter), beforeDecision}}
	}
	deps := mcpsvc.Deps{Tokens: st.Tokens, Audience: r1test.MCPAudience, StorageAudience: content.Audience,
		Decision: mcpsvc.Peer{URL: decision.URL, HTTP: toDecision}, Storage: mcpsvc.Peer{URL: storage.URL, HTTP: asMCP},
		Buckets: []string{"vault", "other"}, Limits: limits, Logger: slog.New(slog.DiscardHandler)}
	if o.Tools != nil {
		toolsGW := &httpapi.Gateway{AdapterOf: workloadOf, Adapters: map[string]bool{r1test.MCPAdapter: true}, Operation: registry.OpMCPInvoke,
			Verifier: st.Verifier(executor.Audience)}
		tools := httptest.NewServer(executor.Handler(o.Tools(st), st.Tokens, func() bool { return true },
			admission.New(admission.DefaultLimits), toolsGW))
		t.Cleanup(tools.Close)
		deps.Tools, deps.ToolsAudience = mcpsvc.Peer{URL: tools.URL, HTTP: asMCP}, executor.Audience
	}
	svc, err := mcpsvc.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)
	return &Deployment{St: st, Storage: storage, MCP: srv}
}

// Workload is a transport that presents a workload identity, as the test
// stack identifies workloads: by a header.
type Workload string

// RoundTrip implements http.RoundTripper.
func (w Workload) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Workload", string(w))
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

// Bearer is a transport that presents a bearer token.
type Bearer string

// RoundTrip implements http.RoundTripper.
func (b Bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

// Token issues user's token for the MCP role.
func (d *Deployment) Token(t *testing.T, user string) string {
	t.Helper()
	tok, err := d.St.Issuer.Issue(user, r1test.Tenant, r1test.MCPAudience, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Connect opens an MCP session for user. With a recipient fingerprint, the
// client declares the encrypted-package capability; otherwise it is a
// generic MCP client. The session closes when the test ends.
func (d *Deployment) Connect(t *testing.T, user, recipient string) (*mcp.ClientSession, error) {
	t.Helper()
	var opts *mcp.ClientOptions
	if recipient != "" {
		opts = &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{
			Experimental: mcpwire.ClientCapability{Version: mcpwire.Version, Recipient: recipient}.Experimental()}}
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, opts)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: d.MCP.URL + "/mcp",
		HTTPClient: &http.Client{Transport: Bearer(d.Token(t, user))}, MaxRetries: -1}, nil)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

// ConnectDelegated opens an MCP session for agent under the delegation dlg
// (mcpwire.DelegationHeader). The session closes when the test ends.
func (d *Deployment) ConnectDelegated(t *testing.T, agent, dlg string) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: d.MCP.URL + "/mcp",
		HTTPClient: &http.Client{Transport: Delegated{Token: d.Token(t, agent), Delegation: dlg}}, MaxRetries: -1}, nil)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

// Delegated is a transport that presents an agent's bearer token and the
// delegation it acts under.
type Delegated struct{ Token, Delegation string }

// RoundTrip implements http.RoundTripper.
func (d Delegated) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+d.Token)
	r.Header.Set(mcpwire.DelegationHeader, d.Delegation)
	return http.DefaultTransport.RoundTrip(r)
}

// Paragraphs are the units of the client-mode document ClientFixture
// publishes.
var Paragraphs = []string{"First client paragraph.", "Second client paragraph, restricted later.", "Third client paragraph."}

// ClientFixture publishes, in the client-mode bucket reports, alice's
// object plan.bin and three-unit document q3.md (Paragraphs), each with
// envelopes for alice and bob, members of p1; carol is of p2. MCP is
// enabled. It returns the object's plaintext and the units' IDs.
func ClientFixture(t *testing.T, d *Deployment) (alice, bob *r1test.Client, plain []byte, units []string) {
	t.Helper()
	d.St.Bucket("reports", "p1")
	alice = d.St.Client("alice", []string{"member"}, "p1")
	bob = d.St.Client("bob", []string{"member"}, "p1")
	d.St.Client("carol", []string{"member"}, "p2")
	alice.Pin(bob)
	bob.Pin(alice)
	plain = bytes.Repeat([]byte("client-mode secret "), 3000)
	if _, err := alice.Put("reports", "plan.bin", plain, alice, bob); err != nil {
		t.Fatal(err)
	}
	up, err := alice.PrepareDocument("reports", "q3.md", Paragraphs, nil, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	for _, u := range up.Intent.Units {
		units = append(units, u.Unit)
	}
	if err := d.St.Catalog.EnableMCP(context.Background(), r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	return alice, bob, plain, units
}
