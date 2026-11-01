package adminapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/adminapi"
	"fga/internal/adminops"
	"fga/internal/authn"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/pgtest"
	"fga/internal/release"
)

var ctx = context.Background()

type fixture struct {
	t          *testing.T
	url        string
	issuer     *authn.Issuer
	journal    *journal.Journal
	journalDir string
	pool       *pgxpool.Pool
	ops        adminops.Ops
	bundle     string
}

// newFixture serves the admin API over a fresh catalog and journal, with
// root the administrator of t-acme and console-1 the console. A request's
// console is its X-Console header here; fga-admin serve takes it from the
// verified client certificate.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, 1000)
}

// newFixtureWith is newFixture with an audit outbox of capacity events.
func newFixtureWith(t *testing.T, capacity int) *fixture {
	t.Helper()
	pool := pgtest.Pool(t, catalog.Migrate)
	dir := t.TempDir()
	j, err := journal.Init(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.RecordJournal(ctx, pool, j.ID(), nil); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	issuer, err := authn.NewIssuer("test-issuer", "k1", priv, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, issuer: issuer, journal: j, journalDir: dir, pool: pool, bundle: signedBundle(t)}
	f.ops = adminops.Ops{Store: catalog.New(pool, capacity), Journal: func() (*journal.Journal, error) { return j, nil }, Now: time.Now}
	srv := httptest.NewServer(adminapi.Handler(adminapi.Config{
		Ops: f.ops, Tokens: authn.NewVerifier("test-issuer", map[string]ed25519.PublicKey{"k1": pub}, time.Now), Audience: "fga-admin",
		Admins: map[string][]string{"t-acme": {"root"}}, Consoles: []string{"console-1"},
		ConsoleOf: func(r *http.Request) (string, error) {
			if c := r.Header.Get("X-Console"); c != "" {
				return c, nil
			}
			return "", errors.New("no verified client certificate")
		},
		Policy: func() (adminapi.Policy, error) { return adminapi.LoadPolicy(f.bundle, publisherKeys) },
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

var publisherPub, publisherPriv, _ = ed25519.GenerateKey(nil)
var publisherKeys = map[string]ed25519.PublicKey{"publisher-1": publisherPub}

// signedBundle copies the example bundle and signs it as fga policy sign
// does.
func signedBundle(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := os.CopyFS(dir, os.DirFS("../../examples/local/bundle")); err != nil {
		t.Fatal(err)
	}
	b, m, err := release.LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Epoch = 1
	digest, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	m.Epoch, m.KeyID = 1, "publisher-1"
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(publisherPriv, release.SigningBytes(1, digest)))
	if err := release.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (f *fixture) token(subject, tenant, audience string) string {
	f.t.Helper()
	tok, err := f.issuer.Issue(subject, tenant, audience, 10*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// call makes a request as console with token and decodes a JSON answer.
func (f *fixture) call(method, path, console, token string, body any) (int, map[string]any, http.Header) {
	f.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, f.url+path, rd)
	if console != "" {
		req.Header.Set("X-Console", console)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out, resp.Header
}

// admin makes a request as root through console-1.
func (f *fixture) admin(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	status, out, _ := f.call(method, path, "console-1", f.token("root", "t-acme", "fga-admin"), body)
	return status, out
}

func (f *fixture) journalKinds() []string {
	f.t.Helper()
	es, err := f.journal.Entries()
	if err != nil {
		f.t.Fatal(err)
	}
	var kinds []string
	for _, e := range es {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// TestRefusals covers ADM-002: only a configured console, presenting a
// valid token of an administrator of the tenant, is served.
func TestRefusals(t *testing.T) {
	f := newFixture(t)
	root := f.token("root", "t-acme", "fga-admin")
	for _, c := range []struct {
		name, console, token string
		want                 int
	}{
		{"no client certificate", "", root, http.StatusForbidden},
		{"another console", "console-2", root, http.StatusForbidden},
		{"no token", "console-1", "", http.StatusUnauthorized},
		{"a malformed token", "console-1", "not-a-token", http.StatusUnauthorized},
		{"another audience", "console-1", f.token("root", "t-acme", "fga-storage"), http.StatusUnauthorized},
		{"not an administrator", "console-1", f.token("bob", "t-acme", "fga-admin"), http.StatusForbidden},
		{"an administrator of another tenant", "console-1", f.token("root", "t-other", "fga-admin"), http.StatusForbidden},
	} {
		status, _, h := f.call("PUT", "/v1/admin/identities/mallory", c.console, c.token, map[string]any{"roles": []string{"admin"}})
		if status != c.want {
			t.Errorf("%s: %d, want %d", c.name, status, c.want)
		}
		if status == http.StatusUnauthorized && !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: no Bearer challenge", c.name)
		}
	}
	if ids, _ := f.ops.Store.ListIdentities(ctx, "t-acme", "", 10); len(ids) != 0 {
		t.Fatalf("a refused request made %+v", ids)
	}
	if status, _, _ := f.call("GET", "/healthz", "", "", nil); status != http.StatusOK {
		t.Fatalf("healthz = %d", status)
	}
}

// TestDirectory drives the directory through the API: every change is
// audited with the administrator and console, and those that take access
// away are journaled first.
func TestDirectory(t *testing.T) {
	f := newFixture(t)
	expect := func(what string, got, want int, out map[string]any) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: %d %v, want %d", what, got, out, want)
		}
	}
	status, out := f.admin("PUT", "/v1/admin/identities/bob", map[string]any{"roles": []string{"member"}, "attributes": map[string]any{"projects": []string{"p1"}}})
	expect("put bob", status, http.StatusNoContent, out)
	status, out = f.admin("PUT", "/v1/admin/identities/agent-7", map[string]any{"roles": []string{"agent"}})
	expect("put agent-7", status, http.StatusNoContent, out)
	status, out = f.admin("PUT", "/v1/admin/identities/bob", `{"roles":["member"],"admin":true}`)
	expect("an unknown field", status, http.StatusBadRequest, out)

	status, out = f.admin("POST", "/v1/admin/identities/bob/capabilities/grant", map[string]any{"preset": "storage"})
	expect("grant a preset", status, http.StatusNoContent, out)
	status, out = f.admin("POST", "/v1/admin/identities/bob/capabilities/grant", map[string]any{"preset": "everything"})
	expect("an unknown preset", status, http.StatusBadRequest, out)
	status, out = f.admin("POST", "/v1/admin/identities/bob/capabilities/grant", map[string]any{"capabilities": map[string][]string{"storage.object": {"fly"}}})
	expect("an unknown action", status, http.StatusBadRequest, out)
	status, out = f.admin("POST", "/v1/admin/identities/ghost/capabilities/grant", map[string]any{"preset": "storage"})
	expect("grant to an unknown identity", status, http.StatusBadRequest, out)

	status, out = f.admin("GET", "/v1/admin/identities?limit=1", nil)
	expect("list identities", status, http.StatusOK, out)
	if items := out["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != "agent-7" || out["next"] != "agent-7" {
		t.Fatalf("first page = %v", out)
	}
	status, out = f.admin("GET", "/v1/admin/identities?after=agent-7", nil)
	expect("next page", status, http.StatusOK, out)
	bob := out["items"].([]any)[0].(map[string]any)
	if caps := bob["capabilities"].(map[string]any)["storage.object"].([]any); !slices.Contains(caps, any("read")) {
		t.Fatalf("bob's capabilities = %v", bob["capabilities"])
	}

	if kinds := f.journalKinds(); len(kinds) != 0 {
		t.Fatalf("additions were journaled: %v", kinds)
	}
	status, out = f.admin("POST", "/v1/admin/identities/bob/capabilities/revoke", map[string]any{"capabilities": map[string][]string{"storage.object": {"read"}}})
	expect("revoke", status, http.StatusOK, out)
	if out["revoked"] != true || !slices.Equal(f.journalKinds(), []string{journal.AccessRemoved}) {
		t.Fatalf("revoke = %v, journal %v", out, f.journalKinds())
	}

	dlg := map[string]any{"id": "dlg-1", "actor": "agent-7", "subject": "bob", "audience": "mcp", "grants": map[string][]string{"storage.object": {"stat"}},
		"expires_in": "1h"}
	status, out = f.admin("POST", "/v1/admin/delegations", dlg)
	expect("add a delegation", status, http.StatusCreated, out)
	status, out = f.admin("POST", "/v1/admin/delegations", dlg)
	expect("the same delegation again", status, http.StatusConflict, out)
	dlg["id"], dlg["actor"] = "dlg-2", "ghost"
	status, out = f.admin("POST", "/v1/admin/delegations", dlg)
	expect("a delegation for an unknown actor", status, http.StatusBadRequest, out)
	status, out = f.admin("GET", "/v1/admin/delegations", nil)
	if items := out["items"].([]any); status != http.StatusOK || len(items) != 1 {
		t.Fatalf("delegations = %d %v", status, out)
	}
	status, out = f.admin("POST", "/v1/admin/delegations/dlg-1/revoke", nil)
	expect("revoke a delegation", status, http.StatusNoContent, out)

	status, out = f.admin("POST", "/v1/admin/buckets", map[string]any{"name": "shared", "project": "p1"})
	expect("create a bucket", status, http.StatusCreated, out)
	if out["encryption"] != "server" {
		t.Fatalf("a bucket's default encryption = %v", out["encryption"])
	}
	status, out = f.admin("POST", "/v1/admin/buckets", map[string]any{"name": "shared", "project": "p1"})
	expect("the same bucket again", status, http.StatusConflict, out)
	status, out = f.admin("POST", "/v1/admin/buckets", map[string]any{"name": "Not A Name"})
	expect("an invalid bucket name", status, http.StatusBadRequest, out)
	status, out = f.admin("POST", "/v1/admin/mcp/enable", nil)
	expect("enable MCP", status, http.StatusNoContent, out)

	status, out = f.admin("POST", "/v1/admin/identities/bob/disable", nil)
	expect("disable bob", status, http.StatusNoContent, out)
	status, out = f.admin("POST", "/v1/admin/identities/ghost/disable", nil)
	expect("disable an unknown identity", status, http.StatusNotFound, out)
	want := []string{journal.AccessRemoved, journal.DelegationRevoked, journal.IdentityDisabled}
	if got := f.journalKinds(); !slices.Equal(got, want) {
		t.Fatalf("journal = %v, want %v (an unknown identity's disable journals nothing)", got, want)
	}

	status, out = f.admin("GET", "/v1/admin/events?limit=200", nil)
	expect("events", status, http.StatusOK, out)
	var changes []string
	for _, item := range out["items"].([]any) {
		e := item.(map[string]any)
		if e["kind"] != "administration" {
			continue
		}
		if e["actor"] != "root" || e["reason"] != "via console console-1" {
			t.Fatalf("event = %v", e)
		}
		changes = append(changes, e["outcome"].(string))
	}
	for _, c := range []string{"identity.put", "capabilities.grant", "capabilities.revoke", "delegation.add", "delegation.revoke", "bucket.create",
		"mcp.enable", "identity.disable"} {
		if !slices.Contains(changes, c) {
			t.Errorf("no %s event among %v", c, changes)
		}
	}
	status, out = f.admin("GET", "/v1/admin/whoami", nil)
	if status != http.StatusOK || out["tenant"] != "t-acme" || out["subject"] != "root" || out["console"] != "console-1" {
		t.Fatalf("whoami = %d %v", status, out)
	}
}

// TestTenantIsolation: an administrator sees and changes its own tenant
// only.
// TestDelegationRefusals covers audit F3: a delegation the catalog refuses
// as given is a bad request (400) with the reason, not an internal error.
func TestDelegationRefusals(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"agent-7", "agent-8", "bob"} {
		if status, out := f.admin("PUT", "/v1/admin/identities/"+id, map[string]any{"roles": []string{"member"}}); status >= 300 {
			t.Fatalf("identity %s: %d %v", id, status, out)
		}
	}
	dlg := func(id, parent, expires string, actions ...string) map[string]any {
		return map[string]any{"id": id, "actor": "agent-8", "subject": "bob", "audience": "mcp",
			"grants": map[string][]string{"storage.object": actions}, "expires_in": expires, "parent": parent}
	}
	parent := dlg("dlg-p", "", "1h", "stat")
	parent["actor"] = "agent-7"
	if status, out := f.admin("POST", "/v1/admin/delegations", parent); status != http.StatusCreated {
		t.Fatalf("the parent: %d %v", status, out)
	}
	revoked := dlg("dlg-r", "", "1h", "stat")
	revoked["actor"] = "agent-7"
	if status, _ := f.admin("POST", "/v1/admin/delegations", revoked); status != http.StatusCreated {
		t.Fatal("the revoked parent")
	}
	if status, _ := f.admin("POST", "/v1/admin/delegations/dlg-r/revoke", nil); status >= 300 {
		t.Fatal("revoking the parent")
	}
	for name, body := range map[string]map[string]any{
		"a missing parent":            dlg("dlg-1", "no-such", "30m", "stat"),
		"a revoked parent":            dlg("dlg-2", "dlg-r", "30m", "stat"),
		"wider than its parent":       dlg("dlg-3", "dlg-p", "30m", "read"),
		"outliving its parent":        dlg("dlg-4", "dlg-p", "2h", "stat"),
		"an ID longer than 128 bytes": dlg(strings.Repeat("d", 129), "", "30m", "stat"),
	} {
		if status, out := f.admin("POST", "/v1/admin/delegations", body); status != http.StatusBadRequest || out["error"] == "internal error" {
			t.Errorf("%s: %d %v, want 400 with the reason", name, status, out)
		}
	}
	if status, out := f.admin("POST", "/v1/admin/delegations", dlg("dlg-5", "dlg-p", "30m", "stat")); status != http.StatusCreated {
		t.Fatalf("a narrowing child: %d %v", status, out)
	}
}

// TestUnavailable covers audit F5: a security journal that cannot record
// a change, a catalog bound to another journal, and a full audit outbox
// refuse the change as unavailable (503), not as an internal error.
func TestUnavailable(t *testing.T) {
	disable := func(f *fixture) int {
		t.Helper()
		if status, out := f.admin("PUT", "/v1/admin/identities/lena", map[string]any{"roles": []string{"member"}}); status >= 300 {
			t.Fatalf("lena: %d %v", status, out)
		}
		status, _ := f.admin("POST", "/v1/admin/identities/lena/disable", nil)
		return status
	}
	f := newFixture(t)
	dir := f.journalDir
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if status := disable(f); status != http.StatusServiceUnavailable {
		t.Errorf("a journal that cannot be written: %d", status)
	}

	f = newFixture(t)
	if _, err := f.pool.Exec(ctx, `UPDATE journal_state SET journal_id = 'another' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if status := disable(f); status != http.StatusServiceUnavailable {
		t.Errorf("a catalog bound to another journal: %d", status)
	}

	f = newFixtureWith(t, 1)
	if status, _ := f.admin("PUT", "/v1/admin/identities/carl", map[string]any{"roles": []string{"member"}}); status >= 300 {
		t.Fatalf("the first change: %d", status)
	}
	if status, _ := f.admin("PUT", "/v1/admin/identities/dana", map[string]any{"roles": []string{"member"}}); status != http.StatusServiceUnavailable {
		t.Errorf("a full audit outbox: %d", status)
	}
}

func TestTenantIsolation(t *testing.T) {
	f := newFixture(t)
	if err := f.ops.PutIdentity(ctx, adminops.Who{Actor: "operator", Via: "test"}, "t-other", "eve", []string{"member", "lead"}, nil); err != nil {
		t.Fatal(err)
	}
	status, out := f.admin("GET", "/v1/admin/identities", nil)
	if status != http.StatusOK || len(out["items"].([]any)) != 0 {
		t.Fatalf("t-acme's administrator sees %v", out)
	}
	if status, out := f.admin("PUT", "/v1/admin/identities/eve", map[string]any{"roles": []string{}}); status != http.StatusNoContent {
		t.Fatalf("put = %d %v", status, out)
	}
	others, _ := f.ops.Store.ListIdentities(ctx, "t-other", "", 10)
	if len(others) != 1 || !slices.Contains(others[0].Roles, "lead") {
		t.Fatalf("t-other's eve changed: %+v", others)
	}
}

// TestPolicy: the console sees the signed bundle, and nothing once the
// bundle no longer matches its signature.
func TestPolicy(t *testing.T) {
	f := newFixture(t)
	status, out := f.admin("GET", "/v1/admin/policy", nil)
	if status != http.StatusOK || out["epoch"] != 1.0 || out["key_id"] != "publisher-1" {
		t.Fatalf("policy = %d %v", status, out)
	}
	docs := out["documents"].(map[string]any)
	if objects, ok := docs["objects.json"].(map[string]any); !ok || objects["resource"] != "storage.object" {
		t.Fatalf("documents = %v", docs)
	}
	path := filepath.Join(f.bundle, "policies", "objects.json")
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(raw, []byte(`"contractor"`), []byte(`"nobody"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, out := f.admin("GET", "/v1/admin/policy", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("a tampered bundle = %d %v", status, out)
	}
}
