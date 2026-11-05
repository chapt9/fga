package nativeapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/authn"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/delegation"
	"fga/internal/journal"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/signing"
)

// TestSignInKeys covers docs/design/sign-in-keys.md end to end: an
// account signs its own token with a registered key; a key's limits deny
// what lies outside them, also for the requests an MCP decision chains
// to; a removed key stops at once and its removal is journaled.
func TestSignInKeys(t *testing.T) {
	d := deploy(t)
	ctx := context.Background()
	st := d.st
	st.Bucket("reports", "p1")
	st.Client("alice", []string{"member"}, "p1")
	if err := st.Catalog.EnableMCP(ctx, r1test.Tenant); err != nil {
		t.Fatal(err)
	}
	ops := adminops.Ops{Store: st.Catalog, Journal: func() (*journal.Journal, error) { return st.Journal, nil }, Now: func() time.Time { return *st.Clock }}
	admin := adminops.Who{Actor: "root", Via: "test"}
	type key struct {
		priv ed25519.PrivateKey
		fp   string
	}
	register := func(principal, label string, limits authn.KeyLimits) key {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		fp, err := ops.AddSignInKey(ctx, admin, r1test.Tenant, principal, pub, label, limits)
		if err != nil {
			t.Fatal(err)
		}
		if fp != cryptowire.SignInKeyFingerprint(pub).String() {
			t.Fatalf("fingerprint %s", fp)
		}
		return key{priv, fp}
	}
	sign := func(k key, principal, audience string) string {
		tok, err := authn.SignInToken(k.priv, k.fp, r1test.Tenant, principal, "fga", audience, *st.Clock, 0)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	var bucket string
	if err := st.Pool.QueryRow(ctx, `SELECT id::text FROM buckets WHERE name = 'reports'`).Scan(&bucket); err != nil {
		t.Fatal(err)
	}
	listAs := func(adapter, principal, evidence, dlg string) decisionsvc.Response {
		id, err := st.Catalog.GetIdentity(ctx, r1test.Tenant, principal)
		if err != nil {
			t.Fatal(err)
		}
		req := decisionsvc.Request{RequestID: cryptowire.NewUUID().String(),
			Tenant: r1test.Tenant, Operation: registry.OpListBucket, OperationID: cryptowire.NewUUID().String(), Audience: content.Audience,
			Actor: decisionsvc.Ref{ID: principal, Revision: id.Revision}, Evidence: evidence, Delegation: dlg,
			Checks: []decisionsvc.Check{{ID: "bucket", Role: registry.RoleBucket, Action: "list", Resource: decisionsvc.Alias{Type: "storage.bucket", ID: bucket}}}}
		if dlg != "" {
			// The delegation's subject, as the storage role names it.
			sub, err := st.Catalog.GetIdentity(ctx, r1test.Tenant, "alice")
			if err != nil {
				t.Fatal(err)
			}
			req.Subject = &decisionsvc.Ref{ID: "alice", Revision: sub.Revision}
		}
		return st.Decisions.Decide(ctx, adapter, req)
	}

	// A person's key: their own token lists their space, through the
	// decision role and over the storage role's HTTP API.
	laptop := register("alice", "Alice's laptop", authn.KeyLimits{})
	if r := listAs(r1test.StorageAdapter, "alice", sign(laptop, "alice", content.Audience), ""); r.Outcome != "ALLOW" {
		t.Fatalf("alice with her key: %s %s", r.Outcome, r.Reason)
	}
	get := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, d.storage.URL+"/v1/buckets/reports/objects", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(sign(laptop, "alice", content.Audience)); code != http.StatusOK {
		t.Fatalf("the storage role refused alice's key-signed token: %d", code)
	}
	// The key signs for alice only.
	st.Client("bob", []string{"member"}, "p1")
	if r := listAs(r1test.StorageAdapter, "bob", sign(laptop, "bob", content.Audience), ""); r.Outcome == "ALLOW" {
		t.Fatal("alice's key signed for bob")
	}

	// A key limited to another space is denied this one, whatever the
	// rules allow; one limited to the push API cannot sign in to keys.
	narrow := register("alice", "a script", authn.KeyLimits{Spaces: []string{"invoices"}})
	if r := listAs(r1test.StorageAdapter, "alice", sign(narrow, "alice", content.Audience), ""); r.Outcome != "DENY" || r.Reason != string(decisionsvc.ReasonKeyLimit) {
		t.Fatalf("a key limited to another space: %s %s", r.Outcome, r.Reason)
	}
	if code := get(sign(narrow, "alice", content.Audience)); code == http.StatusOK {
		t.Fatal("the storage role served a space outside the key's limits")
	}
	low := register("alice", "low", authn.KeyLimits{MaxLabel: "public"})
	if r := listAs(r1test.StorageAdapter, "alice", sign(low, "alice", content.Audience), ""); r.Outcome != "DENY" || r.Reason != string(decisionsvc.ReasonKeyLimit) {
		t.Fatalf("a key below the space's label: %s %s", r.Outcome, r.Reason)
	}

	// Removing a key stops it at once, and the removal is journaled.
	removed, err := ops.RemoveSignInKey(ctx, admin, r1test.Tenant, "alice", laptop.fp)
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if r := listAs(r1test.StorageAdapter, "alice", sign(laptop, "alice", content.Audience), ""); r.Outcome != "DENY" || r.Reason != string(decisionsvc.ReasonAuthentication) {
		t.Fatalf("a removed key: %s %s", r.Outcome, r.Reason)
	}
	if code := get(sign(laptop, "alice", content.Audience)); code != http.StatusUnauthorized {
		t.Fatalf("the storage role took a removed key: %d", code)
	}
	entries, err := st.Journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if last := entries[len(entries)-1]; last.Kind != journal.SignInKeyRemoved || last.Subject != laptop.fp {
		t.Fatalf("journal ends with %+v", last)
	}
	if _, err := ops.AddSignInKey(ctx, admin, r1test.Tenant, "alice", laptop.priv.Public().(ed25519.PublicKey), "again", authn.KeyLimits{}); err == nil {
		t.Fatal("a removed key was registered again")
	}

	// An MCP account has keys of its own. Its MCP decision carries the
	// key, so a request chained to it is held to the key's limits.
	st.User("agent-7", []string{"agent"}, "p1")
	if err := st.Catalog.PutDelegation(ctx, delegation.Delegation{ID: "dlg-alice", Tenant: r1test.Tenant, Actor: "agent-7", Subject: "alice",
		Audience: r1test.MCPAdapter, ExpiresAt: st.Clock.Add(time.Hour), Grants: []delegation.Grant{
			{ResourceType: "agent.tool", Actions: []string{"invoke"}}, {ResourceType: "storage.bucket", Actions: []string{"list"}}}},
		*st.Clock); err != nil {
		t.Fatal(err)
	}
	mcpFor := func(k key) signing.Signed {
		resp := st.Decisions.Decide(ctx, r1test.MCPAdapter, decisionsvc.Request{RequestID: cryptowire.NewUUID().String(), Tenant: r1test.Tenant,
			Operation: registry.OpMCPInvoke, OperationID: cryptowire.NewUUID().String(), Audience: content.Audience,
			Actor: decisionsvc.Ref{ID: "agent-7"}, Delegation: "dlg-alice", Evidence: sign(k, "agent-7", r1test.MCPAudience),
			Checks: []decisionsvc.Check{{ID: "tool", Role: registry.RoleTool, Action: "invoke", Resource: decisionsvc.Alias{Namespace: registry.MCPToolNamespace, Name: "documents.read"}}}})
		if resp.Outcome != "ALLOW" || resp.Signed == nil {
			t.Fatalf("the agent's MCP decision: %s %s", resp.Outcome, resp.Reason)
		}
		payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
		return signing.Signed{Payload: payload, JWS: resp.Signed.JWS}
	}
	agentFree := register("agent-7", "agent-7's bridge", authn.KeyLimits{Services: []string{r1test.MCPAudience}})
	agentNarrow := register("agent-7", "agent-7, invoices only", authn.KeyLimits{Services: []string{r1test.MCPAudience}, Spaces: []string{"invoices"}})
	free, narrowed := mcpFor(agentFree), mcpFor(agentNarrow)
	if r := listAs(r1test.StorageAdapter, "agent-7", free.Evidence(), "dlg-alice"); r.Outcome != "ALLOW" {
		t.Fatalf("chained to the agent's decision: %s %s", r.Outcome, r.Reason)
	}
	if r := listAs(r1test.StorageAdapter, "agent-7", narrowed.Evidence(), "dlg-alice"); r.Outcome != "DENY" || r.Reason != string(decisionsvc.ReasonKeyLimit) {
		t.Fatalf("chained to a narrow key's decision: %s %s", r.Outcome, r.Reason)
	}
	// The agent's key may not sign in to the storage role itself.
	if r := listAs(r1test.StorageAdapter, "agent-7", sign(agentFree, "agent-7", content.Audience), "dlg-alice"); r.Outcome == "ALLOW" {
		t.Fatal("an MCP-only key signed in to the storage role")
	}
	// Removing the agent's key ends what its decisions chain to as well.
	if _, err := ops.RemoveSignInKey(ctx, admin, r1test.Tenant, "agent-7", agentFree.fp); err != nil {
		t.Fatal(err)
	}
	if r := listAs(r1test.StorageAdapter, "agent-7", free.Evidence(), "dlg-alice"); r.Outcome != "DENY" || r.Reason != string(decisionsvc.ReasonAuthentication) {
		t.Fatalf("chained after the key's removal: %s %s", r.Outcome, r.Reason)
	}
}
