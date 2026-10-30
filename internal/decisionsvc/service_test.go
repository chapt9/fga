package decisionsvc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fga/internal/audit"
	"fga/internal/decision"
	"fga/internal/delegation"
	"fga/internal/gate"
	"fga/internal/identity"
	"fga/internal/policy/engine"
	"fga/internal/registry"
	"fga/internal/release"
	"fga/internal/signing"
)

var now = time.Unix(1_800_000_000, 0)

const (
	business = `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[
	  {"id":"reviewers-read-own-projects","effect":"allow","actions":["read"],"roles":["reviewer"],
	   "when":"resource.attributes.project_id in principal.attributes.project_ids"}]}`
	ceiling = `{"format":"fga.policy/v1","set":"ceiling","resource":"document.text_unit","scope":"","rules":[
	  {"id":"only-live","effect":"deny","actions":["read"],"roles":["*"],"when":"resource.attributes.state != 'LIVE'"}]}`
)

type capabilities map[[2]string]bool

func (c capabilities) Allows(_ context.Context, _, actor, rt, action string) (bool, error) {
	return c[[2]string{actor, rt + " " + action}], nil
}

type epochs map[string]uint64

func (e epochs) RequiredEpoch(_ context.Context, tenant string) (uint64, error) {
	return e[tenant], nil
}

type fixture struct {
	svc      *Service
	outbox   *audit.MemoryOutbox
	verifier *signing.Verifier
	epochs   epochs
}

func newFixture(t *testing.T, outboxCapacity int) *fixture {
	t.Helper()
	ctx := context.Background()
	clock := func() time.Time { return now }
	types := registry.R1Types()

	ids := identity.NewMemoryStore()
	ids.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 88, Roles: []string{"reviewer"},
		Attributes: map[string]any{"project_ids": []string{"p1"}}})
	ids.Put(identity.Identity{ID: "agent-7", Tenant: "t-acme", Revision: 12, Roles: []string{"agent"}})
	dels := delegation.NewMemoryStore()
	if err := dels.Put(delegation.Delegation{ID: "dlg-5", Tenant: "t-acme", Actor: "agent-7", Subject: "user-42", Audience: "tools-gw-1",
		ExpiresAt: now.Add(time.Hour), Revision: 3, Grants: []delegation.Grant{{ResourceType: "document.text_unit", Actions: []string{"read"}}}}); err != nil {
		t.Fatal(err)
	}
	cat := registry.NewMemoryCatalog()
	cat.Put(registry.Resource{ID: "u-1", Tenant: "t-acme", Type: "document.text_unit", Generation: 17, MetadataRevision: 2,
		Attributes: map[string]any{"project_id": "p1", "state": "LIVE"}})
	cat.Put(registry.Resource{ID: "u-2", Tenant: "t-acme", Type: "document.text_unit", Generation: 4, MetadataRevision: 1,
		Attributes: map[string]any{"project_id": "p1", "state": "DRAFT"}})
	cat.SetAlias("t-acme", registry.Alias{Namespace: "mcp", Name: "doc://q3#overview"}, "u-1")
	cat.SetAlias("t-acme", registry.Alias{Namespace: "mcp", Name: "doc://q3#draft"}, "u-2")
	resolver := registry.NewResolver(cat, types)
	ep := epochs{"t-acme": 1}

	pub, priv, _ := ed25519.GenerateKey(nil)
	releases := release.NewManager(map[string]ed25519.PublicKey{"pub-1": pub}, types, engine.DefaultOptions, ep, clock)
	b := release.Bundle{Epoch: 1, KeyID: "pub-1", Documents: map[string][]byte{"b.json": []byte(business), "c.json": []byte(ceiling)}}
	digest, _ := b.Digest()
	b.Signature = ed25519.Sign(priv, release.SigningBytes(1, digest))
	if err := releases.Activate(ctx, b); err != nil {
		t.Fatal(err)
	}

	g, err := gate.New(gate.Deps{Identities: ids, Delegations: dels, Resources: resolver, Epochs: ep, Now: clock,
		Capabilities: capabilities{{"agent-7", "document.text_unit read"}: true}})
	if err != nil {
		t.Fatal(err)
	}
	decider, err := decision.NewDecider(g, releases, clock)
	if err != nil {
		t.Fatal(err)
	}
	decPub, decPriv, _ := ed25519.GenerateKey(nil)
	signer, err := signing.NewSigner("dec-1", decPriv)
	if err != nil {
		t.Fatal(err)
	}
	outbox := audit.NewMemoryOutbox(outboxCapacity)
	svc, err := New(Deps{Decider: decider, Gate: g, Releases: releases, Resolver: resolver, Types: types, Signer: signer,
		Outbox: outbox, Audiences: []string{"storage"}, MaxAge: 30 * time.Second, Limits: DefaultLimits, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	keys := func() map[string]signing.Key {
		return map[string]signing.Key{"dec-1": {Public: decPub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	}
	return &fixture{svc: svc, outbox: outbox, epochs: ep,
		verifier: signing.NewVerifier("storage", keys, signing.NewMemoryConsumption(), clock)}
}

func request(alias string) Request {
	return Request{RequestID: "r-81", Tenant: "t-acme", OperationID: "op-9f3", OperationDigest: "sha256:op", Audience: "storage",
		Actor: Ref{ID: "agent-7", Revision: 12}, Subject: &Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5",
		Checks: []Check{{ID: "c1", Action: "read", Resource: Alias{Namespace: "mcp", Name: alias}}}}
}

// TestAllowReturnsAVerifiableSignedDecision follows scenario A.1's read
// check end to end: resolve, gate, ceiling, business, bind, sign, audit.
func TestAllowReturnsAVerifiableSignedDecision(t *testing.T) {
	f := newFixture(t, 10)
	resp := f.svc.Decide(context.Background(), "tools-gw-1", request("doc://q3#overview"))
	if resp.Outcome != "ALLOW" || resp.Signed == nil {
		t.Fatalf("response = %+v, want ALLOW with a signed decision", resp)
	}
	payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	rec, err := f.verifier.Verify(context.Background(), signing.Signed{Payload: payload, JWS: resp.Signed.JWS})
	if err != nil {
		t.Fatal(err)
	}
	if rec.DecisionID != resp.DecisionID || rec.Checks[0].ResourceID != "u-1" || rec.Checks[0].Generation != 17 ||
		rec.Subject.ID != "user-42" || len(rec.DelegationRevisions) != 1 || rec.PolicyEpoch != 1 {
		t.Fatalf("signed record = %+v", rec)
	}
	events, _ := f.outbox.Pending(context.Background(), 10)
	if len(events) != 1 || events[0].Outcome != "ALLOW" || events[0].Checks[0].ResourceID != "u-1" {
		t.Fatalf("audit events = %+v", events)
	}
}

func TestNonAllowOutcomesAreNotSigned(t *testing.T) {
	tests := []struct {
		name        string
		edit        func(*fixture, *Request, *string)
		wantOutcome string
		wantReason  string
	}{
		{"ceiling objects to a DRAFT unit (V-006)", func(_ *fixture, r *Request, _ *string) {
			r.Checks[0].Resource.Name = "doc://q3#draft"
		}, "DENY", "CEILING_DENY"},
		{"unknown alias", func(_ *fixture, r *Request, _ *string) { r.Checks[0].Resource.Name = "doc://nope" }, "DENY", "UNKNOWN_RESOURCE"},
		{"unknown action", func(_ *fixture, r *Request, _ *string) { r.Checks[0].Action = "teleport" }, "DENY", "UNKNOWN_ACTION"},
		{"audience not served", func(_ *fixture, r *Request, _ *string) { r.Audience = "keys" }, "DENY", "INVALID_REQUEST"},
		{"too many checks", func(_ *fixture, r *Request, _ *string) {
			for i := 0; i < DefaultLimits.MaxChecks; i++ {
				r.Checks = append(r.Checks, r.Checks[0])
			}
		}, "DENY", "INVALID_REQUEST"},
		{"presented by another executor (V-023)", func(_ *fixture, _ *Request, adapter *string) { *adapter = "tools-gw-2" }, "DENY", "DELEGATION_AUDIENCE_MISMATCH"},
		{"required epoch above the active bundle (V-091)", func(f *fixture, _ *Request, _ *string) { f.epochs["t-acme"] = 2 }, "ERROR", "POLICY_UNAVAILABLE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, 10)
			req, adapter := request("doc://q3#overview"), "tools-gw-1"
			tt.edit(f, &req, &adapter)
			resp := f.svc.Decide(context.Background(), adapter, req)
			if resp.Outcome != tt.wantOutcome || resp.Reason != tt.wantReason || resp.Signed != nil {
				t.Fatalf("response = %s/%s signed=%v, want %s/%s unsigned", resp.Outcome, resp.Reason, resp.Signed != nil, tt.wantOutcome, tt.wantReason)
			}
			if events, _ := f.outbox.Pending(context.Background(), 10); len(events) != 1 || events[0].Outcome != tt.wantOutcome {
				t.Errorf("audit events = %+v, want one %s event", events, tt.wantOutcome)
			}
		})
	}
}

// TestNoDecisionWithoutAudit covers AUD-002: when the outbox is full, the
// service returns ERROR and no signed decision, even for an allowed request.
func TestNoDecisionWithoutAudit(t *testing.T) {
	f := newFixture(t, 1)
	_ = f.outbox.Append(context.Background(), audit.Event{ID: "earlier"})
	resp := f.svc.Decide(context.Background(), "tools-gw-1", request("doc://q3#overview"))
	if resp.Outcome != "ERROR" || resp.Reason != string(ReasonAuditUnavailable) || resp.Signed != nil {
		t.Fatalf("response = %+v, want ERROR AUDIT_UNAVAILABLE without a signature", resp)
	}
}

func TestHTTP(t *testing.T) {
	f := newFixture(t, 10)
	adapter := func(r *http.Request) (string, error) {
		if r.Header.Get("X-Test-Adapter") == "" {
			return "", http.ErrNoCookie
		}
		return r.Header.Get("X-Test-Adapter"), nil
	}
	srv := httptest.NewServer(f.svc.Handler(adapter))
	defer srv.Close()

	post := func(body string, withAdapter bool) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/decide-batch", bytes.NewBufferString(body))
		if withAdapter {
			req.Header.Set("X-Test-Adapter", "tools-gw-1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good := `{"request_id":"r","tenant":"t-acme","operation_id":"o","operation_digest":"d","audience":"storage","single_use":false,
	  "actor":{"id":"agent-7","revision":12},"subject":{"id":"user-42","revision":88},"delegation":"dlg-5",
	  "checks":[{"id":"c1","action":"read","resource":{"namespace":"mcp","name":"doc://q3#overview"}}]}`
	if code := post(good, true); code != http.StatusOK {
		t.Errorf("valid request: status %d", code)
	}
	// Roles cannot be supplied: the field does not exist and is rejected (V-020).
	if code := post(strings.Replace(good, `"tenant"`, `"roles":["admin"],"tenant"`, 1), true); code != http.StatusBadRequest {
		t.Errorf("request with a roles field: status %d, want 400", code)
	}
	if code := post(good, false); code != http.StatusUnauthorized {
		t.Errorf("request without an authenticated adapter: status %d, want 401", code)
	}
	if code := post(`{"tenant":"t-acme"`+strings.Repeat(" ", MaxRequestBytes)+`}`, true); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized request: status %d, want 413", code)
	}
	resp, _ := http.Get(srv.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz = %d, want 200", resp.StatusCode)
	}
}
