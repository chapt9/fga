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
	   "when":"resource.attributes.project_id in principal.attributes.project_ids"},
	  {"id":"reviewers-share","effect":"allow","actions":["share"],"roles":["reviewer"]}]}`
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
	return newFixtureWith(t, outboxCapacity, business)
}

func newFixtureWith(t *testing.T, outboxCapacity int, business string) *fixture {
	t.Helper()
	ctx := context.Background()
	clock := func() time.Time { return now }
	types := registry.R1Types()

	ids := identity.NewMemoryStore()
	ids.Put(identity.Identity{ID: "user-42", Tenant: "t-acme", Revision: 88, Roles: []string{"reviewer"},
		Attributes: map[string]any{"project_ids": []string{"p1"}}})
	ids.Put(identity.Identity{ID: "agent-7", Tenant: "t-acme", Revision: 12, Roles: []string{"agent"}})
	ids.Put(identity.Identity{ID: "user-77", Tenant: "t-acme", Revision: 5, Roles: []string{"reviewer"},
		Attributes: map[string]any{"project_ids": []string{"p1"}}})
	ids.Put(identity.Identity{ID: "user-90", Tenant: "t-acme", Revision: 2, Roles: []string{"reviewer"},
		Attributes: map[string]any{"project_ids": []string{"p2"}}})
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
	env := release.Environment{Schema: types, SchemaDigest: types.Digest(), OperationsDigest: registry.R1Operations(types).Digest(),
		Audience: "fga-decision", MaxCostLimit: engine.DefaultOptions.CostLimit}
	releases := release.NewManager(map[string]ed25519.PublicKey{"pub-1": pub}, env, ep, clock)
	info := release.Info{Audience: "fga-decision", Business: []string{"b.json"}, CostLimit: engine.DefaultOptions.CostLimit}
	env.Stamp(&info)
	b := release.Bundle{Epoch: 1, KeyID: "pub-1", Info: info, Documents: map[string][]byte{"b.json": []byte(business), "c.json": []byte(ceiling)},
		Ceiling: []string{"c.json"}, CeilingDeclared: true}
	digest, _ := b.Digest()
	b.Signature = ed25519.Sign(priv, release.SigningBytes(1, digest))
	if err := releases.Activate(ctx, b); err != nil {
		t.Fatal(err)
	}

	recipients := gate.MemoryRecipients{
		{"t-acme", "sha256:77"}:  {Fingerprint: "sha256:77", Principal: "user-77", KeyVersion: 1, Revision: 3, Active: true},
		{"t-acme", "sha256:90"}:  {Fingerprint: "sha256:90", Principal: "user-90", KeyVersion: 1, Revision: 1, Active: true},
		{"t-acme", "sha256:old"}: {Fingerprint: "sha256:old", Principal: "user-77", KeyVersion: 0, Revision: 9, Active: false},
	}
	g, err := gate.New(gate.Deps{Recipients: recipients, Identities: ids, Delegations: dels, Resources: resolver, Epochs: ep, Now: clock,
		Capabilities: capabilities{{"agent-7", "document.text_unit read"}: true, {"user-42", "document.text_unit share"}: true}})
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
	ops, err := registry.NewOperations(types, []registry.Operation{
		{Name: "unit.read", Checks: []registry.CheckSpec{{Role: "unit", ResourceType: "document.text_unit", Action: "read"}}},
		{Name: "unit.share", Checks: []registry.CheckSpec{
			{Role: "unit", ResourceType: "document.text_unit", Action: "share"},
			{Role: "recipient-read", ResourceType: "document.text_unit", Action: "read", Kind: registry.KindRecipientEligibility, Repeated: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{Decider: decider, Gate: g, Releases: releases, Resolver: resolver, Types: types, Operations: ops, Signer: signer,
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
	return Request{RequestID: "r-81", Tenant: "t-acme", Operation: "unit.read", OperationID: "op-9f3", OperationDigest: "sha256:op",
		Audience: "storage", Actor: Ref{ID: "agent-7", Revision: 12}, Subject: &Ref{ID: "user-42", Revision: 88}, Delegation: "dlg-5",
		Checks: []Check{{ID: "c1", Role: "unit", Action: "read", Resource: Alias{Namespace: "mcp", Name: alias}}}}
}

// shareRequest is user-42 sharing u-1 with the holders of the given
// recipient keys.
func shareRequest(fingerprints ...string) Request {
	r := Request{RequestID: "r-82", Tenant: "t-acme", Operation: "unit.share", OperationID: "op-a1", OperationDigest: "sha256:share",
		Audience: "storage", Actor: Ref{ID: "user-42", Revision: 88},
		Checks: []Check{{ID: "share", Role: "unit", Action: "share", Resource: Alias{Type: "document.text_unit", ID: "u-1"}}}}
	for _, fp := range fingerprints {
		r.Checks = append(r.Checks, Check{ID: "read-" + fp, Role: "recipient-read", Action: "read", Kind: "RECIPIENT_ELIGIBILITY",
			PrincipalBinding: fp, Resource: Alias{Type: "document.text_unit", ID: "u-1"}})
	}
	return r
}

// TestRecipientChecks covers RES-009 and the check kinds: a recipient
// check is evaluated for the principal its fingerprint resolves to, the
// result names that principal, and the signed record binds it with the
// key's revision. An unknown or inactive key, or a recipient the policy
// does not allow, denies the whole batch.
func TestRecipientChecks(t *testing.T) {
	f := newFixture(t, 10)
	ctx := context.Background()
	resp := f.svc.Decide(ctx, "storage-1", shareRequest("sha256:77"))
	if resp.Outcome != "ALLOW" || resp.Results[0].PrincipalID != "user-42" || resp.Results[1].PrincipalID != "user-77" {
		t.Fatalf("share with user-77 = %+v", resp)
	}
	payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	rec, err := f.verifier.Verify(ctx, signing.Signed{Payload: payload, JWS: resp.Signed.JWS})
	if err != nil {
		t.Fatal(err)
	}
	if c := rec.Checks[1]; c.Kind != "RECIPIENT_ELIGIBILITY" || c.PrincipalBinding != "sha256:77" || c.Principal != (signing.Ref{ID: "user-77", Revision: 5}) || c.KeyRevision != 3 {
		t.Fatalf("signed recipient check = %+v", c)
	}
	if c := rec.Checks[0]; c.Kind != "OPERATION" || c.Principal != (signing.Ref{ID: "user-42", Revision: 88}) {
		t.Fatalf("signed operation check = %+v", c)
	}

	for name, tc := range map[string]struct {
		req    Request
		reason string
	}{
		"unknown fingerprint":       {shareRequest("sha256:nobody"), "RECIPIENT_UNKNOWN"},
		"revoked key":               {shareRequest("sha256:old"), "RECIPIENT_INACTIVE"},
		"recipient may not read":    {shareRequest("sha256:77", "sha256:90"), "BUSINESS_DENY"},
		"no recipient check":        {shareRequest(), "OPERATION_MISMATCH"},
		"unregistered operation":    {func() Request { r := shareRequest("sha256:77"); r.Operation = "unit.delete"; return r }(), "UNKNOWN_OPERATION"},
		"other action for the role": {func() Request { r := shareRequest("sha256:77"); r.Checks[0].Action = "read"; return r }(), "OPERATION_MISMATCH"},
		"operation kind for recipient": {func() Request {
			r := shareRequest("sha256:77")
			r.Checks[1].Kind = ""
			return r
		}(), "OPERATION_MISMATCH"},
		"recipient kind for operation": {func() Request {
			r := shareRequest("sha256:77")
			r.Checks[0].Kind, r.Checks[0].PrincipalBinding = "RECIPIENT_ELIGIBILITY", "sha256:77"
			return r
		}(), "OPERATION_MISMATCH"},
	} {
		resp := f.svc.Decide(ctx, "storage-1", tc.req)
		if resp.Outcome != "DENY" || resp.Reason != tc.reason || resp.Signed != nil {
			t.Errorf("%s: %s %s, want DENY %s", name, resp.Outcome, resp.Reason, tc.reason)
		}
	}
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
	good := `{"request_id":"r","tenant":"t-acme","operation":"unit.read","operation_id":"o","operation_digest":"d","audience":"storage","single_use":false,
	  "actor":{"id":"agent-7","revision":12},"subject":{"id":"user-42","revision":88},"delegation":"dlg-5",
	  "checks":[{"id":"c1","role":"unit","action":"read","resource":{"namespace":"mcp","name":"doc://q3#overview"}}]}`
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

// TestTimeConditionBoundsValidity covers V-143 at the decision boundary:
// a grant that ends at a timestamp literal yields a decision valid only
// until that literal, even when the decision-age limit is later (POL-008,
// DEC-005). At the literal itself the grant no longer holds.
func TestTimeConditionBoundsValidity(t *testing.T) {
	cutoff := now.Add(20 * time.Second)
	timed := `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[
	  {"id":"read-until-cutoff","effect":"allow","actions":["read"],"roles":["reviewer"],
	   "when":"request.now < timestamp('` + cutoff.UTC().Format(time.RFC3339) + `')"}]}`
	f := newFixtureWith(t, 10, timed)
	resp := f.svc.Decide(context.Background(), "tools-gw-1", request("doc://q3#overview"))
	if resp.Outcome != "ALLOW" || resp.ValidUntil == nil || !resp.ValidUntil.Equal(cutoff) {
		t.Fatalf("response = %+v, want ALLOW valid until %v (the age limit is +30s)", resp, cutoff)
	}
	payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	if rec, err := f.verifier.Verify(context.Background(), signing.Signed{Payload: payload, JWS: resp.Signed.JWS}); err != nil || !rec.ValidUntil.Equal(cutoff) {
		t.Fatalf("signed record = %+v, %v", rec, err)
	}
}

// TestPublicProjection covers DEC-010: in the public projection an unknown
// target, a business denial, a ceiling denial and a prerequisite outcome
// look the same, while the internal response keeps them apart; request
// errors and failures stay distinguishable without naming a target.
func TestPublicProjection(t *testing.T) {
	f := newFixture(t, 100)
	ctx := context.Background()
	unknown := f.svc.Decide(ctx, "tools-gw-1", request("doc://q3#missing"))
	ceilingDenied := f.svc.Decide(ctx, "tools-gw-1", request("doc://q3#draft"))
	businessDenied := f.svc.Decide(ctx, "storage-1", shareRequest("sha256:77", "sha256:90"))
	if unknown.Reason != string(ReasonUnknownResource) || ceilingDenied.Reason != "CEILING_DENY" || businessDenied.Reason != "BUSINESS_DENY" {
		t.Fatalf("internal reasons = %s, %s, %s", unknown.Reason, ceilingDenied.Reason, businessDenied.Reason)
	}
	for name, r := range map[string]Response{"unknown": unknown, "ceiling": ceilingDenied, "business": businessDenied,
		"approval": {DecisionID: "x", Outcome: "NEEDS_APPROVAL", Reason: "APPROVAL_REQUIRED"}} {
		p := r.Public()
		p.DecisionID = ""
		if p != (PublicResponse{Outcome: "DENY", Reason: PublicDenied}) {
			t.Errorf("%s: public projection %+v", name, p)
		}
	}
	bad := request("doc://q3#overview")
	bad.Operation = "unit.erase"
	if p := f.svc.Decide(ctx, "tools-gw-1", bad).Public(); p.Reason != PublicInvalid {
		t.Errorf("unknown operation: %+v, want %s", p, PublicInvalid)
	}
	if p := (Response{Outcome: "ERROR", Reason: string(ReasonCatalogUnavailable)}).Public(); p.Outcome != "ERROR" || p.Reason != PublicUnavailable {
		t.Errorf("failure: %+v", p)
	}
	if p := f.svc.Decide(ctx, "tools-gw-1", request("doc://q3#overview")).Public(); p.Outcome != "ALLOW" {
		t.Errorf("allow: %+v", p)
	}
}
