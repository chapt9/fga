package decisionsvc

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fga/internal/admission"
	"fga/internal/authn"
	"fga/internal/registry"
)

// TestSignInKeyRouteIsAdmitted is the regression test of the security
// review of 5 November 2026, finding 3: the gateway's key lookups ran
// outside the decision role's admission. Each now takes one of the
// gateway's request slots, as its decisions do, so a lookup over the
// bound is refused at once with 429; other workloads are refused as
// before.
func TestSignInKeyRouteIsAdmitted(t *testing.T) {
	f := newFixture(t, 100)
	pub, _, _ := ed25519.GenerateKey(nil)
	fp := "sha256:" + strings.Repeat("ab", 32)
	lookups := 0
	f.svc.d.Gateways = map[string][]string{"tools-gw-1": {"storage"}}
	f.svc.d.SignInKeys = func(tenant, fingerprint string) (authn.SignInKey, bool, error) {
		lookups++
		if tenant != "t-acme" || fingerprint != fp {
			return authn.SignInKey{}, false, nil
		}
		return authn.SignInKey{Tenant: tenant, Principal: "agent-7", Public: pub}, true, nil
	}
	f.svc.d.Admission = admission.New(admission.Limits{TenantRequests: 1, TenantStreams: 1, TotalRequests: 4})
	srv := httptest.NewServer(f.svc.Handler(func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Adapter"), nil }))
	defer srv.Close()
	get := func(adapter string) (int, SignInKeyAnswer) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/sign-in-keys/"+fp+"?tenant=t-acme", nil)
		req.Header.Set("X-Test-Adapter", adapter)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var a SignInKeyAnswer
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&a)
		}
		return resp.StatusCode, a
	}
	if code, a := get("tools-gw-1"); code != http.StatusOK || a.Principal != "agent-7" {
		t.Fatalf("the gateway's lookup: %d %+v", code, a)
	}
	if code, _ := get("storage-1"); code != http.StatusForbidden {
		t.Fatalf("a workload that is not a gateway: %d", code)
	}
	occupy, _ := f.svc.d.Admission.Acquire("tools-gw-1", false)
	before := lookups
	if code, _ := get("tools-gw-1"); code != http.StatusTooManyRequests || lookups != before {
		t.Fatalf("a lookup over the gateway's bound: %d, %d lookups ran", code, lookups-before)
	}
	occupy()
	if code, _ := get("tools-gw-1"); code != http.StatusOK {
		t.Fatalf("once the slot was free: %d", code)
	}
}

// TestKeyLimits covers how a sign-in key's limits narrow a decision
// (docs/design/sign-in-keys.md): spaces by a bucket's name or a
// resource's bucket, labels by the release's order, and nothing for a
// resource without a space or label.
func TestKeyLimits(t *testing.T) {
	order := []string{"public", "internal", "confidential", "restricted"}
	res := func(typ string, attrs map[string]any) registry.Resource {
		return registry.Resource{Type: typ, Attributes: attrs}
	}
	bucket := res("storage.bucket", map[string]any{"name": "greenhouse", "label": "internal"})
	reading := res("document.text_unit", map[string]any{"bucket": "greenhouse", "label": "confidential"})
	other := res("storage.object", map[string]any{"bucket": "reports", "label": "internal"})
	tool := res("agent.tool", map[string]any{})
	strange := res("storage.object", map[string]any{"bucket": "greenhouse", "label": "secret"})
	for name, c := range map[string]struct {
		limits authn.KeyLimits
		res    []registry.Resource
		want   bool
	}{
		"no limits":                   {authn.KeyLimits{}, []registry.Resource{bucket, reading, other, tool}, true},
		"its space":                   {authn.KeyLimits{Spaces: []string{"greenhouse"}}, []registry.Resource{bucket, reading, tool}, true},
		"another space":               {authn.KeyLimits{Spaces: []string{"greenhouse"}}, []registry.Resource{bucket, other}, false},
		"at its label":                {authn.KeyLimits{MaxLabel: "confidential"}, []registry.Resource{reading, other}, true},
		"above its label":             {authn.KeyLimits{MaxLabel: "internal"}, []registry.Resource{reading}, false},
		"a label outside the order":   {authn.KeyLimits{MaxLabel: "restricted"}, []registry.Resource{strange}, false},
		"a limit outside the order":   {authn.KeyLimits{MaxLabel: "top"}, []registry.Resource{other}, false},
		"no space or label to limit":  {authn.KeyLimits{Spaces: []string{"x"}, MaxLabel: "public"}, []registry.Resource{tool}, true},
		"services limit no resources": {authn.KeyLimits{Services: []string{"fga-storage"}}, []registry.Resource{other}, true},
	} {
		if got := (&keyUse{limits: c.limits}).allows(c.res, order); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
