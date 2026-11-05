package adminapi_test

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	"fga/internal/cryptowire"
)

// TestSignInKeyRoutes covers the admin API's sign-in key routes
// (docs/design/sign-in-keys.md): an administrator registers, lists and
// removes an account's keys; nobody else does.
func TestSignInKeyRoutes(t *testing.T) {
	f := newFixture(t)
	if status, out := f.admin("PUT", "/v1/admin/identities/greenhouse-sensor", map[string]any{"roles": []string{"device"}}); status != http.StatusNoContent {
		t.Fatalf("identity: %d %v", status, out)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	body := map[string]any{"public_key": []byte(pub), "label": "greenhouse sensor 1",
		"limits": map[string]any{"services": []string{"fga-storage"}, "spaces": []string{"greenhouse"}}}
	status, out := f.admin("POST", "/v1/admin/identities/greenhouse-sensor/sign-in-keys", body)
	fp := cryptowire.SignInKeyFingerprint(pub).String()
	if status != http.StatusCreated || out["fingerprint"] != fp {
		t.Fatalf("add: %d %v", status, out)
	}
	if status, _ := f.admin("POST", "/v1/admin/identities/greenhouse-sensor/sign-in-keys", body); status != http.StatusBadRequest {
		t.Errorf("the same key twice: %d", status)
	}
	if status, _ := f.admin("POST", "/v1/admin/identities/nobody/sign-in-keys", body); status != http.StatusNotFound {
		t.Errorf("an unknown account: %d", status)
	}
	bad := map[string]any{"public_key": []byte("short"), "label": "x"}
	if status, _ := f.admin("POST", "/v1/admin/identities/greenhouse-sensor/sign-in-keys", bad); status != http.StatusBadRequest {
		t.Errorf("a short key: %d", status)
	}
	status, out = f.admin("GET", "/v1/admin/identities/greenhouse-sensor/sign-in-keys", nil)
	items, _ := out["items"].([]any)
	if status != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["status"] != "ACTIVE" ||
		items[0].(map[string]any)["limits"].(map[string]any)["spaces"].([]any)[0] != "greenhouse" {
		t.Fatalf("list: %d %v", status, out)
	}
	// Another account's key is not this one's to remove.
	if status, _ := f.admin("POST", "/v1/admin/identities/bob/sign-in-keys/"+fp+"/remove", nil); status != http.StatusNotFound {
		t.Errorf("removed through another account: %d", status)
	}
	if status, out := f.admin("POST", "/v1/admin/identities/greenhouse-sensor/sign-in-keys/"+fp+"/remove", nil); status != http.StatusOK || out["removed"] != true {
		t.Fatalf("remove: %d %v", status, out)
	}
	if status, out := f.admin("POST", "/v1/admin/identities/greenhouse-sensor/sign-in-keys/"+fp+"/remove", nil); status != http.StatusOK || out["removed"] != false {
		t.Errorf("remove again: %d %v", status, out)
	}
	// A member is not an administrator.
	if status, _, _ := f.call("GET", "/v1/admin/identities/greenhouse-sensor/sign-in-keys", "console-1", f.token("bob", "t-acme", "fga-admin"), nil); status != http.StatusForbidden {
		t.Errorf("a member listed keys: %d", status)
	}
}
