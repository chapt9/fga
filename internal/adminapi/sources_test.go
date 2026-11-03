package adminapi_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

const sourceRecord = `{"format":"fga.source/v1","id":"greenhouse-climate","owner":"team-greenhouse",
 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/humidity","/sensor"]},
           {"name":"location","label":"restricted","fields":["/gps"]}]}`

// TestSourcesAPI drives sources through the admin API (ING-001, ING-008,
// D-G): add with the bucket, try a sample, review by another
// administrator naming the draft's digest, put a new draft, disable; and
// the refusals with their status codes.
func TestSourcesAPI(t *testing.T) {
	f := newFixture(t)
	if err := f.ops.Store.SetLabelOrder(ctx, 1, []string{"public", "internal", "confidential", "restricted"}); err != nil {
		t.Fatal(err)
	}
	expect := func(what string, got, want int, out map[string]any) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: %d %v, want %d", what, got, out, want)
		}
	}
	rita := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		status, out, _ := f.call(method, path, "console-1", f.token("rita", "t-acme", "fga-admin"), body)
		return status, out
	}
	status, out := f.admin("PUT", "/v1/admin/identities/team-greenhouse", map[string]any{"roles": []string{}})
	expect("put the owner", status, http.StatusNoContent, out)

	add := map[string]any{"bucket": map[string]any{"name": "greenhouse-climate", "project": "greenhouse"}, "source": json.RawMessage(sourceRecord)}
	status, out = f.admin("POST", "/v1/admin/sources", add)
	expect("add", status, http.StatusCreated, out)
	digest, _ := out["digest"].(string)
	if out["id"] != "greenhouse-climate" || out["version"] != 1.0 || out["state"] != "DRAFT" || digest == "" {
		t.Fatalf("add answered %v", out)
	}
	status, out = f.admin("POST", "/v1/admin/sources", add)
	expect("add again", status, http.StatusConflict, out)
	status, out = f.admin("POST", "/v1/admin/buckets", map[string]any{"name": "other", "source": "greenhouse-climate"})
	expect("a bucket naming a source", status, http.StatusBadRequest, out)
	status, out = f.admin("GET", "/v1/admin/buckets", nil)
	expect("buckets", status, http.StatusOK, out)
	if items, _ := out["items"].([]any); len(items) != 1 || items[0].(map[string]any)["source"] != "greenhouse-climate" {
		t.Fatalf("buckets %v", out)
	}

	status, out = f.admin("POST", "/v1/admin/sources/greenhouse-climate/try",
		map[string]any{"payload": json.RawMessage(`{"sensor":"gh-north-1","temperature":21.50,"gps":{"lat":48.1}}`)})
	expect("try", status, http.StatusOK, out)
	if units, _ := out["units"].([]any); out["key"] != "sensor/gh-north-1" || len(units) != 2 ||
		units[0] != `{"group":"climate","fields":{"/sensor":"gh-north-1","/temperature":21.50}}` {
		t.Fatalf("try answered %v", out)
	}
	status, out = f.admin("POST", "/v1/admin/sources/greenhouse-climate/try", map[string]any{"payload": json.RawMessage(`{"sensor":"a","pin":"1234"}`)})
	expect("try an unlisted member", status, http.StatusOK, out)
	if out["pointer"] != "/pin" || out["refused"] == nil {
		t.Fatalf("try answered %v", out)
	}

	review := map[string]any{"version": 1, "digest": digest}
	status, out = f.admin("POST", "/v1/admin/sources/greenhouse-climate/review", review)
	expect("the author reviews", status, http.StatusForbidden, out)
	status, out = rita("POST", "/v1/admin/sources/greenhouse-climate/review", map[string]any{"version": 1, "digest": "00"})
	expect("another digest", status, http.StatusConflict, out)
	status, out = rita("POST", "/v1/admin/sources/greenhouse-climate/review", review)
	expect("review", status, http.StatusOK, out)
	if out["state"] != "ACTIVE" {
		t.Fatalf("review answered %v", out)
	}

	var other map[string]any
	_ = json.Unmarshal([]byte(sourceRecord), &other)
	other["id"] = "orchard"
	status, out = f.admin("PUT", "/v1/admin/sources/greenhouse-climate", other)
	expect("a record of another source", status, http.StatusBadRequest, out)
	status, out = f.admin("PUT", "/v1/admin/sources/orchard", other)
	expect("an unknown source", status, http.StatusNotFound, out)
	status, out = rita("PUT", "/v1/admin/sources/greenhouse-climate", json.RawMessage(sourceRecord))
	expect("put", status, http.StatusOK, out)
	if out["version"] != 2.0 || out["state"] != "DRAFT" {
		t.Fatalf("put answered %v", out)
	}
	status, out = f.admin("GET", "/v1/admin/sources", nil)
	expect("list", status, http.StatusOK, out)
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("list answered %v", out)
	}
	src := items[0].(map[string]any)
	active, _ := src["active"].(map[string]any)
	draft, _ := src["draft"].(map[string]any)
	if src["bucket"] != "greenhouse-climate" || active["version"] != 1.0 || active["reviewer"] != "rita" || draft["version"] != 2.0 ||
		draft["author"] != "rita" {
		t.Fatalf("list answered %v", out)
	}

	status, out = f.admin("POST", "/v1/admin/sources/greenhouse-climate/disable", nil)
	expect("disable", status, http.StatusNoContent, out)
	status, out = f.admin("PUT", "/v1/admin/sources/greenhouse-climate", json.RawMessage(sourceRecord))
	expect("put after the disable", status, http.StatusConflict, out)
	if kinds := f.journalKinds(); !slices.Contains(kinds, "source-set") || kinds[len(kinds)-1] != "source-disabled" {
		t.Fatalf("journal %v", kinds)
	}
}
