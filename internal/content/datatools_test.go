package content_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"fga/internal/adminops"
	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/datatools"
	"fga/internal/decisionsvc"
	"fga/internal/delegation"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/internal/sources"
)

// toolsPolicies are readingPolicies with the example bundle's rule letting
// members use the data tools of their projects.
func toolsPolicies() map[string]string {
	p := readingPolicies()
	p["tools.json"] = strings.Replace(p["tools.json"], `"rules":[`, `"rules":[{"id":"members-use-data-tools","effect":"allow",
	  "actions":["discover","invoke"],"roles":["member"],
	  "when":"resource.attributes.kind == \"data\" && resource.attributes.project in principal.attributes.projects"},`, 1)
	return p
}

// toolRecord is a tool over greenhouse-climate: rest completes the record
// after its name and description.
func toolRecord(name, rest string) string {
	return `{"format":"fga.data-tool/v1","name":"` + name + `","description":"Climate of a greenhouse.","source":"greenhouse-climate",` + rest + `}`
}

const (
	// latestTool selects a key by an enum argument and outputs fields of
	// both groups; location is restricted.
	latestTool = `"operation":"latest","arguments":[{"name":"greenhouse","type":"enum","values":["north","south"]}],
	 "select":{"argument":"greenhouse","keys":{"north":"sensor/gh-north-1","south":"sensor/gh-south-2"}},
	 "outputs":[{"name":"air_temperature","group":"climate","field":"/temperature","type":"number"},
	            {"name":"relative_humidity","group":"climate","field":"/humidity","type":"number"},
	            {"name":"sensor_name","group":"climate","field":"/sensor","type":"number"},
	            {"name":"position","group":"location","field":"/gps","type":"object"}]`
	historyTool = `"operation":"history","arguments":[{"name":"sensor","type":"string"}],"select":{"argument":"sensor"},
	 "outputs":[{"name":"air_temperature","group":"climate","field":"/temperature"}],"history":{"max_readings":10}`
)

// tool adds a data tool and reviews it.
func (r *readings) tool(t *testing.T, record string) catalog.RecordVersion {
	t.Helper()
	def, err := datatools.Parse([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.ops.AddDataTool(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant, def)
	if err != nil {
		t.Fatal(err)
	}
	if v, err = r.ops.ReviewDataTool(ctx, adminops.Who{Actor: "root", Via: "test"}, r1test.Tenant, def.Name, v.Version, v.Digest); err != nil {
		t.Fatal(err)
	}
	return v
}

func call(r *readings, c content.Caller, name, args string) (content.DataToolAnswer, error) {
	return r.st.Content.CallDataTool(ctx, c, name, content.DataToolCall{Arguments: json.RawMessage(args)})
}

// outputs returns a latest answer's reading, or each reading of a history.
func outputs(t *testing.T, a content.DataToolAnswer) []map[string]any {
	t.Helper()
	raws := []json.RawMessage{a.Reading}
	if a.Readings != nil {
		raws = nil
		for _, r := range *a.Readings {
			raws = append(raws, r.Reading)
		}
	}
	var out []map[string]any
	for _, raw := range raws {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func toolsFixture(t *testing.T) *readings {
	t.Helper()
	r := newReadingsWith(t, toolsPolicies())
	r.st.User("alice", []string{"member"}, "greenhouse")
	r.st.User("ada", []string{"member", "auditor"}, "greenhouse")
	r.st.User("carl", []string{"member"}, "orchards")
	r.tool(t, toolRecord("read_climate", latestTool))
	r.tool(t, toolRecord("climate_fields", strings.Replace(latestTool, `"operation":"latest"`, `"operation":"latest","on_unreadable":"skip_fields"`, 1)))
	r.tool(t, toolRecord("climate_history", historyTool))
	return r
}

// TestDataToolReview covers DTL-001 and DTL-007: review registers
// mcp.tool:<name> of kind data, a new review advances its generation, a
// disable sets active false; names, sources and fields are checked; a
// source version that drops a field breaks the tool, which then answers
// 409 until a new version is reviewed.
func TestDataToolReview(t *testing.T) {
	r := toolsFixture(t)
	resource := func() (map[string]any, uint64) {
		var attrs map[string]any
		var gen uint64
		if err := r.st.Pool.QueryRow(ctx, `SELECT attributes, generation FROM resources WHERE tenant = $1 AND id = 'mcp.tool:read_climate'`,
			r1test.Tenant).Scan(&attrs, &gen); err != nil {
			t.Fatal(err)
		}
		return attrs, gen
	}
	attrs, gen := resource()
	if attrs["kind"] != "data" || attrs["active"] != true || attrs["source"] != "greenhouse-climate" || attrs["project"] != "greenhouse" ||
		attrs["encryption"] != "server" || attrs["version"] != float64(1) || attrs["definition_digest"] == "" {
		t.Fatalf("registered attributes %v", attrs)
	}
	if n := r.st.Count(`SELECT count(*) FROM aliases WHERE tenant = $1 AND namespace = 'mcp.tool' AND name = 'read_climate'`, r1test.Tenant); n != 1 {
		t.Fatalf("%d aliases", n)
	}
	who := adminops.Who{Actor: "root", Via: "test"}
	def, _ := datatools.Parse([]byte(toolRecord("read_climate", strings.Replace(latestTool, "Climate", "Climate", 1))))
	def.Description = "Latest climate, second version."
	v, err := r.ops.PutDataTool(ctx, who, r1test.Tenant, def)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ops.ReviewDataTool(ctx, who, r1test.Tenant, "read_climate", v.Version, "wrong"); !errors.Is(err, catalog.ErrDraftConflict) {
		t.Fatalf("a review of another digest: %v", err)
	}
	if _, err := r.ops.ReviewDataTool(ctx, who, r1test.Tenant, "read_climate", v.Version, v.Digest); err != nil {
		t.Fatal(err)
	}
	if attrs, gen2 := resource(); gen2 != gen+1 || attrs["version"] != float64(2) {
		t.Fatalf("a new review left generation %d (was %d), attributes %v", gen2, gen, attrs)
	}

	for name, record := range map[string]string{
		"a built-in name":              toolRecord("documents.read", latestTool),
		"an upper-case name":           toolRecord("Read", latestTool),
		"an unknown source":            strings.Replace(toolRecord("x_1", latestTool), `"source":"greenhouse-climate"`, `"source":"orchard"`, 1),
		"a field of no group":          toolRecord("x_2", strings.Replace(latestTool, `"/gps"`, `"/altitude"`, 1)),
		"a key the source cannot give": toolRecord("x_3", strings.Replace(latestTool, `"sensor/gh-south-2"`, `"other/gh-south-2"`, 1)),
		"an unused argument": toolRecord("x_4", strings.Replace(latestTool, `"arguments":[`,
			`"arguments":[{"name":"extra","type":"string"},`, 1)),
		"a free key": toolRecord("x_5", strings.Replace(historyTool, `"select":{"argument":"sensor"}`, `"select":{}`, 1)),
	} {
		def, err := datatools.Parse([]byte(record))
		if err == nil {
			_, err = r.ops.AddDataTool(ctx, who, r1test.Tenant, def)
		}
		if !errors.Is(err, adminops.ErrInvalid) && !errors.Is(err, datatools.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A source version without /humidity breaks the tools that output it.
	src, _ := sources.Parse([]byte(strings.Replace(strings.Replace(climateRecord, "%s", "greenhouse-climate", 1), `"/humidity",`, "", 1)))
	sv, err := r.ops.PutSource(ctx, who, r1test.Tenant, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ops.ReviewSource(ctx, adminops.Who{Actor: "rita", Via: "test"}, r1test.Tenant, "greenhouse-climate", sv.Version, sv.Digest); err != nil {
		t.Fatal(err)
	}
	broken, err := r.ops.BrokenDataTools(ctx, r1test.Tenant, "greenhouse-climate")
	if err != nil || !slices.Equal(broken, []string{"climate_fields", "read_climate"}) {
		t.Fatalf("broken tools %v, %v", broken, err)
	}
	owner := r.st.Caller("team-greenhouse")
	if _, err := call(r, owner, "read_climate", `{"greenhouse":"north"}`); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("a tool that no longer fits its source: %v", err)
	}
	if _, err := call(r, owner, "climate_history", `{"sensor":"gh-north-1"}`); errors.Is(err, content.ErrConflict) {
		t.Fatalf("a tool that still fits: %v", err)
	}

	if err := r.ops.DisableDataTool(ctx, who, r1test.Tenant, "read_climate"); err != nil {
		t.Fatal(err)
	}
	if attrs, gen3 := resource(); attrs["active"] != false || gen3 != gen+2 {
		t.Fatalf("a disabled tool's resource: %v, generation %d", attrs, gen3)
	}
	if _, err := call(r, owner, "read_climate", `{"greenhouse":"north"}`); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a disabled tool: %v", err)
	}
}

// TestDataToolLatest covers DTL-002, DTL-003, DTL-005 and DTL-006 for a
// latest tool: projection, renaming and declared types, both on_unreadable
// modes, origin and label, argument validation, pinned versions, and a
// restart when the head moves mid-call.
func TestDataToolLatest(t *testing.T) {
	r := toolsFixture(t)
	if _, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading); err != nil {
		t.Fatal(err)
	}
	owner, alice, carl := r.st.Caller("team-greenhouse"), r.st.Caller("alice"), r.st.Caller("carl")

	a, err := call(r, owner, "read_climate", `{"greenhouse":"north"}`)
	if err != nil {
		t.Fatal(err)
	}
	got := outputs(t, a)[0]
	// sensor_name is declared a number, so the sensor's string is left out.
	if got["air_temperature"] != 21.5 || got["relative_humidity"] != float64(40) || got["position"] == nil || len(got) != 3 {
		t.Fatalf("the owner's reading %v", got)
	}
	if a.Tool != "read_climate" || a.Version != 1 || a.Origin.Source != "greenhouse-climate" || a.Origin.Label != "restricted" ||
		a.Origin.PublishedAt == "" || a.Origin.DocumentVersion == "" {
		t.Fatalf("answer %+v, origin %+v", a, a.Origin)
	}
	if _, err := call(r, alice, "read_climate", `{"greenhouse":"north"}`); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("skip_reading with an unreadable group: %v", err)
	}
	a, err = call(r, alice, "climate_fields", `{"greenhouse":"north"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := outputs(t, a)[0]; got["air_temperature"] != 21.5 || got["position"] != nil || a.Origin.Label != "internal" {
		t.Fatalf("skip_fields: %v, label %s", got, a.Origin.Label)
	}
	for name, c := range map[string]content.Caller{"another project's member": carl, "the posting system": r.sensor} {
		if _, err := call(r, c, "climate_fields", `{"greenhouse":"north"}`); !errors.Is(err, content.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Arguments are strict; an unknown key answers as a denied one.
	for args, want := range map[string]error{
		`{"greenhouse":"east"}`:              content.ErrInvalid,
		`{"greenhouse":"north","extra":1}`:   content.ErrInvalid,
		`{}`:                                 content.ErrInvalid,
		`{"greenhouse":3}`:                   content.ErrInvalid,
		`{"greenhouse":"north","limit":1}`:   content.ErrInvalid,
		`[1]`:                                content.ErrInvalid,
		`{"greenhouse":"south"}`:             content.ErrNotFound,
		`{"greenhouse":"north","x":1,"x":2}`: content.ErrInvalid,
	} {
		if _, err := call(r, alice, "climate_fields", args); !errors.Is(err, want) {
			t.Errorf("arguments %s: %v, want %v", args, err, want)
		}
	}
	for version, want := range map[int]error{1: nil, 2: content.ErrConflict} {
		_, err := r.st.Content.CallDataTool(ctx, alice, "climate_fields", content.DataToolCall{Arguments: json.RawMessage(`{"greenhouse":"north"}`),
			Version: version})
		if !errors.Is(err, want) {
			t.Errorf("pinned version %d: %v", version, err)
		}
	}

	// A reading published between the decisions and the read: the call
	// starts again and answers the new one.
	posted := false
	r.st.AfterDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpDocSelectUnits && !posted {
			posted = true
			if _, err := r.post(r.sensor, "greenhouse-climate", "r-2", strings.Replace(northReading, "21.5", "23.25", 1)); err != nil {
				t.Error(err)
			}
		}
	}
	a, err = call(r, alice, "climate_fields", `{"greenhouse":"north"}`)
	r.st.AfterDecide = nil
	if err != nil || !posted || outputs(t, a)[0]["air_temperature"] != 23.25 {
		t.Fatalf("a call across a new reading: %v, %v", a, err)
	}
}

// TestDataToolHistory covers DOC-009 and DOC-010 through a history tool:
// newest first, since inclusive and until exclusive, limit, and a caller
// without read-history (or whose delegation leaves it out) gets the
// current reading only.
func TestDataToolHistory(t *testing.T) {
	r := toolsFixture(t)
	for i, temp := range []string{"20", "21", "22"} {
		*r.st.Clock = r.st.Clock.Add(time.Minute)
		if _, err := r.post(r.sensor, "greenhouse-climate", fmt.Sprint("h-", i), strings.Replace(northReading, "21.5", temp, 1)); err != nil {
			t.Fatal(err)
		}
	}
	temps := func(c content.Caller, args string) ([]any, content.DataToolAnswer) {
		t.Helper()
		a, err := call(r, c, "climate_history", args)
		if err != nil {
			t.Fatal(err)
		}
		var out []any
		for _, m := range outputs(t, a) {
			out = append(out, m["air_temperature"])
		}
		return out, a
	}
	ada, alice := r.st.Caller("ada"), r.st.Caller("alice")
	all, a := temps(ada, `{"sensor":"gh-north-1"}`)
	if !slices.Equal(all, []any{float64(22), float64(21), float64(20)}) {
		t.Fatalf("an auditor's history %v", all)
	}
	newest, middle := (*a.Readings)[0].Origin.PublishedAt, (*a.Readings)[1].Origin.PublishedAt
	for args, want := range map[string][]any{
		`{"sensor":"gh-north-1","limit":2}`:                                         {float64(22), float64(21)},
		`{"sensor":"gh-north-1","until":"` + newest + `"}`:                          {float64(21), float64(20)},
		`{"sensor":"gh-north-1","since":"` + middle + `"}`:                          {float64(22), float64(21)},
		`{"sensor":"gh-north-1","since":"` + middle + `","until":"` + newest + `"}`: {float64(21)},
	} {
		got, _ := temps(ada, args)
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", args, got, want)
		}
	}
	if _, err := call(r, ada, "climate_history", `{"sensor":"Bad Sensor"}`); !errors.Is(err, content.ErrInvalid) {
		t.Errorf("a value outside the key pattern: %v", err)
	}
	if _, err := call(r, ada, "climate_history", `{"sensor":"gh-south-2"}`); !errors.Is(err, content.ErrNotFound) {
		t.Errorf("a key without readings answers as a denied one: %v", err)
	}
	if got, _ := temps(alice, `{"sensor":"gh-north-1"}`); !slices.Equal(got, []any{float64(22)}) {
		t.Fatalf("a member without read-history: %v", got)
	}

	// An agent acting for the auditor, whose delegation leaves history out,
	// gets the current reading only (DOC-009).
	r.st.User("agent-1", []string{"agent"})
	if err := r.st.Catalog.PutDelegation(ctx, delegation.Delegation{ID: "dlg-1", Tenant: r1test.Tenant, Actor: "agent-1", Subject: "ada",
		Audience: r1test.StorageAdapter, ExpiresAt: r.st.Clock.Add(time.Hour), Grants: []delegation.Grant{
			{ResourceType: "agent.tool", Actions: []string{"discover", "invoke"}},
			{ResourceType: "document.version", Actions: []string{"read-units", "discover"}},
			{ResourceType: "document.text_unit", Actions: []string{"read"}},
		}}, *r.st.Clock); err != nil {
		t.Fatal(err)
	}
	agent := r.st.Caller("agent-1")
	agent.Subject, agent.Delegation = "ada", "dlg-1"
	if got, _ := temps(agent, `{"sensor":"gh-north-1"}`); !slices.Equal(got, []any{float64(22)}) {
		t.Fatalf("an agent whose delegation leaves out history: %v", got)
	}
}

// TestDataToolSubsetOfNative covers P2 (DTL-002) over callers and modes:
// every group whose fields a tool answers is one the caller reads through
// the native unit read of the same version.
func TestDataToolSubsetOfNative(t *testing.T) {
	r := toolsFixture(t)
	p, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading)
	if err != nil {
		t.Fatal(err)
	}
	r.st.User("agent-2", []string{"agent"})
	if err := r.st.Catalog.PutDelegation(ctx, delegation.Delegation{ID: "dlg-2", Tenant: r1test.Tenant, Actor: "agent-2", Subject: "team-greenhouse",
		Audience: r1test.StorageAdapter, ExpiresAt: r.st.Clock.Add(time.Hour), Grants: []delegation.Grant{
			{ResourceType: "agent.tool", Actions: []string{"discover", "invoke"}},
			{ResourceType: "document.version", Actions: []string{"read-units", "discover"}},
		}}, *r.st.Clock); err != nil {
		t.Fatal(err)
	}
	agent := r.st.Caller("agent-2")
	agent.Subject, agent.Delegation = "team-greenhouse", "dlg-2"
	groupOf := map[string]string{"air_temperature": "climate", "relative_humidity": "climate", "position": "location"}
	units := r.st.UnitIDs(r.st.Caller("team-greenhouse"), "greenhouse-climate", "sensor/gh-north-1", p.DocumentVersion)
	answered := 0
	for name, c := range map[string]content.Caller{"owner": r.st.Caller("team-greenhouse"), "member": r.st.Caller("alice"),
		"auditor": r.st.Caller("ada"), "other project": r.st.Caller("carl"), "agent without unit reads": agent} {
		native := map[string]bool{}
		for i, group := range []string{"climate", "location"} {
			s, err := r.st.Content.ReadUnitPlain(ctx, c, "greenhouse-climate", "sensor/gh-north-1", p.DocumentVersion, units[i])
			if err == nil {
				_, err = io.ReadAll(s)
				s.Close()
			}
			native[group] = err == nil
		}
		for _, tool := range []string{"read_climate", "climate_fields"} {
			a, err := call(r, c, tool, `{"greenhouse":"north"}`)
			if errors.Is(err, content.ErrNotFound) {
				continue
			}
			if err != nil {
				t.Fatalf("%s, %s: %v", name, tool, err)
			}
			answered++
			for out := range outputs(t, a)[0] {
				if !native[groupOf[out]] {
					t.Errorf("%s gets %s through %s without reading group %s natively", name, out, tool, groupOf[out])
				}
			}
		}
	}
	// The owner gets both tools, the member and the auditor the one that
	// skips fields.
	if answered != 4 {
		t.Fatalf("%d answers", answered)
	}
}

// TestDataToolListPreviewAudit covers DTL-004, DTL-006 and DTL-008: the
// listing decides discover per tool and shows no source, bucket, key or
// pointer; a preview needs list on the source's bucket and answers like
// the call; a call is audited with IDs only.
func TestDataToolListPreviewAudit(t *testing.T) {
	r := toolsFixture(t)
	if _, err := r.post(r.sensor, "greenhouse-climate", "r-1", northReading); err != nil {
		t.Fatal(err)
	}
	alice, carl := r.st.Caller("alice"), r.st.Caller("carl")
	page, err := r.st.Content.ListDataTools(ctx, alice, 2, "")
	if err != nil || len(page.Tools) != 2 || page.Continuation == "" {
		t.Fatalf("first page %+v, %v", page, err)
	}
	rest, err := r.st.Content.ListDataTools(ctx, alice, 2, page.Continuation)
	if err != nil || len(rest.Tools) != 1 || rest.Continuation != "" {
		t.Fatalf("second page %+v, %v", rest, err)
	}
	listed, _ := json.Marshal(append(page.Tools, rest.Tools...))
	for _, hidden := range []string{"greenhouse-climate", "sensor/", "/temperature", "/gps"} {
		if strings.Contains(string(listed), hidden) {
			t.Errorf("the listing shows %q: %s", hidden, listed)
		}
	}
	if none, err := r.st.Content.ListDataTools(ctx, carl, 0, ""); err != nil || len(none.Tools) != 0 {
		t.Fatalf("another project's member lists %+v, %v", none, err)
	}

	record := json.RawMessage(toolRecord("climate_fields", strings.Replace(latestTool, `"operation":"latest"`,
		`"operation":"latest","on_unreadable":"skip_fields"`, 1)))
	args := json.RawMessage(`{"greenhouse":"north"}`)
	called, err := call(r, alice, "climate_fields", string(args))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := r.st.Content.PreviewDataTool(ctx, alice, record, content.DataToolCall{Arguments: args})
	if err != nil || string(preview.Reading) != string(called.Reading) || preview.Origin.DocumentVersion != called.Origin.DocumentVersion {
		t.Fatalf("a preview %+v of the published record, the call %+v: %v", preview, called, err)
	}
	if _, err := r.st.Content.PreviewDataTool(ctx, carl, record, content.DataToolCall{Arguments: args}); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a preview without list on the bucket: %v", err)
	}
	unfit := json.RawMessage(strings.Replace(string(record), `"/gps"`, `"/altitude"`, 1))
	if _, err := r.st.Content.PreviewDataTool(ctx, alice, unfit, content.DataToolCall{Arguments: args}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("a preview of a record that does not fit: %v", err)
	}

	if n := r.st.Count(`SELECT count(*) FROM audit_outbox WHERE event::text LIKE '%"DATA_TOOL"%' AND event::text LIKE '%mcp.tool:climate_fields%'
	                    AND event::text LIKE '%document.version%'`); n != 1 {
		t.Fatalf("%d call events", n)
	}
	for _, value := range []string{"21.5", "48.1"} {
		if n := r.st.Count(`SELECT count(*) FROM audit_outbox WHERE event::text LIKE $1`, "%"+value+"%"); n != 0 {
			t.Errorf("the audit holds the value %s", value)
		}
	}
}
