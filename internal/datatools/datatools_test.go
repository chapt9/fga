package datatools

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"fga/internal/sources"
)

const source = `{"format":"fga.source/v1","id":"climate","owner":"lena",
 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
 "groups":[{"name":"climate","label":"internal","fields":["/sensor","/t"]}]}`

const tool = `{"format":"fga.data-tool/v1","name":"history_t","description":"Past temperatures.","source":"climate","operation":"history",
 "arguments":[{"name":"sensor","type":"string","description":"Sensor ID"}],"select":{"argument":"sensor"},
 "outputs":[{"name":"t","group":"climate","field":"/t","type":"number"}],"history":{"max_readings":5}}`

// TestRecord covers DTL-003 and DTL-007: the record's own rules, its fit
// to a source version, strict arguments and the schemas.
func TestRecord(t *testing.T) {
	src, err := sources.Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse([]byte(tool))
	if err != nil || d.Check() != nil || d.Fit(src) != nil {
		t.Fatalf("the record: %v, %v, %v", err, d.Check(), d.Fit(src))
	}
	for name, change := range map[string][2]string{
		"a dotted name":        {`"name":"history_t"`, `"name":"data.list"`},
		"a long description":   {`"Past temperatures."`, `"` + strings.Repeat("x", 1001) + `"`},
		"a control character":  {`"Past temperatures."`, `"Past\u0007"`},
		"an unknown operation": {`"operation":"history"`, `"operation":"sum"`},
		"history bounds":       {`"max_readings":5`, `"max_readings":500`},
		"a reserved argument":  {`"name":"sensor"`, `"name":"limit"`},
		"an unused argument":   {`"select":{"argument":"sensor"}`, `"select":{"fixed":"sensor/a"}`},
		"enum without keys":    {`"type":"string"`, `"type":"enum","values":["a"]`},
		"two ways to select":   {`"select":{"argument":"sensor"}`, `"select":{"argument":"sensor","fixed":"sensor/a"}`},
		"no outputs":           {`"outputs":[{"name":"t","group":"climate","field":"/t","type":"number"}]`, `"outputs":[]`},
		"an unknown member":    {`"history":`, `"extra":1,"history":`},
	} {
		d, err := Parse([]byte(strings.Replace(tool, change[0], change[1], 1)))
		if err == nil {
			err = d.Check()
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	fixed := strings.Replace(strings.Replace(tool, `"arguments":[{"name":"sensor","type":"string","description":"Sensor ID"}],`, "", 1),
		`"select":{"argument":"sensor"}`, `"select":{"fixed":"other/a"}`, 1)
	for name, raw := range map[string]string{
		"a field of no group":    strings.Replace(tool, `"field":"/t"`, `"field":"/h"`, 1),
		"a key the source lacks": fixed,
	} {
		d, err := Parse([]byte(raw))
		if err != nil || d.Check() != nil {
			t.Fatalf("%s: %v %v", name, err, d.Check())
		}
		if err := d.Fit(src); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	for args, want := range map[string]error{
		`{"sensor":"gh-1"}`: nil,
		`{"sensor":"gh-1","limit":5,"since":"2026-11-03T08:00:00Z","until":"2026-11-04T08:00:00Z"}`: nil,
		`{"sensor":"GH"}`:                       ErrArguments,
		`{"sensor":"gh-1","limit":6}`:           ErrArguments,
		`{"sensor":"gh-1","limit":1.5}`:         ErrArguments,
		`{"sensor":"gh-1","since":"yesterday"}`: ErrArguments,
		`{"sensor":"gh-1","since":"2026-11-04T08:00:00Z","until":"2026-11-03T08:00:00Z"}`: ErrArguments,
		`{"sensor":"gh-1","other":true}`: ErrArguments,
		`"gh-1"`:                         ErrArguments,
		``:                               ErrArguments,
	} {
		c, err := d.Resolve(src, json.RawMessage(args))
		if !errors.Is(err, want) || err == nil && (c.Key != "sensor/gh-1" || c.Limit < 1) {
			t.Errorf("arguments %s: %+v, %v", args, c, err)
		}
	}
	var in, out map[string]any
	if json.Unmarshal(d.InputSchema(), &in) != nil || json.Unmarshal(d.OutputSchema(), &out) != nil {
		t.Fatal("the schemas are not JSON")
	}
	if props := in["properties"].(map[string]any); props["sensor"] == nil || props["limit"].(map[string]any)["maximum"] != float64(5) {
		t.Fatalf("input schema %v", in)
	}
	if !strings.Contains(string(d.OutputSchema()), `"readings"`) || strings.Contains(string(d.OutputSchema()), "/t") {
		t.Fatalf("output schema %s", d.OutputSchema())
	}
	_, d1, _ := d.Canonical()
	d.Description = "Other."
	if _, d2, _ := d.Canonical(); d1 == d2 || len(d1) != 64 {
		t.Fatal("the digest does not follow the record")
	}
}
