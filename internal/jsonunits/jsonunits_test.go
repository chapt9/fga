package jsonunits

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// The vectors (docs/design/mcp-data-tools.md, "Profile"): what every
// implementation of the profile, such as a posting client in client mode,
// must produce byte for byte or refuse. With -update the test rewrites
// testdata/vectors.json from vectorInputs; otherwise it checks every
// recorded case against this implementation.
var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorFile = "testdata/vectors.json"

// climate is the layout of the design record's example source.
func climate() Layout {
	return Layout{
		Key: Key{Mode: KeyPointer, Pointer: "/sensor", Pattern: "[a-z0-9-]{1,48}", Prefix: "sensor/"},
		Groups: []Group{
			{Name: "climate", Fields: []string{"/temperature", "/humidity", "/observed_at", "/sensor"}},
			{Name: "location", Fields: []string{"/gps"}},
		},
	}
}

// one is a layout with one group of the given fields and a fixed key.
func one(fields ...string) Layout {
	return Layout{Key: Key{Mode: KeyFixed, Prefix: "station"}, Groups: []Group{{Name: "all", Fields: fields}}}
}

const fullReading = `{"sensor": "gh-north-1", "temperature": 21.50, "humidity": 40,
	"observed_at": "2026-11-03T08:00:00Z", "gps": {"lon": 11.5, "lat": 48.1}}`

func split(t *testing.T, l Layout, payload, principal string) (Reading, error) {
	t.Helper()
	s, err := l.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return s.Split([]byte(payload), principal)
}

func mustSplit(t *testing.T, l Layout, payload, principal string) Reading {
	t.Helper()
	r, err := split(t, l, payload, principal)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	return r
}

func unitStrings(r Reading) []string {
	var out []string
	for _, u := range r.Units {
		out = append(out, string(u))
	}
	return out
}

func equalFields(a, b [][]string) bool {
	return slices.EqualFunc(a, b, func(x, y []string) bool { return slices.Equal(x, y) })
}

func wantUnits(t *testing.T, r Reading, want ...string) {
	t.Helper()
	if got := unitStrings(r); !slices.Equal(got, want) {
		t.Fatalf("units\n got %q\nwant %q", got, want)
	}
}

func TestSplitGroups(t *testing.T) {
	r := mustSplit(t, climate(), fullReading, "")
	if r.Key != "sensor/gh-north-1" {
		t.Fatalf("key %q", r.Key)
	}
	wantUnits(t, r,
		`{"group":"climate","fields":{"/humidity":40,"/observed_at":"2026-11-03T08:00:00Z","/sensor":"gh-north-1","/temperature":21.50}}`,
		`{"group":"location","fields":{"/gps":{"lat":48.1,"lon":11.5}}}`)
	if want := [][]string{{"/humidity", "/observed_at", "/sensor", "/temperature"}, {"/gps"}}; !equalFields(r.Fields, want) {
		t.Fatalf("fields %q, want %q", r.Fields, want)
	}
}

func TestSplitEmptyGroup(t *testing.T) {
	// Every group is a unit in every reading, so the unit count tells
	// nothing (ING-005).
	r := mustSplit(t, climate(), `{"sensor":"a","temperature":1}`, "")
	wantUnits(t, r, `{"group":"climate","fields":{"/sensor":"a","/temperature":1}}`, `{"group":"location","fields":{}}`)
	if r.Fields[1] == nil || len(r.Fields[1]) != 0 {
		t.Fatalf("fields of the empty group %#v, want an empty list", r.Fields[1])
	}
}

func TestSplitValues(t *testing.T) {
	r := mustSplit(t, one("/s", "/n", "/a", "/o", "/b", "/z"),
		`{"s":"<b>&é\n\u0001\u001f \"\\\/x","n":[-0,1E+2,21.50,0.1e-3,123456789012345678901234567890],`+
			`"a":[1,[2,{"y":1,"x":2}],null],"o":{"b":true,"a":false,"":null},"b":false,"z":null}`, "")
	wantUnits(t, r, `{"group":"all","fields":{"/a":[1,[2,{"x":2,"y":1}],null],"/b":false,`+
		`"/n":[-0,1E+2,21.50,0.1e-3,123456789012345678901234567890],"/o":{"":null,"a":false,"b":true},`+
		`"/s":"<b>&é\n\u0001\u001f`+" "+`\"\\/x","/z":null}}`)

	// An escaped lone surrogate becomes U+FFFD, as encoding/json decodes
	// it; a pair is one character.
	r = mustSplit(t, one("/s", "/p"), `{"s":"\ud800x","p":"😀"}`, "")
	wantUnits(t, r, `{"group":"all","fields":{"/p":"`+"\U0001F600"+`","/s":"`+"�"+`x"}}`)
}

func TestSplitDepthBound(t *testing.T) {
	deep := func(n int) string {
		return `{"sensor":"a","gps":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
	}
	// The reading's object is depth 1, so 31 arrays inside it are depth 32.
	mustSplit(t, climate(), deep(MaxDepth-1), "")
	if _, err := split(t, climate(), deep(MaxDepth), ""); !errors.Is(err, ErrReading) {
		t.Fatalf("depth %d: %v", MaxDepth+1, err)
	}
	// Brackets inside strings do not count.
	mustSplit(t, climate(), `{"sensor":"a","gps":"`+strings.Repeat("[{", 40)+`\"]"}`, "")
}

func TestSplitRefusals(t *testing.T) {
	small := climate()
	small.MaxPayload = 40
	nested := Layout{Key: Key{Mode: KeyPointer, Pointer: "/sensor", Pattern: "[a-z]+"},
		Groups: []Group{{Name: "meta", Fields: []string{"/meta/a"}}}}
	for _, c := range []struct {
		name, payload string
		layout        Layout
		pointer       string
	}{
		{"larger than its bound", `{"sensor":"a","temperature":1234567890123456789012345}`, small, ""},
		{"invalid UTF-8", "{\"sensor\":\"a\xff\"}", climate(), ""},
		{"duplicate member", `{"sensor":"a","sensor":"b"}`, climate(), ""},
		{"nested duplicate member", `{"sensor":"a","gps":{"lat":1,"lat":2}}`, climate(), ""},
		{"an array", `["sensor"]`, climate(), ""},
		{"a string", `"sensor"`, climate(), ""},
		{"null", `null`, climate(), ""},
		{"nothing", ``, climate(), ""},
		{"a syntax error", `{"sensor":`, climate(), ""},
		{"trailing data", `{"sensor":"a"} {}`, climate(), ""},
		{"a member in no group", `{"sensor":"a","secret":"x"}`, climate(), "/secret"},
		{"a nested member in no group", `{"sensor":"a","meta":{"a":1,"b":"x"}}`, nested, "/meta/b"},
		{"a path through a non-object", `{"sensor":"a","meta":["x"]}`, nested, "/meta"},
		{"no key member", `{"temperature":1}`, climate(), "/sensor"},
		{"a key member that is no string", `{"sensor":7}`, climate(), "/sensor"},
		{"a key member not matching", `{"sensor":"Secret Name"}`, climate(), "/sensor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := split(t, c.layout, c.payload, "")
			var re *ReadingError
			if !errors.Is(err, ErrReading) || !errors.As(err, &re) || re.Pointer != c.pointer {
				t.Fatalf("got %v, want a refusal at %q", err, c.pointer)
			}
			// A refusal names a field, never a value.
			if msg := err.Error(); strings.Contains(msg, "Secret Name") || strings.Contains(msg, `"x"`) || strings.Contains(msg, "\xff") {
				t.Fatalf("the refusal quotes a value: %v", err)
			}
		})
	}
}

func TestSplitDrop(t *testing.T) {
	l := climate()
	l.Unlisted = Drop
	l.Groups = append(l.Groups, Group{Name: "meta", Fields: []string{"/meta/a"}})
	r := mustSplit(t, l, `{"sensor":"a","secret":"x","meta":{"a":1,"b":2},"temperature":3}`, "")
	wantUnits(t, r, `{"group":"climate","fields":{"/sensor":"a","/temperature":3}}`, `{"group":"location","fields":{}}`,
		`{"group":"meta","fields":{"/meta/a":1}}`)
	r = mustSplit(t, l, `{"sensor":"a","meta":[1]}`, "")
	wantUnits(t, r, `{"group":"climate","fields":{"/sensor":"a"}}`, `{"group":"location","fields":{}}`, `{"group":"meta","fields":{}}`)
}

func TestKeyModes(t *testing.T) {
	climateOnly := []Group{{Name: "climate", Fields: []string{"/temperature"}}}
	principal := Layout{Key: Key{Mode: KeyPrincipal, Pattern: "[a-z0-9-]{1,64}", Prefix: "device/"}, Groups: climateOnly}
	if r := mustSplit(t, principal, `{"temperature":1}`, "dev-7"); r.Key != "device/dev-7" {
		t.Fatalf("principal key %q", r.Key)
	}
	for _, p := range []string{"", "Dev 7", "dev/7"} {
		if _, err := split(t, principal, `{"temperature":1}`, p); !errors.Is(err, ErrReading) {
			t.Fatalf("principal %q: %v", p, err)
		}
	}

	fixed := Layout{Key: Key{Mode: KeyFixed, Prefix: "station-1"}, Groups: climateOnly}
	if r := mustSplit(t, fixed, `{"temperature":1}`, "anyone"); r.Key != "station-1" {
		t.Fatalf("fixed key %q", r.Key)
	}

	// The key's member inside a field: the field holds it too.
	inside := Layout{Key: Key{Mode: KeyPointer, Pointer: "/meta/id", Pattern: "[a-z]+"},
		Groups: []Group{{Name: "meta", Fields: []string{"/meta"}}}}
	r := mustSplit(t, inside, `{"meta":{"site":"x","id":"abc"}}`, "")
	if r.Key != "abc" {
		t.Fatalf("key inside a field %q", r.Key)
	}
	wantUnits(t, r, `{"group":"meta","fields":{"/meta":{"id":"abc","site":"x"}}}`)

	// The key's member outside every group: the key alone covers it.
	outside := Layout{Key: Key{Mode: KeyPointer, Pointer: "/sensor", Pattern: "a|bc"}, Groups: climateOnly}
	r = mustSplit(t, outside, `{"sensor":"bc","temperature":1}`, "")
	if r.Key != "bc" {
		t.Fatalf("key outside the groups %q", r.Key)
	}
	wantUnits(t, r, `{"group":"climate","fields":{"/temperature":1}}`)

	// A pattern matches whole values, alternatives included.
	for _, v := range []string{"abc", "ab", "bca"} {
		if _, err := split(t, outside, `{"sensor":"`+v+`","temperature":1}`, ""); !errors.Is(err, ErrReading) {
			t.Fatalf("value %q matched a|bc: %v", v, err)
		}
	}
}

func TestEscapedPointers(t *testing.T) {
	l := one("/a~1b", "/m~0n", "/x/~01")
	r := mustSplit(t, l, `{"a/b":1,"m~n":2,"x":{"~1":3}}`, "")
	wantUnits(t, r, `{"group":"all","fields":{"/a~1b":1,"/m~0n":2,"/x/~01":3}}`)
	for payload, pointer := range map[string]string{`{"c/d":1}`: "/c~1d", `{"x":{"e~":4}}`: "/x/e~0"} {
		var re *ReadingError
		if _, err := split(t, l, payload, ""); !errors.As(err, &re) || re.Pointer != pointer {
			t.Fatalf("%s: got %v, want a refusal at %q", payload, err, pointer)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a := mustSplit(t, climate(), `{"sensor":"a","temperature":1,"humidity":2,"gps":{"lat":1,"lon":2}}`, "")
	b := mustSplit(t, climate(), "{\n \"gps\" : { \"lon\":2 , \"lat\":1 },\t\"humidity\":2,\"temperature\":1,\"sensor\":\"a\"\n}", "")
	if !slices.Equal(unitStrings(a), unitStrings(b)) || !equalFields(a.Fields, b.Fields) || a.Key != b.Key {
		t.Fatalf("member order or whitespace changed the units:\n%q\n%q", unitStrings(a), unitStrings(b))
	}
}

func TestCompiledLayoutKeepsItsGroups(t *testing.T) {
	l := climate()
	s, err := l.Compile()
	if err != nil {
		t.Fatal(err)
	}
	l.Groups[0].Name = "renamed"
	r, err := s.Split([]byte(`{"sensor":"a"}`), "")
	if err != nil || !strings.HasPrefix(string(r.Units[0]), `{"group":"climate"`) {
		t.Fatalf("%v %q", err, r.Units)
	}
}

func TestLayoutValidate(t *testing.T) {
	with := func(f func(*Layout)) Layout {
		l := climate()
		f(&l)
		return l
	}
	groups := func(n int) []Group {
		var g []Group
		for i := range n {
			g = append(g, Group{Name: fmt.Sprintf("g%d", i), Fields: []string{fmt.Sprintf("/f%d", i)}})
		}
		return g
	}
	fields := func(n int) []string {
		var f []string
		for i := range n {
			f = append(f, fmt.Sprintf("/f%d", i))
		}
		return f
	}
	tokens := func(n int) string { return strings.Repeat("/a", n) }
	invalid := map[string]Layout{
		"no groups":                       with(func(l *Layout) { l.Groups = nil }),
		"too many groups":                 with(func(l *Layout) { l.Groups = groups(MaxGroups + 1) }),
		"an upper-case name":              with(func(l *Layout) { l.Groups[0].Name = "Climate" }),
		"a name with a dash":              with(func(l *Layout) { l.Groups[0].Name = "a-b" }),
		"an empty name":                   with(func(l *Layout) { l.Groups[0].Name = "" }),
		"a long name":                     with(func(l *Layout) { l.Groups[0].Name = strings.Repeat("a", 33) }),
		"duplicate names":                 with(func(l *Layout) { l.Groups[1].Name = "climate" }),
		"a group without fields":          with(func(l *Layout) { l.Groups[1].Fields = nil }),
		"too many fields":                 with(func(l *Layout) { l.Groups = []Group{{Name: "g", Fields: fields(MaxFields + 1)}} }),
		"no leading slash":                with(func(l *Layout) { l.Groups[1].Fields = []string{"gps"} }),
		"the root pointer":                with(func(l *Layout) { l.Groups[1].Fields = []string{"/"} }),
		"an empty token":                  with(func(l *Layout) { l.Groups[1].Fields = []string{"/a//b"} }),
		"a trailing slash":                with(func(l *Layout) { l.Groups[1].Fields = []string{"/gps/"} }),
		"a bad escape":                    with(func(l *Layout) { l.Groups[1].Fields = []string{"/a~2"} }),
		"a lone tilde":                    with(func(l *Layout) { l.Groups[1].Fields = []string{"/a~"} }),
		"too many tokens":                 with(func(l *Layout) { l.Groups[1].Fields = []string{tokens(MaxDepth + 1)} }),
		"a pointer too long":              with(func(l *Layout) { l.Groups[1].Fields = []string{"/" + strings.Repeat("a", maxPointer)} }),
		"a pointer not UTF-8":             with(func(l *Layout) { l.Groups[1].Fields = []string{"/\xff"} }),
		"the same field twice":            with(func(l *Layout) { l.Groups[1].Fields = []string{"/gps", "/gps"} }),
		"the same field in two groups":    with(func(l *Layout) { l.Groups[1].Fields = []string{"/temperature"} }),
		"a field inside a field":          with(func(l *Layout) { l.Groups[1].Fields = []string{"/temperature/x"} }),
		"a field around a field":          with(func(l *Layout) { l.Groups[0].Fields = []string{"/a/b"}; l.Groups[1].Fields = []string{"/a"} }),
		"no key mode":                     with(func(l *Layout) { l.Key.Mode = "" }),
		"an unknown key mode":             with(func(l *Layout) { l.Key.Mode = "random" }),
		"a key without its pattern":       with(func(l *Layout) { l.Key.Pattern = "" }),
		"a pattern that does not compile": with(func(l *Layout) { l.Key.Pattern = "[a-" }),
		"a pattern closing its group":     with(func(l *Layout) { l.Key.Pattern = `x)|(.*` }),
		"a pattern too long":              with(func(l *Layout) { l.Key.Pattern = strings.Repeat("a", maxPattern+1) }),
		"a bad key pointer":               with(func(l *Layout) { l.Key.Pointer = "sensor" }),
		"a field below the key": {Key: Key{Mode: KeyPointer, Pointer: "/id", Pattern: "[a-z]+"},
			Groups: []Group{{Name: "g", Fields: []string{"/id/x"}}}},
		"a principal key with a pointer": with(func(l *Layout) { l.Key.Mode = KeyPrincipal }),
		"a principal key without pattern": with(func(l *Layout) {
			l.Key = Key{Mode: KeyPrincipal}
		}),
		"a fixed key with a pattern":   with(func(l *Layout) { l.Key = Key{Mode: KeyFixed, Prefix: "s", Pattern: "x"} }),
		"a fixed key without a prefix": with(func(l *Layout) { l.Key = Key{Mode: KeyFixed} }),
		"a prefix not UTF-8":           with(func(l *Layout) { l.Key.Prefix = "\xff" }),
		"a negative max_payload":       with(func(l *Layout) { l.MaxPayload = -1 }),
		"max_payload above the limit":  with(func(l *Layout) { l.MaxPayload = MaxPayloadLimit + 1 }),
		"an unknown unlisted rule":     with(func(l *Layout) { l.Unlisted = "maybe" }),
	}
	for name, l := range invalid {
		if err := l.Validate(); !errors.Is(err, ErrLayout) {
			t.Errorf("%s: got %v, want ErrLayout", name, err)
		}
	}
	valid := map[string]Layout{
		"the example":             climate(),
		"the key inside a field":  {Key: Key{Mode: KeyPointer, Pointer: "/m/id", Pattern: "[a-z]+"}, Groups: []Group{{Name: "m", Fields: []string{"/m"}}}},
		"the most groups":         with(func(l *Layout) { l.Groups = groups(MaxGroups) }),
		"the most fields":         with(func(l *Layout) { l.Groups = []Group{{Name: "g", Fields: fields(MaxFields)}} }),
		"the most tokens":         with(func(l *Layout) { l.Groups[1].Fields = []string{tokens(MaxDepth)} }),
		"the longest pointer":     with(func(l *Layout) { l.Groups[1].Fields = []string{"/" + strings.Repeat("a", maxPointer-1)} }),
		"the largest max_payload": with(func(l *Layout) { l.MaxPayload = MaxPayloadLimit }),
		"dropping unlisted":       with(func(l *Layout) { l.Unlisted = Drop }),
		"refusing unlisted":       with(func(l *Layout) { l.Unlisted = Refuse }),
		"escaped tokens":          one("/a~1b", "/m~0n"),
	}
	for name, l := range valid {
		if err := l.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseUnit(t *testing.T) {
	r := mustSplit(t, climate(), fullReading, "")
	for i, u := range r.Units {
		group, fields, err := ParseUnit(u)
		if err != nil || group != climate().Groups[i].Name {
			t.Fatalf("unit %d: %q %v", i, group, err)
		}
		if names := slices.Sorted(maps.Keys(fields)); !slices.Equal(names, r.Fields[i]) {
			t.Fatalf("unit %d fields %q, want %q", i, names, r.Fields[i])
		}
	}
	_, fields, _ := ParseUnit(r.Units[0])
	if got := string(fields["/temperature"]); got != "21.50" {
		t.Fatalf("temperature %s", got)
	}
	for _, bad := range []string{``, `{}`, `[]`, `{"group":"climate"}`, `{"group":"climate","fields":null}`,
		`{"group":"Climate","fields":{}}`, `{"group":"climate","fields":{},"extra":1}`,
		`{"group":"climate","fields":{"temperature":1}}`, `{"group":"climate","group":"x","fields":{}}`} {
		if _, _, err := ParseUnit([]byte(bad)); !errors.Is(err, ErrUnit) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}

type vectorCase struct {
	Name      string     `json:"name"`
	Layout    Layout     `json:"layout"`
	Principal string     `json:"principal,omitempty"`
	Payload   string     `json:"payload"`
	Refused   bool       `json:"refused,omitempty"`
	Key       string     `json:"key,omitempty"`
	Units     []string   `json:"units,omitempty"`
	Fields    [][]string `json:"fields,omitempty"`
}

type vectorSet struct {
	Profile string       `json:"profile"`
	About   string       `json:"about"`
	Cases   []vectorCase `json:"cases"`
}

// vectorInputs are the cases -update records. Payloads are valid UTF-8,
// since the vector file holds them as JSON strings; invalid UTF-8 is
// covered by TestSplitRefusals.
func vectorInputs() []vectorCase {
	withDrop := climate()
	withDrop.Unlisted = Drop
	climateOnly := []Group{{Name: "climate", Fields: []string{"/temperature"}}}
	return []vectorCase{
		{Name: "two groups", Layout: climate(), Payload: fullReading},
		{Name: "a group with no field present", Layout: climate(), Payload: `{"sensor":"gh-south-2","temperature":19}`},
		{Name: "string escapes", Layout: one("/s"), Payload: `{"s":"<b>&é\n\u0001\u001f \"\\\/x"}`},
		{Name: "numbers keep their text", Layout: one("/n"), Payload: `{"n":[-0,1E+2,21.50,0.1e-3,123456789012345678901234567890]}`},
		{Name: "objects sorted, arrays kept", Layout: one("/a", "/o"), Payload: `{"o":{"b":true,"a":false,"":null},"a":[1,[2,{"y":1,"x":2}],null]}`},
		{Name: "escaped pointers", Layout: one("/a~1b", "/m~0n", "/x/~01"), Payload: `{"a/b":1,"m~n":2,"x":{"~1":3}}`},
		{Name: "a lone surrogate", Layout: one("/s"), Payload: `{"s":"\ud800x"}`},
		{Name: "a surrogate pair", Layout: one("/s"), Payload: `{"s":"😀"}`},
		{Name: "principal key", Layout: Layout{Key: Key{Mode: KeyPrincipal, Pattern: "[a-z0-9-]{1,64}", Prefix: "device/"}, Groups: climateOnly},
			Principal: "dev-7", Payload: `{"temperature":1}`},
		{Name: "fixed key", Layout: one("/temperature"), Payload: `{"temperature":1}`},
		{Name: "the key inside a field", Layout: Layout{Key: Key{Mode: KeyPointer, Pointer: "/meta/id", Pattern: "[a-z]+"},
			Groups: []Group{{Name: "meta", Fields: []string{"/meta"}}}}, Payload: `{"meta":{"site":"x","id":"abc"}}`},
		{Name: "unlisted members dropped", Layout: withDrop, Payload: `{"sensor":"a","secret":"x","temperature":3}`},
		{Name: "depth 32", Layout: one("/d"), Payload: `{"d":` + strings.Repeat("[", MaxDepth-1) + strings.Repeat("]", MaxDepth-1) + `}`},
		{Name: "refused: a member in no group", Layout: climate(), Payload: `{"sensor":"a","secret":"x"}`},
		{Name: "refused: a duplicate member", Layout: climate(), Payload: `{"sensor":"a","sensor":"b"}`},
		{Name: "refused: a key not matching", Layout: climate(), Payload: `{"sensor":"Gh North"}`},
		{Name: "refused: deeper than 32", Layout: one("/d"), Payload: `{"d":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `}`},
		{Name: "refused: not an object", Layout: one("/d"), Payload: `[{"d":1}]`},
		{Name: "refused: trailing data", Layout: one("/d"), Payload: `{"d":1}{"d":2}`},
	}
}

func TestVectors(t *testing.T) {
	if *updateVectors {
		set := vectorSet{Profile: Profile, Cases: vectorInputs(),
			About: "Cases of the profile " + Profile + " (docs/design/mcp-data-tools.md). Split each payload, posted by " +
				"principal, under its layout: produce exactly key, units and fields, or refuse where refused is true. " +
				"Payloads and units are the exact bytes, held as JSON strings."}
		for i := range set.Cases {
			c := &set.Cases[i]
			r, err := split(t, c.Layout, c.Payload, c.Principal)
			switch {
			case errors.Is(err, ErrReading):
				c.Refused = true
			case err != nil:
				t.Fatalf("%s: %v", c.Name, err)
			default:
				c.Key, c.Units, c.Fields = r.Key, unitStrings(r), r.Fields
			}
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(set); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorFile, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var set vectorSet
	if err := json.Unmarshal(data, &set); err != nil || set.Profile != Profile || len(set.Cases) == 0 {
		t.Fatalf("%s: %v", vectorFile, err)
	}
	for _, c := range set.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, err := split(t, c.Layout, c.Payload, c.Principal)
			if c.Refused {
				if !errors.Is(err, ErrReading) {
					t.Fatalf("got %v, want a refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Key != c.Key || !slices.Equal(unitStrings(r), c.Units) || !equalFields(r.Fields, c.Fields) {
				t.Fatalf("got %q %q %q\nwant %q %q %q", r.Key, unitStrings(r), r.Fields, c.Key, c.Units, c.Fields)
			}
		})
	}
}
