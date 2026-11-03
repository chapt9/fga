package jsonunits

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestProjection covers DTL-005: outputs name fields of the layout's
// groups; a projection renames them, keeps values of the declared type
// only, and leaves out a reading with an unreadable group under
// skip_reading or with no readable group under skip_fields.
func TestProjection(t *testing.T) {
	l := Layout{Key: Key{Mode: KeyPointer, Pointer: "/id", Pattern: "[a-z]+", Prefix: "s/"},
		Groups: []Group{{Name: "climate", Fields: []string{"/id", "/t", "/note"}}, {Name: "place", Fields: []string{"/gps"}}}}
	out := func(name, group, field, typ string) Output {
		return Output{Name: name, Group: group, Field: field, Type: typ}
	}
	p := Projection{Outputs: []Output{out("temp", "climate", "/t", TypeNumber), out("note", "climate", "/note", TypeNumber),
		out("where", "place", "/gps", TypeObject)}}
	if err := p.Check(l); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Projection{
		"no outputs":       {},
		"a field of none":  {Outputs: []Output{out("x", "climate", "/gps", "")}},
		"an unknown group": {Outputs: []Output{out("x", "other", "/t", "")}},
		"a repeated name":  {Outputs: []Output{out("x", "climate", "/t", ""), out("x", "place", "/gps", "")}},
		"a bad name":       {Outputs: []Output{out("X", "climate", "/t", "")}},
		"a bad type":       {Outputs: []Output{out("x", "climate", "/t", "integer")}},
		"a bad mode":       {Outputs: []Output{out("x", "climate", "/t", "")}, OnUnreadable: "skip"},
	} {
		if err := bad.Check(l); !errors.Is(err, ErrLayout) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s, err := l.Compile()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Split([]byte(`{"id":"north","t":21.5,"note":"warm","gps":{"lat":1}}`), "")
	if err != nil {
		t.Fatal(err)
	}
	both := map[string][]byte{"climate": r.Units[0], "place": r.Units[1]}
	got, ok, err := p.Apply(both)
	if err != nil || !ok || string(got["temp"]) != "21.5" || got["note"] != nil || string(got["where"]) != `{"lat":1}` {
		t.Fatalf("both groups: %s, %v, %v", mustMarshal(got), ok, err)
	}
	if _, ok, err := p.Apply(map[string][]byte{"climate": r.Units[0]}); ok || err != nil {
		t.Fatalf("skip_reading with an unreadable group kept the reading: %v", err)
	}
	p.OnUnreadable = SkipFields
	if got, ok, err := p.Apply(map[string][]byte{"climate": r.Units[0]}); !ok || err != nil || len(got) != 1 || got["where"] != nil {
		t.Fatalf("skip_fields: %s, %v, %v", mustMarshal(got), ok, err)
	}
	if _, ok, _ := p.Apply(map[string][]byte{}); ok {
		t.Fatal("skip_fields kept a reading with no readable group")
	}
	if _, _, err := p.Apply(map[string][]byte{"place": r.Units[0]}); !errors.Is(err, ErrUnit) {
		t.Fatalf("a unit given for another group: %v", err)
	}
	for v, want := range map[string]bool{"north": true, "North": false, "": false} {
		if key, ok := s.KeyFor(v); ok != want || ok && (key != "s/"+v || !s.HasKey(key)) {
			t.Errorf("KeyFor(%q) = %q, %v", v, key, ok)
		}
	}
	if s.HasKey("t/north") || s.HasKey("s/North") {
		t.Error("HasKey admits a key the layout cannot give")
	}
	fixed, _ := Layout{Key: Key{Mode: KeyFixed, Prefix: "all"}, Groups: l.Groups}.Compile()
	if _, ok := fixed.KeyFor("all"); ok || !fixed.HasKey("all") || fixed.HasKey("all2") {
		t.Error("a fixed key")
	}
}

func mustMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
