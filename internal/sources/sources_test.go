package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"fga/internal/jsonunits"
)

const example = `{"format":"fga.source/v1","id":"greenhouse-climate","owner":"team-greenhouse",
 "key":{"mode":"pointer","pointer":"/sensor","pattern":"[a-z0-9-]{1,48}","prefix":"sensor/"},
 "groups":[{"name":"climate","label":"internal","fields":["/temperature","/humidity","/observed_at","/sensor"]},
           {"name":"location","label":"restricted","fields":["/gps"]}],
 "unlisted":"refuse","max_payload":65536}`

var order = []string{"public", "internal", "confidential", "restricted"}

func parsed(t *testing.T) Definition {
	t.Helper()
	d, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParse(t *testing.T) {
	d := parsed(t)
	if d.ID != "greenhouse-climate" || len(d.Groups) != 2 || d.Groups[1].Label != "restricted" || d.Key.Pointer != "/sensor" {
		t.Fatalf("parsed %+v", d)
	}
	for name, bad := range map[string]string{
		"an unknown member":   strings.Replace(example, `"unlisted"`, `"version":2,"unlisted"`, 1),
		"a duplicate member":  strings.Replace(example, `"owner":"team-greenhouse"`, `"owner":"a","owner":"b"`, 1),
		"not JSON":            `{"format":`,
		"trailing data":       example + `{}`,
		"a member in a group": strings.Replace(example, `"label":"internal"`, `"label":"internal","colour":"red"`, 1),
	} {
		if _, err := Parse([]byte(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheck(t *testing.T) {
	if err := parsed(t).Check("server"); err != nil {
		t.Fatal(err)
	}
	client := parsed(t)
	client.Groups[0].Recipients = []string{"lena", "omar"}
	client.Groups[1].Recipients = []string{"facility-1"}
	if err := client.Check("client"); err != nil {
		t.Fatal(err)
	}
	with := func(f func(*Definition)) Definition {
		d := parsed(t)
		f(&d)
		return d
	}
	many := make([]string, MaxRecipients+1)
	for i := range many {
		many[i] = "r" + strings.Repeat("x", i+1)
	}
	for name, c := range map[string]struct {
		def  Definition
		mode string
	}{
		"another format":                   {with(func(d *Definition) { d.Format = "fga.source/v2" }), "server"},
		"an upper-case ID":                 {with(func(d *Definition) { d.ID = "Greenhouse" }), "server"},
		"an ID too long":                   {with(func(d *Definition) { d.ID = strings.Repeat("a", 41) }), "server"},
		"no owner":                         {with(func(d *Definition) { d.Owner = "" }), "server"},
		"an unknown mode":                  {parsed(t), "hybrid"},
		"overlapping fields":               {with(func(d *Definition) { d.Groups[1].Fields = []string{"/temperature"} }), "server"},
		"a bad key":                        {with(func(d *Definition) { d.Key.Pattern = "" }), "server"},
		"a group without a label":          {with(func(d *Definition) { d.Groups[0].Label = "" }), "server"},
		"recipients in server mode":        {with(func(d *Definition) { d.Groups[0].Recipients = []string{"lena"} }), "server"},
		"no recipients in client mode":     {parsed(t), "client"},
		"client recipients in server mode": {client, "server"},
		"a client group without recipient": {with(func(d *Definition) { d.Groups[0].Recipients = []string{"lena"} }), "client"},
		"too many recipients": {with(func(d *Definition) {
			d.Groups[0].Recipients, d.Groups[1].Recipients = many, []string{"lena"}
		}), "client"},
		"a recipient twice": {with(func(d *Definition) {
			d.Groups[0].Recipients, d.Groups[1].Recipients = []string{"lena", "omar", "lena"}, []string{"lena"}
		}), "client"},
	} {
		if err := c.def.Check(c.mode); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestIdentities(t *testing.T) {
	d := parsed(t)
	d.Groups[0].Recipients = []string{"lena", "omar"}
	d.Groups[1].Recipients = []string{"omar", "team-greenhouse", "facility-1"}
	if got, want := d.Identities(), []string{"team-greenhouse", "lena", "omar", "facility-1"}; !slices.Equal(got, want) {
		t.Fatalf("identities %v, want %v", got, want)
	}
}

func TestCheckLabels(t *testing.T) {
	d := parsed(t)
	if err := d.CheckLabels(order, "internal"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		label, floor string
	}{
		"a label below the bucket's": {"public", "internal"},
		"an unknown label":           {"secret", "internal"},
		"an unknown bucket label":    {"internal", "secret"},
	} {
		d := parsed(t)
		d.Groups[0].Label = c.label
		if err := d.CheckLabels(order, c.floor); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCanonical(t *testing.T) {
	d := parsed(t)
	raw, digest, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(Format+"\x00"), raw...))
	if digest != hex.EncodeToString(sum[:]) || Digest(raw) != digest {
		t.Fatalf("digest %s", digest)
	}
	// The stored bytes parse to the same record and give the same bytes,
	// whatever the submitted spacing and member order.
	again, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, digest2, _ := again.Canonical()
	if string(raw2) != string(raw) || digest2 != digest {
		t.Fatalf("stored bytes changed:\n%s\n%s", raw, raw2)
	}
	d.Groups[1].Label = "confidential"
	if _, other, _ := d.Canonical(); other == digest {
		t.Fatal("a changed label kept the digest")
	}
}

func TestLayout(t *testing.T) {
	s, err := parsed(t).Layout().Compile()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Split([]byte(`{"sensor":"gh-north-1","temperature":21.5,"gps":{"lat":1}}`), "")
	if err != nil || r.Key != "sensor/gh-north-1" || len(r.Units) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.Split([]byte(`{"sensor":"gh-north-1","secret":1}`), ""); !errors.Is(err, jsonunits.ErrReading) {
		t.Fatalf("an unlisted member: %v", err)
	}
}
