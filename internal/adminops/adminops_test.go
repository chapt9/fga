package adminops

import (
	"errors"
	"reflect"
	"testing"

	"fga/internal/delegation"
)

func TestCapabilities(t *testing.T) {
	got, err := Capabilities("approver", nil)
	if err != nil || !reflect.DeepEqual(got["storage.object"], []string{"approve"}) {
		t.Fatalf("approver = %v, %v", got, err)
	}
	got["storage.object"] = nil
	if Presets["approver"]["storage.object"] == nil {
		t.Fatal("a caller changed the preset")
	}
	if _, err := Capabilities("", map[string][]string{"storage.object": {"read", "stat"}}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		preset  string
		actions map[string][]string
	}{
		"nothing":            {},
		"both":               {"storage", map[string][]string{"storage.object": {"read"}}},
		"an unknown preset":  {preset: "everything"},
		"an unknown type":    {actions: map[string][]string{"storage.vault": {"read"}}},
		"an unknown action":  {actions: map[string][]string{"storage.object": {"fly"}}},
		"a type, no actions": {actions: map[string][]string{"storage.object": {}}},
	} {
		if _, err := Capabilities(c.preset, c.actions); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseGrants(t *testing.T) {
	got, err := ParseGrants("storage.object:read, stat; agent.tool:*")
	want := []delegation.Grant{{ResourceType: "agent.tool", Actions: []string{"*"}}, {ResourceType: "storage.object", Actions: []string{"read", "stat"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("grants = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "storage.object", "storage.object:", "storage.vault:read", "storage.object:fly"} {
		if _, err := ParseGrants(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestCheckID(t *testing.T) {
	for _, ok := range []string{"alice", "agent-7", "auth0|5f8a", "user@example.com", "00u1ab2C3D"} {
		if err := checkID("identity", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a/b", "tab\there", string(make([]byte, 257))} {
		if err := checkID("identity", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
}
