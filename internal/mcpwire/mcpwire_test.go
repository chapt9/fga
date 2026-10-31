package mcpwire

import (
	"encoding/json"
	"testing"
)

// TestCapability covers the capability's form: it round trips through the
// JSON of an MCP initialize request, and another version or a value
// without a recipient fingerprint is not the capability.
func TestCapability(t *testing.T) {
	want := ClientCapability{Version: Version, Recipient: "sha256:ab12"}
	b, err := json.Marshal(want.Experimental())
	if err != nil {
		t.Fatal(err)
	}
	var experimental map[string]any
	if err := json.Unmarshal(b, &experimental); err != nil {
		t.Fatal(err)
	}
	if got, ok := ParseCapability(experimental); !ok || got != want {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	for name, v := range map[string]any{
		"another version":  map[string]any{"version": 2, "recipient": "sha256:ab12"},
		"no recipient":     map[string]any{"version": 1},
		"not a digest":     map[string]any{"version": 1, "recipient": "alice"},
		"not an object":    "yes",
		"another key only": nil,
	} {
		exp := map[string]any{Capability: v}
		if name == "another key only" {
			exp = map[string]any{"other": true}
		}
		if got, ok := ParseCapability(exp); ok {
			t.Errorf("%s: parsed %+v", name, got)
		}
	}
}
