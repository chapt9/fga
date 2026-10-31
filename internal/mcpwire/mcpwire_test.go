package mcpwire

import (
	"encoding/json"
	"testing"
)

// TestCapability covers the capability's form: it round trips through the
// JSON of MCP client capabilities, under extensions and under the earlier
// experimental key, and another version or a value without a recipient
// fingerprint is not the capability.
func TestCapability(t *testing.T) {
	want := ClientCapability{Version: Version, Recipient: "sha256:ab12"}
	for name, m := range map[string]map[string]any{
		"extensions":   {Extension: want.Settings()},
		"experimental": want.Experimental(),
	} {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		ext, exp := decoded, map[string]any(nil)
		if name == "experimental" {
			ext, exp = nil, decoded
		}
		if got, ok := ParseCapability(ext, exp); !ok || got != want {
			t.Fatalf("%s round trip: %+v %v", name, got, ok)
		}
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
		if got, ok := ParseCapability(nil, exp); ok {
			t.Errorf("%s: parsed %+v", name, got)
		}
	}
}
