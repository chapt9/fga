package main

import (
	"testing"

	"fga/internal/depcheck"
)

// TestImportAllowlist covers MOD-004 and T-20 for the storage role: it
// links only reviewed packages, and no client decryption, key unwrapping,
// MCP or executor code.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	depcheck.CheckForbidden(t)
}

// TestNoKeyEncryptionKeys covers SSE-002 and MOD-004: the storage role
// links neither the key-encryption keys nor the code that seals and
// releases data keys; it receives a data key only from the keys role.
func TestNoKeyEncryptionKeys(t *testing.T) {
	for _, dep := range depcheck.Deps(t) {
		if dep == "fga/internal/kek" || dep == "fga/internal/datakeys" || dep == "fga/internal/datakeysapi" {
			t.Errorf("the storage role links %s", dep)
		}
	}
}
