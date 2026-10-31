package main

import (
	"testing"

	"fga/internal/depcheck"
)

// TestImportAllowlist covers MOD-004 and T-20 for the keys role: it
// links only reviewed packages, and no client decryption, key unwrapping,
// MCP or executor code.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	depcheck.CheckForbidden(t)
}
