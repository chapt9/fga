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
	depcheck.CheckForbidden(t, depcheck.PayloadCipher...)
}

// TestNoStorageCode: the keys role links neither the blob store nor the
// content service; it has no blob directory and serves no object bytes
// (MOD-002).
func TestNoStorageCode(t *testing.T) {
	for _, dep := range depcheck.Deps(t) {
		if dep == "fga/internal/blob" || dep == "fga/internal/content" {
			t.Errorf("the keys role links %s", dep)
		}
	}
}
