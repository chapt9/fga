package main

import (
	"slices"
	"strings"
	"testing"

	"fga/internal/depcheck"
)

// TestNoClientCrypto covers MOD-004 for the administrator's tool: it links
// no client decryption, key unwrapping, MCP or executor code.
func TestNoClientCrypto(t *testing.T) {
	for _, dep := range depcheck.Deps(t) {
		if slices.ContainsFunc(depcheck.Forbidden, func(f string) bool { return dep == f || strings.HasPrefix(dep, f+"/") }) {
			t.Errorf("fga-admin links %s", dep)
		}
	}
}
