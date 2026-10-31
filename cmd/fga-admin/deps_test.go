package main

import (
	"slices"
	"strings"
	"testing"

	"fga/internal/depcheck"
)

// TestNoClientCrypto covers MOD-004 for the administrator's tool: it links
// no envelope unwrapping (HPKE), client SDK, MCP or executor code, and not
// the server-mode payload cipher. It may link Tink's streaming AEAD, which
// encrypts backups (AVL-005), and the KEK ring, to rotate (SSE-002); it
// holds no data key, so it cannot decrypt content.
func TestNoClientCrypto(t *testing.T) {
	forbidden := append(slices.Clone(depcheck.Forbidden), "fga/internal/payload")
	for _, dep := range depcheck.Deps(t) {
		if slices.ContainsFunc(forbidden, func(f string) bool { return dep == f || strings.HasPrefix(dep, f+"/") }) {
			t.Errorf("fga-admin links %s", dep)
		}
	}
}
