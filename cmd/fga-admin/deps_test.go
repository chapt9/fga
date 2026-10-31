package main

import (
	"slices"
	"strings"
	"testing"

	"fga/internal/depcheck"
)

// TestNoClientCrypto covers MOD-004 for the administrator's tool: it links
// no envelope unwrapping (HPKE), client SDK, MCP or executor code. It may
// link Tink's streaming AEAD, which encrypts backups (AVL-005); it holds no
// payload key, so it cannot decrypt client content with it.
func TestNoClientCrypto(t *testing.T) {
	forbidden := slices.DeleteFunc(slices.Clone(depcheck.Forbidden), func(f string) bool {
		return f == "github.com/tink-crypto/tink-go/v2/streamingaead"
	})
	for _, dep := range depcheck.Deps(t) {
		if slices.ContainsFunc(forbidden, func(f string) bool { return dep == f || strings.HasPrefix(dep, f+"/") }) {
			t.Errorf("fga-admin links %s", dep)
		}
	}
}
