package main

import (
	"testing"

	"fga/internal/depcheck"
)

// TestNoServerCode covers MOD-004 and MCP-005 for the client: the CLI and
// its MCP bridge link the client's own crypto and the MCP SDK, but none
// of the server roles' catalog, content, payload, key-encryption,
// envelope, fence, decision-service or MCP-role code.
func TestNoServerCode(t *testing.T) {
	// The client encrypts client-mode payloads itself with Tink's
	// streaming AEAD; the server's payload code is another matter.
	server := append([]string{"fga/internal/payload", "fga/internal/catalog", "fga/internal/content", "fga/internal/blob",
		"fga/internal/envelope", "fga/internal/fence", "fga/internal/journal", "fga/internal/decisionsvc", "fga/internal/gate",
		"fga/internal/nativeapi", "fga/internal/httpapi", "fga/internal/mcpsvc", "fga/internal/roleconfig", "fga/internal/rpc",
		"github.com/jackc/"}, depcheck.KeyEncryption...)
	for _, dep := range depcheck.Deps(t) {
		if bad := depcheck.Disallowed([]string{dep}, server); len(bad) == 0 {
			t.Errorf("the CLI links %s", dep)
		}
	}
}
