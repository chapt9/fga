package main

import (
	"testing"

	"fga/internal/depcheck"
)

// TestImportAllowlist covers MOD-004 and D-13 for the key management role:
// it links only reviewed packages, and no payload cipher, client
// decryption, MCP or executor code.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	depcheck.CheckForbidden(t, depcheck.PayloadCipher...)
}

// TestNoAuthorityCode: the role holds keys and decides nothing; it links
// no catalog, policy, decision or storage code.
func TestNoAuthorityCode(t *testing.T) {
	for _, dep := range depcheck.Deps(t) {
		switch dep {
		case "fga/internal/catalog", "fga/internal/policy", "fga/internal/decisionsvc", "fga/internal/content", "fga/internal/datakeys",
			"github.com/jackc/pgx/v5":
			t.Errorf("the key management role links %s", dep)
		}
	}
}
