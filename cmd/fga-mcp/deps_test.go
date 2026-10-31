package main

import (
	"slices"
	"testing"

	"fga/internal/depcheck"
)

// noMCPRole are packages the MCP role may not link: no permission rules or
// evaluator, catalog, blob store, key or payload code, client decryption
// or executor (MCP-002, MCP-006, MCP-008, MOD-004).
var noMCPRole = slices.Concat(
	slices.DeleteFunc(slices.Clone(depcheck.Forbidden), func(p string) bool { return p == "github.com/modelcontextprotocol/go-sdk/mcp" }),
	depcheck.PayloadCipher, depcheck.KeyEncryption,
	[]string{"fga/internal/catalog", "fga/internal/blob", "fga/internal/content", "fga/internal/fence", "fga/internal/journal",
		"fga/internal/envelope", "fga/internal/keyfile", "fga/internal/policy", "fga/internal/decision", "fga/internal/decisionsvc",
		"fga/internal/gate", "fga/internal/registry", "fga/internal/release", "fga/internal/roleconfig", "fga/internal/rpc",
		"github.com/jackc/pgx/v5", "cel.dev/expr", "github.com/tink-crypto/tink-go/v2/aead"})

// TestImportAllowlist covers MOD-004, T-20 and MCP-008 for the MCP role:
// it links only reviewed packages, and the allowlist admits none of
// noMCPRole.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	allow := depcheck.Allowlist(t, "allowed-imports.txt")
	for _, dep := range noMCPRole {
		if bad := depcheck.Disallowed([]string{dep}, allow); len(bad) != 1 {
			t.Errorf("allowed-imports.txt admits %s", dep)
		}
	}
}
