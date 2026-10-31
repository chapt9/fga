package main

import (
	"slices"
	"testing"

	"fga/internal/depcheck"
)

// TestImportAllowlist covers MOD-004 and T-20: the decision role's
// transitive non-standard imports must all be on the checked-in allowlist,
// and the allowlist admits no client decryption, MCP or executor package.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	depcheck.CheckForbidden(t)
}

// TestAllowlistCatchesForbiddenImports covers V-101 and V-137 with
// synthetic import graphs, so the check is known to fail when it should.
func TestAllowlistCatchesForbiddenImports(t *testing.T) {
	allow := depcheck.Allowlist(t, "allowed-imports.txt")
	for name, dep := range map[string]string{
		"S3 handlers (V-101)": "fga/internal/s3/handlers",
		"MCP SDK (V-137)":     "github.com/modelcontextprotocol/go-sdk/mcp",
		"tool connectors":     "fga/internal/tools/connectors",
		"look-alike prefix":   "fga/internal/policyx",
	} {
		if bad := depcheck.Disallowed([]string{"fga/internal/decision", dep}, allow); !slices.Equal(bad, []string{dep}) {
			t.Errorf("%s: disallowed = %v, want [%s]", name, bad, dep)
		}
	}
}
