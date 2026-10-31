package main

import (
	"slices"
	"testing"

	"fga/internal/depcheck"
)

// TestImportAllowlist covers MOD-004 and T-20 for the tools role: it links
// only reviewed packages, and the allowlist admits no payload cipher,
// key-encryption, client decryption, storage content or MCP package.
func TestImportAllowlist(t *testing.T) {
	depcheck.Check(t)
	allow := depcheck.Allowlist(t, "allowed-imports.txt")
	executor := []string{"fga/internal/tools", "fga/internal/toolstore", "fga/internal/invocation"}
	forbidden := slices.DeleteFunc(slices.Clone(depcheck.Forbidden), func(p string) bool { return slices.Contains(executor, p) })
	for _, dep := range slices.Concat(forbidden, depcheck.PayloadCipher, depcheck.KeyEncryption,
		[]string{"fga/internal/content", "fga/internal/blob", "fga/internal/journal", "fga/internal/mcpsvc"}) {
		if bad := depcheck.Disallowed([]string{dep}, allow); len(bad) != 1 {
			t.Errorf("allowed-imports.txt admits %s", dep)
		}
	}
}

// TestValidate covers MOD-003 for the tools role's own settings.
func TestValidate(t *testing.T) {
	for _, c := range []Config{{OutboxCapacity: 0}, {OutboxCapacity: 10, Lease: "soon"}, {OutboxCapacity: 10, ConnectorTimeout: "-1s"}} {
		if c.Validate() == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}
