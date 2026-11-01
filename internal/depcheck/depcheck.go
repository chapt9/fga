// Package depcheck checks a role's transitive imports against its reviewed
// allowlist (specification 2.5, MOD-004, T-20). Role tests call it.
package depcheck

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Disallowed returns the packages of deps that no allowlist entry covers.
// An entry ending in "/" covers every path under it; any other entry covers
// that package and its subpackages, but not a look-alike such as
// "policyx" for "policy".
func Disallowed(deps, allow []string) []string {
	covers := func(entry, dep string) bool {
		if strings.HasSuffix(entry, "/") {
			return strings.HasPrefix(dep, entry)
		}
		return dep == entry || strings.HasPrefix(dep, entry+"/")
	}
	var out []string
	for _, d := range deps {
		if !slices.ContainsFunc(allow, func(e string) bool { return covers(e, d) }) {
			out = append(out, d)
		}
	}
	return out
}

// Allowlist reads an allowlist file: one entry per line, # comments.
func Allowlist(t testing.TB, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var allow []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			allow = append(allow, line)
		}
	}
	return allow
}

// Deps lists the non-standard transitive imports of the package in the
// current directory.
func Deps(t testing.TB) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	return strings.Fields(string(out))
}

// Check fails t if the current package imports anything off allowed-imports.txt.
func Check(t testing.TB) {
	t.Helper()
	if bad := Disallowed(Deps(t), Allowlist(t, "allowed-imports.txt")); len(bad) > 0 {
		t.Fatalf("the role imports packages that are not on allowed-imports.txt:\n  %s", strings.Join(bad, "\n  "))
	}
}

// Forbidden are packages no server role may link: client decryption and
// envelope unwrapping, MCP, and the optional tool executor (MOD-004).
var Forbidden = []string{
	"github.com/tink-crypto/tink-go/v2/hybrid",
	"fga/sdk/go/crypto",
	"github.com/modelcontextprotocol/go-sdk/mcp",
	"fga/internal/tools",
	"fga/internal/toolstore",
	"fga/internal/invocation",
}

// PayloadCipher is the server-mode payload cipher (specification 2.6,
// SSE-001): only the storage role, which encrypts and decrypts server-mode
// payloads, may link it; every other server role passes it to
// CheckForbidden (MOD-004).
var PayloadCipher = []string{
	"github.com/tink-crypto/tink-go/v2/streamingaead",
	"fga/internal/payload",
}

// KeyEncryption is the server-mode key-encryption code: only the keys role
// and the key management role, fga-kms, may link it (SSE-002, D-13).
var KeyEncryption = []string{
	"fga/internal/kek",
	"fga/internal/datakeys",
	"fga/internal/datakeysapi",
}

// CheckForbidden fails t if the allowlist would admit a forbidden package,
// or one of also, so the check is known to fail when it should.
func CheckForbidden(t testing.TB, also ...string) {
	t.Helper()
	allow := Allowlist(t, "allowed-imports.txt")
	for _, dep := range append(slices.Clone(Forbidden), also...) {
		if bad := Disallowed([]string{dep}, allow); len(bad) != 1 {
			t.Errorf("allowed-imports.txt admits %s", dep)
		}
	}
}
