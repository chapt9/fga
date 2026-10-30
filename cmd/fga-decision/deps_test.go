package main

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// disallowed returns the packages of deps that no allowlist entry covers. An
// entry ending in "/" covers every path under it; any other entry covers that
// package and its subpackages, but not a look-alike such as "policyx" for
// "policy".
func disallowed(deps, allow []string) []string {
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

func readAllowlist(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("allowed-imports.txt")
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

// TestImportAllowlist covers MOD-004 and T-20: the decision role's
// transitive non-standard imports must all be on the checked-in allowlist.
func TestImportAllowlist(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if bad := disallowed(deps, readAllowlist(t)); len(bad) > 0 {
		t.Fatalf("the decision role imports packages that are not on allowed-imports.txt:\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestAllowlistCatchesForbiddenImports covers V-101 and V-137 with
// synthetic import graphs, so the check is known to fail when it should.
func TestAllowlistCatchesForbiddenImports(t *testing.T) {
	allow := readAllowlist(t)
	for name, dep := range map[string]string{
		"S3 handlers (V-101)": "fga/internal/s3/handlers",
		"MCP SDK (V-137)":     "github.com/modelcontextprotocol/go-sdk/mcp",
		"tool connectors":     "fga/internal/tools/connectors",
		"look-alike prefix":   "fga/internal/policyx",
	} {
		if bad := disallowed([]string{"fga/internal/decision", dep}, allow); !slices.Equal(bad, []string{dep}) {
			t.Errorf("%s: disallowed = %v, want [%s]", name, bad, dep)
		}
	}
}
