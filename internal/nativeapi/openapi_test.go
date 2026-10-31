package nativeapi_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestOpenAPICoversRoutes is the regression test of review v3 F12: four
// public routes were missing from the OpenAPI description. Every /v1
// route the native API registers must be described there with its method.
func TestOpenAPICoversRoutes(t *testing.T) {
	src, err := os.ReadFile("nativeapi.go")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile("../../docs/design/native-api.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// The path blocks of the description: "  /v1/...:" followed by its
	// four-space-indented methods.
	methods := map[string]map[string]bool{}
	var path string
	for _, line := range strings.Split(string(spec), "\n") {
		switch {
		case strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":"):
			path = strings.TrimSuffix(strings.TrimSpace(line), ":")
			methods[path] = map[string]bool{}
		case strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && path != "":
			if m := strings.TrimSuffix(strings.TrimSpace(line), ":"); m != strings.TrimSpace(line) {
				methods[path][strings.ToUpper(m)] = true
			}
		case !strings.HasPrefix(line, " "):
			path = ""
		}
	}
	routes := regexp.MustCompile(`HandleFunc\("([A-Z]+) (/v1/[^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(routes) < 40 {
		t.Fatalf("found %d routes; the scan is broken", len(routes))
	}
	for _, r := range routes {
		if !methods[r[2]][r[1]] {
			t.Errorf("%s %s is not in the OpenAPI description", r[1], r[2])
		}
	}
}
