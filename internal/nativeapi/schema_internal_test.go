package nativeapi

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"fga/internal/httpapi"
)

// schemaProperties returns the property names of a component schema of
// the OpenAPI description, as this file formats it.
func schemaProperties(t *testing.T, spec, name string) []string {
	t.Helper()
	var props []string
	in, inProps := false, false
	for _, line := range strings.Split(spec, "\n") {
		switch {
		case line == "    "+name+":":
			in = true
		case in && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			return props
		case in && line == "      properties:":
			inProps = true
		case in && inProps && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         "):
			props = append(props, strings.TrimSpace(strings.SplitN(line, ":", 2)[0]))
		case in && inProps && strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "       "):
			inProps = false
		}
	}
	if !in {
		t.Fatalf("no schema %s", name)
	}
	return props
}

// TestRequestSchemas is the regression test of review v4 F15: a strict
// request schema (additionalProperties: false) must name every field the
// handler reads, or a client built from the description cannot send a
// valid request.
func TestRequestSchemas(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/native-api.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	for _, c := range []struct {
		body    any
		schemas []string
	}{
		{beginBody{}, []string{"BeginRequest"}},
		{finalizeBody{}, []string{"FinalizeRequest", "ServerFinalizeRequest"}},
		{httpapi.EnvelopeBody{}, []string{"Envelope"}},
		{labelBody{}, []string{"LabelRequest"}},
		{encryptionBody{}, []string{"EncryptionRequest"}},
		{proposalBody{}, []string{"ProposalRequest"}},
	} {
		var props []string
		for _, s := range c.schemas {
			props = append(props, schemaProperties(t, spec, s)...)
		}
		typ := reflect.TypeOf(c.body)
		for i := range typ.NumField() {
			name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if name != "" && name != "-" && !slices.Contains(props, name) {
				t.Errorf("%s reads %q, which %v does not allow", typ.Name(), name, c.schemas)
			}
		}
	}
}
