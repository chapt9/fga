package decisionsvc

import (
	"testing"

	"fga/internal/authn"
	"fga/internal/registry"
)

// TestKeyLimits covers how a sign-in key's limits narrow a decision
// (docs/design/sign-in-keys.md): spaces by a bucket's name or a
// resource's bucket, labels by the release's order, and nothing for a
// resource without a space or label.
func TestKeyLimits(t *testing.T) {
	order := []string{"public", "internal", "confidential", "restricted"}
	res := func(typ string, attrs map[string]any) registry.Resource {
		return registry.Resource{Type: typ, Attributes: attrs}
	}
	bucket := res("storage.bucket", map[string]any{"name": "greenhouse", "label": "internal"})
	reading := res("document.text_unit", map[string]any{"bucket": "greenhouse", "label": "confidential"})
	other := res("storage.object", map[string]any{"bucket": "reports", "label": "internal"})
	tool := res("agent.tool", map[string]any{})
	strange := res("storage.object", map[string]any{"bucket": "greenhouse", "label": "secret"})
	for name, c := range map[string]struct {
		limits authn.KeyLimits
		res    []registry.Resource
		want   bool
	}{
		"no limits":                   {authn.KeyLimits{}, []registry.Resource{bucket, reading, other, tool}, true},
		"its space":                   {authn.KeyLimits{Spaces: []string{"greenhouse"}}, []registry.Resource{bucket, reading, tool}, true},
		"another space":               {authn.KeyLimits{Spaces: []string{"greenhouse"}}, []registry.Resource{bucket, other}, false},
		"at its label":                {authn.KeyLimits{MaxLabel: "confidential"}, []registry.Resource{reading, other}, true},
		"above its label":             {authn.KeyLimits{MaxLabel: "internal"}, []registry.Resource{reading}, false},
		"a label outside the order":   {authn.KeyLimits{MaxLabel: "restricted"}, []registry.Resource{strange}, false},
		"a limit outside the order":   {authn.KeyLimits{MaxLabel: "top"}, []registry.Resource{other}, false},
		"no space or label to limit":  {authn.KeyLimits{Spaces: []string{"x"}, MaxLabel: "public"}, []registry.Resource{tool}, true},
		"services limit no resources": {authn.KeyLimits{Services: []string{"fga-storage"}}, []registry.Resource{other}, true},
	} {
		if got := (&keyUse{limits: c.limits}).allows(c.res, order); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
