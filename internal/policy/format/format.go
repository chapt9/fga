// Package format defines policy documents in the project's own format,
// fga.policy/v1, and validates them (specification 2.2, Section 1.4.2,
// POL-002, POL-007, POL-014).
package format

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"fga/internal/strictjson"
)

// Version is the only supported value of Document.Format.
const Version = "fga.policy/v1"

// Policy sets.
const (
	SetBusiness = "business"
	SetCeiling  = "ceiling"
)

// Rule effects.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Wildcard matches any action or any role.
const Wildcard = "*"

// Limits on a bundle (POL-009, DEC-009).
const (
	MaxConditionBytes = 8 << 10
	MaxRulesPerBundle = 10_000
	MaxScopeDepth     = 8
)

// Document holds the rules of one policy set for one resource type in one
// scope.
type Document struct {
	Format   string `json:"format"`
	Set      string `json:"set"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	Rules    []Rule `json:"rules"`
}

// Rule allows or denies actions for roles, optionally under a condition.
type Rule struct {
	ID      string   `json:"id"`
	Effect  string   `json:"effect"`
	Actions []string `json:"actions"`
	Roles   []string `json:"roles"`
	// When is a CEL expression; empty means the rule always applies.
	When string `json:"when,omitempty"`
}

// Schema reports which resource types and actions are registered (RES-001).
type Schema interface {
	HasResourceType(resourceType string) bool
	HasAction(resourceType, action string) bool
}

var (
	identifier   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopeSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
)

// Parse decodes one document. Unknown fields, duplicate fields and trailing
// data are rejected, so a misspelled or repeated field is never ignored.
func Parse(data []byte) (Document, error) {
	var d Document
	if err := strictjson.Decode(data, &d); err != nil {
		return Document{}, fmt.Errorf("policy document: %w", err)
	}
	return d, nil
}

// ValidateBundle checks every document of a bundle against the format and
// the registry. It reports all problems at once.
func ValidateBundle(docs []Document, schema Schema) error {
	type docKey struct{ set, resource, scope string }
	var errs []error
	seenDocs := map[docKey]bool{}
	seenRules := map[string]bool{}
	ruleCount := 0
	for i, d := range docs {
		where := fmt.Sprintf("document %d (%s, %s, scope %q)", i, d.Set, d.Resource, d.Scope)
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...)))
		}
		if d.Format != Version {
			fail("unsupported format %q", d.Format)
		}
		if d.Set != SetBusiness && d.Set != SetCeiling {
			fail("unknown policy set %q", d.Set)
		}
		knownType := schema.HasResourceType(d.Resource)
		if !knownType {
			fail("unknown resource type %q", d.Resource)
		}
		if !ValidScope(d.Scope) {
			fail("invalid scope")
		}
		key := docKey{d.Set, d.Resource, d.Scope}
		if seenDocs[key] {
			fail("another document has the same set, resource type and scope")
		}
		seenDocs[key] = true
		if len(d.Rules) == 0 {
			fail("no rules")
		}
		for _, r := range d.Rules {
			ruleCount++
			if !identifier.MatchString(r.ID) {
				fail("invalid rule id %q", r.ID)
			} else if seenRules[r.ID] {
				fail("duplicate rule id %q", r.ID)
			}
			seenRules[r.ID] = true
			switch r.Effect {
			case EffectDeny:
			case EffectAllow:
				if d.Set == SetCeiling {
					fail("rule %q: the ceiling set allows only deny rules", r.ID)
				}
			default:
				fail("rule %q: unknown effect %q", r.ID, r.Effect)
			}
			if len(r.Actions) == 0 {
				fail("rule %q: no actions", r.ID)
			}
			for _, a := range r.Actions {
				if a != Wildcard && knownType && !schema.HasAction(d.Resource, a) {
					fail("rule %q: action %q is not registered for %s", r.ID, a, d.Resource)
				}
			}
			if len(r.Roles) == 0 {
				fail("rule %q: no roles", r.ID)
			}
			for _, role := range r.Roles {
				if role != Wildcard && !identifier.MatchString(role) {
					fail("rule %q: invalid role %q", r.ID, role)
				}
			}
			if len(r.When) > MaxConditionBytes {
				fail("rule %q: condition longer than %d bytes", r.ID, MaxConditionBytes)
			}
		}
	}
	if ruleCount > MaxRulesPerBundle {
		errs = append(errs, fmt.Errorf("bundle has %d rules, limit is %d", ruleCount, MaxRulesPerBundle))
	}
	return errors.Join(errs...)
}

// ValidScope reports whether scope is the root ("") or a dot-separated chain
// of lowercase segments no deeper than MaxScopeDepth.
func ValidScope(scope string) bool {
	if scope == "" {
		return true
	}
	segments := strings.Split(scope, ".")
	if len(segments) > MaxScopeDepth {
		return false
	}
	for _, s := range segments {
		if !scopeSegment.MatchString(s) {
			return false
		}
	}
	return true
}

// ScopeChain returns scope followed by each of its ancestors, ending with the
// root "" (POL-014). For "acme.eu" it returns "acme.eu", "acme" and "".
func ScopeChain(scope string) []string {
	chain := []string{}
	for scope != "" {
		chain = append(chain, scope)
		i := strings.LastIndexByte(scope, '.')
		if i < 0 {
			break
		}
		scope = scope[:i]
	}
	return append(chain, "")
}
