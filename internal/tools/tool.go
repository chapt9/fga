// Package tools holds the trusted tool registry: what a tool is, which
// arguments it accepts, where it sends and which checks it needs
// (specification 2.5, AGT-001, AGT-004, DAT-005). Tool descriptions from
// agents or MCP servers are never trusted; only these records are.
//
// Part of the optional R2 executor (feature executor). No R1 role links it.
package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"fga/internal/opplan"
	"fga/internal/registry"
	"fga/internal/strictjson"
)

// ArgType is the type of a tool argument.
type ArgType string

const (
	ArgString   ArgType = "string"
	ArgInteger  ArgType = "integer"
	ArgMoney    ArgType = "money"
	ArgEnum     ArgType = "enum"
	ArgResource ArgType = "resource"
)

// DefaultMaxLength bounds a string argument that sets no limit.
const DefaultMaxLength = 1024

// ArgSpec declares one argument. A resource argument names a resource by
// alias in Namespace and adds a check of Action on ResourceType, bound to
// the argument's name.
type ArgSpec struct {
	Name         string   `json:"name"`
	Type         ArgType  `json:"type"`
	Required     bool     `json:"required"`
	MaxLength    int      `json:"max_length,omitempty"`
	Values       []string `json:"values,omitempty"`
	Namespace    string   `json:"namespace,omitempty"`
	ResourceType string   `json:"resource_type,omitempty"`
	Action       string   `json:"action,omitempty"`
}

// Endpoint is the call the connector makes on the destination.
type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Tool is a registry record.
type Tool struct {
	ID          string    `json:"id"`
	Version     int       `json:"version"`
	Description string    `json:"description"`
	Destination string    `json:"destination"`
	Endpoint    Endpoint  `json:"endpoint"`
	Arguments   []ArgSpec `json:"arguments"`
	// Budget and AmountArgument name the budget charged and the money
	// argument reserved when a policy requires a reservation.
	Budget         string `json:"budget,omitempty"`
	AmountArgument string `json:"amount_argument,omitempty"`
	// MaxHoldAge bounds how long an UNKNOWN outcome waits before escalation
	// (INV-006).
	MaxHoldAge string `json:"max_hold_age"`
}

var (
	toolID   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	argName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	currency = regexp.MustCompile(`^[A-Z]{3}$`)
	methods  = []string{"POST", "PUT", "PATCH", "DELETE"}
)

// Validate checks the record's structure and that its operation uses only
// registered resource types and actions.
func (t Tool) Validate(types *registry.Types) error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("tool %q: "+format, append([]any{t.ID}, args...)...))
	}
	if !toolID.MatchString(t.ID) {
		fail("invalid id")
	}
	if t.Version < 1 {
		fail("version must be positive")
	}
	if !toolID.MatchString(t.Destination) {
		fail("invalid destination")
	}
	if !slices.Contains(methods, t.Endpoint.Method) || !strings.HasPrefix(t.Endpoint.Path, "/") {
		fail("endpoint needs a method in %v and a path starting with /", methods)
	}
	if age, err := time.ParseDuration(t.MaxHoldAge); err != nil || age <= 0 {
		fail("max_hold_age must be a positive duration")
	}
	seen := map[string]bool{"tool": true, "destination": true} // reserved check roles
	for _, a := range t.Arguments {
		if !argName.MatchString(a.Name) || seen[a.Name] {
			fail("invalid or duplicate argument %q", a.Name)
		}
		seen[a.Name] = true
		switch a.Type {
		case ArgString, ArgInteger, ArgMoney:
		case ArgEnum:
			if len(a.Values) == 0 {
				fail("enum argument %q has no values", a.Name)
			}
		case ArgResource:
			if a.Namespace == "" || !types.HasAction(a.ResourceType, a.Action) {
				fail("resource argument %q needs a namespace and a registered resource type and action", a.Name)
			}
		default:
			fail("argument %q has unknown type %q", a.Name, a.Type)
		}
	}
	if (t.Budget == "") != (t.AmountArgument == "") {
		fail("budget and amount_argument go together")
	}
	if t.AmountArgument != "" {
		i := slices.IndexFunc(t.Arguments, func(a ArgSpec) bool { return a.Name == t.AmountArgument })
		if i < 0 || t.Arguments[i].Type != ArgMoney || !t.Arguments[i].Required {
			fail("amount_argument must name a required money argument")
		}
	}
	if len(errs) == 0 {
		if _, err := registry.NewOperations(types, []registry.Operation{t.Operation()}); err != nil {
			fail("%v", err)
		}
	}
	return errors.Join(errs...)
}

// Operation returns the checks one invocation needs: invoking the tool,
// sending to its destination, and the declared action on every resource
// argument (RES-006).
func (t Tool) Operation() registry.Operation {
	op := registry.Operation{Name: "tool:" + t.ID, Checks: []registry.CheckSpec{
		{Role: "tool", ResourceType: "agent.tool", Action: "invoke"},
		{Role: "destination", ResourceType: "network.destination", Action: "send"},
	}}
	for _, a := range t.Arguments {
		if a.Type == ArgResource {
			op.Checks = append(op.Checks, registry.CheckSpec{Role: a.Name, ResourceType: a.ResourceType, Action: a.Action})
		}
	}
	return op
}

// SchemaDigest identifies the record. A registration is usable only while
// its reviewed digest equals this value (AGT-001).
func (t Tool) SchemaDigest() string {
	raw, _ := json.Marshal(t) // a struct of plain fields always marshals
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Money is an amount in integer minor units with an explicit currency
// (DAT-005).
type Money struct {
	Currency string `json:"currency"`
	Minor    int64  `json:"minor"`
}

// Args are validated arguments in canonical form.
type Args struct {
	values map[string]any
}

// ParseArguments decodes and checks a JSON object of arguments against the
// tool's specification. Unknown, repeated, missing or ill-typed arguments
// are rejected.
func (t Tool) ParseArguments(raw []byte) (Args, error) {
	var in map[string]json.RawMessage
	if err := strictjson.Decode(raw, &in); err != nil {
		return Args{}, fmt.Errorf("arguments: %w", err)
	}
	out := Args{values: map[string]any{}}
	for name := range in {
		if !slices.ContainsFunc(t.Arguments, func(a ArgSpec) bool { return a.Name == name }) {
			return Args{}, fmt.Errorf("arguments: unknown argument %q", name)
		}
	}
	for _, spec := range t.Arguments {
		v, ok := in[spec.Name]
		if !ok {
			if spec.Required {
				return Args{}, fmt.Errorf("arguments: %q is required", spec.Name)
			}
			continue
		}
		parsed, err := parseValue(spec, v)
		if err != nil {
			return Args{}, fmt.Errorf("arguments: %q: %w", spec.Name, err)
		}
		out.values[spec.Name] = parsed
	}
	return out, nil
}

func parseValue(spec ArgSpec, raw json.RawMessage) (any, error) {
	switch spec.Type {
	case ArgString, ArgEnum, ArgResource:
		var s string
		if err := strictjson.Decode(raw, &s); err != nil {
			return nil, errors.New("must be a string")
		}
		limit := spec.MaxLength
		if limit == 0 {
			limit = DefaultMaxLength
		}
		if !utf8.ValidString(s) || len(s) > limit || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' }) {
			return nil, fmt.Errorf("must be valid text of at most %d bytes", limit)
		}
		if spec.Type == ArgEnum && !slices.Contains(spec.Values, s) {
			return nil, fmt.Errorf("must be one of %v", spec.Values)
		}
		if spec.Type == ArgResource && s == "" {
			return nil, errors.New("must name a resource")
		}
		return s, nil
	case ArgInteger:
		return parseInt(raw)
	case ArgMoney:
		var m struct {
			Currency string          `json:"currency"`
			Minor    json.RawMessage `json:"minor"`
		}
		if err := strictjson.Decode(raw, &m); err != nil {
			return nil, errors.New("must be {currency, minor}")
		}
		minor, err := parseInt(m.Minor)
		if err != nil || minor < 0 || !currency.MatchString(m.Currency) {
			return nil, errors.New("needs a three-letter currency and non-negative integer minor units")
		}
		return Money{Currency: m.Currency, Minor: minor}, nil
	}
	return nil, fmt.Errorf("unknown type %q", spec.Type)
}

// parseInt accepts only a JSON integer: no fraction, exponent or quotes.
func parseInt(raw json.RawMessage) (int64, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil || strings.ContainsAny(n.String(), ".eE") {
		return 0, errors.New("must be an integer")
	}
	return n.Int64()
}

// Canonical returns the arguments as JSON with sorted keys. The same
// arguments always give the same bytes.
func (a Args) Canonical() []byte {
	raw, _ := json.Marshal(a.values) // strings, int64 and Money always marshal
	return raw
}

// Money returns a money argument.
func (a Args) Money(name string) (Money, bool) {
	m, ok := a.values[name].(Money)
	return m, ok
}

// String returns a string, enum or resource argument.
func (a Args) String(name string) (string, bool) {
	s, ok := a.values[name].(string)
	return s, ok
}

// OperationDigest identifies one exact invocation: tool, version, schema
// and canonical arguments. Any change to them is a new operation that needs
// new authority (AGT-004, INV-004).
func OperationDigest(t Tool, a Args) string {
	h := sha256.New()
	fmt.Fprintf(h, "fga.operation/v1\n%s\n%d\n%s\n", t.ID, t.Version, t.SchemaDigest())
	h.Write(a.Canonical())
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Summarize renders the approval summary of an invocation as a neutral
// operation plan. Every field is derived from the registry and the
// canonical arguments; the agent's note is kept apart and marked unverified
// (APR-005). resources maps argument roles to the canonical resources they
// were resolved to.
func Summarize(t Tool, a Args, resources map[string]string, agentNote string) opplan.Summary {
	s := opplan.Summary{Operation: "tool:" + t.ID, OperationDigest: OperationDigest(t, a), Action: "invoke",
		Targets:     []opplan.Target{{Role: "tool", Type: "agent.tool", ID: t.ID, Version: strconv.Itoa(t.Version)}},
		Destination: t.Destination, Details: a.Canonical(), UnverifiedNote: agentNote,
		Changes: map[string]string{"endpoint": t.Endpoint.Method + " " + t.Endpoint.Path}}
	for _, role := range slices.Sorted(maps.Keys(resources)) {
		s.Targets = append(s.Targets, opplan.Target{Role: role, ID: resources[role]})
	}
	return s
}

// Destination is a registered downstream service. The connector reaches it
// only at BaseURL, only at addresses inside AllowedCIDRs, and with the
// credential read from CredentialFile, never one supplied by an agent
// (AGT-005, AGT-006).
type Destination struct {
	ID             string
	BaseURL        string
	AllowedCIDRs   []netip.Prefix
	CredentialFile string
	// ReconcilePath, when set, lets the connector ask the destination for the
	// outcome of an idempotency key (INV-003). It contains "{key}".
	ReconcilePath string
}
