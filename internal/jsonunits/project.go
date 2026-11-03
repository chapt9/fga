package jsonunits

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// A data tool views readings through a projection (docs/design/mcp-data-tools.md,
// DTL-005, DTL-009): each output is one field of one group, renamed and of
// a declared type. The storage role projects server-mode readings, and a
// reader's own client the client-mode units it opened, with this one
// function, so both modes answer alike.

// Output types; an empty Type is TypeAny.
const (
	TypeAny     = "any"
	TypeString  = "string"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeObject  = "object"
	TypeArray   = "array"
)

// What a projection does with a group the reader may not read.
const (
	// SkipReading leaves the reading out; it is the default.
	SkipReading = "skip_reading"
	// SkipFields leaves out that group's outputs, and the reading when no
	// group of its outputs is readable.
	SkipFields = "skip_fields"
)

// MaxOutputs bounds a projection's outputs.
const MaxOutputs = 32

var outputName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Output is one output: the value of Field in the unit of Group, named
// Name, kept only when it is of Type.
type Output struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Field string `json:"field"`
	Type  string `json:"type,omitempty"`
}

// Projection is a data tool's view of one reading.
type Projection struct {
	Outputs      []Output `json:"outputs"`
	OnUnreadable string   `json:"on_unreadable,omitempty"`
}

// Check checks the projection against a layout: 1 to MaxOutputs outputs
// with distinct names, each one field of one of the layout's groups and of
// a known type, and a known mode.
func (p Projection) Check(l Layout) error {
	if len(p.Outputs) == 0 || len(p.Outputs) > MaxOutputs {
		return layoutErr("a projection has 1 to %d outputs", MaxOutputs)
	}
	if p.OnUnreadable != "" && p.OnUnreadable != SkipReading && p.OnUnreadable != SkipFields {
		return layoutErr("on_unreadable %q: %q or %q", p.OnUnreadable, SkipReading, SkipFields)
	}
	names := map[string]bool{}
	for _, o := range p.Outputs {
		if !outputName.MatchString(o.Name) || names[o.Name] {
			return layoutErr("output name %q: distinct, lower-case letters, digits and underscores", o.Name)
		}
		names[o.Name] = true
		i := slices.IndexFunc(l.Groups, func(g Group) bool { return g.Name == o.Group })
		if i < 0 || !slices.Contains(l.Groups[i].Fields, o.Field) {
			return layoutErr("output %q: %q is not a field of a group %q", o.Name, o.Field, o.Group)
		}
		switch o.Type {
		case "", TypeAny, TypeString, TypeNumber, TypeBoolean, TypeObject, TypeArray:
		default:
			return layoutErr("output %q: type %q", o.Name, o.Type)
		}
	}
	return nil
}

// Groups returns the groups the outputs use, each once, in output order.
func (p Projection) Groups() []string {
	var out []string
	for _, o := range p.Outputs {
		if !slices.Contains(out, o.Group) {
			out = append(out, o.Group)
		}
	}
	return out
}

// Apply projects one reading. units holds, by group name, the units the
// reader may read; a group missing from units is unreadable. It returns
// the outputs and whether the reading is kept: under SkipReading only when
// every group the outputs use is readable, under SkipFields when one is.
// A field missing from its unit, or of another type than declared, is left
// out.
func (p Projection) Apply(units map[string][]byte) (map[string]json.RawMessage, bool, error) {
	fields := map[string]map[string]json.RawMessage{}
	for _, g := range p.Groups() {
		b, ok := units[g]
		if !ok {
			if p.OnUnreadable != SkipFields {
				return nil, false, nil
			}
			continue
		}
		group, f, err := ParseUnit(b)
		if err != nil {
			return nil, false, err
		}
		if group != g {
			return nil, false, fmt.Errorf("%w: the unit given for group %q is of group %q", ErrUnit, g, group)
		}
		fields[g] = f
	}
	if len(fields) == 0 {
		return nil, false, nil
	}
	out := map[string]json.RawMessage{}
	for _, o := range p.Outputs {
		if v, ok := fields[o.Group][o.Field]; ok && ofType(v, o.Type) {
			out[o.Name] = v
		}
	}
	return out, true, nil
}

// ofType reports whether a JSON value is of an output type.
func ofType(v json.RawMessage, typ string) bool {
	v = bytes.TrimLeft(v, " \t\r\n")
	if len(v) == 0 {
		return false
	}
	switch typ {
	case "", TypeAny:
		return true
	case TypeString:
		return v[0] == '"'
	case TypeObject:
		return v[0] == '{'
	case TypeArray:
		return v[0] == '['
	case TypeBoolean:
		return v[0] == 't' || v[0] == 'f'
	case TypeNumber:
		return v[0] == '-' || v[0] >= '0' && v[0] <= '9'
	}
	return false
}

// KeyFor returns the key of the readings whose key value is v, for a
// layout keyed by pointer or principal: the prefix and v, when v matches
// the key pattern. A data tool's string argument names a reading so
// (DTL-003).
func (s *Splitter) KeyFor(v string) (string, bool) {
	if s.pattern == nil || !s.pattern.MatchString(v) {
		return "", false
	}
	return s.layout.Key.Prefix + v, true
}

// HasKey reports whether the layout can give a reading the key k.
func (s *Splitter) HasKey(k string) bool {
	if s.layout.Key.Mode == KeyFixed {
		return k == s.layout.Key.Prefix
	}
	v, ok := strings.CutPrefix(k, s.layout.Key.Prefix)
	return ok && s.pattern.MatchString(v)
}
