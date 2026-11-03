// Package jsonunits is the ingestion profile fga.json/groups-v1 for JSON
// readings (docs/design/mcp-data-tools.md, ING-004, ING-005, ING-010): it
// derives a reading's key and splits the reading into one unit per field
// group of a source's layout. The storage role applies it to readings
// posted in server mode; in client mode the posting client applies it
// before encrypting. The vectors in testdata fix its bytes for every
// implementation. It holds no cryptography and does no I/O.
package jsonunits

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"fga/internal/strictjson"
)

// Profile names the profile; a reading's manifest records it as its
// normalization version.
const Profile = "fga.json/groups-v1"

// Bounds of the profile.
const (
	// DefaultMaxPayload applies to a layout that sets no MaxPayload.
	DefaultMaxPayload = 64 << 10
	// MaxPayloadLimit is the largest MaxPayload, the native API's JSON
	// body bound.
	MaxPayloadLimit = 1 << 20
	// MaxDepth bounds the nesting of objects and arrays; the reading's
	// own object is depth 1.
	MaxDepth = 32
	// MaxGroups bounds the groups of a layout.
	MaxGroups = 16
	// MaxFields bounds the pointers of one group.
	MaxFields = 64

	maxPointer = 512
	maxPattern = 256
	// maxShown bounds a pointer quoted in a refusal.
	maxShown = 256
)

// Key modes.
const (
	// KeyPointer takes the key from a string member of the reading.
	KeyPointer = "pointer"
	// KeyPrincipal takes the key from the posting principal's ID.
	KeyPrincipal = "principal"
	// KeyFixed gives every reading the same key.
	KeyFixed = "fixed"
)

// What happens to a member that no field covers.
const (
	// Refuse refuses the reading; it is the default.
	Refuse = "refuse"
	// Drop discards the member.
	Drop = "drop"
)

var (
	// ErrLayout is returned for a layout the profile refuses.
	ErrLayout = errors.New("jsonunits: invalid layout")
	// ErrReading matches every *ReadingError.
	ErrReading = errors.New("jsonunits: reading refused")
	// ErrUnit is returned by ParseUnit for bytes that are not a unit.
	ErrUnit = errors.New("jsonunits: not a unit of " + Profile)
)

// Layout is the profile's part of a source version.
type Layout struct {
	Key    Key     `json:"key"`
	Groups []Group `json:"groups"`
	// Unlisted is Refuse, also when empty, or Drop.
	Unlisted string `json:"unlisted,omitempty"`
	// MaxPayload bounds a reading in bytes; zero is DefaultMaxPayload.
	MaxPayload int `json:"max_payload,omitempty"`
}

// Key says how a reading's key is derived.
type Key struct {
	// Mode is KeyPointer, KeyPrincipal or KeyFixed.
	Mode string `json:"mode"`
	// Pointer names the string member that gives the key (KeyPointer).
	Pointer string `json:"pointer,omitempty"`
	// Pattern must match the whole value: the member's string
	// (KeyPointer) or the principal's ID (KeyPrincipal).
	Pattern string `json:"pattern,omitempty"`
	// Prefix comes before the value; with KeyFixed it is the key.
	Prefix string `json:"prefix,omitempty"`
}

// Group is a named set of fields: RFC 6901 pointers whose values form one
// unit.
type Group struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// Reading is a split reading.
type Reading struct {
	// Key is the document key the reading is published at. The caller
	// still checks it as a key of its store.
	Key string
	// Units holds one unit per group, in layout order.
	Units [][]byte
	// Fields holds, per unit, the fields present in it, sorted: names
	// without values, which a client-mode publication declares in clear
	// (ING-010).
	Fields [][]string
}

// Splitter is a compiled layout.
type Splitter struct {
	layout  Layout
	root    *node
	keyPath []string
	pattern *regexp.Regexp
	max     int
	drop    bool
}

// node is one step of the layout's field tree.
type node struct {
	group    int    // the group whose field ends here, or -1
	pointer  string // that field
	key      bool   // the key pointer ends here
	children map[string]*node
}

func newNode() *node { return &node{group: -1, children: map[string]*node{}} }

// ReadingError is a refused reading. Its message names at most the pointer
// of the member concerned, never a value.
type ReadingError struct {
	Reason  string
	Pointer string
	cause   error
}

func (e *ReadingError) Error() string {
	if e.Pointer == "" {
		return "jsonunits: reading refused: " + e.Reason
	}
	p := e.Pointer
	if len(p) > maxShown {
		p = strings.ToValidUTF8(p[:maxShown], "") + "…"
	}
	return fmt.Sprintf("jsonunits: reading refused: %s: %q", e.Reason, p)
}

// Is makes every ReadingError match ErrReading.
func (e *ReadingError) Is(target error) bool { return target == ErrReading }

// Unwrap returns the JSON parser's own error, which may quote the reading:
// it is for an administrator trying a sample, never for the answer to a
// posting client.
func (e *ReadingError) Unwrap() error { return e.cause }

func refuse(reason, pointer string, cause error) error {
	return &ReadingError{Reason: reason, Pointer: pointer, cause: cause}
}

func layoutErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrLayout}, args...)...)
}

var groupName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Validate reports whether the layout is one the profile accepts.
func (l Layout) Validate() error {
	_, err := l.Compile()
	return err
}

// Compile checks the layout and prepares it for Split.
func (l Layout) Compile() (*Splitter, error) {
	s := &Splitter{layout: l, root: newNode(), max: l.MaxPayload}
	// The splitter keeps its own copy, so a caller's later change to the
	// layout cannot rename its groups.
	s.layout.Groups = slices.Clone(l.Groups)
	if s.max == 0 {
		s.max = DefaultMaxPayload
	}
	if s.max < 0 || s.max > MaxPayloadLimit {
		return nil, layoutErr("max_payload must be between 1 and %d", MaxPayloadLimit)
	}
	switch l.Unlisted {
	case "", Refuse:
	case Drop:
		s.drop = true
	default:
		return nil, layoutErr("unlisted must be %q or %q", Refuse, Drop)
	}
	if len(l.Groups) == 0 || len(l.Groups) > MaxGroups {
		return nil, layoutErr("a layout has 1 to %d groups", MaxGroups)
	}
	names := map[string]bool{}
	for i, g := range l.Groups {
		if !groupName.MatchString(g.Name) || names[g.Name] {
			return nil, layoutErr("invalid or duplicate group name %q", g.Name)
		}
		names[g.Name] = true
		if len(g.Fields) == 0 || len(g.Fields) > MaxFields {
			return nil, layoutErr("group %q needs 1 to %d fields", g.Name, MaxFields)
		}
		for _, p := range g.Fields {
			path, err := parsePointer(p)
			if err != nil {
				return nil, err
			}
			if err := s.root.addField(path, i, p); err != nil {
				return nil, err
			}
		}
	}
	if err := s.compileKey(l.Key); err != nil {
		return nil, err
	}
	return s, nil
}

// addField adds a group's field to the tree. Fields never overlap: no
// field is another one, or lies inside another one, in any group, so each
// value lands in exactly one unit.
func (n *node) addField(path []string, group int, pointer string) error {
	for _, t := range path {
		c := n.children[t]
		if c == nil {
			c = newNode()
			n.children[t] = c
		} else if c.group >= 0 {
			return layoutErr("fields %q and %q overlap", c.pointer, pointer)
		}
		n = c
	}
	if n.group >= 0 || len(n.children) > 0 {
		return layoutErr("field %q overlaps another field", pointer)
	}
	n.group, n.pointer = group, pointer
	return nil
}

func (s *Splitter) compileKey(k Key) error {
	if !utf8.ValidString(k.Prefix) {
		return layoutErr("the key prefix is not valid UTF-8")
	}
	switch k.Mode {
	case KeyPointer:
		path, err := parsePointer(k.Pointer)
		if err != nil {
			return err
		}
		if err := s.compilePattern(k.Pattern); err != nil {
			return err
		}
		// The key's member may lie inside a field, which then holds it
		// too; no field may lie below it, since its value is a string.
		n := s.root
		for _, t := range path {
			c := n.children[t]
			if c == nil {
				c = newNode()
				n.children[t] = c
			}
			n = c
		}
		if len(n.children) > 0 {
			return layoutErr("a field lies below the key pointer %q", k.Pointer)
		}
		n.key, s.keyPath = true, path
	case KeyPrincipal:
		if k.Pointer != "" {
			return layoutErr("a principal key takes no pointer")
		}
		return s.compilePattern(k.Pattern)
	case KeyFixed:
		if k.Pointer != "" || k.Pattern != "" || k.Prefix == "" {
			return layoutErr("a fixed key is a prefix alone")
		}
	default:
		return layoutErr("key mode %q: one of %q, %q and %q", k.Mode, KeyPointer, KeyPrincipal, KeyFixed)
	}
	return nil
}

// compilePattern compiles a key pattern to match whole values. The pattern
// must compile on its own first, so that it cannot close the group it is
// wrapped in.
func (s *Splitter) compilePattern(p string) error {
	if p == "" || len(p) > maxPattern {
		return layoutErr("the key needs a pattern of 1 to %d bytes", maxPattern)
	}
	if _, err := regexp.Compile(p); err != nil {
		return layoutErr("key pattern: %v", err)
	}
	re, err := regexp.Compile(`^(?:` + p + `)$`)
	if err != nil {
		return layoutErr("key pattern: %v", err)
	}
	s.pattern = re
	return nil
}

// parsePointer returns the reference tokens of an RFC 6901 pointer. Every
// token is non-empty and escapes only "~" (as ~0) and "/" (as ~1), so a
// path has exactly one spelling.
func parsePointer(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") || len(p) > maxPointer || !utf8.ValidString(p) {
		return nil, layoutErr("pointer %q: a / and tokens, at most %d bytes of UTF-8", p, maxPointer)
	}
	var path []string
	for _, raw := range strings.Split(p[1:], "/") {
		t, ok := unescapeToken(raw)
		if !ok || t == "" {
			return nil, layoutErr("pointer %q: every token is non-empty and escapes only ~0 and ~1", p)
		}
		path = append(path, t)
	}
	if len(path) > MaxDepth {
		return nil, layoutErr("pointer %q has more than %d tokens", p, MaxDepth)
	}
	return path, nil
}

func unescapeToken(raw string) (string, bool) {
	if !strings.Contains(raw, "~") {
		return raw, true
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '~' {
			b.WriteByte(raw[i])
			continue
		}
		if i+1 == len(raw) {
			return "", false
		}
		switch raw[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", false
		}
		i++
	}
	return b.String(), true
}

func escapeToken(t string) string {
	return strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1")
}

// Split derives the key of a reading that principal posted and splits the
// reading into one unit per group. The reading is UTF-8 JSON holding one
// object, at most the layout's MaxPayload bytes and MaxDepth deep, with no
// duplicate member names and nothing after it. Numbers keep their literal
// text; an escaped lone surrogate becomes U+FFFD, as encoding/json decodes
// it.
func (s *Splitter) Split(payload []byte, principal string) (Reading, error) {
	if len(payload) > s.max {
		return Reading{}, refuse(fmt.Sprintf("larger than %d bytes", s.max), "", nil)
	}
	if !utf8.Valid(payload) {
		return Reading{}, refuse("not valid UTF-8", "", nil)
	}
	// Depth is bounded before parsing, so deep input never reaches the
	// parsers' recursion.
	if !shallow(payload) {
		return Reading{}, refuse(fmt.Sprintf("nested deeper than %d", MaxDepth), "", nil)
	}
	var raw json.RawMessage
	if err := strictjson.Decode(payload, &raw); err != nil {
		return Reading{}, refuse("not strict JSON: a syntax error, a duplicate member name or trailing data", "", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return Reading{}, refuse("not strict JSON", "", err)
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return Reading{}, refuse("a reading is one JSON object", "", nil)
	}
	key, err := s.key(root, principal)
	if err != nil {
		return Reading{}, err
	}
	fields := make([]map[string]any, len(s.layout.Groups))
	for i := range fields {
		fields[i] = map[string]any{}
	}
	if err := s.walk(root, s.root, "", fields); err != nil {
		return Reading{}, err
	}
	r := Reading{Key: key}
	for i, g := range s.layout.Groups {
		unit, present := encodeUnit(g.Name, fields[i])
		r.Units = append(r.Units, unit)
		r.Fields = append(r.Fields, present)
	}
	return r, nil
}

// shallow reports whether JSON text nests objects and arrays at most
// MaxDepth deep, skipping strings and their escapes. For valid JSON it
// counts what a parser would.
func shallow(b []byte) bool {
	depth, inString, escaped := 0, false, false
	for _, c := range b {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			if depth++; depth > MaxDepth {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

func (s *Splitter) key(root map[string]any, principal string) (string, error) {
	k := s.layout.Key
	switch k.Mode {
	case KeyFixed:
		return k.Prefix, nil
	case KeyPrincipal:
		if principal == "" || !s.pattern.MatchString(principal) {
			return "", refuse("the posting principal does not match the key pattern", "", nil)
		}
		return k.Prefix + principal, nil
	}
	v, ok := lookup(root, s.keyPath)
	str, isString := v.(string)
	if !ok || !isString {
		return "", refuse("the key member is missing or not a string", k.Pointer, nil)
	}
	if !s.pattern.MatchString(str) {
		return "", refuse("the key member does not match the key pattern", k.Pointer, nil)
	}
	return k.Prefix + str, nil
}

func lookup(v any, path []string) (any, bool) {
	for _, t := range path {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = obj[t]; !ok {
			return nil, false
		}
	}
	return v, true
}

// walk puts each member of obj, found at pointer at, into the group whose
// field covers it. A member is covered by a field that names it or one of
// its ancestors, or by the key pointer when it names it. Members are taken
// in name order, so the member a refusal names does not depend on map
// order.
func (s *Splitter) walk(obj map[string]any, n *node, at string, fields []map[string]any) error {
	for _, name := range slices.Sorted(maps.Keys(obj)) {
		v := obj[name]
		p := at + "/" + escapeToken(name)
		c := n.children[name]
		switch {
		case c == nil:
		case c.group >= 0:
			fields[c.group][c.pointer] = v
			continue
		case len(c.children) == 0:
			// Only the key's own member ends a path without a field; key
			// checked that it is a string.
			continue
		default:
			if inner, ok := v.(map[string]any); ok {
				if err := s.walk(inner, c, p, fields); err != nil {
					return err
				}
				continue
			}
		}
		if !s.drop {
			return refuse("a member is in no group", p, nil)
		}
	}
	return nil
}

// encodeUnit returns a group's unit and the fields present in it. A unit is
// {"group":<name>,"fields":{<field>:<value>,...}} with fields sorted by
// their bytes and no insignificant whitespace.
func encodeUnit(group string, fields map[string]any) ([]byte, []string) {
	present := append(make([]string, 0, len(fields)), slices.Sorted(maps.Keys(fields))...)
	b := appendString([]byte(`{"group":`), group)
	b = append(b, `,"fields":{`...)
	for i, p := range present {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(appendString(b, p), ':')
		b = appendValue(b, fields[p])
	}
	return append(b, "}}"...), present
}

// appendValue appends a value in the profile's canonical form: object
// members sorted by the bytes of their names, numbers as received.
func appendValue(b []byte, v any) []byte {
	switch v := v.(type) {
	case nil:
		return append(b, "null"...)
	case bool:
		if v {
			return append(b, "true"...)
		}
		return append(b, "false"...)
	case json.Number:
		return append(b, v...)
	case string:
		return appendString(b, v)
	case []any:
		b = append(b, '[')
		for i, e := range v {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValue(b, e)
		}
		return append(b, ']')
	case map[string]any:
		b = append(b, '{')
		for i, k := range slices.Sorted(maps.Keys(v)) {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(appendString(b, k), ':')
			b = appendValue(b, v[k])
		}
		return append(b, '}')
	}
	// Decoding with UseNumber yields only the types above.
	panic(fmt.Sprintf("jsonunits: unexpected JSON value of type %T", v))
}

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string: '"' and '\' escaped with a
// backslash; \b, \f, \n, \r and \t for those controls; \u00xx in lower
// case for the other controls; every other character as its UTF-8 bytes.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// ParseUnit reads a unit: its group and each field's value as JSON text.
// It reads what any implementation of the profile wrote and does not
// require the canonical form.
func ParseUnit(b []byte) (string, map[string]json.RawMessage, error) {
	var u struct {
		Group  string                     `json:"group"`
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := strictjson.Decode(b, &u); err != nil || !groupName.MatchString(u.Group) || u.Fields == nil {
		return "", nil, ErrUnit
	}
	for p := range u.Fields {
		if _, err := parsePointer(p); err != nil {
			return "", nil, ErrUnit
		}
	}
	return u.Group, u.Fields, nil
}
