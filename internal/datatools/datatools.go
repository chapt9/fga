// Package datatools is the record of a data tool, fga.data-tool/v1
// (docs/design/mcp-data-tools.md, DTL-001 to DTL-009): a reviewed view of
// one source's readings, which grants nothing. fga-admin checks a record
// before it stores a version and against the source's active version at
// review; the storage role checks that fit again at every call, resolves
// the call's arguments to one key of the source's bucket and projects
// what the caller may read. Versions are numbered by the catalog, so a
// record carries none. It does no I/O.
package datatools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"fga/internal/jsonunits"
	"fga/internal/registry"
	"fga/internal/sources"
	"fga/internal/strictjson"
)

// Format names the record.
const Format = "fga.data-tool/v1"

// Operations of a tool.
const (
	OpLatest  = "latest"
	OpHistory = "history"
)

// Argument types: the ones a key selection uses.
const (
	ArgEnum   = "enum"
	ArgString = "string"
)

// Bounds of a record and a call.
const (
	MaxArguments   = 8
	MaxDescription = 1000
	// MaxTitle bounds a tool's title.
	MaxTitle = 100
	// DefaultReadings and MaxReadings bound a history call's readings.
	DefaultReadings = 50
	MaxReadings     = 200
)

var (
	// ErrInvalid marks a record the rules refuse.
	ErrInvalid = errors.New("datatools: invalid data tool record")
	// ErrArguments marks a call's arguments the record refuses.
	ErrArguments = errors.New("datatools: invalid arguments")
)

// reserved are the arguments every history tool takes.
var reserved = []string{"since", "until", "limit"}

// ValidName reports whether s is a data tool name. Every built-in MCP tool
// name holds a dot, which no data tool name does (DTL-007, D-I).
func ValidName(s string) bool { return registry.IsDataToolName(s) }

// Definition is a data tool record as submitted and stored.
type Definition struct {
	Format string `json:"format"`
	Name   string `json:"name"`
	// Title is a short name for people, shown by MCP clients as the tool's
	// title (MCP Tool.title); optional, plain text of up to MaxTitle
	// characters.
	Title        string             `json:"title,omitempty"`
	Description  string             `json:"description"`
	Source       string             `json:"source"`
	Operation    string             `json:"operation"`
	Arguments    []Argument         `json:"arguments,omitempty"`
	Select       Select             `json:"select"`
	Outputs      []jsonunits.Output `json:"outputs"`
	OnUnreadable string             `json:"on_unreadable,omitempty"`
	History      *History           `json:"history,omitempty"`
}

// Argument is a declared argument; the key selection uses it.
type Argument struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Values      []string `json:"values,omitempty"`
}

// Select says how a call's key is chosen inside the source's bucket
// (DTL-003): one fixed key; an enum argument's value mapped to listed keys;
// or a string argument that the source's key pattern admits, after the
// key prefix. A tool never takes a bucket or a free key.
type Select struct {
	Fixed    string            `json:"fixed,omitempty"`
	Argument string            `json:"argument,omitempty"`
	Keys     map[string]string `json:"keys,omitempty"`
}

// History bounds a history tool.
type History struct {
	// MaxReadings bounds a call's readings; zero is DefaultReadings.
	MaxReadings int `json:"max_readings,omitempty"`
}

// Call is a call's resolved arguments.
type Call struct {
	Key string
	// Since and Until bound a history call's publication times; zero is
	// unbounded. Since is inclusive and Until exclusive.
	Since, Until time.Time
	Limit        int
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func badArgs(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrArguments, fmt.Sprintf(format, args...))
}

// Parse reads a record strictly: no unknown or duplicate members.
func Parse(b []byte) (Definition, error) {
	var d Definition
	if err := strictjson.Decode(b, &d); err != nil {
		return Definition{}, invalid("%v", err)
	}
	return d, nil
}

// plain reports whether s is plain text of 1 to MaxDescription characters.
func plain(s string) bool { return plainOf(s, MaxDescription) }

// plainOf reports whether s is plain text of 1 to max characters.
func plainOf(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n > 0 && n <= max &&
		!slices.ContainsFunc([]rune(s), func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}

// Check applies the record's own rules: the format, the name, a plain
// description, the source's ID, the operation, the arguments, one way to
// select the key, and bounds. Its fit to the source is Fit.
func (d Definition) Check() error {
	switch {
	case d.Format != Format:
		return invalid("format %q, want %q", d.Format, Format)
	case !ValidName(d.Name):
		return invalid("tool name %q: a lower-case letter, then up to 63 lower-case letters, digits and underscores", d.Name)
	case d.Title != "" && (!plainOf(d.Title, MaxTitle) || strings.ContainsAny(d.Title, "\n\t")):
		return invalid("the title is one line of plain text of at most %d characters", MaxTitle)
	case !plain(d.Description):
		return invalid("the description is plain text of 1 to %d characters", MaxDescription)
	case !sources.ValidID(d.Source):
		return invalid("source ID %q", d.Source)
	case d.Operation != OpLatest && d.Operation != OpHistory:
		return invalid("operation %q: %q or %q", d.Operation, OpLatest, OpHistory)
	case d.History != nil && (d.Operation != OpHistory || d.History.MaxReadings < 0 || d.History.MaxReadings > MaxReadings):
		return invalid("history bounds belong to a history tool, with max_readings of at most %d", MaxReadings)
	case len(d.Arguments) > MaxArguments:
		return invalid("at most %d arguments", MaxArguments)
	case len(d.Outputs) == 0 || len(d.Outputs) > jsonunits.MaxOutputs:
		return invalid("a tool has 1 to %d outputs", jsonunits.MaxOutputs)
	}
	for i, a := range d.Arguments {
		switch {
		case !ValidName(a.Name) || slices.Contains(reserved, a.Name) || slices.ContainsFunc(d.Arguments[:i], func(b Argument) bool { return b.Name == a.Name }):
			return invalid("argument name %q: distinct, of the tool name pattern, and none of %v", a.Name, reserved)
		case a.Description != "" && !plain(a.Description):
			return invalid("argument %q: the description is plain text of at most %d characters", a.Name, MaxDescription)
		case a.Name != d.Select.Argument:
			return invalid("argument %q is not the one the key selection uses", a.Name)
		case a.Type == ArgString && len(a.Values) == 0:
		case a.Type == ArgEnum && len(a.Values) > 0:
			if sorted := slices.Sorted(slices.Values(a.Values)); len(slices.Compact(sorted)) != len(a.Values) || slices.Contains(a.Values, "") {
				return invalid("argument %q: distinct, non-empty values", a.Name)
			}
		default:
			return invalid("argument %q: type %q with values, or %q", a.Name, ArgEnum, ArgString)
		}
	}
	arg := d.argument()
	switch s := d.Select; {
	case s.Fixed != "" && s.Argument == "" && s.Keys == nil:
	case s.Fixed == "" && arg != nil && arg.Type == ArgEnum && len(s.Keys) == len(arg.Values):
		for _, v := range arg.Values {
			if s.Keys[v] == "" {
				return invalid("select: value %q of argument %q has no key", v, arg.Name)
			}
		}
	case s.Fixed == "" && arg != nil && arg.Type == ArgString && s.Keys == nil:
	default:
		return invalid("select: one fixed key, an enum argument with a key for each value, or a string argument")
	}
	return nil
}

// argument returns the argument the key selection uses, if declared.
func (d Definition) argument() *Argument {
	for i := range d.Arguments {
		if d.Arguments[i].Name == d.Select.Argument {
			return &d.Arguments[i]
		}
	}
	return nil
}

// Projection is the tool's view of one reading.
func (d Definition) Projection() jsonunits.Projection {
	mode := d.OnUnreadable
	if mode == "" {
		mode = jsonunits.SkipReading
	}
	return jsonunits.Projection{Outputs: d.Outputs, OnUnreadable: mode}
}

// MaxReadings bounds a history call's readings.
func (d Definition) MaxReadings() int {
	if d.History == nil || d.History.MaxReadings == 0 {
		return DefaultReadings
	}
	return d.History.MaxReadings
}

// Fit checks the tool against a version of its source: every output one
// field of one of its groups, every listed key one the layout can give,
// and a string argument only for a layout keyed by pointer or principal.
// A tool that no longer fits its source's active version cannot be called
// until a new version is reviewed.
func (d Definition) Fit(src sources.Definition) error {
	if src.ID != d.Source {
		return invalid("the tool is over source %q, not %q", d.Source, src.ID)
	}
	l := src.Layout()
	if err := d.Projection().Check(l); err != nil {
		return invalid("%v", err)
	}
	splitter, err := l.Compile()
	if err != nil {
		return invalid("source %q: %v", src.ID, err)
	}
	keys := slices.Collect(maps.Values(d.Select.Keys))
	if d.Select.Fixed != "" {
		keys = append(keys, d.Select.Fixed)
	}
	for _, k := range keys {
		if !splitter.HasKey(k) {
			return invalid("select: %q is not a key of source %q", k, src.ID)
		}
	}
	if arg := d.argument(); arg != nil && arg.Type == ArgString && l.Key.Mode == jsonunits.KeyFixed {
		return invalid("select: a string argument needs a source keyed by pointer or principal")
	}
	return nil
}

// Resolve checks a call's arguments strictly, as one JSON object with no
// unknown member, and resolves them to a key of src's bucket and, for a
// history tool, the call's bounds (DTL-003). src is the version the tool
// fits.
func (d Definition) Resolve(src sources.Definition, raw json.RawMessage) (Call, error) {
	args := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := strictjson.Decode(raw, &args); err != nil || args == nil {
			return Call{}, badArgs("the arguments are one JSON object")
		}
	}
	for k := range args {
		if !slices.ContainsFunc(d.Arguments, func(a Argument) bool { return a.Name == k }) && (d.Operation != OpHistory || !slices.Contains(reserved, k)) {
			return Call{}, badArgs("unknown argument %q", k)
		}
	}
	c := Call{Key: d.Select.Fixed, Limit: d.MaxReadings()}
	if c.Key == "" {
		var v string
		if raw, ok := args[d.Select.Argument]; !ok || json.Unmarshal(raw, &v) != nil {
			return Call{}, badArgs("argument %q is a required string", d.Select.Argument)
		}
		ok := false
		if d.Select.Keys != nil {
			c.Key, ok = d.Select.Keys[v]
		} else if splitter, err := src.Layout().Compile(); err == nil {
			c.Key, ok = splitter.KeyFor(v)
		}
		if !ok {
			return Call{}, badArgs("argument %q: not a value the tool takes", d.Select.Argument)
		}
	}
	if d.Operation != OpHistory {
		return c, nil
	}
	for name, dst := range map[string]*time.Time{"since": &c.Since, "until": &c.Until} {
		raw, ok := args[name]
		if !ok {
			continue
		}
		var s string
		t, err := time.Time{}, json.Unmarshal(raw, &s)
		if err == nil {
			t, err = time.Parse(time.RFC3339, s)
		}
		if err != nil {
			return Call{}, badArgs("argument %q is an RFC 3339 time", name)
		}
		*dst = t
	}
	if !c.Since.IsZero() && !c.Until.IsZero() && !c.Since.Before(c.Until) {
		return Call{}, badArgs("since is before until")
	}
	if raw, ok := args["limit"]; ok {
		if err := json.Unmarshal(raw, &c.Limit); err != nil || c.Limit < 1 || c.Limit > d.MaxReadings() {
			return Call{}, badArgs("limit is an integer from 1 to %d", d.MaxReadings())
		}
	}
	return c, nil
}

// InputSchema is the JSON Schema of a call's arguments.
func (d Definition) InputSchema() json.RawMessage {
	props := map[string]any{}
	required := []string{}
	for _, a := range d.Arguments {
		p := map[string]any{"type": "string"}
		if a.Description != "" {
			p["description"] = a.Description
		}
		if a.Type == ArgEnum {
			p["enum"] = a.Values
		}
		props[a.Name], required = p, append(required, a.Name)
	}
	if d.Operation == OpHistory {
		props["since"] = map[string]any{"type": "string", "format": "date-time", "description": "Readings published at or after this time"}
		props["until"] = map[string]any{"type": "string", "format": "date-time",
			"description": "Readings published before this time; to page back, the oldest published_at returned"}
		props["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": d.MaxReadings()}
	}
	return mustJSON(map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false})
}

// OutputSchema is the JSON Schema of a call's answer once projected: the
// storage role's answer for a server-mode source, the reader's client's
// for a client-mode one.
func (d Definition) OutputSchema() json.RawMessage {
	props := map[string]any{}
	for _, o := range d.Outputs {
		props[o.Name] = map[string]any{}
		if o.Type != "" && o.Type != jsonunits.TypeAny {
			props[o.Name] = map[string]any{"type": o.Type}
		}
	}
	str := map[string]any{"type": "string"}
	reading := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	origin := map[string]any{"type": "object", "properties": map[string]any{"source": str, "document_version_id": str, "published_at": str, "label": str}}
	out := map[string]any{"type": "object", "properties": map[string]any{"tool": str, "version": map[string]any{"type": "integer"},
		"reading": reading, "origin": origin}, "required": []string{"tool", "version", "reading", "origin"}}
	if d.Operation == OpHistory {
		item := map[string]any{"type": "object", "properties": map[string]any{"reading": reading, "origin": origin}, "required": []string{"reading", "origin"}}
		out = map[string]any{"type": "object", "properties": map[string]any{"tool": str, "version": map[string]any{"type": "integer"},
			"readings": map[string]any{"type": "array", "items": item}}, "required": []string{"tool", "version", "readings"}}
	}
	return mustJSON(out)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // maps of strings and numbers always encode
	}
	return b
}

// Canonical returns the record as the catalog stores it and its digest:
// SHA-256 of Format, a zero byte and the stored bytes, in lower-case hex.
// A review names the digest, so it activates exactly the version its
// reviewer saw.
func (d Definition) Canonical() ([]byte, string, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	h := sha256.New()
	h.Write([]byte(Format))
	h.Write([]byte{0})
	h.Write(raw)
	return raw, hex.EncodeToString(h.Sum(nil)), nil
}
