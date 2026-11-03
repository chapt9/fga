// Package sources is the record of a source of JSON readings,
// fga.source/v1 (docs/design/mcp-data-tools.md, ING-001 to ING-011): its
// owner, how a reading's key is derived, and its field groups with their
// labels and, in client mode, their recipients. fga-admin checks a record
// before it stores a version and again before it is reviewed; the storage
// role reads the active version for every reading. Versions are numbered
// by the catalog, so a record carries none. It does no I/O.
package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"fga/internal/jsonunits"
	"fga/internal/labels"
	"fga/internal/strictjson"
)

// Format names the record.
const Format = "fga.source/v1"

// MaxRecipients bounds the recipients of one group in client mode.
const MaxRecipients = 16

// ErrInvalid marks a record the rules refuse.
var ErrInvalid = errors.New("sources: invalid source record")

var id = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ValidID reports whether s is a source ID: 1 to 40 lower-case letters,
// digits and dashes, starting with a letter or digit.
func ValidID(s string) bool { return id.MatchString(s) }

// Definition is a source record as submitted and stored.
type Definition struct {
	Format string `json:"format"`
	ID     string `json:"id"`
	// Owner becomes the owner attribute of the readings' documents,
	// versions and units (D-C).
	Owner      string        `json:"owner"`
	Key        jsonunits.Key `json:"key"`
	Groups     []Group       `json:"groups"`
	Unlisted   string        `json:"unlisted,omitempty"`
	MaxPayload int           `json:"max_payload,omitempty"`
}

// Group is a field group: its unit's label and, in client mode, the
// identities whose recipient keys get an envelope for it (ING-011).
type Group struct {
	Name       string   `json:"name"`
	Label      string   `json:"label"`
	Fields     []string `json:"fields"`
	Recipients []string `json:"recipients,omitempty"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parse reads a record strictly: no unknown or duplicate members.
func Parse(b []byte) (Definition, error) {
	var d Definition
	if err := strictjson.Decode(b, &d); err != nil {
		return Definition{}, invalid("%v", err)
	}
	return d, nil
}

// Layout is the record's part for the profile.
func (d Definition) Layout() jsonunits.Layout {
	l := jsonunits.Layout{Key: d.Key, Unlisted: d.Unlisted, MaxPayload: d.MaxPayload}
	for _, g := range d.Groups {
		l.Groups = append(l.Groups, jsonunits.Group{Name: g.Name, Fields: g.Fields})
	}
	return l
}

// Check applies the record's own rules for a bucket in encryption mode:
// the format, the ID, an owner, a layout the profile accepts, a label for
// every group, and recipients in client mode only, 1 to MaxRecipients
// distinct ones per group. Identities and labels are checked against the
// catalog by the caller (CheckLabels).
func (d Definition) Check(mode string) error {
	switch {
	case d.Format != Format:
		return invalid("format %q, want %q", d.Format, Format)
	case !ValidID(d.ID):
		return invalid("source ID %q: 1 to 40 lower-case letters, digits and dashes", d.ID)
	case d.Owner == "":
		return invalid("a source names its owner")
	case mode != "server" && mode != "client":
		return invalid("encryption mode %q", mode)
	}
	if err := d.Layout().Validate(); err != nil {
		return invalid("%v", err)
	}
	for _, g := range d.Groups {
		if g.Label == "" {
			return invalid("group %q has no label", g.Name)
		}
		switch {
		case mode == "server" && len(g.Recipients) > 0:
			return invalid("group %q names recipients, which only a client-mode source has", g.Name)
		case mode == "client" && (len(g.Recipients) == 0 || len(g.Recipients) > MaxRecipients):
			return invalid("group %q of a client-mode source needs 1 to %d recipients", g.Name, MaxRecipients)
		}
		if sorted := slices.Sorted(slices.Values(g.Recipients)); len(slices.Compact(sorted)) != len(g.Recipients) {
			return invalid("group %q names a recipient twice", g.Name)
		}
	}
	return nil
}

// Identities are the owner and every recipient, each once, which must be
// known and enabled identities of the tenant.
func (d Definition) Identities() []string {
	out := []string{d.Owner}
	for _, g := range d.Groups {
		for _, r := range g.Recipients {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out
}

// CheckLabels checks that every group's label is in the active label
// order and at least floor, the bucket's default label (ING-006).
func (d Definition) CheckLabels(order []string, floor string) error {
	floorRank, known := labels.Rank(order, floor)
	if !known {
		return invalid("the bucket's label %q is not in the label order", floor)
	}
	for _, g := range d.Groups {
		rank, known := labels.Rank(order, g.Label)
		switch {
		case !known:
			return invalid("group %q: label %q is not in the label order", g.Name, g.Label)
		case rank < floorRank:
			return invalid("group %q: label %q is below the bucket's label %q", g.Name, g.Label, floor)
		}
	}
	return nil
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
	return raw, Digest(raw), nil
}

// Digest is the digest of stored record bytes.
func Digest(stored []byte) string {
	h := sha256.New()
	h.Write([]byte(Format))
	h.Write([]byte{0})
	h.Write(stored)
	return hex.EncodeToString(h.Sum(nil))
}
