package cryptowire

import (
	"encoding/json"
	"time"

	"fga/internal/strictjson"
)

// Signed lineage of a derived output (DRV-001): the exact sources its
// computation received, declared and signed by the uploading client.

// TypeLineage is the JWS type of a signed lineage.
const TypeLineage = "fga-lineage+jws"

// Lineage format and bounds.
const (
	LineageVersion    = "fga.lineage/v1"
	MaxLineageSources = 1000
	MaxLineageBytes   = 256 << 10
)

// Lineage source types.
const (
	SourceObject  = "storage.object"
	SourceUnit    = "document.text_unit"
	SourceDerived = "document.derived"
)

// LineageSource is one input at an exact version.
type LineageSource struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Lineage names a derived output's version and its direct sources.
type Lineage struct {
	Version   string          `json:"version"`
	TenantID  string          `json:"tenant_id"`
	ObjectID  string          `json:"object_id"`
	VersionID string          `json:"version_id"`
	Sources   []LineageSource `json:"sources"`
	Signer    string          `json:"signer"`
	CreatedAt time.Time       `json:"created_at"`
}

// Marshal encodes l once for signing.
func (l Lineage) Marshal() ([]byte, error) {
	l.Version = LineageVersion
	l.CreatedAt = l.CreatedAt.UTC().Truncate(time.Second)
	b, err := json.Marshal(l)
	if err != nil {
		return nil, formatErr("lineage")
	}
	if _, err := ParseLineage(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseLineage parses strictly: known source types, UUID identifiers,
// distinct sources, between 1 and MaxLineageSources of them.
func ParseLineage(b []byte) (Lineage, error) {
	var l Lineage
	if len(b) > MaxLineageBytes {
		return l, formatErr("lineage size")
	}
	if err := strictjson.Decode(b, &l); err != nil {
		return l, formatErr("lineage: %v", err)
	}
	if l.Version != LineageVersion || len(l.Sources) == 0 || len(l.Sources) > MaxLineageSources || l.CreatedAt.IsZero() {
		return l, formatErr("lineage version, sources or time")
	}
	if err := uuids(l.TenantID, l.ObjectID, l.VersionID); err != nil {
		return l, err
	}
	if _, err := ParseDigest(l.Signer); err != nil {
		return l, err
	}
	seen := map[LineageSource]bool{}
	for _, s := range l.Sources {
		if s.Type != SourceObject && s.Type != SourceUnit && s.Type != SourceDerived || seen[s] {
			return l, formatErr("lineage source")
		}
		if err := uuids(s.ID, s.Version); err != nil {
			return l, err
		}
		seen[s] = true
	}
	return l, nil
}
