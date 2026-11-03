package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"fga/internal/catalog"
	"fga/internal/registry"
	"fga/internal/sources"
)

// Readings of sources (docs/design/mcp-data-tools.md, ING-002 to ING-007):
// a system posts a JSON reading to a source; the storage role splits it
// under the source's active version, profile fga.json/groups-v1, and
// publishes it as a new version of the document at the reading's key in
// the source's bucket, one unit per field group. The poster names no
// bucket, key, label, owner or group: they come from the source version.

// readingSpec is what a source's active version gives a reading's begin:
// the source, the version, the owner of the readings, and per unit its
// group and label.
type readingSpec struct {
	source  string
	version int
	owner   string
	groups  []string
	labels  []string
}

// digest binds a reading's begin to its source version, so an idempotency
// key reused under another version is refused.
func (r *readingSpec) digest(begin string) string {
	return fmt.Sprintf("%s reading %q %d %q %q", begin, r.source, r.version, strings.Join(r.groups, ","), strings.Join(r.labels, ","))
}

// ReadingRequest names a reading's source and idempotency key.
type ReadingRequest struct {
	Source, IdempotencyKey string
}

// ReadingPublished is a published reading.
type ReadingPublished struct {
	DocumentPublished
	Key string `json:"key"`
}

// PutReading publishes a server-mode reading of r.Source. The document's
// checks are those of any server-mode document (create-object on the
// bucket for a new key, new-version on the document otherwise). A retry
// under the same idempotency key returns that attempt's outcome, as for
// text; a retry whose reading has another key is refused.
func (s *Service) PutReading(ctx context.Context, c Caller, r ReadingRequest, payload []byte) (ReadingPublished, error) {
	if s.d.DataKeys == nil {
		return ReadingPublished{}, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	src, def, err := s.activeSource(ctx, c.Tenant, r.Source)
	if err != nil {
		return ReadingPublished{}, err
	}
	splitter, err := def.Layout().Compile()
	if err != nil {
		return ReadingPublished{}, fmt.Errorf("%w: the source's active version: %v", ErrUnavailable, err)
	}
	reading, err := splitter.Split(payload, c.Principal)
	if err != nil {
		// The profile's reasons name fields, never values.
		return ReadingPublished{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !ValidKey(reading.Key) {
		return ReadingPublished{}, fmt.Errorf("%w: the reading's key is not a valid key", ErrInvalid)
	}
	spec := &readingSpec{source: src.ID, version: src.Active.Version, owner: def.Owner}
	units := make([]string, len(reading.Units))
	for i, g := range def.Groups {
		spec.groups, spec.labels = append(spec.groups, g.Name), append(spec.labels, g.Label)
		units[i] = string(reading.Units[i])
	}
	begin := DocumentBeginRequest{Bucket: src.Bucket, Key: reading.Key, IdempotencyKey: r.IdempotencyKey, Units: make([]DocumentUnitSpec, len(units))}
	in, err := s.docIntentByIdempotency(ctx, c, r.IdempotencyKey)
	switch {
	case err == nil:
		// A retry: the attempt it names, if it began this reading's key in
		// this source under the same version.
		if in.encryption != "server" {
			return ReadingPublished{}, ErrEncryptionMode
		}
		if in.requestDigest != spec.digest(begin.digest()) {
			return ReadingPublished{}, fmt.Errorf("%w: the idempotency key was used for another reading", ErrConflict)
		}
		if in.state == "COMMITTED" {
			// The poster may not read its readings, so a retry is
			// answered while the same post would still be allowed (ruling
			// 7), as a begin's retry is, rather than by discover.
			op, ch := docChecks(in, registry.OpDocBeginCreate, registry.OpDocBeginVersion)
			_, rec, err := s.decide(ctx, c, op, Audience, false, []check{ch})
			if err != nil {
				return ReadingPublished{}, err
			}
			if err := s.checked(ctx, rec); err != nil {
				return ReadingPublished{}, err
			}
			var p DocumentPublished
			if err := json.Unmarshal(in.result, &p); err != nil {
				return ReadingPublished{}, fmt.Errorf("%w: stored result", ErrUnavailable)
			}
			return ReadingPublished{DocumentPublished: p, Key: in.key}, nil
		}
	case !errors.Is(err, ErrNotFound):
		return ReadingPublished{}, err
	default:
		// The mode is checked after the decision, in the begin (ENC-002).
		if in, err = s.beginDocument(ctx, c, begin, "server", spec); err != nil {
			return ReadingPublished{}, err
		}
	}
	p, err := s.stageAndFinalize(ctx, c, in, units, nil)
	return ReadingPublished{DocumentPublished: p, Key: reading.Key}, err
}

// activeSource returns an enabled source with an active version and that
// version's record. Any other source is not found.
func (s *Service) activeSource(ctx context.Context, tenant, id string) (catalog.Source, sources.Definition, error) {
	if !sources.ValidID(id) {
		return catalog.Source{}, sources.Definition{}, ErrNotFound
	}
	src, err := s.d.Catalog.Source(ctx, tenant, id)
	if errors.Is(err, catalog.ErrNoRow) || err == nil && (src.Disabled || src.Active == nil) {
		return catalog.Source{}, sources.Definition{}, ErrNotFound
	}
	if err != nil {
		return catalog.Source{}, sources.Definition{}, err
	}
	def, err := sources.Parse(src.Active.Definition)
	if err != nil || def.ID != id || len(def.Groups) == 0 {
		return catalog.Source{}, sources.Definition{}, fmt.Errorf("%w: the source's active version cannot be read", ErrUnavailable)
	}
	return src, def, nil
}
