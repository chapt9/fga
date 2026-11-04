package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/jsonunits"
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
	// Nothing of the layout is answered, not even that a payload does not
	// fit it, to a caller who may not post (CNT-004; security review of 4
	// November 2026, finding 1).
	if err := s.postGate(ctx, c, src); err != nil {
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
	spec := newReadingSpec(src, def)
	units := make([]string, len(reading.Units))
	for i := range def.Groups {
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

// newReadingSpec is what src's active version, def, gives a reading.
func newReadingSpec(src catalog.Source, def sources.Definition) *readingSpec {
	spec := &readingSpec{source: src.ID, version: src.Active.Version, owner: def.Owner}
	for _, g := range def.Groups {
		spec.groups, spec.labels = append(spec.groups, g.Name), append(spec.labels, g.Label)
	}
	return spec
}

// extractionVersion is the manifest's extraction version of a reading: the
// source version it was split under.
func (in storedDocIntent) extractionVersion() string {
	src, _ := in.attributes["source"].(string)
	version, _ := in.attributes["source_version"].(float64)
	return fmt.Sprintf("%s:%s:%d", sources.Format, src, int(version))
}

// SourceLayout is a source's active version as a posting client needs it
// (ING-010, ING-011): its record, and per group the active recipient keys
// of the recipients the group names.
type SourceLayout struct {
	Source     string           `json:"source"`
	Version    int              `json:"version"`
	Digest     string           `json:"digest"`
	Encryption string           `json:"encryption"`
	Definition json.RawMessage  `json:"definition"`
	Recipients [][]RecipientKey `json:"recipients"`
}

// RecipientKey is a recipient's active key, by fingerprint. The server is
// no trust anchor: a client seals only for keys it pinned itself.
type RecipientKey struct {
	Principal   string `json:"principal"`
	Fingerprint string `json:"fingerprint"`
	KeyVersion  uint64 `json:"key_version"`
}

// SourceLayout answers the active version of r.Source to a caller allowed
// to post to it.
func (s *Service) SourceLayout(ctx context.Context, c Caller, source string) (SourceLayout, error) {
	src, def, err := s.activeSource(ctx, c.Tenant, source)
	if err != nil {
		return SourceLayout{}, err
	}
	if err := s.postGate(ctx, c, src); err != nil {
		return SourceLayout{}, err
	}
	keys, err := s.recipientKeys(ctx, c.Tenant, def)
	if err != nil {
		return SourceLayout{}, err
	}
	return SourceLayout{Source: src.ID, Version: src.Active.Version, Digest: src.Active.Digest, Encryption: src.Encryption,
		Definition: src.Active.Definition, Recipients: keys}, nil
}

// ReadingBeginRequest begins a client-mode reading (ING-010): the source
// version the client split it under, its key, and per group the fields
// present, in clear; the values stay encrypted.
type ReadingBeginRequest struct {
	Source, Key, IdempotencyKey string
	SourceVersion               int
	Fields                      [][]string
}

// BeginReading begins a client-mode reading of r.Source as a document
// version with one unit per group, whose units the client then encrypts,
// stages and finalizes as for any client-mode document. The declaration
// must follow the active version, which must be the one the client used.
func (s *Service) BeginReading(ctx context.Context, c Caller, r ReadingBeginRequest) (DocumentIntent, error) {
	src, def, err := s.activeSource(ctx, c.Tenant, r.Source)
	if err != nil {
		return DocumentIntent{}, err
	}
	if err := s.postGate(ctx, c, src); err != nil {
		return DocumentIntent{}, err
	}
	if r.SourceVersion != src.Active.Version {
		return DocumentIntent{}, fmt.Errorf("%w: the source's active version is %d; read its layout again", ErrConflict, src.Active.Version)
	}
	splitter, err := def.Layout().Compile()
	if err != nil {
		return DocumentIntent{}, fmt.Errorf("%w: the source's active version: %v", ErrUnavailable, err)
	}
	if err := splitter.CheckDeclared(r.Key, c.Principal, r.Fields); err != nil || !ValidKey(r.Key) {
		return DocumentIntent{}, errors.Join(ErrInvalid, err)
	}
	// The mode is checked after the begin's decision (ENC-002).
	in, err := s.beginDocument(ctx, c, DocumentBeginRequest{Bucket: src.Bucket, Key: r.Key, IdempotencyKey: r.IdempotencyKey,
		Units: make([]DocumentUnitSpec, len(def.Groups))}, "client", newReadingSpec(src, def))
	return in.DocumentIntent, err
}

// postGate decides post-reading on src's bucket before anything of the
// source's version is answered.
func (s *Service) postGate(ctx context.Context, c Caller, src catalog.Source) error {
	_, rec, err := s.decide(ctx, c, registry.OpReadingLayout, Audience, false,
		[]check{{id: "bucket", role: registry.RoleBucket, action: "post-reading", ref: canonical("storage.bucket", src.BucketID)}})
	if err != nil {
		return err
	}
	return s.checked(ctx, rec)
}

// recipientKeys returns per group of def the active recipient keys of the
// recipients the group names.
func (s *Service) recipientKeys(ctx context.Context, tenant string, def sources.Definition) ([][]RecipientKey, error) {
	out := make([][]RecipientKey, len(def.Groups))
	for i, g := range def.Groups {
		out[i] = []RecipientKey{}
		if len(g.Recipients) == 0 {
			continue
		}
		rows, err := s.d.Catalog.Pool().Query(ctx, `SELECT principal, fingerprint, key_version FROM recipient_keys
		                                            WHERE tenant = $1 AND status = 'ACTIVE' AND principal = ANY($2) ORDER BY principal, fingerprint`,
			tenant, g.Recipients)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k RecipientKey
			if err := rows.Scan(&k.Principal, &k.Fingerprint, &k.KeyVersion); err != nil {
				rows.Close()
				return nil, err
			}
			out[i] = append(out[i], k)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readingEnvelopes checks a client-mode reading's finalize against the
// source version it began under (ING-011, D-K): the manifest names the
// profile and that version, and each group's unit has envelopes for
// exactly the active keys of the recipients the group names, none missing
// and none for anyone else.
func (s *Service) readingEnvelopes(ctx context.Context, tenant string, in storedDocIntent, m cryptowire.Manifest, units []checkedUnit) error {
	if m.NormalizationVersion != jsonunits.Profile || m.ExtractionVersion != in.extractionVersion() {
		return fmt.Errorf("%w: a reading's manifest names the profile and the source version", ErrInvalid)
	}
	src, _ := in.attributes["source"].(string)
	version, _ := in.attributes["source_version"].(float64)
	sv, err := s.d.Catalog.SourceVersion(ctx, tenant, src, int(version))
	if err != nil {
		return fmt.Errorf("%w: the reading's source version: %v", ErrUnavailable, err)
	}
	def, err := sources.Parse(sv.Definition)
	if err != nil || len(def.Groups) != len(units) {
		return fmt.Errorf("%w: the reading's source version cannot be read", ErrUnavailable)
	}
	keys, err := s.recipientKeys(ctx, tenant, def)
	if err != nil {
		return err
	}
	for i, u := range units {
		want := map[string]bool{}
		for _, k := range keys[i] {
			want[k.Fingerprint] = true
		}
		got := map[string]bool{}
		for _, e := range u.envs {
			got[e.ctx.Recipient.String()] = true
		}
		if !maps.Equal(got, want) {
			return fmt.Errorf("%w: the envelopes of group %q are not for exactly its recipients' active keys; read the layout again", ErrConflict,
				def.Groups[i].Name)
		}
	}
	return nil
}

// activeSource returns an enabled source with an active version and that
// version's record. Any other source is not found.
func (s *Service) activeSource(ctx context.Context, tenant, id string) (catalog.Source, sources.Definition, error) {
	src, def, err := s.reviewedSource(ctx, tenant, id)
	if err == nil && src.Disabled {
		return catalog.Source{}, sources.Definition{}, ErrNotFound
	}
	return src, def, err
}

// reviewedSource returns a source with an active version and that
// version's record, also when the source is disabled: its readings stay
// readable, by data tools too. Any other source is not found.
func (s *Service) reviewedSource(ctx context.Context, tenant, id string) (catalog.Source, sources.Definition, error) {
	if !sources.ValidID(id) {
		return catalog.Source{}, sources.Definition{}, ErrNotFound
	}
	src, err := s.d.Catalog.Source(ctx, tenant, id)
	if errors.Is(err, catalog.ErrNoRow) || err == nil && src.Active == nil {
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
