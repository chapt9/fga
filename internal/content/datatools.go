package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/datatools"
	"fga/internal/jsonunits"
	"fga/internal/labels"
	"fga/internal/registry"
	"fga/internal/signing"
	"fga/internal/sources"
)

// Data tools (docs/design/mcp-data-tools.md, DTL-001 to DTL-009). A data
// tool is a reviewed view of one source's readings and grants nothing:
// besides invoke on the tool, a call makes exactly the decisions of the
// native reads it is made of, for the same caller chain, so its answer is
// within what those reads answer (DTL-002). A server-mode call reads each
// unit as GET .../document/unit/content does and projects it; a
// client-mode call answers the caller's unit packages and ciphertext, as
// .../unit/package and .../unit/ciphertext do, with the projection the
// caller's own client applies (DTL-009).

// MaxToolAnswer bounds a call's answer (DTL-006).
const MaxToolAnswer = 1 << 20

// DataToolEntry is one data tool as the listing answers it (DTL-004),
// without its source, bucket, keys or field pointers.
type DataToolEntry struct {
	Name         string          `json:"name"`
	Version      int             `json:"version"`
	Description  string          `json:"description"`
	Encryption   string          `json:"encryption"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema"`
}

// DataToolPage is a page of the listing.
type DataToolPage struct {
	Tools        []DataToolEntry `json:"tools"`
	Continuation string          `json:"continuation,omitempty"`
}

// DataToolCall is a call: its arguments, a pinned version, which must be
// the active one, and for a tool over a client-mode source the caller's
// recipient key fingerprint.
type DataToolCall struct {
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Version   int             `json:"version,omitempty"`
	Recipient string          `json:"recipient,omitempty"`
}

// DataToolAnswer is a call's answer: for a latest tool the reading's
// Origin with its Reading, or over a client-mode source the caller's
// Packages; for a history tool Readings, newest first. A client-mode
// answer is Encrypted: the caller's client opens the packages and applies
// Projection, which gives the server-mode answer.
type DataToolAnswer struct {
	Tool       string                `json:"tool"`
	Version    int                   `json:"version"`
	Encrypted  bool                  `json:"encrypted,omitempty"`
	Projection *jsonunits.Projection `json:"projection,omitempty"`
	Reading    json.RawMessage       `json:"reading,omitempty"`
	Origin     *ReadingOrigin        `json:"origin,omitempty"`
	Packages   []ToolPackage         `json:"packages,omitempty"`
	Readings   *[]ToolReading        `json:"readings,omitempty"`
}

// ToolReading is one reading of an answer.
type ToolReading struct {
	Reading  json.RawMessage `json:"reading,omitempty"`
	Origin   ReadingOrigin   `json:"origin"`
	Packages []ToolPackage   `json:"packages,omitempty"`
}

// ReadingOrigin says where a reading comes from. Label is the highest
// label of the units the reading used: metadata for whoever receives it,
// never an access decision (DTL-006).
type ReadingOrigin struct {
	Source          string `json:"source"`
	DocumentVersion string `json:"document_version_id"`
	PublishedAt     string `json:"published_at,omitempty"`
	Label           string `json:"label"`
}

// ToolPackage is one unit of a client-mode reading for the caller's key,
// as GET .../document/unit/package answers it, with the ciphertext.
type ToolPackage struct {
	Unit             UnitEntry    `json:"unit"`
	EnvelopeID       string       `json:"envelope_id"`
	Envelope         ToolEnvelope `json:"envelope"`
	Receipt          []byte       `json:"receipt"`
	ReceiptSignature string       `json:"receipt_signature"`
	Ciphertext       []byte       `json:"ciphertext"`
}

// ToolEnvelope is the caller's envelope of a ToolPackage.
type ToolEnvelope struct {
	Context    []byte `json:"context"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// ListDataTools lists the enabled data tools the caller may discover, in
// name order, deciding discover on each in batches (DTL-004). The
// continuation is sealed and bound to the caller, as for unit listings.
func (s *Service) ListDataTools(ctx context.Context, c Caller, limit int, continuation string) (DataToolPage, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	id, err := s.d.Catalog.GetIdentity(ctx, c.Tenant, c.Principal)
	if err != nil {
		return DataToolPage{}, ErrNotFound
	}
	cur := cursor{Tenant: c.Tenant, Principal: c.Principal, Revision: id.Revision, Bucket: "data-tools"}
	if continuation != "" {
		prev, err := s.openToken(continuation)
		if err != nil || prev.Tenant != cur.Tenant || prev.Principal != cur.Principal || prev.Revision != cur.Revision ||
			prev.Bucket != cur.Bucket || !s.d.Now().Before(prev.Expires) {
			return DataToolPage{}, ErrInvalid
		}
		cur.After = prev.After
	}
	page := DataToolPage{Tools: []DataToolEntry{}}
	exhausted := false
	for scanned := 0; len(page.Tools) < limit && scanned < s.d.Limits.ListScanBudget && !exhausted; {
		tools, err := s.d.Catalog.ListDataTools(ctx, c.Tenant, "", cur.After, discoverBatch)
		if err != nil {
			return DataToolPage{}, err
		}
		exhausted, scanned = len(tools) < discoverBatch, scanned+len(tools)
		if len(tools) > 0 {
			cur.After = tools[len(tools)-1].Name
		}
		var listed []catalog.DataTool
		var checks []check
		for _, t := range tools {
			if !t.Disabled && t.Active != nil {
				checks = append(checks, check{id: "tool-" + strconv.Itoa(len(listed)), role: registry.RoleTool, action: "discover",
					ref: canonical("agent.tool", registry.MCPToolNamespace+":"+t.Name)})
				listed = append(listed, t)
			}
		}
		if len(listed) == 0 {
			continue
		}
		visible, err := s.eachAllowed(ctx, c, registry.OpMCPDiscover, checks)
		if err != nil {
			return DataToolPage{}, err
		}
		for i, t := range listed {
			if !visible[i] {
				continue
			}
			def, err := datatools.Parse(t.Active.Definition)
			if err != nil {
				return DataToolPage{}, fmt.Errorf("%w: data tool %s cannot be read", ErrUnavailable, t.Name)
			}
			page.Tools = append(page.Tools, DataToolEntry{Name: t.Name, Version: t.Active.Version, Description: def.Description,
				Encryption: t.Encryption, InputSchema: def.InputSchema(), OutputSchema: def.OutputSchema()})
			if len(page.Tools) == limit {
				// The page ends here; the next one goes on after this tool.
				exhausted = exhausted && t.Name == cur.After
				cur.After = t.Name
				break
			}
		}
	}
	if !exhausted {
		cur.Expires = s.d.Now().Add(s.d.Limits.TokenLifetime)
		var err error
		if page.Continuation, err = s.sealToken(cur); err != nil {
			return DataToolPage{}, err
		}
	}
	return page, nil
}

// CallDataTool calls data tool name: its active version, which a pinned
// version must be. A disabled or unknown tool is not found before any
// decision; the caller then needs invoke on the tool (DTL-004), which a
// gateway's decision for exactly this tool already is (MCP-009), and the
// tool must fit its source's active version.
func (s *Service) CallDataTool(ctx context.Context, c Caller, name string, r DataToolCall) (DataToolAnswer, error) {
	if !datatools.ValidName(name) {
		return DataToolAnswer{}, ErrNotFound
	}
	tool, err := s.d.Catalog.DataTool(ctx, c.Tenant, name)
	if errors.Is(err, catalog.ErrNoRow) || err == nil && (tool.Disabled || tool.Active == nil) {
		return DataToolAnswer{}, ErrNotFound
	}
	if err != nil {
		return DataToolAnswer{}, err
	}
	var rec signing.Record
	if c.Tool != "" {
		signed, ok := signing.ParseEvidence(c.Token)
		if c.Tool != name || !ok {
			return DataToolAnswer{}, ErrNotFound
		}
		if rec, err = s.d.Verifier.Check(signed); err != nil {
			return DataToolAnswer{}, ErrNotFound
		}
	} else if _, rec, err = s.decide(ctx, c, registry.OpMCPInvoke, Audience, false,
		[]check{{id: "tool", role: registry.RoleTool, action: "invoke", ref: canonical("agent.tool", registry.MCPToolNamespace+":"+name)}}); err != nil {
		return DataToolAnswer{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return DataToolAnswer{}, err
	}
	if r.Version != 0 && r.Version != tool.Active.Version {
		return DataToolAnswer{}, fmt.Errorf("%w: version %d of the tool is not active", ErrConflict, r.Version)
	}
	def, err := datatools.Parse(tool.Active.Definition)
	if err != nil || def.Name != name {
		return DataToolAnswer{}, fmt.Errorf("%w: data tool %s cannot be read", ErrUnavailable, name)
	}
	src, srcDef, err := s.reviewedSource(ctx, c.Tenant, def.Source)
	if err == nil && def.Fit(srcDef) != nil {
		err = fmt.Errorf("%w: the tool no longer fits its source; a new version must be reviewed", ErrConflict)
	}
	if err != nil {
		return DataToolAnswer{}, err
	}
	return s.runTool(ctx, c, rec, def, tool.Active.Version, tool.Active.Digest, src, srcDef, r)
}

// PreviewDataTool runs a draft definition as the caller, for the console's
// builder (DTL-008): it needs list on the source's bucket, then exactly the
// reads of a call. No tool resource exists yet, so nothing is invoked, and
// no gateway decision opens this route.
func (s *Service) PreviewDataTool(ctx context.Context, c Caller, raw json.RawMessage, r DataToolCall) (DataToolAnswer, error) {
	def, err := datatools.Parse(raw)
	if err == nil {
		err = def.Check()
	}
	if err != nil {
		return DataToolAnswer{}, errors.Join(ErrInvalid, err)
	}
	src, srcDef, err := s.reviewedSource(ctx, c.Tenant, def.Source)
	if err != nil {
		return DataToolAnswer{}, err
	}
	_, rec, err := s.decide(ctx, c, registry.OpListBucket, Audience, false,
		[]check{{id: "bucket", role: registry.RoleBucket, action: "list", ref: canonical("storage.bucket", src.BucketID)}})
	if err != nil {
		return DataToolAnswer{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return DataToolAnswer{}, err
	}
	if err := def.Fit(srcDef); err != nil {
		return DataToolAnswer{}, errors.Join(ErrInvalid, err)
	}
	_, digest, err := def.Canonical()
	if err != nil {
		return DataToolAnswer{}, err
	}
	return s.runTool(ctx, c, rec, def, 0, digest, src, srcDef, r)
}

// toolRun is one run of a tool's reads for a caller.
type toolRun struct {
	s         *Service
	c         Caller
	def       datatools.Definition
	proj      jsonunits.Projection
	src       catalog.Source
	recipient string
	order     []string
	// disclosed are the document versions and units the answer holds.
	disclosed []audit.Target
}

// runTool resolves the arguments, reads, and audits the answer: one event
// with the tool, its version and digest, and the document versions and
// units disclosed, by ID only (DTL-006, DSC-003). A run that meets a
// moving head starts again, at most three times.
func (s *Service) runTool(ctx context.Context, c Caller, rec signing.Record, def datatools.Definition, version int, digest string,
	src catalog.Source, srcDef sources.Definition, r DataToolCall) (DataToolAnswer, error) {
	call, err := def.Resolve(srcDef, r.Arguments)
	if err != nil {
		return DataToolAnswer{}, errors.Join(ErrInvalid, err)
	}
	// A client-mode answer is the caller's packages for its own key; a
	// caller who names none is told the mode (ENC-002).
	if _, err := cryptowire.ParseDigest(r.Recipient); src.Encryption == "client" && err != nil {
		if r.Recipient == "" {
			return DataToolAnswer{}, ErrEncryptionMode
		}
		return DataToolAnswer{}, fmt.Errorf("%w: the recipient is a key fingerprint", ErrInvalid)
	}
	_, order, err := catalog.LabelOrder(ctx, s.d.Catalog.Pool(), false)
	if err != nil {
		return DataToolAnswer{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var ans DataToolAnswer
	var t *toolRun
	for range 3 {
		t = &toolRun{s: s, c: c, def: def, proj: def.Projection(), src: src, recipient: r.Recipient, order: order}
		if ans, err = t.run(ctx, call); !errors.Is(err, ErrConflict) {
			break
		}
	}
	if err != nil {
		return DataToolAnswer{}, err
	}
	ans.Tool, ans.Version = def.Name, version
	if src.Encryption == "client" {
		ans.Encrypted, ans.Projection = true, &t.proj
	}
	if b, err := json.Marshal(ans); err != nil || len(b) > MaxToolAnswer {
		return DataToolAnswer{}, ErrTooLarge
	}
	outcome := "DATA_TOOL"
	if version == 0 {
		outcome = "DATA_TOOL_PREVIEW"
	}
	e := s.event(audit.KindReadAdmission, rec, outcome, append([]audit.Target{{Type: "agent.tool",
		ID: registry.MCPToolNamespace + ":" + def.Name, Version: strconv.Itoa(version), Digest: digest}}, t.disclosed...)...)
	e.Subject, e.Delegation = rec.Subject.ID, rec.Delegation
	if err := s.d.Catalog.Append(ctx, e); err != nil {
		return DataToolAnswer{}, err
	}
	return ans, nil
}

// run reads the latest reading, or a history newest first within the
// call's bounds, leaving out readings the caller may not read.
func (t *toolRun) run(ctx context.Context, call datatools.Call) (DataToolAnswer, error) {
	s, c := t.s, t.c
	if t.def.Operation == datatools.OpLatest {
		d, err := s.documentVersion(ctx, c.Tenant, t.src.Bucket, call.Key, "")
		if err != nil {
			return DataToolAnswer{}, err
		}
		r, ok, err := t.reading(ctx, d)
		switch {
		case err != nil:
			return DataToolAnswer{}, err
		case !ok:
			return DataToolAnswer{}, ErrNotFound
		}
		return DataToolAnswer{Reading: r.Reading, Origin: &r.Origin, Packages: r.Packages}, nil
	}
	readings, size := []ToolReading{}, 0
	for continuation := ""; len(readings) < call.Limit; {
		page, err := s.documentVersionsIn(ctx, c, t.src.Bucket, call.Key, call.Limit-len(readings), continuation, window{call.Since, call.Until})
		if err != nil {
			return DataToolAnswer{}, err
		}
		for _, v := range page.Versions {
			d, err := s.documentVersion(ctx, c.Tenant, t.src.Bucket, call.Key, v.DocumentVersion)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return DataToolAnswer{}, err
			}
			r, ok, err := t.reading(ctx, d)
			if err != nil {
				return DataToolAnswer{}, err
			}
			if !ok {
				continue
			}
			// A history stops before the answer would exceed its bound; the
			// caller pages on with until.
			b, _ := json.Marshal(r)
			if size += len(b) + 1; size > MaxToolAnswer-1024 {
				if len(readings) == 0 {
					return DataToolAnswer{}, ErrTooLarge
				}
				return DataToolAnswer{Readings: &readings}, nil
			}
			if readings = append(readings, r); len(readings) == call.Limit {
				break
			}
		}
		if continuation = page.Continuation; continuation == "" {
			break
		}
	}
	return DataToolAnswer{Readings: &readings}, nil
}

// reading reads one reading of d through the native reads: the units of
// the groups the outputs use, decided as document.select-units does, all
// or nothing for skip_reading and one by one for skip_fields; then each
// unit's plaintext in server mode, or the caller's package and the
// ciphertext in client mode. It reports false for a reading left out.
func (t *toolRun) reading(ctx context.Context, d docVersion) (ToolReading, bool, error) {
	s, c := t.s, t.c
	ms, err := s.members(ctx, c.Tenant, d.id, -1, cryptowire.MaxUnits, nil)
	if err != nil {
		return ToolReading{}, false, err
	}
	ids := []string{d.id.String()}
	for _, m := range ms {
		ids = append(ids, m.entry.Unit)
	}
	rows, err := s.d.Catalog.Pool().Query(ctx, `SELECT id, coalesce(attributes->>'group', ''), coalesce(attributes->>'label', ''),
	                                                   coalesce(attributes->>'published_at', '')
	                                              FROM resources WHERE tenant = $1 AND id = ANY($2)`, c.Tenant, ids)
	if err != nil {
		return ToolReading{}, false, err
	}
	group, label := map[string]string{}, map[string]string{}
	origin := ReadingOrigin{Source: t.src.ID, DocumentVersion: d.id.String()}
	for rows.Next() {
		var id, g, l, published string
		if err := rows.Scan(&id, &g, &l, &published); err != nil {
			rows.Close()
			return ToolReading{}, false, err
		}
		if id == origin.DocumentVersion {
			origin.PublishedAt = published
		} else {
			group[id], label[id] = g, l
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ToolReading{}, false, err
	}
	groups := t.proj.Groups()
	var need []member
	for _, m := range ms {
		if slices.Contains(groups, group[m.entry.Unit]) {
			need = append(need, m)
		}
	}
	skipFields := t.proj.OnUnreadable == jsonunits.SkipFields
	if len(need) == 0 || !skipFields && len(need) < len(groups) {
		return ToolReading{}, false, nil
	}
	readable := need
	if skipFields {
		readable = nil
		for _, m := range need {
			ok, err := s.allowed(ctx, c, d.units.selectOp, d, []member{m})
			if err != nil {
				return ToolReading{}, false, err
			}
			if ok {
				readable = append(readable, m)
			}
		}
	} else if ok, err := s.allowed(ctx, c, d.units.selectOp, d, need); err != nil || !ok {
		return ToolReading{}, false, err
	}
	out := ToolReading{Origin: origin}
	units := map[string][]byte{}
	rank := -1
	var targets []audit.Target
	for _, m := range readable {
		var stream *Stream
		var pkg UnitPackageOut
		if t.src.Encryption == "client" {
			if pkg, err = s.unitPackage(ctx, c, d, m, t.recipient); err == nil {
				stream, err = s.readUnitCiphertext(ctx, c, d, m)
			}
		} else {
			stream, err = s.readUnitPlain(ctx, c, d, m)
		}
		if errors.Is(err, ErrNotFound) && skipFields {
			continue
		}
		if errors.Is(err, ErrNotFound) {
			return ToolReading{}, false, nil
		}
		if err != nil {
			return ToolReading{}, false, err
		}
		b, err := io.ReadAll(io.LimitReader(stream, MaxToolAnswer+1))
		if cerr := stream.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return ToolReading{}, false, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if t.src.Encryption == "client" {
			e := pkg.Envelope
			out.Packages = append(out.Packages, ToolPackage{Unit: pkg.Unit, EnvelopeID: e.EnvelopeID,
				Envelope: ToolEnvelope{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature}, Receipt: e.Receipt,
				ReceiptSignature: e.ReceiptSignature, Ciphertext: b})
		} else {
			units[group[m.entry.Unit]] = b
		}
		if r, known := labels.Rank(t.order, label[m.entry.Unit]); known && r > rank {
			rank, out.Origin.Label = r, label[m.entry.Unit]
		}
		targets = append(targets, audit.Target{Type: d.units.typ, ID: m.entry.Unit, Version: m.entry.UnitVersion})
	}
	if t.src.Encryption == "client" {
		if len(out.Packages) == 0 {
			return ToolReading{}, false, nil
		}
	} else {
		projected, ok, err := t.proj.Apply(units)
		if err != nil || !ok {
			return ToolReading{}, false, err
		}
		if out.Reading, err = json.Marshal(projected); err != nil {
			return ToolReading{}, false, err
		}
	}
	t.disclosed = append(append(t.disclosed, audit.Target{Type: "document.version", ID: d.id.String()}), targets...)
	return out, true, nil
}
