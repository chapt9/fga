package adminops

import (
	"context"
	"errors"

	"fga/internal/catalog"
	"fga/internal/datatools"
	"fga/internal/sources"
)

// Data tools (docs/design/mcp-data-tools.md, DTL-001, DTL-007): a tool is
// added with a draft, each new version is a draft, and a review naming the
// version and digest seen makes it active and registers it as the
// agent.tool resource mcp.tool:<name>. A tool grants nothing, so its
// author may review it (D-G). Every record is checked here before it is
// stored, against its source's active version when there is one, and at
// review against that version, which it must fit.

// AddDataTool creates a data tool and its draft version 1.
func (o Ops) AddDataTool(ctx context.Context, who Who, tenant string, def datatools.Definition) (catalog.RecordVersion, error) {
	if err := o.checkTool(ctx, tenant, def); err != nil {
		return catalog.RecordVersion{}, err
	}
	raw, digest, err := def.Canonical()
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	now := o.Now().UTC()
	err = o.Store.Administer(ctx, o.event(tenant, who, "data-tool.add", "data-tool", def.Name), o.journal(), func(a *catalog.Admin) error {
		return a.CreateDataTool(ctx, tenant, def.Name, def.Source, raw, digest, who.Actor, now)
	})
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	return catalog.RecordVersion{Version: 1, State: "DRAFT", Digest: digest, Definition: raw, Author: who.Actor, CreatedAt: now}, nil
}

// PutDataTool stores a data tool's next version as its draft. A tool stays
// over the source it was added with.
func (o Ops) PutDataTool(ctx context.Context, who Who, tenant string, def datatools.Definition) (catalog.RecordVersion, error) {
	tool, err := o.dataTool(ctx, tenant, def.Name)
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	if def.Source != tool.Source {
		return catalog.RecordVersion{}, invalid("data tool %q stays over source %q", def.Name, tool.Source)
	}
	if err := o.checkTool(ctx, tenant, def); err != nil {
		return catalog.RecordVersion{}, err
	}
	raw, digest, err := def.Canonical()
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	now := o.Now().UTC()
	var version int
	err = o.Store.Administer(ctx, o.event(tenant, who, "data-tool.put", "data-tool", def.Name), o.journal(), func(a *catalog.Admin) error {
		version, err = a.PutDataToolDraft(ctx, tenant, def.Name, raw, digest, who.Actor, now)
		return err
	})
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	return catalog.RecordVersion{Version: version, State: "DRAFT", Digest: digest, Definition: raw, Author: who.Actor, CreatedAt: now}, nil
}

// ReviewDataTool makes a data tool's draft its active version and
// registers it; version and digest name the draft the reviewer saw. The
// resource carries what policy may decide on: the source, its bucket and
// project, the mode, the version and the definition's digest.
func (o Ops) ReviewDataTool(ctx context.Context, who Who, tenant, name string, version int, digest string) (catalog.RecordVersion, error) {
	tool, err := o.dataTool(ctx, tenant, name)
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	if tool.Draft == nil || tool.Draft.Version != version || tool.Draft.Digest != digest {
		return catalog.RecordVersion{}, catalog.ErrDraftConflict
	}
	def, err := datatools.Parse(tool.Draft.Definition)
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	src, err := o.Store.Source(ctx, tenant, def.Source)
	if err != nil {
		return catalog.RecordVersion{}, err
	}
	if src.Active == nil {
		return catalog.RecordVersion{}, invalid("source %q has no active version to review the tool against", def.Source)
	}
	if err := o.checkTool(ctx, tenant, def); err != nil {
		return catalog.RecordVersion{}, err
	}
	attrs := map[string]any{"name": name, "kind": "data", "active": true, "source": src.ID, "bucket": src.Bucket, "project": src.Project,
		"encryption": src.Encryption, "version": version, "definition_digest": digest}
	var v catalog.RecordVersion
	err = o.Store.Administer(ctx, o.event(tenant, who, "data-tool.review", "data-tool", name), o.journal(), func(a *catalog.Admin) error {
		v, err = a.ReviewDataTool(ctx, tenant, name, version, digest, who.Actor, true, attrs, o.Now().UTC())
		return err
	})
	return v, err
}

// DisableDataTool disables a data tool: it is no longer listed, and calls
// answer not found. It is final.
func (o Ops) DisableDataTool(ctx context.Context, who Who, tenant, name string) error {
	if !datatools.ValidName(name) {
		return invalid("data tool name %q", name)
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "data-tool.disable", "data-tool", name), o.journal(), func(a *catalog.Admin) error {
		return a.DisableDataTool(ctx, tenant, name)
	})
}

// BrokenDataTools names the enabled data tools over source whose active
// version does not fit the source's active version: they answer 409 until
// a new version is reviewed. A source review reports them.
func (o Ops) BrokenDataTools(ctx context.Context, tenant, source string) ([]string, error) {
	src, err := o.Store.Source(ctx, tenant, source)
	if err != nil || src.Active == nil {
		return nil, err
	}
	def, err := sources.Parse(src.Active.Definition)
	if err != nil {
		return nil, err
	}
	broken := []string{}
	for after := ""; ; {
		tools, err := o.Store.ListDataTools(ctx, tenant, source, after, 100)
		if err != nil {
			return nil, err
		}
		for _, t := range tools {
			if t.Disabled || t.Active == nil {
				continue
			}
			if tool, err := datatools.Parse(t.Active.Definition); err != nil || tool.Fit(def) != nil {
				broken = append(broken, t.Name)
			}
		}
		if len(tools) < 100 {
			return broken, nil
		}
		after = tools[len(tools)-1].Name
	}
}

func (o Ops) dataTool(ctx context.Context, tenant, name string) (catalog.DataTool, error) {
	if !datatools.ValidName(name) {
		return catalog.DataTool{}, invalid("data tool name %q", name)
	}
	return o.Store.DataTool(ctx, tenant, name)
}

// checkTool checks a record's own rules, that its source is one of the
// tenant's, and its fit to the source's active version when there is one.
func (o Ops) checkTool(ctx context.Context, tenant string, def datatools.Definition) error {
	if err := def.Check(); err != nil {
		return invalid("%v", err)
	}
	src, err := o.Store.Source(ctx, tenant, def.Source)
	if errors.Is(err, catalog.ErrNoRow) {
		return invalid("source %q is not a source of the tenant", def.Source)
	}
	if err != nil || src.Active == nil {
		return err
	}
	srcDef, err := sources.Parse(src.Active.Definition)
	if err != nil {
		return err
	}
	if err := def.Fit(srcDef); err != nil {
		return invalid("%v", err)
	}
	return nil
}
