package adminops

import (
	"context"
	"errors"

	"fga/internal/catalog"
	"fga/internal/identity"
	"fga/internal/jsonunits"
	"fga/internal/sources"
)

// Sources of JSON readings (docs/design/mcp-data-tools.md, ING-001,
// ING-008, D-G): a source is added with its bucket and a draft, each new
// version is a draft, and another administrator reviews a draft, naming
// the version and digest seen, which makes it active. A review and a
// disable are journaled first. Every record is checked here, before it is
// stored and again before it is reviewed: its own rules for the bucket's
// mode, its owner and recipients as enabled identities, and its labels
// against the active label order and the bucket's label.

// AddSource creates a source, its bucket and its draft version 1. The
// bucket is created in b's encryption mode and names the source.
func (o Ops) AddSource(ctx context.Context, who Who, tenant string, b catalog.Bucket, def sources.Definition) (catalog.SourceVersion, error) {
	if !catalog.BucketName.MatchString(b.Name) {
		return catalog.SourceVersion{}, invalid("bucket name %q", b.Name)
	}
	if err := o.checkSource(ctx, tenant, def, b.Encryption, b.Label); err != nil {
		return catalog.SourceVersion{}, err
	}
	raw, digest, err := def.Canonical()
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	now := o.Now().UTC()
	err = o.Store.Administer(ctx, o.event(tenant, who, "source.add", "source", def.ID), o.journal(), func(a *catalog.Admin) error {
		_, err := a.CreateSource(ctx, tenant, b, def.ID, raw, digest, who.Actor, now)
		return err
	})
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	return catalog.SourceVersion{Version: 1, State: "DRAFT", Digest: digest, Definition: raw, Author: who.Actor, CreatedAt: now}, nil
}

// PutSource stores a source's next version as its draft.
func (o Ops) PutSource(ctx context.Context, who Who, tenant string, def sources.Definition) (catalog.SourceVersion, error) {
	src, err := o.source(ctx, tenant, def.ID)
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	if err := o.checkSource(ctx, tenant, def, src.Encryption, src.Label); err != nil {
		return catalog.SourceVersion{}, err
	}
	raw, digest, err := def.Canonical()
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	now := o.Now().UTC()
	var version int
	err = o.Store.Administer(ctx, o.event(tenant, who, "source.put", "source", def.ID), o.journal(), func(a *catalog.Admin) error {
		version, err = a.PutSourceDraft(ctx, tenant, def.ID, raw, digest, who.Actor, now)
		return err
	})
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	return catalog.SourceVersion{Version: version, State: "DRAFT", Digest: digest, Definition: raw, Author: who.Actor, CreatedAt: now}, nil
}

// TrySource splits a sample payload with a version's layout, the draft's
// by default (version 0), else the active one's. Nothing is stored, and no
// reading is read: the sample is the administrator's own.
func (o Ops) TrySource(ctx context.Context, tenant, id string, version int, payload []byte, principal string) (jsonunits.Reading, error) {
	src, err := o.source(ctx, tenant, id)
	if err != nil {
		return jsonunits.Reading{}, err
	}
	var v *catalog.SourceVersion
	switch {
	case version > 0:
		got, err := o.Store.SourceVersion(ctx, tenant, id, version)
		if err != nil {
			return jsonunits.Reading{}, err
		}
		v = &got
	case src.Draft != nil:
		v = src.Draft
	case src.Active != nil:
		v = src.Active
	default:
		return jsonunits.Reading{}, catalog.ErrNoRow
	}
	def, err := sources.Parse(v.Definition)
	if err != nil {
		return jsonunits.Reading{}, err
	}
	s, err := def.Layout().Compile()
	if err != nil {
		return jsonunits.Reading{}, invalid("%v", err)
	}
	return s.Split(payload, principal)
}

// ReviewSource makes a source's draft its active version: version and
// digest name the draft the reviewer saw. The draft is checked again,
// since labels, the label order and identities may have changed.
func (o Ops) ReviewSource(ctx context.Context, who Who, tenant, id string, version int, digest string) (catalog.SourceVersion, error) {
	src, err := o.source(ctx, tenant, id)
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	if src.Draft == nil || src.Draft.Version != version || src.Draft.Digest != digest {
		return catalog.SourceVersion{}, catalog.ErrSourceConflict
	}
	def, err := sources.Parse(src.Draft.Definition)
	if err != nil {
		return catalog.SourceVersion{}, err
	}
	if err := o.checkSource(ctx, tenant, def, src.Encryption, src.Label); err != nil {
		return catalog.SourceVersion{}, err
	}
	var v catalog.SourceVersion
	err = o.Store.Administer(ctx, o.event(tenant, who, "source.review", "source", id), o.journal(), func(a *catalog.Admin) error {
		v, err = a.ReviewSource(ctx, tenant, id, version, digest, who.Actor, o.AllowSelfReview, o.Now().UTC())
		return err
	})
	return v, err
}

// DisableSource disables a source, journaled first; it accepts no reading
// after. It is final, as an identity's disable is.
func (o Ops) DisableSource(ctx context.Context, who Who, tenant, id string) error {
	if !sources.ValidID(id) {
		return invalid("source ID %q", id)
	}
	return o.Store.Administer(ctx, o.event(tenant, who, "source.disable", "source", id), o.journal(), func(a *catalog.Admin) error {
		return a.DisableSource(ctx, tenant, id)
	})
}

func (o Ops) source(ctx context.Context, tenant, id string) (catalog.Source, error) {
	if !sources.ValidID(id) {
		return catalog.Source{}, invalid("source ID %q", id)
	}
	return o.Store.Source(ctx, tenant, id)
}

// checkSource checks a record for a bucket in mode whose label is floor.
func (o Ops) checkSource(ctx context.Context, tenant string, def sources.Definition, mode, floor string) error {
	if err := def.Check(mode); err != nil {
		return invalid("%v", err)
	}
	for _, id := range def.Identities() {
		if err := checkID("identity", id); err != nil {
			return err
		}
		i, err := o.Store.GetIdentity(ctx, tenant, id)
		if errors.Is(err, identity.ErrUnknown) || err == nil && i.Disabled {
			return invalid("identity %q is not an enabled identity of the tenant", id)
		}
		if err != nil {
			return err
		}
	}
	_, order, err := catalog.LabelOrder(ctx, o.Store.Pool(), false)
	if errors.Is(err, catalog.ErrNoLabelOrder) {
		return invalid("no label order is active")
	}
	if err != nil {
		return err
	}
	if err := def.CheckLabels(order, floor); err != nil {
		return invalid("%v", err)
	}
	return nil
}
