package content

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/labels"
	"fga/internal/opplan"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Labels (docs/design/labels-and-approvals.md, LAB-001 to LAB-005, D-06).
// The storage role reads the active label order that the decision role
// published from its signed release, and checks inside the fence that a
// decision about a label was made under that same order generation.

// labelAllowed reports whether label may be set in a collection whose
// floor is floor: it is in the active order and not below the floor.
func (s *Service) labelAllowed(ctx context.Context, label, floor string) error {
	_, order, err := catalog.LabelOrder(ctx, s.d.Catalog.Pool(), false)
	if errors.Is(err, catalog.ErrNoLabelOrder) {
		return fmt.Errorf("%w: no label order is active", ErrInvalid)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return checkLabel(order, label, floor)
}

func checkLabel(order []string, label, floor string) error {
	rank, known := labels.Rank(order, label)
	if !known {
		return fmt.Errorf("%w: the label is not in the label order", ErrInvalid)
	}
	if floorRank, _ := labels.Rank(order, floor); rank < floorRank {
		return fmt.Errorf("%w: the label is below the collection's floor", ErrInvalid)
	}
	return nil
}

// labelOrderHolds runs in the fence: the active order is the one rec was
// decided under, and label is still allowed in it.
func (s *Service) labelOrderHolds(ctx context.Context, tx pgx.Tx, rec signing.Record, label string, bucket cryptowire.UUID) error {
	generation, order, err := catalog.LabelOrder(ctx, tx, true)
	if errors.Is(err, catalog.ErrNoLabelOrder) || err == nil && generation != rec.Context.LabelOrderGeneration {
		return fmt.Errorf("%w: the label order changed", ErrConflict)
	}
	if err != nil {
		return err
	}
	var floor string
	if err := tx.QueryRow(ctx, `SELECT default_label FROM buckets WHERE tenant = $1 AND id = $2`, rec.Tenant, bucket).Scan(&floor); err != nil {
		return err
	}
	return checkLabel(order, label, floor)
}

// LabelOutcome reports a label change.
type LabelOutcome struct {
	Object           string `json:"object_id"`
	Label            string `json:"label"`
	Previous         string `json:"previous_label"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

// SetLabel sets a key's protected label (LAB-002, LAB-004). Raising it, or
// setting the same label, needs label; lowering it needs relabel, which a
// policy may make subject to an approval. A label is never set outside the
// order or below the bucket's floor. The change advances the object's
// metadata revision, so every decision and lease bound to the old one
// fails (LAB-005); ciphertext and envelopes are unchanged.
func (s *Service) SetLabel(ctx context.Context, c Caller, bucketName, key, label string) (LabelOutcome, error) {
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return LabelOutcome{}, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, key)
	if err != nil {
		return LabelOutcome{}, err
	}
	return s.setLabel(ctx, c, labelTarget{typ: "storage.object", id: o.ID.String(), bucket: b, attrs: o.Attributes, meta: o.Meta,
		role: registry.RoleObject, labelOp: registry.OpLabel, relabelOp: registry.OpRelabel,
		details: map[string]string{"bucket": bucketName, "key": key}}, label)
}

// SetUnitLabel sets the label of a document unit (LAB-001, LAB-004): the
// unit must belong to the selected version of the document at bucket/key.
// The label is the unit's, in every document version that includes it;
// derived outputs that name it lose their authority (LAB-005, DRV-009).
// Text entries take their collection's label and are not labelled alone.
func (s *Service) SetUnitLabel(ctx context.Context, c Caller, bucketName, key, versionSel, unit, label string) (LabelOutcome, error) {
	d, m, err := s.unitTarget(ctx, c, bucketName, key, versionSel, unit)
	if err != nil {
		return LabelOutcome{}, err
	}
	if d.units != textUnits {
		return LabelOutcome{}, fmt.Errorf("%w: text entries take their collection's label", ErrInvalid)
	}
	return s.labelResource(ctx, c, bucketName, "document.text_unit", m.entry.Unit, registry.RoleUnit, registry.OpUnitLabel, registry.OpUnitRelabel,
		map[string]string{"bucket": bucketName, "key": key, "unit": unit}, label)
}

// SetDerivedLabel sets a derived output's label. Raising it is label;
// lowering it, also below its lineage maximum, is relabel, which a policy
// may make subject to an approval (LAB-004, DRV-007). It is never set
// below the bucket's floor.
func (s *Service) SetDerivedLabel(ctx context.Context, c Caller, bucketName, key, label string) (LabelOutcome, error) {
	output, _, err := s.derivedTarget(ctx, c.Tenant, bucketName, key, "")
	if err != nil {
		return LabelOutcome{}, err
	}
	return s.labelResource(ctx, c, bucketName, "document.derived", output.String(), registry.RoleOutput, registry.OpDerivedLabel,
		registry.OpDerivedRelabel, map[string]string{"bucket": bucketName, "key": key}, label)
}

// labelResource loads a resource and its bucket and sets its label.
func (s *Service) labelResource(ctx context.Context, c Caller, bucketName, typ, id, role, labelOp, relabelOp string, details map[string]string,
	label string) (LabelOutcome, error) {
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return LabelOutcome{}, err
	}
	r, err := s.d.Catalog.GetResource(ctx, c.Tenant, id)
	if err != nil || r.Type != typ {
		return LabelOutcome{}, ErrNotFound
	}
	return s.setLabel(ctx, c, labelTarget{typ: typ, id: id, bucket: b, attrs: r.Attributes, meta: r.MetadataRevision, role: role,
		labelOp: labelOp, relabelOp: relabelOp, details: details}, label)
}

// labelTarget is a resource whose protected label is set.
type labelTarget struct {
	typ, id            string
	bucket             bucket
	attrs              map[string]any
	meta               uint64
	role               string
	labelOp, relabelOp string
	details            map[string]string
}

// setLabel sets t's protected label (LAB-002, LAB-004): raising it, or
// setting the same label, needs label; lowering it needs relabel, which a
// policy may make subject to an approval. A label is never set outside the
// order or below the bucket's floor. The change advances the resource's
// metadata revision, so every decision and lease bound to the old one
// fails (LAB-005); ciphertext and envelopes are unchanged.
func (s *Service) setLabel(ctx context.Context, c Caller, t labelTarget, label string) (LabelOutcome, error) {
	if len(label) > 64 {
		return LabelOutcome{}, ErrInvalid
	}
	orderGen, order, err := catalog.LabelOrder(ctx, s.d.Catalog.Pool(), false)
	if errors.Is(err, catalog.ErrNoLabelOrder) {
		return LabelOutcome{}, fmt.Errorf("%w: no label order is active", ErrInvalid)
	}
	if err != nil {
		return LabelOutcome{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := checkLabel(order, label, t.bucket.Label); err != nil {
		return LabelOutcome{}, err
	}
	previous, _ := t.attrs["label"].(string)
	newRank, _ := labels.Rank(order, label)
	oldRank, _ := labels.Rank(order, previous)
	op, action := t.labelOp, "label"
	if newRank < oldRank {
		op, action = t.relabelOp, "relabel"
	}
	rec, err := s.decidePlanned(ctx, c, op,
		[]check{{id: t.role, role: t.role, action: action, ref: planned(registry.ChangeLabel, t.id+"|"+label)}},
		opplan.Summary{Action: action, Targets: []opplan.Target{{Role: t.role, Type: t.typ, ID: t.id}},
			Changes: map[string]string{"label": label, "previous_label": previous}, Details: details(t.details)})
	if err != nil {
		return LabelOutcome{}, err
	}
	out := LabelOutcome{Object: t.id, Label: label, Previous: previous, MetadataRevision: t.meta}
	err = s.fenced(ctx, rec, []string{t.id}, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.labelOrderHolds(ctx, tx, rec, label, t.bucket.ID); err != nil {
			return err
		}
		// The change was classified as label or relabel from the label and
		// the order read before the decision; both must still hold, or a
		// raise in between would let a lowering pass as label (review v3
		// F01). The fence holds the resource row for update.
		var current string
		if err := tx.QueryRow(ctx, `SELECT coalesce(attributes->>'label', '') FROM resources WHERE tenant = $1 AND id = $2`,
			c.Tenant, t.id).Scan(&current); err != nil {
			return err
		}
		if current != previous || orderGen != rec.Context.LabelOrderGeneration {
			return fmt.Errorf("%w: the label changed since the request was classified", ErrConflict)
		}
		if label == previous {
			return nil
		}
		meta, err := catalog.SetLabel(ctx, tx, c.Tenant, t.typ, t.id, label)
		if err != nil {
			return err
		}
		out.MetadataRevision = meta
		outcome := "LABEL_RAISED"
		if action == "relabel" {
			outcome = "RELABELED"
		}
		// Labels are not written to the audit record (AUD-003); the
		// resource's metadata revision identifies the change.
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, outcome, audit.Target{Type: t.typ, ID: t.id, Generation: meta}))
	})
	if err != nil {
		return LabelOutcome{}, err
	}
	return out, nil
}

// ProposeLabel records a client classifier's label proposal for a key
// (LAB-002 source 3). It needs propose-label, is always advisory and never
// changes the label or any revision (V-147); a principal applies it with
// SetLabel.
func (s *Service) ProposeLabel(ctx context.Context, c Caller, bucketName, key, label, classifier string) (catalog.Proposal, error) {
	if label == "" || len(label) > 64 || classifier == "" || len(classifier) > 128 {
		return catalog.Proposal{}, ErrInvalid
	}
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return catalog.Proposal{}, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, key)
	if err != nil {
		return catalog.Proposal{}, err
	}
	_, rec, err := s.decide(ctx, c, registry.OpProposeLabel, Audience, true,
		[]check{{id: "object", role: registry.RoleObject, action: "propose-label", ref: canonical("storage.object", o.ID.String())}})
	if err != nil {
		return catalog.Proposal{}, err
	}
	var p catalog.Proposal
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		p, err = catalog.AddProposal(ctx, tx, c.Tenant, catalog.Proposal{ResourceType: "storage.object", ResourceID: o.ID.String(),
			Label: label, Classifier: classifier, Proposer: c.Principal, CreatedAt: s.d.Now()})
		if err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "LABEL_PROPOSED",
			audit.Target{Type: "storage.object", ID: o.ID.String(), Generation: o.Generation}))
	})
	return p, err
}
