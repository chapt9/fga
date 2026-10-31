package catalog

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/cryptowire"
	"fga/internal/labels"
	"fga/internal/registry"
)

// ErrNoLabelOrder means no release with a label order is active, so no
// label can be set or changed (FLW-004).
var ErrNoLabelOrder = errors.New("catalog: no label order is active")

// SetLabelOrder publishes the label order of the release the decision role
// activated (D-06). An order is immutable within its generation; reusing a
// generation for another order is refused. Generation 0 (no order) clears
// the active order.
func (s *Store) SetLabelOrder(ctx context.Context, generation uint64, order []string) error {
	if generation == 0 {
		_, err := s.pool.Exec(ctx, `DELETE FROM label_order_active`)
		return err
	}
	if !labels.Valid(order) {
		return fmt.Errorf("catalog: invalid label order %q", order)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO label_orders VALUES ($1, $2) ON CONFLICT DO NOTHING`, generation, order); err != nil {
			return err
		}
		var stored []string
		if err := tx.QueryRow(ctx, `SELECT labels FROM label_orders WHERE generation = $1`, generation).Scan(&stored); err != nil {
			return err
		}
		if !slices.Equal(stored, order) {
			return fmt.Errorf("catalog: label generation %d already names another order", generation)
		}
		_, err := tx.Exec(ctx, `INSERT INTO label_order_active VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET generation = excluded.generation`, generation)
		return err
	})
}

// LabelOrder returns the active label order and its generation, read with
// a share lock when q is a transaction that must hold it. Without an
// active order it returns ErrNoLabelOrder.
func LabelOrder(ctx context.Context, q Querier, lock bool) (uint64, []string, error) {
	sql := `SELECT o.generation, o.labels FROM label_order_active a JOIN label_orders o ON o.generation = a.generation`
	if lock {
		sql += ` FOR SHARE OF a`
	}
	var generation uint64
	var order []string
	err := q.QueryRow(ctx, sql).Scan(&generation, &order)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrNoLabelOrder
	}
	return generation, order, err
}

// LabelFloor returns the floor of an object's label: its bucket's default
// label (LAB-003, D-06).
func LabelFloor(ctx context.Context, q Querier, tenant, object string) (string, error) {
	var floor string
	err := q.QueryRow(ctx, `SELECT b.default_label FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
	                         WHERE o.tenant = $1 AND o.id::text = $2`, tenant, object).Scan(&floor)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", registry.ErrUnknownResource
	}
	return floor, err
}

// SetLabel stores a resource's new protected label and advances its
// metadata revision (its access revision, LAB-005) inside tx, and returns
// the new revision.
func SetLabel(ctx context.Context, tx pgx.Tx, tenant, typ, id, label string) (uint64, error) {
	var meta uint64
	err := tx.QueryRow(ctx, `UPDATE resources SET attributes = attributes || jsonb_build_object('label', $4::text),
	                                metadata_revision = metadata_revision + 1
	                          WHERE tenant = $1 AND type = $2 AND id = $3 RETURNING metadata_revision`, tenant, typ, id, label).Scan(&meta)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, registry.ErrUnknownResource
	}
	return meta, err
}

// Proposal is an advisory label proposal (LAB-002 source 3).
type Proposal struct {
	ID            string    `json:"proposal_id"`
	ResourceType  string    `json:"resource_type"`
	ResourceID    string    `json:"resource_id"`
	Label         string    `json:"label"`
	Classifier    string    `json:"classifier"`
	Proposer      string    `json:"proposer"`
	Authoritative bool      `json:"authoritative"`
	CreatedAt     time.Time `json:"created_at"`
}

// AddProposal records an advisory proposal inside tx. It never changes the
// label or the resource's revisions (V-147).
func AddProposal(ctx context.Context, tx pgx.Tx, tenant string, p Proposal) (Proposal, error) {
	p.ID, p.Authoritative = cryptowire.NewUUID().String(), false
	_, err := tx.Exec(ctx, `INSERT INTO label_proposals (tenant, id, resource_type, resource_id, label, classifier, proposer, created_at)
	                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tenant, p.ID, p.ResourceType, p.ResourceID, p.Label, p.Classifier, p.Proposer, p.CreatedAt)
	return p, err
}

var _ registry.Changer = resourceView{}

// Changed implements registry.Changer: a proposed label for an existing
// object, document unit or derived output resolves to it as it is, with
// new_label and floor added; a proposed encryption mode for a bucket
// resolves to the bucket with new_encryption added.
func (v resourceView) Changed(ctx context.Context, tenant string, alias registry.Alias) (registry.Resource, error) {
	if alias.Namespace == registry.ChangeEncryption {
		return v.changedEncryption(ctx, tenant, alias)
	}
	if alias.Namespace != registry.ChangeLabel {
		return registry.Resource{}, registry.ErrUnknownAlias
	}
	id, label, ok := strings.Cut(alias.Name, "|")
	if !ok || id == "" || label == "" {
		return registry.Resource{}, registry.ErrUnknownAlias
	}
	r, err := v.s.GetResource(ctx, tenant, id)
	if err != nil {
		return registry.Resource{}, err
	}
	if r.Type != "storage.object" && r.Type != "document.text_unit" && r.Type != "document.derived" {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	floor, err := LabelFloor(ctx, v.s.pool, tenant, id)
	if err != nil {
		return registry.Resource{}, err
	}
	attrs := make(map[string]any, len(r.Attributes)+2)
	for k, val := range r.Attributes {
		attrs[k] = val
	}
	attrs["new_label"], attrs["floor"] = label, floor
	r.Attributes = attrs
	return r, nil
}
