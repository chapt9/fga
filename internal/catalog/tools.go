package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"fga/internal/registry"
)

// RegisterTool records a reviewed tool for a tenant (AGT-001): its
// agent.tool resource "tool:<id>", aliased in registry.ToolNamespace, and
// its invocation's operation with exactly its checks. A changed
// registration advances the resource's generation and metadata revision,
// so a decision made under the earlier one fails at its fence. op must be
// valid for the core types; attrs are the resource's attributes, which
// policy sees.
func (s *Store) RegisterTool(ctx context.Context, tenant, id string, op registry.Operation, attrs map[string]any) error {
	if _, err := registry.NewOperations(registry.CoreTypes(), []registry.Operation{op}); err != nil || op.Name != registry.ToolOperationPrefix+id {
		return fmt.Errorf("catalog: tool %q: operation %q is not valid: %v", id, op.Name, err)
	}
	checks, err := json.Marshal(op.Checks)
	if err != nil {
		return err
	}
	a, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	rid := registry.ToolOperationPrefix + id
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO resources VALUES ($1, $2, 'agent.tool', '', 1, 1, 1, $3)
			ON CONFLICT (tenant, id) DO UPDATE SET attributes = EXCLUDED.attributes,
			       generation = resources.generation + 1, metadata_revision = resources.metadata_revision + 1
			 WHERE resources.type = 'agent.tool'`, tenant, rid, a); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			tenant, registry.ToolNamespace, id, rid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO tool_operations VALUES ($1, $2, $3)
			ON CONFLICT (tenant, name) DO UPDATE SET checks = EXCLUDED.checks`, tenant, op.Name, checks)
		return err
	})
}

// RegisterDestination records a network.destination resource
// "destination:<id>", aliased in registry.DestinationNamespace, which
// policy allows to send to.
func (s *Store) RegisterDestination(ctx context.Context, tenant, id string, attrs map[string]any) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return RegisterDestinationTx(ctx, tx, tenant, id, attrs) })
}

// RegisterDestinationTx is RegisterDestination inside tx.
func RegisterDestinationTx(ctx context.Context, tx pgx.Tx, tenant, id string, attrs map[string]any) error {
	a, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	rid := registry.DestinationNamespace + ":" + id
	tag, err := tx.Exec(ctx, `
		INSERT INTO resources VALUES ($1, $2, 'network.destination', '', 1, 1, 1, $3)
		ON CONFLICT (tenant, id) DO UPDATE SET attributes = EXCLUDED.attributes,
		       generation = resources.generation + 1, metadata_revision = resources.metadata_revision + 1
		 WHERE resources.type = 'network.destination'`, tenant, rid, a)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("catalog: %s is another type of resource", rid)
	}
	_, err = tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		tenant, registry.DestinationNamespace, id, rid)
	return err
}

// ResourceAttributesTx returns a resource's attributes inside tx.
func ResourceAttributesTx(ctx context.Context, tx pgx.Tx, tenant, id string) (map[string]any, error) {
	var attrs map[string]any
	err := tx.QueryRow(ctx, `SELECT attributes FROM resources WHERE tenant = $1 AND id = $2 FOR SHARE`, tenant, id).Scan(&attrs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoRow
	}
	return attrs, err
}

// ToolOperation returns a tenant's registered tool operation, if any. The
// decision role decides it like a registered operation (DEC-001).
func (s *Store) ToolOperation(ctx context.Context, tenant, name string) (registry.Operation, bool, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT checks FROM tool_operations WHERE tenant = $1 AND name = $2`, tenant, name).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Operation{}, false, nil
	}
	if err != nil {
		return registry.Operation{}, false, err
	}
	op := registry.Operation{Name: name}
	if err := json.Unmarshal(raw, &op.Checks); err != nil {
		return registry.Operation{}, false, fmt.Errorf("catalog: tool operation %q: %w", name, err)
	}
	return op, true, nil
}
