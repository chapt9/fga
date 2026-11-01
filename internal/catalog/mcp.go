package catalog

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"fga/internal/registry"
)

// EnableMCP registers the MCP service's tools for a tenant (MCP-003): each
// is an agent.tool resource, named by its alias in the mcp.tool namespace,
// which policy allows to discover and invoke. A tenant without them has
// no MCP access, whatever its content permissions (default deny). It is
// idempotent.
func (s *Store) EnableMCP(ctx context.Context, tenant string) error {
	return enableMCP(ctx, s.pool, tenant)
}

func enableMCP(ctx context.Context, q db, tenant string) error {
	return pgx.BeginFunc(ctx, q, func(tx pgx.Tx) error {
		for _, name := range registry.MCPTools {
			id := registry.MCPToolNamespace + ":" + name
			attrs, _ := json.Marshal(map[string]any{"name": name, "kind": "mcp"})
			if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'agent.tool', '', 1, 1, 1, $3) ON CONFLICT DO NOTHING`,
				tenant, id, attrs); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
				tenant, registry.MCPToolNamespace, name, id); err != nil {
				return err
			}
		}
		return nil
	})
}
