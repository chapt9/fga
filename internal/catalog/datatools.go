package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"fga/internal/registry"
)

// Data tools (docs/design/mcp-data-tools.md, DTL-001), reviewed records
// (records.go) over one source each. A review registers the tool as the
// agent.tool resource "mcp.tool:<name>", aliased as <name> in namespace
// mcp.tool, where policy decides discover and invoke on it. Data tools
// grant nothing, so their changes are audited and not journaled.

// DataTool is a data tool with its source's bucket mode and its active
// and draft versions.
type DataTool struct {
	Name       string         `json:"name"`
	Source     string         `json:"source"`
	Encryption string         `json:"encryption"`
	Disabled   bool           `json:"disabled"`
	CreatedAt  time.Time      `json:"created_at"`
	Active     *RecordVersion `json:"active,omitempty"`
	Draft      *RecordVersion `json:"draft,omitempty"`
}

// CreateDataTool creates a data tool over source with its draft version 1.
func (a *Admin) CreateDataTool(ctx context.Context, tenant, name, source string, definition []byte, digest, author string, now time.Time) error {
	if _, err := a.tx.Exec(ctx, `INSERT INTO data_tools (tenant, id, source, disabled, created_at) VALUES ($1, $2, $3, false, $4)`,
		tenant, name, source, now); err != nil {
		return err
	}
	return toolRecords.insertDraft(ctx, a.tx, tenant, name, 1, definition, digest, author, now)
}

// PutDataToolDraft adds a data tool's next version as its draft.
func (a *Admin) PutDataToolDraft(ctx context.Context, tenant, name string, definition []byte, digest, author string, now time.Time) (int, error) {
	return toolRecords.putDraft(ctx, a.tx, tenant, name, definition, digest, author, now)
}

// ReviewDataTool makes the draft a review names a data tool's active
// version (records.reviewable) and registers its resource with attrs,
// which policy sees. A registration that existed advances its generation
// and metadata revision, so a decision made under the earlier one fails at
// its fence.
func (a *Admin) ReviewDataTool(ctx context.Context, tenant, name string, version int, digest, reviewer string, allowSelf bool,
	attrs map[string]any, now time.Time) (RecordVersion, error) {
	v, err := toolRecords.reviewable(ctx, a.tx, tenant, name, version, digest, reviewer, allowSelf)
	if err != nil {
		return RecordVersion{}, err
	}
	if err := toolRecords.activate(ctx, a.tx, tenant, name, version, reviewer, now); err != nil {
		return RecordVersion{}, err
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return RecordVersion{}, err
	}
	rid := registry.MCPToolNamespace + ":" + name
	tag, err := a.tx.Exec(ctx, `
		INSERT INTO resources VALUES ($1, $2, 'agent.tool', '', 1, 1, 1, $3)
		ON CONFLICT (tenant, id) DO UPDATE SET attributes = EXCLUDED.attributes,
		       generation = resources.generation + 1, metadata_revision = resources.metadata_revision + 1
		 WHERE resources.type = 'agent.tool' AND resources.attributes->>'kind' = 'data'`, tenant, rid, raw)
	if err != nil {
		return RecordVersion{}, err
	}
	if tag.RowsAffected() != 1 {
		return RecordVersion{}, fmt.Errorf("catalog: %s is another tool", rid)
	}
	if _, err := a.tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		tenant, registry.MCPToolNamespace, name, rid); err != nil {
		return RecordVersion{}, err
	}
	v.State, v.Reviewer, v.ReviewedAt = "ACTIVE", reviewer, &now
	return v, nil
}

// DisableDataTool disables a data tool: its resource's attribute active
// becomes false and its generation advances, and listings and calls no
// longer see it. An unknown tool is refused and a disabled one left as it
// is; a disable is final.
func (a *Admin) DisableDataTool(ctx context.Context, tenant, name string) error {
	disabled, err := toolRecords.lock(ctx, a.tx, tenant, name)
	if err != nil || disabled {
		return err
	}
	if _, err := a.tx.Exec(ctx, `UPDATE data_tools SET disabled = true WHERE tenant = $1 AND id = $2`, tenant, name); err != nil {
		return err
	}
	_, err = a.tx.Exec(ctx, `UPDATE resources SET attributes = attributes || '{"active": false}',
	                         generation = generation + 1, metadata_revision = metadata_revision + 1
	                         WHERE tenant = $1 AND id = $2 AND type = 'agent.tool'`, tenant, registry.MCPToolNamespace+":"+name)
	return err
}

// DataTool returns a data tool with its active and draft versions.
func (s *Store) DataTool(ctx context.Context, tenant, name string) (DataTool, error) {
	list, err := s.dataTools(ctx, tenant, name, "", "", 1)
	if err != nil {
		return DataTool{}, err
	}
	if len(list) == 0 {
		return DataTool{}, ErrNoRow
	}
	return list[0], nil
}

// ListDataTools returns a page of a tenant's data tools in name order;
// source, when set, keeps the tools over that source.
func (s *Store) ListDataTools(ctx context.Context, tenant, source, after string, limit int) ([]DataTool, error) {
	return s.dataTools(ctx, tenant, "", source, after, limit)
}

func (s *Store) dataTools(ctx context.Context, tenant, only, source, after string, limit int) ([]DataTool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.source, b.encryption, t.disabled, t.created_at
		  FROM data_tools t JOIN sources s ON s.tenant = t.tenant AND s.id = t.source JOIN buckets b ON b.tenant = s.tenant AND b.id = s.bucket
		 WHERE t.tenant = $1 AND ($2::text = '' OR t.id = $2::text) AND ($3::text = '' OR t.source = $3::text) AND t.id > $4::text
		 ORDER BY t.id LIMIT $5`, tenant, only, source, after, limit)
	if err != nil {
		return nil, err
	}
	out := []DataTool{}
	for rows.Next() {
		var t DataTool
		if err := rows.Scan(&t.Name, &t.Source, &t.Encryption, &t.Disabled, &t.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Active, out[i].Draft, err = toolRecords.current(ctx, s.pool, tenant, out[i].Name); err != nil {
			return nil, err
		}
	}
	return out, nil
}
