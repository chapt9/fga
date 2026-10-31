package catalog

import (
	"context"

	"fga/internal/cryptowire"
)

// TransitiveLineage returns every source in a derived version's transitive
// lineage, each once, following derived sources at most depth levels
// (DRV-002, DRV-009).
func TransitiveLineage(ctx context.Context, q Querier, tenant string, version cryptowire.UUID, depth int) ([]cryptowire.LineageSource, error) {
	rows, err := q.Query(ctx, `
		WITH RECURSIVE t(source_type, source_id, source_version, depth) AS (
		    SELECT source_type, source_id, source_version, 1 FROM lineage WHERE tenant = $1 AND derived_version = $2
		    UNION
		    SELECT l.source_type, l.source_id, l.source_version, t.depth + 1 FROM t
		      JOIN lineage l ON l.tenant = $1 AND l.derived_version = t.source_version
		     WHERE t.source_type = 'document.derived' AND t.depth < $3)
		SELECT DISTINCT source_type, source_id, source_version::text FROM t ORDER BY 1, 2, 3`, tenant, version, depth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cryptowire.LineageSource
	for rows.Next() {
		var src cryptowire.LineageSource
		if err := rows.Scan(&src.Type, &src.ID, &src.Version); err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}
