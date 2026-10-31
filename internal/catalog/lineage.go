package catalog

import (
	"context"
	"fmt"

	"fga/internal/cryptowire"
	"fga/internal/signing"
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

// Dependencies returns a derived version's transitive lineage with each
// source's current generation and metadata revision, for a decision that
// depends on the sources without deciding them (DRV-009).
func (s *Store) Dependencies(ctx context.Context, tenant, version string) ([]signing.Dependency, error) {
	v, err := cryptowire.ParseUUID(version)
	if err != nil {
		return nil, err
	}
	sources, err := TransitiveLineage(ctx, s.pool, tenant, v, 32)
	if err != nil {
		return nil, err
	}
	out := make([]signing.Dependency, 0, len(sources))
	for _, src := range sources {
		d := signing.Dependency{ResourceType: src.Type, ResourceID: src.ID, Version: src.Version}
		if err := s.pool.QueryRow(ctx, `SELECT generation, metadata_revision FROM resources WHERE tenant = $1 AND id = $2 AND type = $3`,
			tenant, src.ID, src.Type).Scan(&d.Generation, &d.MetadataRevision); err != nil {
			return nil, fmt.Errorf("catalog: lineage source %s %s: %w", src.Type, src.ID, err)
		}
		out = append(out, d)
	}
	return out, nil
}
