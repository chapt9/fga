// Package keycheck verifies the further decisions that a key release needs
// besides its own: for an original file, the complete-content decisions,
// raw-read on the document version and read on every unit (CNT-003,
// review finding 3). The keys role admits their bindings in the same fence
// as the release, for a client-mode envelope (internal/envelope) and a
// server-mode data key (internal/datakeys) alike, so a change to any unit
// between the storage role's checks and the release blocks it.
package keycheck

import (
	"context"
	"errors"

	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/registry"
	"fga/internal/signing"
)

// ErrDecision means the further decisions do not authorize the release.
var ErrDecision = errors.New("keycheck: the decisions do not cover the release")

// CompleteContent verifies that extra are single-use document.raw-read
// decisions of primary's tenant and actor, each naming raw-read on
// documentVersion, that together name read on every unit version of that
// document version exactly once, and nothing else. It returns their fence
// bindings.
func CompleteContent(ctx context.Context, q catalog.Querier, v *signing.Verifier, primary signing.Record, documentVersion cryptowire.UUID,
	extra []signing.Signed) ([]fence.Binding, error) {
	members := map[string]string{}
	rows, err := q.Query(ctx, `SELECT unit::text, unit_version::text FROM document_units WHERE tenant = $1 AND document_version = $2`,
		primary.Tenant, documentVersion)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var unit, version string
		if err := rows.Scan(&unit, &version); err != nil {
			rows.Close()
			return nil, err
		}
		members[unit] = version
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	var out []fence.Binding
	for _, x := range extra {
		rec, err := v.Check(x)
		if err != nil || !rec.SingleUse || rec.Operation != registry.OpDocRawRead || rec.Tenant != primary.Tenant || rec.Actor != primary.Actor {
			return nil, ErrDecision
		}
		version := false
		for _, c := range rec.Checks {
			switch {
			case c.Kind != string(registry.KindOperation):
				return nil, ErrDecision
			case c.ResourceType == "document.version" && c.Action == "raw-read" && c.ResourceID == documentVersion.String():
				version = true
			case c.ResourceType == "document.text_unit" && c.Action == "read" && members[c.ResourceID] == c.Version && !covered[c.ResourceID]:
				covered[c.ResourceID] = true
			default:
				return nil, ErrDecision
			}
		}
		if !version {
			return nil, ErrDecision
		}
		b, err := fence.FromRecord(rec)
		if err != nil {
			return nil, ErrDecision
		}
		out = append(out, b)
	}
	if len(covered) != len(members) {
		return nil, ErrDecision
	}
	return out, nil
}
