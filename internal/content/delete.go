package content

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/registry"
)

// DeleteOutcome reports a deletion.
type DeleteOutcome struct {
	Version    string `json:"version_id"`
	State      string `json:"state"`
	Generation uint64 `json:"generation"`
}

// DeleteKey writes a delete marker as the current version (PUB-005). Older
// versions keep their state and stay readable with historical rights. A key
// whose current version is already a delete marker is left as it is.
func (s *Service) DeleteKey(ctx context.Context, c Caller, bucketName, key string) (DeleteOutcome, error) {
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return DeleteOutcome{}, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, key)
	if err != nil || o.Current == nil {
		return DeleteOutcome{}, ErrNotFound
	}
	_, rec, err := s.decide(ctx, c, registry.OpDelete, Audience, true,
		[]check{{id: "object", role: registry.RoleObject, action: "delete", ref: canonical("storage.object", o.ID.String())}})
	if err != nil {
		return DeleteOutcome{}, err
	}
	var out DeleteOutcome
	err = s.fenced(ctx, rec, []string{o.ID.String()}, func(ctx context.Context, tx pgx.Tx) error {
		var current *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_version FROM objects WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, o.ID).Scan(&current); err != nil {
			return err
		}
		cur, err := s.versionByID(ctx, tx, c.Tenant, *current, true)
		if err != nil {
			return err
		}
		if cur.DeleteMarker {
			out = DeleteOutcome{Version: cur.ID.String(), State: "DELETE_MARKER", Generation: o.Generation}
			return nil
		}
		marker, gen, err := s.writeMarker(ctx, tx, c.Tenant, o.ID)
		if err != nil {
			return err
		}
		out = DeleteOutcome{Version: marker.String(), State: "DELETE_MARKER", Generation: gen}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "DELETE_MARKER",
			audit.Target{Type: "storage.object", ID: o.ID.String(), Version: marker.String()}))
	})
	return out, err
}

// writeMarker makes a new delete marker the current version and advances
// the object's generation.
func (s *Service) writeMarker(ctx context.Context, tx pgx.Tx, tenant string, object cryptowire.UUID) (cryptowire.UUID, uint64, error) {
	marker := cryptowire.NewUUID()
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO object_versions (tenant, id, object, delete_marker, state, created_at, published_at)
	                            VALUES ($1, $2, $3, true, 'LIVE', $4, $4)`, tenant, marker, object, now); err != nil {
		return marker, 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE objects SET current_version = $3 WHERE tenant = $1 AND id = $2`, tenant, object, marker); err != nil {
		return marker, 0, err
	}
	var gen uint64
	err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2 RETURNING generation`,
		tenant, object.String()).Scan(&gen)
	return marker, gen, err
}

// DeleteVersion withdraws one exact version (PUB-005): it checks
// delete-version and the reference guard, moves LIVE to WITHDRAWN and
// schedules physical removal. Withdrawing the current version leaves a
// delete marker; it never restores an older version. There is no
// time-based retention in R1 (owner ruling 4).
func (s *Service) DeleteVersion(ctx context.Context, c Caller, bucketName, key, versionSel string) (DeleteOutcome, error) {
	_, o, v, _, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil || versionSel == "" {
		return DeleteOutcome{}, ErrNotFound
	}
	_, rec, err := s.decide(ctx, c, registry.OpDeleteVersion, Audience, true, []check{{id: "object", role: registry.RoleObject,
		action: "delete-version", ref: canonical("storage.object", o.ID.String()), version: v.ID.String()}})
	if err != nil {
		return DeleteOutcome{}, err
	}
	var out DeleteOutcome
	err = s.fenced(ctx, rec, []string{o.ID.String()}, func(ctx context.Context, tx pgx.Tx) error {
		var current *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_version FROM objects WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, o.ID).Scan(&current); err != nil {
			return err
		}
		locked, err := s.versionByID(ctx, tx, c.Tenant, v.ID, true)
		if err != nil {
			return err
		}
		if locked.State != "LIVE" {
			return ErrNotFound
		}
		// Reference guard: an open upload that names this version as its
		// expected current version keeps it.
		var referenced bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upload_intents WHERE tenant = $1 AND if_match = $2 AND state IN ('RESERVED', 'STAGED'))`,
			c.Tenant, ETag(v.ID)).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			return fmt.Errorf("%w: an open upload references the version", ErrConflict)
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE object_versions SET state = 'WITHDRAWN' WHERE tenant = $1 AND id = $2`, c.Tenant, v.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE envelopes SET status = 'RETIRED' WHERE tenant = $1 AND version = $2 AND status = 'ACTIVE'`, c.Tenant, v.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO retirements (tenant, version, blob, requested_at) VALUES ($1, $2, $3, $4)`,
			c.Tenant, v.ID, v.Blob, now); err != nil {
			return err
		}
		gen := o.Generation
		if current != nil && *current == v.ID {
			if _, gen, err = s.writeMarker(ctx, tx, c.Tenant, o.ID); err != nil {
				return err
			}
		} else if err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2 RETURNING generation`,
			c.Tenant, o.ID.String()).Scan(&gen); err != nil {
			return err
		}
		out = DeleteOutcome{Version: v.ID.String(), State: "WITHDRAWN", Generation: gen}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "WITHDRAWN",
			audit.Target{Type: "storage.object", ID: o.ID.String(), Version: v.ID.String(), Digest: v.SHA256}))
	})
	return out, err
}
