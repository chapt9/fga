package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/blob"
	"fga/internal/cryptowire"
)

// Reclaimed reports a reclamation run.
type Reclaimed struct {
	Retired int
	Aborted int
	// KeysDestroyed counts the sealed server-mode data keys removed from
	// the catalog at At: of retired versions, and of aborted uploads. A
	// backup taken before At still holds them, so that content stays
	// recoverable until every such backup is gone (SSE-006).
	KeysDestroyed int
	At            time.Time
}

// Reclaim removes the blobs of withdrawn versions and of expired uploads
// (PUB-005, PUB-006). Each removal is decided from catalog identity under a
// row lock, never from file age or a backend listing, and is idempotent.
// Retiring a server-mode version destroys its sealed data key and records
// when, and the sealed keys of aborted uploads are destroyed too
// (SSE-006).
func Reclaim(ctx context.Context, pool *pgxpool.Pool, blobs *blob.Store, now time.Time) (Reclaimed, error) {
	out := Reclaimed{At: now}
	type item struct {
		tenant                  string
		tenantID, version, blob cryptowire.UUID
	}
	collect := func(sql string, args ...any) ([]item, error) {
		rows, err := pool.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.tenant, &it.tenantID, &it.version, &it.blob); err != nil {
				return nil, err
			}
			items = append(items, it)
		}
		return items, rows.Err()
	}
	retirements, err := collect(`SELECT r.tenant, t.id, r.version, r.blob FROM retirements r JOIN tenants t ON t.name = r.tenant WHERE r.done_at IS NULL`)
	if err != nil {
		return out, err
	}
	for _, it := range retirements {
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var state string
			if err := tx.QueryRow(ctx, `SELECT state FROM object_versions WHERE tenant = $1 AND id = $2 FOR UPDATE`, it.tenant, it.version).Scan(&state); err != nil {
				return err
			}
			if state != "WITHDRAWN" {
				return errSkip
			}
			// A unit version a LIVE document version references keeps its
			// ciphertext (DOC-002, V-064).
			var referenced bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM document_units u JOIN document_versions d ON d.tenant = u.tenant AND d.id = u.document_version
			                                            WHERE u.tenant = $1 AND u.unit_version = $2 AND d.state = 'LIVE' FOR SHARE OF d)`,
				it.tenant, it.version).Scan(&referenced); err != nil {
				return err
			}
			if referenced {
				return errSkip
			}
			if err := blobs.Remove(blob.Ref{Tenant: it.tenantID, Blob: it.blob}); err != nil {
				return err
			}
			var destroyed bool
			if err := tx.QueryRow(ctx, `UPDATE object_versions SET state = 'RETIRED', sealed_key = NULL, kek_version = NULL,
			                                   key_destroyed_at = CASE WHEN sealed_key IS NULL THEN NULL ELSE $3::timestamptz END
			                             WHERE tenant = $1 AND id = $2 RETURNING key_destroyed_at IS NOT NULL`, it.tenant, it.version, now).
				Scan(&destroyed); err != nil {
				return err
			}
			if destroyed {
				out.KeysDestroyed++
			}
			// The upload intent kept a copy of the sealed key.
			if _, err := tx.Exec(ctx, `UPDATE upload_intents SET sealed_key = NULL, kek_version = NULL
			                            WHERE tenant = $1 AND version = $2 AND sealed_key IS NOT NULL`, it.tenant, it.version); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE retirements SET done_at = $3 WHERE tenant = $1 AND version = $2`, it.tenant, it.version, now)
			return err
		})
		switch {
		case errors.Is(err, errSkip):
		case err != nil:
			return out, err
		default:
			out.Retired++
		}
	}
	expired, err := collect(`SELECT i.tenant, t.id, i.version, i.blob FROM upload_intents i JOIN tenants t ON t.name = i.tenant
	                          WHERE i.state IN ('RESERVED', 'STAGED') AND i.expires_at <= $1`, now)
	if err != nil {
		return out, err
	}
	for _, it := range expired {
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'ABORTED'
			                           WHERE tenant = $1 AND version = $2 AND state IN ('RESERVED', 'STAGED') AND expires_at <= $3`,
				it.tenant, it.version, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errSkip
			}
			// An unpublished intent's blob is referenced by no version.
			return blobs.Remove(blob.Ref{Tenant: it.tenantID, Blob: it.blob})
		})
		switch {
		case errors.Is(err, errSkip):
		case err != nil:
			return out, err
		default:
			out.Aborted++
		}
	}
	// An aborted upload's data key protects nothing, and a committed
	// upload's copy duplicates its version's (SSE-004).
	tag, err := pool.Exec(ctx, `UPDATE upload_intents SET sealed_key = NULL, kek_version = NULL
	                             WHERE state = 'ABORTED' AND sealed_key IS NOT NULL`)
	if err != nil {
		return out, err
	}
	out.KeysDestroyed += int(tag.RowsAffected())
	if _, err := pool.Exec(ctx, `UPDATE upload_intents SET sealed_key = NULL, kek_version = NULL
	                              WHERE state = 'COMMITTED' AND sealed_key IS NOT NULL`); err != nil {
		return out, err
	}
	return out, nil
}

var errSkip = errors.New("skip")
