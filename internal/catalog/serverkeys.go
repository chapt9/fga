package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/cryptowire"
)

// Server-mode key-encryption key versions (specification 2.6, SSE-002).
// The keys role's ring holds the keys; the catalog says which versions
// exist and which one seals new data keys. The catalog never sees a key:
// RotateKEK hands each sealed data key to a reseal function the caller
// supplies, so this package links no key-encryption code (MOD-004).

// SealedKey is one sealed data key: of a server-mode version or upload
// intent, with the identity it was sealed for.
type SealedKey struct {
	KEKVersion                                   uint32
	Sealed                                       []byte
	Tenant, Object, Version, CryptoVersion, Blob cryptowire.UUID
}

// RotateKEK makes version the tenant's ACTIVE key-encryption key and
// reseals every sealed data key of the tenant under it, in one
// transaction (SSE-002). It locks the tenant's versions first, so the keys
// role seals no data key under the old version while they change. Earlier
// versions become RETIRED; ciphertext is unchanged. It returns how many
// keys were resealed.
func (s *Store) RotateKEK(ctx context.Context, tenant string, version uint32, now time.Time,
	reseal func(SealedKey) ([]byte, error)) (int, error) {
	if _, err := s.EnsureTenant(ctx, tenant); err != nil {
		return 0, err
	}
	n := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT version FROM kek_versions WHERE tenant = $1 FOR UPDATE`, tenant)
		if err != nil {
			return err
		}
		var newest uint32
		for rows.Next() {
			var v uint32
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return err
			}
			newest = max(newest, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if version <= newest {
			return fmt.Errorf("catalog: KEK version %d is not newer than %d", version, newest)
		}
		if _, err := tx.Exec(ctx, `UPDATE kek_versions SET state = 'RETIRED' WHERE tenant = $1 AND state = 'ACTIVE'`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO kek_versions (tenant, version, state, created_at) VALUES ($1, $2, 'ACTIVE', $3)`,
			tenant, int64(version), now); err != nil {
			return err
		}
		for _, q := range []struct{ table, version string }{{"object_versions", "x.id"}, {"upload_intents", "x.version"}} {
			rows, err := tx.Query(ctx, `
				SELECT x.id, x.kek_version, x.sealed_key, t.id, x.object, `+q.version+`, x.crypto_version, x.blob
				  FROM `+q.table+` x JOIN tenants t ON t.name = x.tenant
				 WHERE x.tenant = $1 AND x.sealed_key IS NOT NULL
				 FOR UPDATE OF x`, tenant)
			if err != nil {
				return err
			}
			type row struct {
				id cryptowire.UUID
				k  SealedKey
			}
			var all []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.k.KEKVersion, &r.k.Sealed, &r.k.Tenant, &r.k.Object, &r.k.Version, &r.k.CryptoVersion,
					&r.k.Blob); err != nil {
					rows.Close()
					return err
				}
				all = append(all, r)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range all {
				sealed, err := reseal(r.k)
				if err != nil {
					return fmt.Errorf("catalog: resealing a data key of %s: %w", q.table, err)
				}
				if _, err := tx.Exec(ctx, `UPDATE `+q.table+` SET sealed_key = $3, kek_version = $4 WHERE tenant = $1 AND id = $2`,
					tenant, r.id, sealed, int64(version)); err != nil {
					return err
				}
				n++
			}
		}
		return nil
	})
	return n, err
}
