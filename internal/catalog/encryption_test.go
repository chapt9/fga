package catalog

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/pgtest"
)

// TestEncryptionModesMigration covers ENC-003: data published before
// encryption modes was client-encrypted, so migration 0015 puts existing
// buckets, open uploads and versions in client mode and shows the mode to
// policy; a delete marker gets none. New rows must name their mode.
func TestEncryptionModesMigration(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t, func(ctx context.Context, pool *pgxpool.Pool) error {
		before := fstest.MapFS{}
		names, err := fs.Glob(migrations, "migrations/*.sql")
		if err != nil {
			return err
		}
		for _, name := range names {
			if name < "migrations/0015" {
				data, err := fs.ReadFile(migrations, name)
				if err != nil {
					return err
				}
				before[name] = &fstest.MapFile{Data: data}
			}
		}
		return ApplyMigrations(ctx, pool, before, "migrations", "")
	})
	const (
		bucket  = "00000000-0000-0000-0000-0000000000b1"
		object  = "00000000-0000-0000-0000-0000000000c1"
		version = "00000000-0000-0000-0000-0000000000d1"
		marker  = "00000000-0000-0000-0000-0000000000d2"
	)
	for _, stmt := range []string{
		`INSERT INTO tenants VALUES ('t-acme', '00000000-0000-0000-0000-0000000000a1')`,
		`INSERT INTO buckets (tenant, id, name, default_project, default_label) VALUES ('t-acme', '` + bucket + `', 'reports', 'p1', 'internal')`,
		`INSERT INTO resources VALUES ('t-acme', '` + bucket + `', 'storage.bucket', '', 1, 1, 1, '{"name":"reports"}')`,
		`INSERT INTO objects (tenant, id, bucket, key) VALUES ('t-acme', '` + object + `', '` + bucket + `', 'a.txt')`,
		`INSERT INTO resources VALUES ('t-acme', '` + object + `', 'storage.object', '', 1, 2, 1, '{"owner":"alice"}')`,
		`INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
		                             signer, descriptor, created_at)
		 VALUES ('t-acme', '` + version + `', '` + object + `', gen_random_uuid(), gen_random_uuid(), 'LIVE', 10, 'sha256:x', 1, 1, 'fp', 'd', now())`,
		`INSERT INTO object_versions (tenant, id, object, delete_marker, state, created_at)
		 VALUES ('t-acme', '` + marker + `', '` + object + `', true, 'LIVE', now())`,
		`INSERT INTO upload_intents (tenant, id, principal, actor, idempotency_key, request_digest, bucket, key, object, new_object, version,
		                            crypto_version, blob, attempt, expected_generation, planned_scope, planned_attributes, state, expires_at, created_at)
		 VALUES ('t-acme', gen_random_uuid(), 'alice', 'alice', 'k1', 'd', '` + bucket + `', 'b.txt', gen_random_uuid(), true, gen_random_uuid(),
		         gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 0, '', '{"owner":"alice"}', 'RESERVED', now(), now())`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var bucketMode, intentMode, intentAttr, versionMode string
	var markerMode *string
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT encryption FROM buckets), (SELECT encryption FROM upload_intents), (SELECT planned_attributes->>'encryption' FROM upload_intents),
		(SELECT encryption FROM object_versions WHERE id = '`+version+`'), (SELECT encryption FROM object_versions WHERE id = '`+marker+`')`).
		Scan(&bucketMode, &intentMode, &intentAttr, &versionMode, &markerMode); err != nil {
		t.Fatal(err)
	}
	if bucketMode != "client" || intentMode != "client" || intentAttr != "client" || versionMode != "client" || markerMode != nil {
		t.Fatalf("after migration: bucket %q, intent %q (planned %q), version %q, marker %v", bucketMode, intentMode, intentAttr, versionMode, markerMode)
	}
	for _, id := range []string{bucket, object} {
		var mode string
		if err := pool.QueryRow(ctx, `SELECT attributes->>'encryption' FROM resources WHERE id = $1`, id).Scan(&mode); err != nil || mode != "client" {
			t.Fatalf("resource %s shows %q to policy: %v", id, mode, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO buckets (tenant, id, name) VALUES ('t-acme', gen_random_uuid(), 'other')`); err == nil {
		t.Fatal("a bucket was created without naming its mode")
	}
}
