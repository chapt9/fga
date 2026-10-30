// Package pgtest gives tests a migrated PostgreSQL schema of their own in the
// database named by FGA_TEST_DATABASE_URL, and skips them when it is unset.
package pgtest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool creates a fresh schema, applies migrate to it twice (the second run
// must be a no-op) and drops the schema when the test ends.
func Pool(t testing.TB, migrate func(context.Context, *pgxpool.Pool) error) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("FGA_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("FGA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_%d", time.Now().UnixNano())
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	for range 2 {
		if err := migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

// Exec runs fixture statements and fails the test on the first error.
func Exec(t testing.TB, pool *pgxpool.Pool, stmts ...string) {
	t.Helper()
	for _, stmt := range stmts {
		if _, err := pool.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}
