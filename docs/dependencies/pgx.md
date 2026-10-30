# Dependency record: pgx (LIB-002)

| Field | Record |
|---|---|
| Module | `github.com/jackc/pgx/v5` v5.11.0 (pinned in `go.mod` and `go.sum`) |
| Owner | Catalog (`internal/catalog`) |
| License | MIT, from the `LICENSE` file of the downloaded module. Notices are to be carried in `LICENSES/` before distribution. |
| Why | PostgreSQL driver and connection pool for the authoritative catalog (ADR-04, D-02). |
| Alternatives | `database/sql` with a driver: rejected, because pgx gives direct access to PostgreSQL types (arrays, jsonb) and pooling. `sqlc` remains a candidate for generating query bindings (SMALL-002). |
| Maintainers | Jack Christensen and contributors. |
| Advisories | None checked yet. `govulncheck` must run in CI before release (LIB-003). |
| Our evidence | `internal/catalog` tests against a local PostgreSQL 18 (`make check-pg`): tenant scoping, cross-tenant foreign keys, consumption exactly once across connections, outbox capacity and idempotency, and the gate wired to the catalog. |
| Transitive footprint | `github.com/jackc/puddle/v2` (pool), `github.com/jackc/pgpassfile`, `github.com/jackc/pgservicefile`, plus `golang.org/x/text` and `golang.org/x/sync`. |
| Replacement path | SQL is confined to `internal/catalog`; the other packages depend only on their store interfaces. |
