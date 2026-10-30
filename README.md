# fga: Fine-Grained Access Platform

An implementation of the Fine-Grained Access Platform specification 2.2 (draft), which is kept in [docs/spec](docs/spec) together with its test vectors and consistency check. `fga` is a placeholder name (decision D-11).

The policy engine and the object storage are our own code. MinIO and Cerbos are studied for ideas only (decisions D-01 to D-03 in [docs/decisions](docs/decisions)). Everything runs locally.

## Status

Release R1, phase A (decision core) is implemented:

| Package | What it does | Specification |
|---|---|---|
| `internal/policy/format` | Policy format `fga.policy/v1`, strict parsing and bundle validation | POL-002, POL-007, POL-014 |
| `internal/policy/engine` | CEL policy engine: deny overrides, deny-only ceiling set, strict errors, cost limit | Section 1.4.2, POL-005, POL-009 |
| `internal/decision` | Batch decision: gate, then ceiling, then business; only an explicit allow counts | POL-003, DEC-002 to DEC-004 |
| `internal/gate` | Envelope checks, principal from authoritative state, admission and commit rechecks | ID-002, ID-004, DLG-*, DEC-005, DEC-006 |
| `internal/delegation` | Delegation chains: narrowing, expiry, revocation, audience | DLG-001 to DLG-007 |
| `internal/identity` | Identities with revisions | ID-003, ID-004 |
| `internal/registry` | Resource types and actions, aliases to canonical resources, operation mapping | RES-001 to RES-008 |
| `internal/release` | Signed policy bundles, activation states, required epochs | REL-001 to REL-005 |
| `internal/signing` | Signed decisions (detached JWS), single-use consumption, key rotation | DEC-008, DEC-011, DEC-012 |
| `internal/audit` | Audit outbox that refuses rather than drops | AUD-001 to AUD-003 |
| `internal/catalog` | PostgreSQL authority for all of the above | DAT-001 to DAT-004 |
| `internal/decisionsvc` | DecideBatch service and HTTP/JSON API | DEC-001, DEC-007 |
| `cmd/fga-decision` | Decision role binary: strict config and import allowlist | MOD-003, MOD-004 |
| `cmd/fga` | Key generation, and bundle validation and signing | REL-001 |

**Not built yet:**
- R1-B: tool executor, approvals, reservations, invocation state.
- R1-C: content service, our single-node object store, documents, labels, disclosure, MCP.
- R2: key custody. R3: S3 API and replication.
- A control API for writing identities, delegations and resources. For now they are seeded with SQL.

Supporting records:
- Mechanism matrix (what was taken from MinIO and Cerbos): [docs/research/mechanism-matrix.md](docs/research/mechanism-matrix.md)
- Dependency records: [docs/dependencies](docs/dependencies)

## Checks

Requires Go 1.27.3 and, for `check-pg`, a local PostgreSQL (Homebrew `postgresql@18`).

```bash
make check
```

```bash
make check-pg
```

```bash
make spec
```

- `make check` runs gofmt, `go vet` and `go test -race`.
- `make check-pg` adds the PostgreSQL-backed tests, each in a throwaway schema.
- `make spec` runs the specification consistency check.

## Run locally

The `.local/` directory is ignored by git and holds keys, the signed bundle and the configuration.

1. Build the binaries and generate a publisher key and a decision-signing key:

   ```bash
   mkdir -p .local/bin && go build -o .local/bin/ ./cmd/...
   ```

   ```bash
   .local/bin/fga keys generate -out .local/publisher && .local/bin/fga keys generate -out .local/decision
   ```

2. Copy the example bundle, validate it and sign it as epoch 1:

   ```bash
   cp -R examples/local/bundle .local/bundle && .local/bin/fga policy validate .local/bundle
   ```

   ```bash
   .local/bin/fga policy sign -key .local/publisher.key -key-id publisher-1 -epoch 1 .local/bundle
   ```

3. Create the database:

   ```bash
   createdb -h localhost fga_local
   ```

4. Write `.local/decision.json`. The development profile without TLS listens on loopback only:

   ```json
   {"version": 1, "profile": "development", "listen": "127.0.0.1:7443", "dev_adapter_id": "local-dev",
    "database_url": "postgres://localhost:5432/fga_local?sslmode=disable", "bundle_dir": ".local/bundle",
    "publisher_keys": {"publisher-1": "<contents of .local/publisher.pub>"},
    "signing_key_file": ".local/decision.key", "signing_key_id": "decision-1",
    "audiences": ["storage"], "decision_max_age": "30s", "outbox_capacity": 1000}
   ```

5. Start the service. It migrates the schema on start:

   ```bash
   .local/bin/fga-decision -config .local/decision.json
   ```

6. In another terminal, load the example tenant and ask for a decision:

   ```bash
   psql -h localhost -d fga_local -f examples/local/seed.sql
   ```

   ```bash
   curl -s -X POST --data @examples/local/request.json http://127.0.0.1:7443/v1/decide-batch
   ```

The example request reads a LIVE unit and returns `ALLOW` with a signed decision. Change its resource to `doc://q3#draft` and the ceiling denies it.
