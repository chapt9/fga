# fga: Fine-Grained Access Platform

An implementation of the Fine-Grained Access Platform specification 2.5 (draft), which is kept in [docs/spec](docs/spec) with its handoff, errata, test vectors and consistency check. `fga` is a placeholder name (decision D-11).

The policy engine and the object storage are our own code. MinIO and Cerbos are studied for ideas only (decisions D-01 to D-03 in [docs/decisions](docs/decisions)); the [mechanism matrix](docs/research/mechanism-matrix.md) records what was taken and what was rejected. Everything runs locally.

## Status (31 October 2026)

Focus: object storage plus access control (R1). MCP (R2) comes after R1 is accepted.

- **R1-A, shared authority:** built, including the catch-up list of the [handoff](docs/spec/HANDOFF.md) (section 5).
- **R1-B, client-encrypted object storage:** built and running locally. That covers the storage and keys roles, the client SDK, the native API, backup, restore and reconcile.
- **R1-C:** in progress. Built so far:
  - default deny for every user action, key lookups included (ruling 7);
  - labels on storage objects (label order, ranks, label, relabel, advisory proposals);
  - approvals of storage operations;
  - document publication: client-side splitting into separately encrypted text units, signed manifest and unit descriptors (wire profile 2), batched decisions admitted together by the fence.

  The encrypted original file, disclosure of units, derived outputs, export and metadata search are not built yet.
- **R2 and R3:** not built.

**Nothing here is qualified (GATE-001).** No release manifest exists and no execution evidence is recorded. Passing tests and a passing smoke run are development evidence only.

| Area | Packages | Specification |
|---|---|---|
| Policy | `internal/policy/format`, `internal/policy/engine`: `fga.policy/v1`, deny overrides, deny-only ceiling set, strict errors, cost limit, `request.now` only against timestamp literals | "Policy format", POL-001 to POL-014 |
| Decisions | `internal/decision`, `internal/gate`, `internal/decisionsvc`, `cmd/fga-decision`. Check kinds with per-check principals, registered operations only, first-hop token evidence, public projection, signed record v2 with recovery incarnation | DEC-001 to DEC-012, RES-009, TRU-003 |
| Releases | `internal/release`: signed bundles whose manifest names the business and ceiling sets, evaluator build, registry digests, label order and cost limit | REL-001 to REL-005, POL-007 |
| Authority | `internal/identity`, `internal/delegation`, `internal/registry` (R1 types, operations, planned resources), `internal/catalog`, `internal/audit`, `internal/authn` (development token profile) | ID-*, DLG-*, RES-*, DAT-*, AUD-* |
| Authority fence | `internal/fence`: checks, consumption and transition in one transaction under a fixed lock order | DAT-007, DEC-006, DEC-011 |
| Storage | `internal/content` (content service), `internal/blob` (single-node store), `internal/nativeapi`, `cmd/fga-storage` | CNT-*, PUB-*, BKD-* |
| Keys | `internal/envelope` (recipient registry, envelope publication, delivery, retirement), `cmd/fga-keys` | KEY-*, RCP-*, TRU-005 |
| Client | `internal/cryptowire` (wire profile 1), `sdk/go/crypto` (Tink streaming AEAD and HPKE), `sdk/go/client`, `cmd/fga` | CRY-*, KEY-006, RCP-006 to RCP-008 |
| Recovery | `internal/journal` (security journal), `internal/recovery` (backup, restore, reconcile, reclaim), `internal/backupcrypt` (encrypted backups), `cmd/fga-admin` | AVL-005, AVL-008, KEY-017, PUB-005, PUB-006 |
| Operations | `internal/auditexport` (outbox to durable files), `internal/admission` (per-tenant limits), `internal/roleconfig` (configuration, mutual TLS) | AUD-002, AUD-003, AVL-006, TRU-002 |
| Labels | `internal/labels` (order arithmetic); ranks in `internal/decision`; the label order published to the catalog on activation; label, relabel and proposals in `internal/content` ([labels-and-approvals.md](docs/design/labels-and-approvals.md)) | LAB-001 to LAB-005, FLW-004 (storage objects so far) |
| Approvals | `internal/approval` with neutral operation plans (`internal/opplan`). The decision role opens and verifies approvals, the fence consumes them, and finalize, delete, version delete and label changes use them | APR-001 to APR-005 |

Executor (built for specification 2.2, parked as the optional R2 feature `executor`): `internal/tools`, `internal/toolstore` (its tables are applied only by `toolstore.Migrate`), `internal/tools/connector`, `internal/invocation`, `internal/reservation`. No R1 role links it. It will be connected into the overall system after object storage and fine-grained access control are done, together with MCP.

Design records: [docs/design](docs/design). Owner rulings for R1: [docs/decisions/rulings-2026-10-31.md](docs/decisions/rulings-2026-10-31.md). Dependency records: [docs/dependencies](docs/dependencies).

### Specification fixtures

`internal/conformance` runs the fixture-ready R1-A and R1-B cases as [fixture-binding.md](docs/design/fixture-binding.md) describes:

| Case | Result |
|---|---|
| V-001, V-142, V-144, V-146, V-149 | Pass |
| V-147 | Pass, bound to a storage object until document units exist |
| V-143 | Passes with fence clock margin 0. One host clock in the local profile. With the default one-second margin, the admission one second before the cutoff is refused (more restrictive than the fixture). |
| V-141 | Unbound. Its decision carries a `metadata_projection` obligation. R1 maps no obligations (POL-011 not built), so verifiers reject every obligation. |
| V-145, V-148 | Not built yet (R1-C derived outputs) |

### Known gaps (not done or not verified)

- **D-04 (identity providers) is open.** Only the development token profile exists. Production refuses the development issuer, and no production issuer has been configured or tested.
- **D-08 (client key custody) is open.** Client private keys and the backup key are files (mode 0600). They can optionally be protected with a passphrase (Argon2id and Tink AES-256-GCM, [key-files.md](docs/design/key-files.md)) and are then decrypted in memory only when used. The passphrase comes from an environment variable or a file; there is no interactive prompt. Server roles' keys are not covered.
- **Crypto interoperability (RCP-007)** is tested only against our own implementation. Frozen positive and negative wire examples exist; no independent implementation has been run.
- **Audit export** goes to local files only. There is no external collector and no signing or hash-chaining of export files. Events recorded after the last export and before a restore are still lost by the restore ([audit-export.md](docs/design/audit-export.md)).
- **Admission limits** are counts of concurrent requests and streams, with unmeasured defaults (D-10 open). There are no byte-rate budgets and no sizing measurements (SIZ-001).
- **Catalog encryption at rest (DAT-006)** is left to the volume.
- **Content-signing keys** are provisioned by the administrator. Their resource type allows only `discover`, so self-service enrollment fails closed.
- **Approvals on keys-role operations** are not wired: such an operation sends no plan, so `NEEDS_APPROVAL` there stays a denial. There is no registry of trusted label classifiers (D-06), so every label proposal is advisory.
- **No CI** runs the checks, the import allowlists or the vulnerability scan; they run locally ([vulnerability-scan.md](docs/dependencies/vulnerability-scan.md)).

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
- `make check-pg` adds the PostgreSQL-backed tests, each in a throwaway schema, including the conformance cases.
- `make spec` runs the specification consistency check in check-only mode and its tests.

## Run the storage roles locally

`scripts/smoke.sh` builds every binary and creates a throwaway database. It starts `fga-decision`, `fga-keys` and `fga-storage` on loopback, then drives them with `fga-admin` and `fga`. The run covers recipient enrollment, an encrypted round trip, denial before sharing, sharing and listing. It covers a label raise, a lowering that needs a lead's approval (requested, listed, approved, consumed, refused on reuse), a label proposal, a document publication, and deletion. It then exports the audit outbox, takes an encrypted backup, journals a recipient revocation, restores (admission stays closed until reconcile), reconciles and checks the result. The database is dropped at the end.

```bash
scripts/smoke.sh .local/smoke
```

The script is also the reference for configuring the three roles: it writes `decision.json`, `keys.json` and `storage.json` into its working directory. Production profiles require mutual TLS and refuse the development token issuer. The mutual-TLS transport between the roles is covered by a test with a throwaway certificate authority (`internal/roleconfig`); the smoke run itself uses the development profile on loopback.

## Run the decision role alone

The `.local/` directory is ignored by git.

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

The example request is an agent reading an object of its user's project through a delegation, and returns `ALLOW` with a signed decision. Change its name to `reports/q4.txt` and the business policy denies it.
