# fga: Fine-Grained Access Platform

An implementation of the Fine-Grained Access Platform specification 2.6.2 (draft), which is kept in [docs/spec](docs/spec) with its handoff, errata, test vectors and consistency check. Specification 2.6 added encryption modes (decision [D-12](docs/decisions/D-12-encryption-modes.md)), 2.6.1 corrected which resources and actions a share grant can name, and 2.6.2 how recovery reopens without a journal record and approvals for collection entries; server mode is built (see Known gaps for KEK custody). `fga` is a placeholder name (decision D-11).

The policy engine and the object storage are our own code. MinIO and Cerbos are studied for ideas only (decisions D-01 to D-03 in [docs/decisions](docs/decisions)); the [mechanism matrix](docs/research/mechanism-matrix.md) records what was taken and what was rejected. Everything runs locally.

## Status (31 October 2026)

Focus: object storage plus access control (R1). MCP (R2) comes after R1 is accepted.

- **R1-A, shared authority:** built, including the catch-up list of the [handoff](docs/spec/HANDOFF.md) (section 5).
- **R1-B, encrypted object storage:** built and running locally. That covers the storage and keys roles, server mode (the default: the platform encrypts under data keys released only for exact decisions) and client mode (opt-in per bucket), share grants, the client SDK, the native API, backup, restore and reconcile.
- **R1-C, documents, labels and approvals:** built and running locally. That covers:
  - default deny for every user action, key lookups included (ruling 7);
  - labels (signed label order, computed ranks, label, relabel, advisory proposals) and approvals of storage operations;
  - documents split on the client into separately encrypted text units with a signed manifest (wire profile 2), and the encrypted original file;
  - disclosure of units (explicit selection, authorized subset without hidden counts, manifest only when complete), export to a recipient, and metadata search;
  - text collections of `text.entry` entries;
  - derived outputs with signed lineage.

  The fixes for the eight findings of the 31 October code review (`code_review_v1.txt`) each have a regression test.
- **R2, MCP over encrypted storage:** the MCP role and the local bridge are built (stretches M1 to M4); the optional executor is next. The storage and decision roles accept the MCP role's calls for its users through a signed decision per MCP tool call ([mcp-gateway.md](docs/design/mcp-gateway.md), ruling 8); the `fga-mcp` role serves MCP resources, the read tools and export over the native API, with unit filtering, user-bound sessions and its own bounds; server-mode content as plaintext, client-mode content only as encrypted packages to clients that declare the capability ([mcp-role.md](docs/design/mcp-role.md), stretches M2 and M3); `fga mcp-bridge` opens those packages with the user's keys for the local application that started it ([mcp-bridge.md](docs/design/mcp-bridge.md)).
- **R3:** not built.

**Nothing here is qualified (GATE-001).** No release manifest exists and no execution evidence is recorded. Passing tests and a passing smoke run are development evidence only.

| Area | Packages | Specification |
|---|---|---|
| Policy | `internal/policy/format`, `internal/policy/engine`: `fga.policy/v1`, deny overrides, deny-only ceiling set, strict errors, cost limit, `request.now` only against timestamp literals | "Policy format", POL-001 to POL-014 |
| Decisions | `internal/decision`, `internal/gate`, `internal/decisionsvc`, `cmd/fga-decision`. Check kinds with per-check principals, registered operations only, first-hop token evidence, public projection, signed record v2 with recovery incarnation | DEC-001 to DEC-012, RES-009, TRU-003 |
| Releases | `internal/release`: signed bundles whose manifest names the business and ceiling sets, evaluator build, registry digests, label order and cost limit | REL-001 to REL-005, POL-007 |
| Authority | `internal/identity`, `internal/delegation`, `internal/registry` (R1 types, operations, planned resources), `internal/catalog`, `internal/audit`, `internal/authn` (development token profile) | ID-*, DLG-*, RES-*, DAT-*, AUD-* |
| Authority fence | `internal/fence`: checks, consumption and transition in one transaction under a fixed lock order | DAT-007, DEC-006, DEC-011 |
| Storage | `internal/content` (content service), `internal/blob` (single-node store), `internal/nativeapi`, `cmd/fga-storage` | CNT-*, PUB-*, BKD-* |
| Keys | `internal/envelope` (recipient registry, envelope publication, delivery of object, unit, original, derived and export envelopes, retirement), `cmd/fga-keys` | KEY-*, RCP-*, TRU-005 |
| Documents | `internal/content` (documents.go, disclosure.go, export.go, units.go), `internal/cryptowire` (wire profile 2, manifest, unit descriptor), `sdk/go/crypto` (splitting, unit sealing) ([documents.md](docs/design/documents.md)) | DOC-*, DSC-*, CNT-003, SRH-* |
| Derived outputs | `internal/content/derived.go`, `internal/cryptowire/lineage.go` ([derived-outputs.md](docs/design/derived-outputs.md)) | DRV-001 to DRV-003, DRV-007 to DRV-009 |
| Share grants | `internal/content/grants.go`, `internal/catalog/grants.go`; `shared_with` and grant-bounded validity in `internal/decisionsvc`; removals journaled ([share-grants.md](docs/design/share-grants.md)) | SHR-001 to SHR-003 |
| Client | `internal/cryptowire` (wire profile 1), `sdk/go/crypto` (Tink streaming AEAD and HPKE), `sdk/go/client`, `cmd/fga` | CRY-*, KEY-006, RCP-006 to RCP-008 |
| Recovery | `internal/journal` (security journal), `internal/recovery` (backup, restore, reconcile against the KEK ring, reclaim with data-key destruction), `internal/backupcrypt` (encrypted backups), `cmd/fga-admin` | AVL-005, AVL-008, KEY-017, PUB-005, PUB-006, SSE-006 |
| Operations | `internal/auditexport` (outbox to durable files), `internal/admission` (per-tenant limits), `internal/roleconfig` (configuration, mutual TLS) | AUD-002, AUD-003, AVL-006, TRU-002 |
| Fault isolation | One process per role; `internal/guard` keeps a panic inside its request or goroutine ([fault-isolation.md](docs/design/fault-isolation.md)) | MOD-002, AVL-006 |
| MCP | `internal/mcpsvc`, `cmd/fga-mcp` on the official MCP Go SDK: resources, read tools and export over the native API, decisions per call through the gateway hop; `internal/mcpwire`, the encrypted-package profile; `internal/mcpbridge` and `fga mcp-bridge`, the local bridge ([mcp-role.md](docs/design/mcp-role.md), [mcp-gateway.md](docs/design/mcp-gateway.md), [mcp-bridge.md](docs/design/mcp-bridge.md)) | MCP-001 to MCP-008 |
| Labels | `internal/labels` (order arithmetic); ranks in `internal/decision`; the label order published to the catalog on activation; label, relabel and proposals in `internal/content` ([labels-and-approvals.md](docs/design/labels-and-approvals.md)) | LAB-001 to LAB-005, FLW-004 (storage objects so far) |
| Approvals | `internal/approval` with neutral operation plans (`internal/opplan`). The decision role opens and verifies approvals, the fence consumes them, and finalize, delete, version delete and label changes use them | APR-001 to APR-005 |

Executor (built for specification 2.2, parked as the optional R2 feature `executor`): `internal/tools`, `internal/toolstore` (its tables are applied only by `toolstore.Migrate`), `internal/tools/connector`, `internal/invocation`, `internal/reservation`. No R1 role links it. It will be connected into the overall system after object storage and fine-grained access control are done, together with MCP.

Design records: [docs/design](docs/design). Owner rulings for R1: [docs/decisions/rulings-2026-10-31.md](docs/decisions/rulings-2026-10-31.md). Dependency records: [docs/dependencies](docs/dependencies).

### Specification fixtures

`internal/conformance` runs the fixture-ready R1-A and R1-B cases as [fixture-binding.md](docs/design/fixture-binding.md) describes:

| Case | Result |
|---|---|
| V-001, V-142, V-144, V-145, V-146, V-148, V-149 | Pass |
| V-147 | Pass, bound to a storage object |
| V-143 | Passes with fence clock margin 0. One host clock in the local profile. With the default one-second margin, the admission one second before the cutoff is refused (more restrictive than the fixture). |
| V-141 | Unbound. Its decision carries a `metadata_projection` obligation. R1 maps no obligations (POL-011 not built), so verifiers reject every obligation. |

### Known gaps (not done or not verified)

- **Server mode (specification 2.6, D-12) is built: objects, documents, collections, derived outputs, share grants and recovery.**
  - **Bucket modes:** buckets have an encryption mode, server by default, which policy can see and a project lead can change ([encryption-modes.md](docs/design/encryption-modes.md), S1).
  - **Keys role:** it holds each tenant's key-encryption keys and seals and releases data keys under exact decisions ([server-keys.md](docs/design/server-keys.md), S2).
  - **Objects:** in a server-mode bucket, objects are uploaded and read as plaintext, which the storage role encrypts and decrypts, and policy alone decides who reads ([server-objects.md](docs/design/server-objects.md), S3).
  - **Documents and collections:** text is split, encrypted per unit and read unit by unit under each unit's own checks ([server-documents.md](docs/design/server-documents.md), S4a).
  - **Originals and exports:** an original file uploaded beside the text, released only with complete-content permission checked in the keys role's fence, and exports of selected units (S4b).
  - **Derived outputs:** the lineage is declared with the upload and bound to the caller's decision; a reader reads under their own reader path, which the keys role checks again when it releases the key (S4b).
  - **Share grants:** a user with `share` names a reader of the same tenant, actions from the resource type's read set and an expiry; policy sees the grantees as `resource.attributes.shared_with`, and only a rule that tests it turns a grant into an allow ([share-grants.md](docs/design/share-grants.md), S5).
  - **Recovery:** backups hold sealed data keys and never a KEK; reconcile needs the KEK ring and quarantines versions whose keys do not open; final removal destroys a version's data key and reports that older backups still hold it ([server-keys.md](docs/design/server-keys.md), S6).
  - **Key custody:** KEKs are kept in a development ring file, which production refuses; KEK custody (D-13) is open.
- **D-04 (identity providers) is open.** Only the development token profile exists. Production refuses the development issuer, and no production issuer has been configured or tested.
- **D-08 (client key custody) is open.** Client private keys and the backup key are files (mode 0600). They can optionally be protected with a passphrase (Argon2id and Tink AES-256-GCM, [key-files.md](docs/design/key-files.md)) and are then decrypted in memory only when used. The passphrase comes from an environment variable or a file; there is no interactive prompt. Server roles' keys are not covered.
- **Crypto interoperability (RCP-007)** is tested only against our own implementation. Frozen positive and negative wire examples exist; no independent implementation has been run.
- **Audit export** goes to local files only. There is no external collector and no signing or hash-chaining of export files. Events recorded after the last export and before a restore are still lost by the restore ([audit-export.md](docs/design/audit-export.md)).
- **Admission limits** are counts of concurrent requests and streams, with unmeasured defaults (D-10 open). There are no byte-rate budgets and no sizing measurements (SIZ-001).
- **Catalog encryption at rest (DAT-006)** is left to the volume.
- **Content-signing keys** are provisioned by the administrator. Their resource type allows only `discover`, so self-service enrollment fails closed.
- **Approvals** cover publication, deletion and label changes of objects, documents, units and derived outputs, and sharing. Envelope retirement, enrollment and revocation send no plan, so `NEEDS_APPROVAL` there stays a denial. There is no registry of trusted label classifiers (D-06), so every label proposal is advisory.
- **Security journal:** it must be created once with `fga-admin journal init` before the keys and storage roles start. Restore and reconcile refuse a journal that cannot be shown complete, unless an operator passes `-accept-journal-loss`.
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

`scripts/smoke.sh` builds every binary and creates a throwaway database and security journal (`fga-admin journal init`). It starts `fga-decision`, `fga-keys` and `fga-storage` on loopback, then drives them with `fga-admin` and `fga`. The run covers:
- recipient enrollment, an encrypted round trip, denial before sharing, sharing and listing;
- a derived output (only its owner reads it) and a check that no blob holds plaintext;
- a label raise, and a lowering that needs a lead's approval (requested, listed, approved, consumed, refused on reuse), and a label proposal;
- a document read back unit by unit by both recipients, an original file only its owner may read, and a metadata search;
- in a server-mode bucket, an object, a document, an appended collection and a derived output that another member reads by policy alone, an original only its owner may read, and a share grant that lets a member of another project read an object until it is removed;
- reclaim retiring a withdrawn server-mode version and destroying its data key;
- deletion.

It then exports the audit outbox, takes an encrypted backup, journals a recipient revocation, restores (admission stays closed until reconcile), reconciles (refused without the KEK ring, then checking every server-mode data key against it) and checks the result. The database is dropped at the end.

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
