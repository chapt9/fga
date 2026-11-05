# Handoff: build fga against specification 2.5

Written 31 October 2026 for a fresh Claude session. Read this file first, then
`ERRATA-2.4-to-2.5.md`. Do not write code until you have presented the plan in section 6
and the owner has agreed to it.

## Focus (owner, 31 October 2026)

**Foremost this is object storage plus access control. MCP is coded after that.**
- R1 is a usable, client-encrypted object store with one shared access-control authority. It
  is accepted with MCP, models and external tools absent (GATE-004). Do not start MCP work, and
  do not extend the tools/executor stack, until R1 is accepted.
- MCP (R2) is then a separate service and a *client* of the storage foundation: it adds no
  store, no permission rules and no decryption (MCP-002, MCP-006, MCP-008).
- Order of work: R1-A shared authority, R1-B object storage with client-side encryption and
  envelope delivery, R1-C documents and text units, then R2 MCP, then R3 S3 and replication.

## 1. Project and working rules

- Project `fga` (placeholder name, D-11) is an object-storage and fine-grained
  access-control platform in Go. Code: `/Volumes/workdata/new_idea` (module `fga`, Go 1.27.3,
  local PostgreSQL). Specification: this directory (`fga-spec-v2.5`, PDF one level up).
- **Explain before coding.** For each coding stretch, first describe what runs as a
  separate program, what is our own code, which dependencies or downloads are involved, the
  order, and the stop points. Wait for agreement. Option labels must not hide a dependency or
  a reversal of the project's intent.
- **Decided by the owner (do not reopen):**
  - **D-01.** Own evaluator, own policy format `fga.policy/v1`. A matching deny overrides an
    allow across roles and scopes. No Cerbos format, no compatibility promise, no oracle.
  - **D-02.** Own single-node local blob store in R1. Local only: no cloud, no AWS S3, no
    external object store. The multi-node topology is a later target (`ha` profile).
  - **D-03.** MinIO and Cerbos are studied for ideas only. See section 2.
- Report faithfully. Passing tests are not qualification (GATE-001); say what was not verified.
- Do not commit or push unless asked. `papers/` is untracked and not part of the repository history.
- Changing normative spec text changes the spec version (TEST-003). Do not edit 2.5 in place
  to suit the code; raise it with the owner.

## 2. Inspiration, not transcription (MinIO and Cerbos)

We studied MinIO and Cerbos and mapped their behavior. **Take inspiration from the mapped
ideas; never copy code from either project.** This is requirement SRC-001 and decision D-03.
The reason is licensing: the owner wants freedom over the license of the project's own code
(MinIO is expected to be AGPL-3.0, Cerbos Apache-2.0; both unverified, SRC-004 completes the
record before first distribution).

Rules:
- Do not copy, translate, paraphrase, vendor, link, embed or run upstream code, tests,
  comments, assets, binaries or containers, in the product or in tests. Renaming symbols or
  changing the language does not make a copy acceptable.
- Do not open upstream source files, and do not write from recollection of them. Write from
  the spec and the project's own records. General-purpose libraries (cel-go, pgx, go-jose,
  Tink, ...) are fine after the dependency record LIB-002 / LIB-003.
- Do not name a product after either project. A mechanism not yet in the matrix gets a row
  (behavior, decision, our contract) **before** it is coded.
- Working sequence: read the matrix row, restate the behavior in your own words, design our
  smaller contract, implement from that contract, test from the requirements (never from
  upstream tests), update the matrix.

Where the mapping lives:
- **`docs/research/mechanism-matrix.md`** (SRC-002 record) in the implementation repository.
  Nine Cerbos and seven MinIO rows, each with observed behavior, decision (adopt, adapt,
  reject, defer) and our contract. Pinned commits: MinIO `7aac2a2c5b7c882e68c1ce017d8256be2feea27f`,
  Cerbos `ae014ba2ea919771216bc666c4f654d18a1c1a52`. Source of the rows: the private research
  snapshot `fine-grained-access-research/FUNCTIONALITY_MAP.txt` (not located on
  `/Volumes/workdata` during this review; ask the owner for it, and read only its behavioral
  descriptions). The spec cites `map_cerbos.json`, `map_minio_storage.json` and
  `map_minio_access.json` in a separate research report, also not located.
- **Spec Part 6, table "Selected upstream ideas and their original implementation"**
  (eight rows). In 2.5 its first row records upstream precedence as Reject.
- Provenance discrepancy: Part 6 and `engineering-notes.tex` say six short upstream excerpts
  (158 lines) were inspected by the spec's authors. The matrix says no upstream source file was
  opened. For implementation, follow the stricter rule: open nothing.

What the code already written took from them:

| Our code | Idea studied | Decision recorded |
|---|---|---|
| `internal/policy/engine`, `internal/policy/format` | Cerbos: CEL expressions, checked programs | **Adopt the idea** through cel-go (a library), not Cerbos code (POL-009, POL-010) |
| same | Cerbos: effect combination, principal policies first, independent role paths | **Reject.** Deny overrides across roles and scopes; a per-principal rule is a condition (POL-003, POL-014; V-005, V-008) |
| same | Cerbos: lenient CEL error default | **Reject.** Strict only: an error denies or objects (POL-005) |
| same | Cerbos: hierarchical scopes and modes | **Adapt.** Ancestry kept; all scopes combine by deny-overrides; no modes (POL-014) |
| `internal/release` | Cerbos: hot reload, last valid state | **Adapt.** Keep the last valid snapshot only while it meets the required epoch (REL-001, REL-003) |
| policy indexing | Cerbos: indexed rule tables | **Adapt later.** Plain maps until measured (POL-010) |
| later listing prefilter | Cerbos: data-filter query plans | **Defer.** Sound superset prefilter plus exact checks (CNT-007) |
| not built | Cerbos: derived roles, variables, outputs | **Defer** ("Left out of v1") |
| `internal/delegation`, `internal/identity` | MinIO: derived credentials with parent restrictions | In the spec table only; the matrix has no row. A child delegation can only narrow |
| future `internal/backend` (R1-B) | MinIO: local commit durability (exclusive temp file, size check, fdatasync, commit) | **Adopt the idea** (BKD-001 to BKD-003) |
| same | MinIO: transport checksums, bitrot protection | **Adapt.** Whole-blob SHA-256 now |
| future catalog | MinIO: version journal and bucket versioning | **Reject.** PostgreSQL catalog is the version authority; blobs immutable (PUB-001 to PUB-005) |
| future publication | MinIO: namespace locking | **Reject.** Catalog row locks and compare-and-swap (PUB-007) |
| future listing | MinIO: metacache and lifecycle side effects | **Reject.** Listing has no hidden effects (CNT-006) |
| R3 only | MinIO: Reed-Solomon, quorum | **Defer.** Full-copy replication later; erasure coding out of scope |
| future upload path | MinIO: streaming PUT and conditional commit | **Adapt.** Preconditions on the committed catalog version (PUB-003, PUB-007) |

No upstream mapping exists in the repository for: client-side envelope encryption and HPKE
(the spec table has a MinIO "envelope keys" row, decision Adapt, client-only decryption replaces
the server-decryption model), repair and evacuation (R3), SigV4 (R3). **Add matrix rows for
these before coding R1-B crypto and envelope delivery.** The signing, audit, catalog, gate,
tools, approval, invocation and reservation packages have no upstream mapping; they are our design.

## 3. Current state (verified 31 October 2026)

`/Volumes/workdata/new_idea`: 8.2k lines of Go. `go build`, `go vet` and `go test` pass;
PostgreSQL-backed tests skip without `FGA_TEST_DATABASE_URL`. Commits through `b7bb205`.
The README status section is stale (it lists R1-B work as not built).

| Package | State |
|---|---|
| `internal/policy/format`, `engine` | `fga.policy/v1`, deny-overrides, strict errors, cel-go with cost limit. `request.now` is unrestricted |
| `internal/decision` | Gate, then ceiling, then business. One principal for all checks |
| `internal/gate` | `Admit`, `Bind`, `Recheck`. `ValidUntil` = min(max age, delegation expiries) |
| `internal/signing` | `fga.decision/v1` JSON, detached EdDSA JWS, `Consume(decisionID, until)` |
| `internal/registry` | Types, aliases, operations. `R1Types` includes R2 types |
| `internal/release` | Signed bundles, activation states, epoch checks. `Bundle` has no manifest |
| `internal/catalog` | PostgreSQL stores, migrations 0001 (core) and 0002 (tools) |
| `internal/decisionsvc`, `cmd/fga-decision` | JSON facade, mTLS adapter identity, import allowlist (MOD-004) |
| `internal/audit`, `delegation`, `identity` | Outbox, delegation chains, identities with revisions |
| `internal/tools`, `toolstore`, `tools/connector`, `invocation`, `reservation`, `approval` | Built for 2.2's R1-B. **Optional R2 (feature `executor`) in 2.5** |

## 4. What changed in the build order (2.2 to 2.5)

R1-A shared authority. R1-B usable object storage with **mandatory client-side encryption**,
envelope service, native HTTP API, backup and restore. R1-C documents and text units. R2 MCP
service plus the optional executor. R3 S3 and replication. About 30 key-custody requirements
moved R2 to R1-B, about 31 storage requirements R1-C to R1-B, about 20 executor requirements
R1-B to R2, about 18 MCP and flow requirements R1-C to R2. The tools stack stays in the repo
as optional R2. Do not extend it; the decision role already excludes it, keep it that way.

## 5. The R1-A catch-up list (the code against 2.5)

1. **First-hop authentication** (TRU-003, DEC-007, ID-001, ID-007). `decisionsvc.Request`
   carries actor and subject claims; `gate.Admit` trusts them. No token verification exists.
   D-04 (identity providers) is open: define the evidence interface and a development
   profile, choose no provider.
2. **Per-check principal** (RES-009; check kinds in the Decision API section). `Decider`
   uses one principal for all checks.
3. **Signed record** (DEC-008, DEC-003). Add recovery incarnation, per-check effects, the
   obligation set with mapping version and digest, evaluator version, resource-bindings
   digest, context revisions. `Requires` is not signed today.
4. **Validity** (DEC-005, POL-008). Implement the time-literal rule of "Policy format";
   reject other uses of `request.now`; bound `valid_until` by identity expiry too. Fixture
   V-143 asserts this.
5. **Ceiling declaration** (POL-007). The engine treats a missing ceiling as PASS and
   `ValidateBundle` rejects a document with no rules. A manifest must declare the ceiling set
   (empty allowed, omitted rejected). Vector V-153.
6. **Public projection** (DEC-010). `UNKNOWN_RESOURCE` and `BUSINESS_DENY` are
   distinguishable today. Add a public projection next to the internal enforcement response.
7. **Authority fence** (DAT-007, DEC-011, AVL-008). `Gate.Recheck` is a separate read;
   `catalog.Consume` is its own statement and cannot commit with a protected transition; there
   is no recovery incarnation. Needs a design record first (section 6, step 1).
8. **Registry.** Add `crypto.recipient`, `crypto.envelope`; add `read-history`,
   `discover-history`, `delete-version`, `share` (storage.object), `share`/`export`
   (document.*); move R2 types out of `R1Types`.
9. **Release manifest** (REL-001): label order, operation registry, cost model, expression-library
   version and the rest of the listed contents.
10. **Decouple approvals.** `internal/approval` imports `internal/tools`. APR-005 wants a
    platform-rendered canonical plan and MOD-004 forbids storage and control depending on
    tool execution. Introduce a neutral operation-plan type.
11. Update doc comments that cite "specification 2.2" and the README status.

## 6. Proposed plan (present to the owner; wait for agreement)

- **Step 0.** Decide whether 2.5 replaces `docs/spec` (2.2) in the repository.
- **Step 1, design records, no code.** (a) Authority fence: lock order, what rows, the
  `ConsumeTx` shape, recovery incarnation (DAT-007, DEC-011, AVL-008). (b) Crypto wire
  profile and API contracts: `RecipientEnvelopeContextV1`, signature and digest algorithms,
  fingerprint encoding, descriptor format (RCP-006/007), the native OpenAPI contract and error
  mapping (CNT-009), the envelope service API and enrollment protocol (RCP-002). (c) How
  fixtures bind to the code's public boundary. Add the missing mechanism-matrix rows.
- **Step 2, R1-A catch-up** (section 5), one item at a time, with tests written from the
  requirements.
- **Step 3, R1-B build.** New programs: `storage` role (content service, publication), `keys`
  role (opaque envelope delivery, no unwrap), client SDK (`sdk/go/crypto`). Our own code: the
  single-node blob backend, catalog migrations (upload intent, versions, envelopes, recipient
  keys), native HTTP API. New dependencies to admit under LIB-002: Tink for Go (streaming AEAD
  and HPKE; **verify HPKE support**, the spec lists it as unverified), a protobuf generator, an
  OIDC library once D-04 closes. No MCP, no tools stack.

## 7. Open owner decisions

D-04 identity providers, D-05 HA design (later), D-06 label order, D-08 client key custody
(before any production payload), D-09 recipient hierarchy, D-10 limits, D-11 name and license.
Plus: DEC-001 gRPC or JSON in R1; retention semantics; the server-visible metadata list. See
`ERRATA-2.4-to-2.5.md`.

## 8. Verification

```bash
cd /Volumes/workdata/new_idea && make check
```

```bash
cd /Volumes/workdata/new_idea && make check-pg
```

Spec checks (use `--check-only`; without it the checker rewrites `generated/`):

```bash
python3 -I /Volumes/workdata/new_idea/papers/fga-spec-v2.5/tools/check_spec.py --check-only
```

`make spec` checks `docs/spec` (2.2), not 2.5.
