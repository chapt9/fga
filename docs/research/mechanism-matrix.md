# Mechanism evaluation matrix (SRC-002)

This is the record of ideas taken from studying MinIO and Cerbos, and of the decision made for each. The source of every row is a record in the private research snapshot (`fine-grained-access-research/FUNCTIONALITY_MAP.txt`), which links to these pinned commits:

| Project | Pinned commit |
|---|---|
| MinIO | `7aac2a2c5b7c882e68c1ce017d8256be2feea27f` |
| Cerbos | `ae014ba2ea919771216bc666c4f654d18a1c1a52` |

Only the map's behavioral descriptions were read. No upstream source file was opened or copied (D-03). A later code similarity check, on 31 October 2026, read the Cerbos and MinIO trees mechanically and displayed about 80 lines of Cerbos and none of MinIO's code; it found no code of either here ([similarity-check.md](similarity-check.md)).

## Policy evaluation (studied: Cerbos)

| Map record | Observed behavior | Decision | Our contract |
|---|---|---|---|
| CEL expressions and built-in libraries | Typed CEL environment; checked AST; programs cached and reused | **Adopt the idea.** We use CEL through cel-go, a library dependency, not Cerbos code. | `docs/design/policy-format-v1.md`; POL-009, POL-010 |
| Precise effect combination and defaults | Principal policies first; independent role paths, so a deny in one role path does not stop an allow from another; no match denies | **Reject.** A matching deny always overrides an allow, across roles and scopes. | POL-003, POL-014; V-005, V-008 |
| Principal-specific override rules | A definitive principal result ends evaluation before resource policies | **Reject for v1.** Per-principal rules are conditions on `principal.id`, so ceilings cannot be bypassed. | POL-007; F-01 |
| Configurable CEL error behavior | Lenient by default: an erroring condition is skipped | **Reject the default.** Strict only: an error denies or objects. | POL-005 |
| Hierarchical scopes and permissions | Dot-separated ancestry; override-parent by default, parental consent as an option | **Adapt.** Ancestry is kept; all scopes combine by deny-overrides, with no modes. | POL-014 |
| Hot policy reload and last valid state | A failed rebuild keeps the previous table, which may keep old authorization in force | **Adapt.** Keep the last valid snapshot only while it meets the required epoch. | REL-001, REL-003 |
| Indexed rule tables and deduplicated programs | Bitmap indexes by scope, version, resource, role and action; program cache | **Adapt later.** Start with plain maps keyed by resource type and scope. | POL-010 |
| Data-filter query plans via partial CEL | Partial evaluation produces residual filters | **Defer.** Listing uses a sound superset prefilter plus exact checks first. | CNT-007 |
| Derived roles, variables and constants, outputs | Conditional role expansion; dependency-ordered variables; computed outputs | **Defer.** Each can be added to the format later without changing existing meaning. | `policy-format-v1.md`, "Left out of v1" |

## Object storage (studied: MinIO)

| Map record | Observed behavior | Decision | Our contract |
|---|---|---|---|
| Local XL storage and commit durability | Temporary files with exclusive create, size checks and fdatasync; commit by rename | **Adopt the idea.** | BKD-001, BKD-002, BKD-003 |
| Transport/object checksums and bitrot protection | Per-shard checksums verified before reconstruction | **Adapt.** Whole-blob SHA-256 now; chunked digests are a candidate for range reads. | BKD-001, REP-005 |
| Version journal and bucket versioning | Versions and delete markers in a per-object metadata file | **Reject.** The PostgreSQL catalog is the version authority; blobs are immutable. | PUB-001 to PUB-005 |
| Local and distributed namespace locking | In-process and distributed read/write locks | **Reject.** Catalog row locks and compare-and-swap serialize commits. | PUB-007 |
| Distributed listing and metacache | Listing can queue lifecycle and replication work | **Reject.** Listing has no hidden effects. | CNT-006 |
| Reed-Solomon coding and quorum | Erasure-coded shards with read and write quorum | **Defer.** Full-copy replication comes later; erasure coding is out of scope. | Part 5, ADR-08 |
| Streaming PUT and conditional commit | Preconditions evaluated under lock before commit; small objects can be stored inline | **Adapt.** Preconditions on the committed catalog version; inline small objects deferred. | PUB-003, PUB-007 |

## Added for specification 2.5 R1-B (31 October 2026)

Sources: the research map's records "SSE-S3, SSE-KMS and SSE-C object encryption", "Bucket default/automatic encryption and key rotation", "KMS/KES/static-key connections and key operations", "Partial-operation and replacement-drive healing", "Explicit pool rebalancing", "Pool decommission and resumable evacuation" and "AWS Signature V4 signed and presigned requests". Only their behavioral descriptions were read; no upstream source file was opened.

| Map record | Observed behavior | Decision | Our contract |
|---|---|---|---|
| Server-side object encryption with envelope keys | A fresh object key per object, sealed under a server-held or KMS-held key and bound to the object path; the server decrypts on read | **Adapt (revised for 2.6, D-12).** Keep the idea of a fresh key per immutable version and a binding of key to identity. Server mode, the default, now holds keys on the server in our own shape: a fresh data key per version, sealed under a tenant KEK that only the keys role holds and unsealed only under a signed decision verified in the authority fence, bound to tenant, object, version and blob rather than a path. Client mode keeps client keysets and HPKE envelopes that the server cannot unwrap. | [D-12](../decisions/D-12-encryption-modes.md), [crypto-wire-profile](../design/crypto-wire-profile.md), [envelope-service](../design/envelope-service.md); ENC-001, SSE-001 to SSE-003, CRY-001 to CRY-005, KEY-001, KEY-013 |
| Key rotation by resealing object keys | Rotation unseals and reseals object keys on the server | **Adapt for server mode (2.6).** The keys role rewraps data keys under a new KEK version without touching ciphertext. In client mode the server still cannot rewrap: recipient-key rotation is a client operation that publishes a new envelope under revision checks. | SSE-002, KEY-004, KEY-016 |
| External KMS connection and key operations | Server calls a KMS to generate and decrypt data keys | **Defer (D-13).** Server-mode KEKs are local key files in development; whether production uses an organization KMS or a hardware module is decision D-13. Client mode has no platform KMS unwrap dependency; its key custody is the client's (D-08 open). | SSE-002, KEY-005, KEY-013 |
| Healing of incomplete writes and replaced drives | A bounded in-memory queue of partial operations, persisted only on orderly shutdown; trackers resume per-drive healing | **Defer to R3, adapt.** Repair state will be durable catalog records, never only an in-memory queue. | REP-005 (R3) |
| Rebalancing and decommission | Resumable copy between pools with progress records; verification before completion | **Defer to R3, adapt.** Evacuation copies and verifies identical ciphertext, then compare-and-swaps the placement generation. | REP-004, REP-006 (R3) |
| SigV4 request authentication | Canonicalize signed headers, query, path and payload; derive the signing key; compare signatures; presigned requests have expiry | **Defer to R3, adapt.** Our own verifier from the public specification, constant-time comparison, no presigned or streaming modes in profile v1. | S3P-002, S3P-003 (R3) |

## Position relative to MinIO after D-12 (31 October 2026)

Decision D-12 made server-side encryption the default and client-side encryption an opt-in per bucket. That brings the storage model closer to MinIO's server-side encryption: in a server-mode bucket the storage role handles plaintext, and an unsealed data key for one upload or read at a time, and the platform can read that content (non-guarantee N-09). The confidentiality that holds even against the platform now applies to client-mode versions only.

What stays our own design:

| Area | Difference |
|---|---|
| Key release | A data key is unsealed only by the keys role, against a signed, single-use decision for the exact operation and version, admitted in the authority fence (SSE-003). It is not unsealed because a request is authenticated, and a key never outlives one stream |
| Authorization | One decision authority (our policy engine, default deny, ceilings, approvals, share grants honored only by explicit rules) decides every read, key release and disclosure; the storage role decides nothing itself (CNT-002) |
| Documents | Documents and text collections are split into units, each under its own data key and checks, so a reader gets only the units policy allows; originals need complete-content permission (DOC-006, CNT-003) |
| Derived outputs | Lineage-bound delivery: a reader needs their own read of every source, or a declassification (DRV-002) |
| Client mode | Kept as in 2.5: client keysets and HPKE envelopes the server cannot unwrap |
| Recovery | Revocations, including removed share grants, are journaled in a hash chain and replayed after a restore; a restore needs the KEK ring, kept apart from backups (AVL-008, SSE-006) |
