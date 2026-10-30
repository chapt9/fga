# Mechanism evaluation matrix (SRC-002)

This is the record of ideas taken from studying MinIO and Cerbos, and of the decision made for each. The source of every row is a record in the private research snapshot (`fine-grained-access-research/FUNCTIONALITY_MAP.txt`), which links to these pinned commits:

| Project | Pinned commit |
|---|---|
| MinIO | `7aac2a2c5b7c882e68c1ce017d8256be2feea27f` |
| Cerbos | `ae014ba2ea919771216bc666c4f654d18a1c1a52` |

Only the map's behavioral descriptions were read. No upstream source file was opened or copied (D-03).

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
