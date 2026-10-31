# R1-B object storage (BKD, PUB, CNT, KEY-017, AVL-008)

Status: design record, 31 October 2026. Mechanism-matrix rows "Local XL storage and commit durability" (Adopt the idea), "Version journal" (Reject), "Namespace locking" (Reject), "Metacache" (Reject) and "Streaming PUT and conditional commit" (Adapt) apply. Deployment profile `local` only (D-02, N-08).

## Programs

| Program | Our code | Talks to |
|---|---|---|
| `fga-decision` | Policy authority (existing) | PostgreSQL |
| `fga-storage` | `internal/content`, `internal/nativeapi`, `internal/blob` | Decision role (HTTP, adapter identity), keys role (internal delivery), PostgreSQL, blob directory |
| `fga-keys` | `internal/envelope` | Decision role, PostgreSQL |
| `fga-admin` | Bootstrap, buckets, identities, revocations, backup, restore, reconcile | PostgreSQL, blob directory, security journal (local administrator, ADM-003) |
| `fga` | Client CLI over `sdk/go/client` and `sdk/go/crypto` | Storage and keys roles |

## Blob backend (`internal/blob`)

Contract of BKD-001 in Go:

```go
type Backend interface {
    Begin(ctx context.Context, b BlobRef) (Writer, error)          // exclusive temp file
    Finalize(ctx context.Context, w Writer, length int64, sha256 [32]byte) (Receipt, error)
    Open(ctx context.Context, r Receipt) (io.ReadCloser, error)
    Remove(ctx context.Context, plan Retirement) error
}
```

- Layout under one service-owned root opened with `os.Root` (no traversal, no symlink escape): `tmp/<random>` for staging, `blobs/<tenant-uuid>/<aa>/<blob-uuid>` for finalized blobs, where `aa` is the first two hex digits of the blob ID. Names come only from generated UUIDs, never from bucket names or keys (PUB-001).
- Directories `0700`, files `0600`.
- Finalize: write fully, check length and SHA-256, `fsync` the file, link it to its final name without replacing an existing file, `fsync` the directory, remove the temp name. If the final name exists with the same length and digest, the call is idempotent; different bytes conflict.
- The receipt binds tenant, blob ID, length and digest. The catalog, not the file system, decides visibility; the backend is never listed to find user objects.
- `Remove` accepts only a retirement plan read from the catalog in the same call path and is idempotent.

## Catalog (migration 0003)

New tables, every key including the tenant: `tenants` (name, UUID), `authority_state`, `buckets`, `objects` (head: object UUID, bucket, key, current version or NULL, delete-marker flag, generation), `object_versions` (version UUID, crypto version, blob, state, length, digest, suite, format, signer, descriptor and signature, delete-marker flag), `upload_intents`, `recipient_keys`, `signing_keys`, `envelopes`, `enrollment_challenges`, `read_admissions`, `retirements`. Buckets and objects also have rows in `resources` (types `storage.bucket`, `storage.object`) and `aliases` (namespaces `native.bucket`, `native.object`), so the decision role resolves them like any other resource. `identities` gains `expires_at`. `consumed_decisions` gains the incarnation.

Migration 0002 (tool tables) moves behind the `executor` feature: it is applied only when a role enables the executor.

## Publication (PUB-002 to PUB-008)

Version states: RESERVED (intent created) → WRITING (bytes arriving) → STAGED (durable receipt) → LIVE (committed); ABORTED or QUARANTINED from any pre-LIVE state; LIVE → WITHDRAWN → RETIRED for explicit version deletion. A delete marker is a version row with the marker flag that becomes the head's current version.

The finalize transaction is one fence ([authority fence](authority-fence.md)). Operation rows locked in step 7: the object head (`FOR UPDATE`), the version row, the intent. Checks: intent COMMITTING not already COMMITTED, expected head generation unchanged, preconditions, version STAGED with a receipt matching the descriptor. Effects: version LIVE, initial envelopes inserted ACTIVE, head current pointer and generation + 1, object resource generation + 1 (a new object gets its resource and alias rows here), intent COMMITTED with its stored result, audit `OBJECT_PUBLISHED`.

A new key's planned protected attributes (owner = principal, project and label = bucket defaults, scope = bucket scope) are stored on the intent; the decision role evaluates prospective checks for a not-yet-published object against that planned state (RES-009), resolved from the intent row, never from the request.

## Deletion and reclamation

- Key deletion: `delete` decision; fence; a delete-marker version becomes current; head and resource generation + 1; older versions unchanged (PUB-005).
- Version deletion: `delete-version` decision; fence; reference guard (the version is not the target of an open intent's expected version and has no other live reference); LIVE → WITHDRAWN; if it was current, a delete marker becomes current; a `retirements` row is written in the same transaction.
- Reclamation: `fga-admin reclaim` reads `retirements`, rechecks in a fence-like transaction that the version is still WITHDRAWN and unreferenced, removes the blob, marks the version RETIRED. Expired RESERVED, WRITING or STAGED intents are ABORTED by the same command; their staged blobs are removed only by catalog identity, never by file age (PUB-006).
- No time-based retention or legal hold (owner ruling 4).

## Backup and restore (KEY-017, AVL-005, AVL-008)

- **Security journal.** Revocations (identity disabled, delegation revoked, recipient key revoked, signing key compromised), restrictive epoch raises and incarnation changes are first written durably to a journal directory outside the catalog (one file per entry, file and directory fsynced), then committed to the catalog. A journal entry for a change that later failed to commit is harmless on replay because every entry is restrictive.
- **Backup** (`fga-admin backup`): one REPEATABLE READ snapshot copies every catalog table (`COPY ... TO STDOUT`), then copies the blobs that the snapshot references, and writes a manifest with each file's SHA-256, the snapshot's incarnation and the time. The backup holds ciphertext, descriptors and opaque envelopes only; it holds no payload keys or client private keys (AVL-005). Backup encryption at rest is left to the volume (not built in R1; recorded as a gap).
- **Restore** (`fga-admin restore`): closes admission, replaces every catalog table from the backup in dependency order, restores blobs after checking each digest, sets a new incarnation above both the backup's and every journal incarnation, and leaves admission closed.
- **Reconcile** (`fga-admin reconcile`): replays every journal entry, verifies each LIVE, STAGED or WITHDRAWN version's blob length and digest, marks mismatched or missing ones QUARANTINED, writes an incarnation entry, then reopens admission. Decisions from before the restore fail the incarnation check. If the journal is unavailable, reconcile refuses to reopen admission (pending explicit reauthorization).
