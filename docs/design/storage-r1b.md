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
- Reclamation: `fga-admin reclaim` reads `retirements`, rechecks in a fence-like transaction that the version is still WITHDRAWN and unreferenced, removes the blob, marks the version RETIRED, and destroys a server-mode version's sealed data key ([server-keys.md](server-keys.md), SSE-006). Expired RESERVED, WRITING or STAGED intents are ABORTED by the same command; their staged blobs are removed only by catalog identity, never by file age (PUB-006). An upload makes its blob durable only while it holds the intent's row and the intent is still RESERVED, in the transaction that marks it STAGED. Reclamation, which aborts under the same row, therefore runs either before the blob exists or after it is named, and never leaves a blob that no intent names (review v2 finding 5).
- No time-based retention or legal hold (owner ruling 4).

## Backup and restore (KEY-017, AVL-005, AVL-008)

- **Security journal.** Revocations (identity disabled, delegation revoked, recipient key revoked, signing key compromised, share grant removed; [share-grants.md](share-grants.md)), restrictive epoch raises and incarnation changes are first written durably to a journal directory outside the catalog (one file per entry, file and directory fsynced, published atomically under its position), then committed to the catalog. The entries form a hash chain from the journal's identity: each names its position and the chain value of the entry before it, so a lost, altered or reordered entry breaks the chain (review v2 finding 1). Entries written before the chain are accepted only as a prefix, which the chain then covers. A journal entry for a change that later failed to commit is harmless on replay because every entry is restrictive. The journal is created once at setup (`fga-admin journal init`), which writes a random identity file and binds the catalog to it (`journal_state`). Opening a missing journal fails; it is never recreated implicitly. Every journaled change records the journal's entry count and the chain value of its last entry in the catalog after its entry is durable. The recorded binding moves forward only along a chain that still holds the recorded head at its position, so entries appended after a loss never become the recorded history.
- **Continuity (review finding 1).** Restore checks the journal before it replaces anything. The journal must have the identity the live catalog is bound to (or, on an empty catalog, the backup's), an unbroken chain, at least the recorded number of entries and the recorded head at its position. A count alone could be restored by a later entry after one was lost (review v2 finding 1). When the catalog kept no record of the journal, as on a restore onto an empty catalog, only the backup's record is left. It shows the journal complete up to the backup, not after it, so the restore marks the authority state "journal unproven". Reconcile then keeps admission closed until the operator states that the journal is complete (`fga-admin reconcile -journal-complete`) or accepts its loss. Either statement is written to the audit outbox (specification 2.6.2, AVL-008, V-179, review v3 F02). Reconcile checks it again against the restored binding. A lost, re-initialized or older journal could miss revocations made after the backup, so both refuse it and admission stays closed. Only an explicit `-accept-journal-loss` from an operator who has restored those changes by other means proceeds; it rebinds the catalog to the journal at hand.
- **Backup** (`fga-admin backup`): one REPEATABLE READ snapshot copies every catalog table (`COPY ... TO STDOUT`), then copies the blobs that the snapshot references, and writes a manifest with each file's SHA-256, the snapshot's incarnation and the time. Each blob is checked against the catalog's length and digest as it is copied (review v3 F09), and the backup's directories are flushed before it reports success (F14). A blob of a LIVE or WITHDRAWN version that cannot be read or does not match fails the backup (`ErrIncomplete`) and its directory is removed. With `-allow-missing` the backup completes and the manifest lists such blobs as missing, as it always does for quarantined versions' (review v2 finding 4). The backup holds ciphertext, descriptors, opaque envelopes and server-mode data keys sealed under the keys role's KEKs; it holds no KEK, unsealed payload key or client private key (AVL-005, SSE-006). Backup encryption at rest is left to the volume (not built in R1; recorded as a gap).
- **Restore** (`fga-admin restore`): closes admission, replaces every catalog table from the backup in dependency order, restores blobs after checking each digest, sets a new incarnation above both the backup's and every journal incarnation, aborts every upload and document intent that was in flight (a backup holds no staged ciphertext; review finding 5), and leaves admission closed. Independently, finalize verifies the staged ciphertext's length and digest in the blob store before publishing, so a version is never published without its ciphertext.
- **Reconcile** (`fga-admin reconcile [-kek-file FILE]`): refuses without the KEK ring when the catalog holds server-mode data keys, replays every journal entry, verifies each LIVE, STAGED or WITHDRAWN version's blob length and digest, opens each server-mode data key under the ring (SSE-006), marks mismatched or missing ones QUARANTINED, writes an incarnation entry, then reopens admission. Decisions from before the restore fail the incarnation check. If the journal is unavailable, reconcile refuses to reopen admission (pending explicit reauthorization).
