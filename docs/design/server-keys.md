# Server-mode keys: KEKs and data-key release (D-12, stretch S2)

In server mode (specification 2.6, [D-12](../decisions/D-12-encryption-modes.md)) the storage role encrypts each version under a fresh data key. Stretch S2 builds the keys role's part: it holds each tenant's key-encryption keys (KEKs), seals a data key for an upload, and releases a version's data key for a read. Each step happens only against a decision for that exact upload or version (SSE-001 to SSE-004). The storage role's part, which encrypts and decrypts payloads with the data key, is stretch S3 ([server-objects.md](server-objects.md)).

## Who holds what

| Role | Holds |
|---|---|
| kms (`cmd/fga-kms`, `internal/kms`), production custody | The ring of KEKs, alone. It seals and opens data keys for the keys role and decides nothing (D-13) |
| keys (`internal/datakeys`) | Data keys while it seals or releases one, under its fence. In development it may read the ring itself (`kek_file`). It never sees blobs, ciphertext streams or payload plaintext |
| storage | Blobs, and a data key only for the duration of one upload or read stream (S3). It links no KEK code, which `cmd/fga-storage` `TestNoKeyEncryptionKeys` checks |
| decision, MCP, tools | Neither KEKs nor data keys |
| catalog | Each version's and upload intent's sealed data key and KEK version (`sealed_key`, `kek_version`), and which KEK versions exist and which is active (`kek_versions`). Never a key |

The import allowlist of `cmd/fga-keys` admits the KEK code and Tink's AES-GCM `aead` package. It still forbids Tink's `streamingaead` (payload) and `hybrid` (HPKE) packages.

## The ring

`fga-admin kek init -file F [-encrypt]` creates a ring file. With `-encrypt`, the file is protected with the passphrase from `$FGA_KEK_PASSPHRASE` or `-passphrase-file` (Argon2id and AES-256-GCM, as for other [key files](key-files.md)). The keys role opens it from `kek_file` in its configuration, with `$FGA_KEK_PASSPHRASE` or `kek_passphrase_file`. Without `kek_file`, the data-key routes are not served.

**Custody (D-13, [ruling](../decisions/D-13-kek-custody.md)).**
- **Production.** The KEKs live only in the key management role, `fga-kms`. It reads the ring, which production requires to be passphrase-protected, with the passphrase from `kek_passphrase_file`. It serves `POST /v1/seal` and `POST /v1/open` over mutual TLS to the workloads in `clients` (the keys role's certificate) and refuses every other caller. The keys role names it as `kms` (url, client certificate) and refuses `kek_file` in production.
- **Development.** The keys role may read the ring itself from `kek_file`, or use `fga-kms` on loopback with one `dev_client`.
- **Error mapping.** A version the ring lacks answers 404 and a key that does not open answers 422; the client maps them back to the ring's errors.
- **Requests.** Requests are bounded to 4 KiB, and both sides clear the keys they handled.
- **Imports.** `fga-kms` links no catalog, policy, decision, storage or data-key code (`cmd/fga-kms` `TestNoAuthorityCode`). The keys role has already authorized every release under its fence before it asks.

A ring holds, per tenant, numbered versions of 32-byte AES-256-GCM keys. The catalog decides which version is active, so the ring itself has no state flag.

## Rotation

`fga-admin kek rotate -tenant T -file F` works in two steps:

1. It adds the tenant's next version to the ring and writes the file.
2. In one transaction, it locks the tenant's `kek_versions` rows, so no data key is sealed meanwhile. It retires the active version, makes the new one active, and reseals every sealed data key of the tenant's versions and upload intents under it. Ciphertext does not change (V-166).

If step 2 fails, the ring holds an unused version and nothing refers to it. Old versions stay in the ring. The role that holds the ring (`fga-kms`, or the keys role with `kek_file`) reads the ring file again when asked for a version it does not hold, so a rotation needs no restart. `fga-admin kek rotate` runs on the host of the ring.

`kek init` and `kek rotate` hold an exclusive lock on `<ring>.lock` from reading the ring until the catalog step is done. So two rotations, of one tenant or of different tenants sharing the ring, cannot write different keys for the same version or drop each other's versions (review v3 F07). The ring file is replaced atomically and its directory is flushed before the catalog commits the resealed keys, so the new version survives a crash in between (F14).

## Sealing and release

A data key is 32 random bytes; the keys role does not know which payload cipher uses it. It is sealed with AES-256-GCM (Tink, no output prefix) under the KEK version. The associated data is the domain `fga-kek-seal/v1`, a zero byte, the KEK version (4 bytes, big-endian), and the tenant, object, logical version, crypto version and blob IDs (16 bytes each). A sealed key moved to another version, object or tenant does not open (SSE-001).

| Internal route (storage workload certificate only) | Decision for the keys role, single-use | The keys role checks inside the authority fence |
|---|---|---|
| `POST /internal/v1/data-keys/seal` `{payload, jws, intent_id}` | `storage.key.seal-create`: `create-object` on the intent's bucket; or `storage.key.seal-version`: `new-version` on its object. Both are preparatory: an approval is decided at the commit | The intent belongs to the decision's actor, is a server-mode object upload, is RESERVED and unexpired, and has no key yet. The tenant has an ACTIVE KEK version. The key is stored on the intent once |
| `POST /internal/v1/data-keys/release` `{payload, jws, version_id}` | `storage.key.release`: `read` on the version; or `storage.key.release-history`: `read` and `read-history` | The version is in server mode and LIVE. For a plain read, it is still the object's current version (review finding 2) |

**What both routes enforce**

- The decision's checks must be exactly the operation's, and every check must name the intent's bucket or object, or the exact version.
- The fence consumes the decision and checks the policy epoch, revisions and approvals, as for envelope delivery.
- Each seal and release appends a `key_release` audit record with outcome `DATA_KEY_SEALED` or `DATA_KEY_RELEASED`. The record names the object, version and KEK version, never the key.
- The response carries the data key to the storage role. That role owns it and clears it after the stream (SSE-004).

**Errors.** A refused decision answers `403`; an absent or not-LIVE target answers `404`, which the storage role's client maps to the shared not-found; an intent that already has its key answers `409`; and a tenant without an active KEK answers `503`.

Document units, originals, exports and derived outputs get their release operations with S4. The server-mode payload format is added to the crypto profile with S3.

## Backups, reconciliation and destruction (S6, SSE-006)

- **Backups** include `kek_versions` and the sealed keys with the catalog, but never the ring or an unsealed key. The ring is recovered apart from backups (development custody until D-13 is decided).
- **Reconcile** (`fga-admin reconcile -kek-file FILE`). Without the ring it refuses before changing anything, and admission stays closed. With it, reconcile checks the following before reopening admission, and opened keys are cleared at once:
  - every KEK version that `kek_versions` records must be in the ring; a missing one is reported as `tenant/version`;
  - the sealed key of every LIVE or WITHDRAWN server-mode version (objects, units, originals and derived outputs alike) must open under its tenant's KEK version and its binding. A version whose key does not open is quarantined.
- **Final removal** (`fga-admin reclaim`). Retiring a withdrawn server-mode version destroys its sealed key and records when (`key_destroyed_at`, migration 0021). It also removes the upload intent's copy of the key, so the catalog no longer holds it. The command reports the destroyed keys and says that backups taken before that time still hold them: the content is unrecoverable only once every such backup is deleted. Reclaim also destroys the sealed keys of aborted uploads and drops the redundant copies held by committed ones.

## Tests

| Test | Covers |
|---|---|
| `internal/kek` | Sealing is bound to tenant, version and identity; resealing; the protected ring file; reading the file again after a rotation; malformed rings |
| `internal/datakeys` `TestSeal` | One key per intent; replay; another bucket, principal, operation or mode; audit without key material |
| `TestSealWithoutKEK` | No active KEK, no key |
| `TestRelease` | V-162 (another version), V-161 (head advanced; the history read still works), another operation, client mode, audit |
| `TestReleaseStaleEpoch` | V-160 |
| `TestRotation` | V-166: resealing versions and intents, unchanged digests, new seals under the new version |
| `TestRoutes` | Only the storage workload may call the routes; the storage role's RPC client |
| `cmd/fga-keys` | The allowlist; production refusing `kek_file` |
| `internal/kms` `TestSealAndOpen`, `cmd/fga-kms` | Seal and open through the key management role; another binding, an unknown version, a workload that is not a client; production rules (mutual TLS, protected ring, passphrase file); the role's allowlist |
| `internal/recovery` `TestBackupHoldsSealedKeysOnly` | A backup holds the sealed key, never the unsealed key or a KEK |
| `TestReconcileChecksKeys` | No ring: admission stays closed; a ring without the KEK version, or an altered sealed key, quarantines; the right ring reopens and the content reads |
| `TestReclaimDestroysKeys` | Retirement destroys the version's and the intent's sealed keys; a backup taken before still restores them |
| `scripts/smoke.sh` | A protected ring, the first rotation, and the keys role sealing and opening through `fga-kms`; reclaim destroying a withdrawn version's key; reconcile refusing without the ring and reopening with it |
