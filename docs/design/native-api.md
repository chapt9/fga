# Native storage API v1 (CNT-009, Table "Native storage operations")

Status: design record, 31 October 2026. The machine-readable contract is [native-api.openapi.yaml](native-api.openapi.yaml); this record explains the rules it encodes. Implemented by `internal/nativeapi` (storage role) and `internal/envelope` (keys role), both delegating to the shared services (CNT-001, CNT-002).

## Roles and audiences

| Role | Binary | Token audience | Serves |
|---|---|---|---|
| storage | `fga-storage` | `fga-storage` | Uploads, reads, stat, listing, deletion |
| keys | `fga-keys` | `fga-keys` | Recipient and content-signing key registry, envelope publication and retirement; internal envelope delivery to the storage role |

Every request carries `Authorization: Bearer <access token>` ([first-hop authentication](first-hop-authentication.md)). Bucket creation is a control operation performed with `fga-admin` (ADM-003); clients cannot set authority metadata.

## Operations

Object keys travel in the `key` query parameter, never in the path, so Go's `ServeMux` path cleaning cannot change them (LIB-001). Keys are 1 to 1024 bytes of valid UTF-8 without NUL; bucket names match `^[a-z0-9][a-z0-9-]{2,62}$`.

| Operation | Method and path | Checks (registered operation) |
|---|---|---|
| Begin upload | `POST /v1/buckets/{bucket}/uploads` | New key: bucket `create-object` (`storage.object.begin-create`). Existing key: object `new-version` (`storage.object.begin-version`). An idempotent retry takes the same decision again; it is never answered from the stored intent alone |
| Upload ciphertext | `PUT /v1/uploads/{intent}/ciphertext` | Owner of the intent (same tenant, subject and actor) and a fresh single-use decision: bucket `create-object` (`storage.object.stage-create`) or object `new-version` (`storage.object.stage-version`), consumed in the fence; an identical retry needs it too. Bytes are staged only. The body streams under a lease that aborts on any change to the bound authority; it is not cut at the decision's `valid_until`, because staged bytes stay invisible until a commit with its own decision |
| Finalize | `POST /v1/uploads/{intent}/finalize` | Fresh decision: `create-object` or `new-version`, plus per initial envelope: publisher `share` on the object and `create` on the planned envelope, recipient `read` and `receive-key` (`storage.object.publish`) |
| Stat | `GET /v1/buckets/{bucket}/object?key=&version=` | `stat`; a non-current version also `discover-history` |
| Package | `GET /v1/buckets/{bucket}/object/package?key=&version=&recipient=` | Storage: `read` (+ `read-history`). Keys role: `GetRecipientEnvelope` checks (caller `read`, envelope `release`, recipient `read`, `receive-key`) |
| Ciphertext | `GET /v1/buckets/{bucket}/object/ciphertext?key=&version=` | `read` (+ `read-history`); admission and stream lease |
| List objects | `GET /v1/buckets/{bucket}/objects?prefix=&limit=&continuation=` | Bucket `list`, then per entry `discover` |
| List versions | `GET /v1/buckets/{bucket}/object/versions?key=&limit=&continuation=` | Bucket `list`, object `discover`, and `discover-history` for non-current entries |
| Delete key | `DELETE /v1/buckets/{bucket}/object?key=` | `delete`; writes a delete marker |
| Delete version | `DELETE /v1/buckets/{bucket}/object?key=&version=` | `delete-version`; retention and reference guards |
| Enroll recipient | `POST /v1/recipients`, then `POST /v1/recipients/{fp}/activate` | `crypto.recipient` `enroll`, then `activate`, with possession proof |
| Revoke recipient | `DELETE /v1/recipients/{fp}` | `crypto.recipient` `revoke` |
| Content-signing keys | `fga-admin signing-key add`, `retire`, `compromise` | Trusted provisioning by the local administrator (RCP-002). Each key is also a `crypto.signing-key` resource whose only action is `discover`, so a self-service operation fails closed (RES-001) |
| Look up a key | `GET /v1/recipients/{fp}`, `GET /v1/signing-keys/{fp}` | `crypto.recipient` `discover` (`crypto.recipient.discover`; a PENDING key is decided as its planned resource) or `crypto.signing-key` `discover` (`crypto.signing-key.discover`), with a fence check. Without a rule the lookup is denied (ruling 7). A directory answer is not a trust anchor (RCP-002) |
| Share | `POST /v1/envelopes` | `PublishRecipientEnvelope`: publisher `share`, envelope `create`, recipient `read`, `receive-key` |
| Retire envelope | `DELETE /v1/envelopes/{id}` | envelope `retire` |

Range requests are rejected (`Range` header present: 400). Copy, multipart and presigned URLs do not exist.

## Write sequence

1. Begin: the storage role resolves the key, obtains a decision, and records an upload intent with fresh object (new keys only), logical-version, crypto-version, blob and attempt IDs, the expected head generation, the planned protected attributes and the idempotency key. An identical retry returns the same intent; a different request under the same idempotency key is a conflict.
2. The client encrypts with the returned IDs, signs the descriptor and envelope contexts, and uploads the ciphertext. `Content-Length` is required and bounded; `Fga-Ciphertext-Sha256` names the digest. The backend checks both and returns a durable receipt. Repeating identical bytes returns the same receipt; different bytes for the same blob conflict.
3. Finalize: the server verifies the descriptor, envelopes and signer, obtains a fresh decision, and commits under the [authority fence](authority-fence.md): head generation and `If-Match`/`If-None-Match` preconditions, intent state, all bound revisions, consumption, version LIVE, envelopes, head pointer, intent COMMITTED, audit. A finalize that already succeeded returns the stored result after a fresh `stat` check of the caller.

## Conditional writes

Preconditions are sent at begin (`if_match` with an ETag, or `if_none_match: "*"`) and evaluated only at commit inside the fence, after authorization (PUB-007). `If-None-Match: *` means "no current live version at commit"; a key whose head is a delete marker accepts a new version. An ETag is `"` + logical version ID + `"`: opaque, never an MD5 or plaintext hash.

## Errors

Every error body is `{"error": CODE}` with no protected identifiers.

| HTTP | Code | When |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed body, parameters, descriptor or envelope; range request |
| 401 | `UNAUTHENTICATED` | Missing or invalid token |
| 404 | `NOT_FOUND` | Absent target, **and** any policy denial of an object, version or bucket operation (DEC-010, CNT-004): absent and denied look the same |
| 409 | `CONFLICT` | Idempotency mismatch, intent in the wrong state, different bytes for a blob, stale authority after a bounded retry |
| 412 | `PRECONDITION_FAILED` | `If-Match` or `If-None-Match` failed at commit (only after the operation was authorized) |
| 413 | `TOO_LARGE` | Body above the bound |
| 429 | `OVERLOADED` | Admission limits (AVL-006) |
| 503 | `UNAVAILABLE` | Decision, catalog, keys role or backend unavailable; admission closed for recovery |

A failure after response headers are sent aborts the connection instead of completing a shorter body.

## Bounds (D-10 open; configuration values)

| Bound | Default |
|---|---|
| Ciphertext per version | 256 MiB |
| JSON request body | 1 MiB |
| Initial envelopes per upload | 16 |
| List page size | 100 (maximum 1000) |
| Listing scan budget per page | 5,000 catalog candidates |
| Upload intent lifetime | 1 hour |
| Continuation token lifetime | 15 minutes |

## Listing (CNT-005 to CNT-007)

Listing checks bucket `list`, scans committed heads with a LIVE current version in key order after the cursor, batch-checks `discover` per candidate (50 per decision batch), and returns visible entries until the page is full or the scan budget is used. A short or empty page may carry a continuation. The continuation is sealed with AES-256-GCM under a storage-role key and binds tenant, principal, identity revision, bucket, prefix, policy epoch, recovery incarnation, expiry and the last scanned key; a token presented by anyone else, for another query, after expiry or after an incarnation change is rejected. Delimiters are not supported (CNT-005). Listing has no side effects (CNT-006).
