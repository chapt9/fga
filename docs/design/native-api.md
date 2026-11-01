# Native storage API v1 (CNT-009, Table "Native storage operations")

Status: design record, 31 October 2026. The machine-readable contract is [native-api.openapi.yaml](native-api.openapi.yaml); this record explains the rules it encodes. Implemented by `internal/nativeapi` (storage role) and `internal/envelope` (keys role), both delegating to the shared services (CNT-001, CNT-002).

## Roles and audiences

| Role | Binary | Token audience | Serves |
|---|---|---|---|
| storage | `fga-storage` | `fga-storage` | Uploads, reads, stat, listing, deletion |
| keys | `fga-keys` | `fga-keys` | Recipient and content-signing key registry, envelope publication and retirement; internal envelope delivery to the storage role |

Every request carries `Authorization: Bearer <access token>` ([first-hop authentication](first-hop-authentication.md)). Every role reads the scheme in any case (RFC 9110; `authn.Bearer`, audit F8). The one exception is the MCP role's call for a user (TB3). It comes from a configured MCP workload with no bearer token, and carries in `Fga-Decision` the decision the MCP role obtained for the user's MCP tool call. Every route then checks it as for the user ([mcp-gateway.md](mcp-gateway.md)). Bucket creation is a control operation performed with `fga-admin` (ADM-003); clients cannot set authority metadata.

## Operations

Object keys travel in the `key` query parameter, never in the path, so Go's `ServeMux` path cleaning cannot change them (LIB-001). Keys are 1 to 1024 bytes of valid UTF-8 without NUL; bucket names match `^[a-z0-9][a-z0-9-]{2,62}$`.

| Operation | Method and path | Checks (registered operation) |
|---|---|---|
| Begin upload | `POST /v1/buckets/{bucket}/uploads` | An explicit `label` is accepted for a new key only (in the order, not below the floor). New key: bucket `create-object` (`storage.object.begin-create`). Existing key: object `new-version` (`storage.object.begin-version`). An idempotent retry takes the same decision again; it is never answered from the stored intent alone |
| Upload ciphertext | `PUT /v1/uploads/{intent}/ciphertext` | Owner of the intent (same tenant, subject and actor) and a fresh single-use decision: bucket `create-object` (`storage.object.stage-create`) or object `new-version` (`storage.object.stage-version`), consumed in the fence; an identical retry needs it too. Bytes are staged only. The body streams under a lease that aborts on any change to the bound authority; it is not cut at the decision's `valid_until`, because staged bytes stay invisible until a commit with its own decision |
| Finalize | `POST /v1/uploads/{intent}/finalize` | Fresh decision: `create-object` or `new-version`, plus per initial envelope: publisher `share` on the object and `create` on the planned envelope, recipient `read` and `receive-key` (`storage.object.publish-create` or `-version`); with an explicit label also `label` on the planned object (`storage.object.publish-create-labeled`) |
| Stat | `GET /v1/buckets/{bucket}/object?key=&version=` | `stat`; a non-current version also `discover-history` |
| Package | `GET /v1/buckets/{bucket}/object/package?key=&version=&recipient=` | Storage: `read` (+ `read-history`). Keys role: `GetRecipientEnvelope` checks (caller `read`, envelope `release`, recipient `read`, `receive-key`) |
| Ciphertext | `GET /v1/buckets/{bucket}/object/ciphertext?key=&version=` | `read` (+ `read-history`); admission and stream lease |
| List objects | `GET /v1/buckets/{bucket}/objects?prefix=&limit=&continuation=` | Bucket `list`, then per entry `discover` |
| List versions | `GET /v1/buckets/{bucket}/object/versions?key=&limit=&continuation=` | Bucket `list`, object `discover`, and `discover-history` for non-current entries. Pages of at most `limit` (default 100), newest first, with a continuation bound to the caller and the key (review v3 F11). The head and the versions are read in one snapshot after the decisions, and the listing starts again if the head moved, so an old version is never shown as current (F10) |
| Delete key | `DELETE /v1/buckets/{bucket}/object?key=` | `delete`; writes a delete marker |
| Delete version | `DELETE /v1/buckets/{bucket}/object?key=&version=` | `delete-version`; retention and reference guards |
| Enroll recipient | `POST /v1/recipients`, then `POST /v1/recipients/{fp}/activate` | `crypto.recipient` `enroll`, then `activate`, with possession proof |
| Revoke recipient | `DELETE /v1/recipients/{fp}[?confirm_unreadable=true]` | `crypto.recipient` `revoke`. The last key that opens some client-mode files answers `409 LAST_READER` with their number per bucket until confirmed ([admin-api.md](admin-api.md), "Last readers") |
| Content-signing keys | `fga-admin signing-key add`, `retire`, `compromise` | Trusted provisioning by the local administrator (RCP-002). Each key is also a `crypto.signing-key` resource whose only action is `discover`, so a self-service operation fails closed (RES-001) |
| Look up a key | `GET /v1/recipients/{fp}`, `GET /v1/signing-keys/{fp}` | `crypto.recipient` `discover` (`crypto.recipient.discover`; a PENDING key is decided as its planned resource) or `crypto.signing-key` `discover` (`crypto.signing-key.discover`), with a fence check. Without a rule the lookup is denied (ruling 7). A directory answer is not a trust anchor (RCP-002) |
| Set a label | `PUT /v1/buckets/{bucket}/object/label?key=` | Object `label` (`storage.object.label`) to raise or keep, `relabel` (`storage.object.relabel`) to lower, on the proposed change `change.label` (labels-and-approvals.md) |
| Bucket encryption mode | `GET /v1/buckets/{bucket}/encryption` | Bucket `list` (`storage.bucket.list`); answers the mode |
| Server-mode upload | `PUT /v1/buckets/{bucket}/object?key=` (plaintext body) | Begin, data-key seal, staging and publication (`storage.object.publish-server-*`), as in server-objects.md; `202` names the approval and the intent |
| Server-mode read | `GET /v1/buckets/{bucket}/object/content?key=&version=` | Object `read` (plus `read-history` for an older version), then data-key release (`storage.key.release*`); plaintext body |
| Server-mode text | `POST /v1/buckets/{bucket}/documents/text?key=[&collection=1\|&append=1]` (UTF-8 body) | Document begin, document data-key seal (`storage.key.seal-document-*`), staging and the document publication decisions, as in server-documents.md; `202` names the approval and the intent |
| Server-mode original | `GET /v1/buckets/{bucket}/document/original/content?key=&version=` | Complete-content decisions for the storage role, then for the keys role with `storage.key.release-original`, admitted in the release fence (V-163); plaintext body |
| Server-mode unit export | `POST /v1/buckets/{bucket}/document/export/content?key=&version=` `{"units": [...]}` | `document.export`, then each unit's release; plaintext units as JSON |
| Server-mode unit | `GET /v1/buckets/{bucket}/document/unit/content?key=&unit=&version=` | The unit read's checks, then the unit's data-key release (`storage.key.release-unit` or `-entry`); plaintext body |
| Server-mode export | `GET /v1/buckets/{bucket}/object/export?key=&version=` | Object `export` and `read` (`storage.object.export`), then release; plaintext body |
| Server-mode derived upload | `POST /v1/buckets/{bucket}/derived/content?key=` (multipart: `lineage` `{"sources": [...]}`, then `content`) | Derived begin, data-key seal, staging and publication (`derived.publish-server*`) with the declared lineage, as in server-documents.md; `202` names the approval and the intent, finalized with `{"sources": [...]}` |
| Server-mode derived read | `GET /v1/buckets/{bucket}/derived/content?key=&version=` | `deliver` and the caller's reader path, then the data-key release (`storage.key.release-derived`) with a reader path the keys role checks in its fence; plaintext body |
| Share grants | `POST /v1/buckets/{bucket}/grants?[key=&version=&unit=]` `{"grantee","actions","expires_at"}`, `DELETE …/grants?…&grantee=`, `GET …/grants?…` | `share` on the bucket, object, document version, unit, entry or derived output (`<type>.record-grant`, `-remove-grant`, `-list-grants`); recording resolves `change.grant`, which shows the grantee and the grant to policy; see share-grants.md |
| Set a bucket's encryption mode | `PUT /v1/buckets/{bucket}/encryption` | Bucket `manage` (`storage.bucket.set-encryption`) on the proposed change `change.encryption`, which shows `new_encryption` to policy; applies to uploads begun afterwards (encryption-modes.md) |
| Propose a label | `POST /v1/buckets/{bucket}/object/label-proposals?key=` | Object `propose-label` (`storage.object.propose-label`); advisory only |
| Who am I | `GET /v1/me` | `principal.self` `read` (`principal.self.read`) on the caller's own record, resolved from its identity as `planned.self` and never stored, so the fence finds it absent. Answers the caller's `id`, `roles`, `attributes`, `disabled`, `expires_at` and `capabilities`, never another identity's; refused (`400`) under a delegation. `principal.self` is our addition to the spec's action table, approved by the owner on 1 November 2026, for a console that shows each person only what their rights allow |
| List approvals | `GET /v1/approvals?after=&limit=` | Per pending approval, a fresh `approve` decision on its target (`storage.object.approve` or `storage.bucket.approve`); others are left out |
| Decide an approval | `POST /v1/approvals/{id}` | Single-use `approve` decision on the target, under the fence; never by the requester or acting agent |
| Begin a document | `POST /v1/buckets/{bucket}/documents` | New key: bucket `create-object` (`document.begin-create`); existing document: `new-version` (`document.begin-version`). Returns one unit intent per new unit (documents.md) |
| Finalize a document | `POST /v1/document-uploads/{intent}/finalize` | The batches of documents.md (`document.publish-*`, `document.label-units`, `document.reuse-units`, `document.share-version`, `document.share-units`), admitted together by the fence; body up to 48 MiB |
| Disclose units | `POST …/document/units/select`, `GET …/document/units`, `GET …/document/manifest`, `GET …/document/unit/package`, `GET …/document/unit/ciphertext` | See documents.md, "Implementation (step 4)" |
| Original file | `GET …/document/original/package`, `GET …/document/original/ciphertext` | `raw-read` on the version and `read` on every unit; the keys role releases the envelope against `raw-read` for caller and recipient (CNT-003) |
| Derived outputs | Begin with `"derived": true`, finalize with `lineage` and `lineage_signature`; `GET …/derived/package`, `GET …/derived/ciphertext`, `POST …/derived/envelopes` | See derived-outputs.md, "Implementation" |
| Export units | `POST /v1/buckets/{bucket}/document/export?key=&version=` | `document.export`, then per unit `document.export-envelope` at the keys role (documents.md, step 6) |
| Search documents | `GET /v1/buckets/{bucket}/documents/search?prefix=&project=&max_label=` | Bucket `list`, then `discover` per candidate version (`document.search`) |
| Share | `POST /v1/envelopes` | `PublishRecipientEnvelope`: publisher `share`, envelope `create`, recipient `read`, `receive-key` |
| Retire envelope | `DELETE /v1/envelopes/{id}` | envelope `retire` |

Range requests are rejected (`Range` header present: 400). Copy, multipart and presigned URLs do not exist.

## Write sequence

1. Begin: the storage role resolves the key, obtains a decision, and records an upload intent with fresh object (new keys only), logical-version, crypto-version, blob and attempt IDs, the expected head generation, the planned protected attributes and the idempotency key. An identical retry returns the same intent; a different request under the same idempotency key is a conflict.
2. The client encrypts with the returned IDs, signs the descriptor and envelope contexts, and uploads the ciphertext. `Content-Length` is required and bounded; `Fga-Ciphertext-Sha256` names the digest. The backend checks both and returns a durable receipt. Repeating identical bytes returns the same receipt; different bytes for the same blob conflict.
3. Finalize: the server verifies the descriptor, envelopes and signer, obtains a fresh decision, and commits under the [authority fence](authority-fence.md): head generation and `If-Match`/`If-None-Match` preconditions, intent state, all bound revisions, consumption, version LIVE, envelopes, head pointer, intent COMMITTED, audit. A finalize that already succeeded returns the stored result after a fresh `stat` check of the caller.

## Conditional writes

Preconditions are sent at begin (`if_match` with an ETag, or `if_none_match: "*"`) and evaluated only at commit inside the fence, after authorization (PUB-007). `If-None-Match: *` means "no current live version at commit"; a key whose head is a delete marker accepts a new version. A derived output's new version is held to them the same way, and a key another upload created since begin fails `If-None-Match` with `412` on every route (review v5 F05). An ETag is `"` + logical version ID + `"`: opaque, never an MD5 or plaintext hash.

## Errors

Every error body is `{"error": CODE}` with no protected identifiers.

| HTTP | Code | When |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed body, parameters, descriptor or envelope; range request |
| 401 | `UNAUTHENTICATED` | Missing or invalid token |
| 404 | `NOT_FOUND` | Absent target, **and** any policy denial of an object, version or bucket operation (DEC-010, CNT-004): absent and denied look the same |
| 409 | `CONFLICT` | Idempotency mismatch, intent in the wrong state, different bytes for a blob, stale authority after a bounded retry |
| 409 | `ENCRYPTION_MODE` | The bucket or version is in the other encryption mode than the route serves (ENC-002); only the routes above marked server-mode serve server-mode objects, documents, collections and derived outputs. Only an authorized caller gets it; anyone else gets `NOT_FOUND` |
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

## Approvals on the wire

Finalize, delete, version delete and label changes carry a plan (labels-and-approvals.md). When a policy allows such an operation only with an approval, the answer is `202` with `{"status":"APPROVAL_REQUIRED","approval_id":"…"}`; nothing changes. After an approver approves it, the caller repeats the same request with the header `Fga-Approval: <id>`. A pending approval answers `202` again with the same ID. An approval that does not cover the request (rejected, expired, consumed, another requester, operation, digest, policy epoch or resource state) answers `409 APPROVAL_NOT_USABLE`. A finalize keeps its staged ciphertext, so only the finalize request is repeated.
