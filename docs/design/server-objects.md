# Server-mode objects (D-12, stretch S3)

In a server-mode bucket (the default since specification 2.6, [D-12](../decisions/D-12-encryption-modes.md)), the client sends and receives plaintext over TLS. The storage role encrypts each version as it arrives and decrypts it for an authorized read. Both use a data key that the keys role seals for the upload and releases for the read, each against its own decision ([server-keys.md](server-keys.md)). Who may read is decided by policy alone: there is no recipient key, envelope or sharing step.

## Routes

| Route | Operation and checks |
|---|---|
| `GET /v1/buckets/{b}/encryption` | Bucket `list` (`storage.bucket.list`); the answer is `{"encryption": "server"}` or `{"encryption": "client"}` |
| `PUT /v1/buckets/{b}/object?key=` | Plaintext body with `Content-Length`. Optional headers: `Idempotency-Key`, `If-Match`, `If-None-Match: *`, `Fga-Label`. See the upload steps below |
| `GET /v1/buckets/{b}/object/content?key=[&version=]` | Admission like a ciphertext read (`storage.object.read`, or `read-history` for an older version), then release; the body is plaintext with `Content-Length`, `ETag` and `Fga-Version-Id` |
| `GET /v1/buckets/{b}/object/export?key=[&version=]` | `storage.object.export` (`export` and `read`, plus `read-history` for an older version), then release; the body is plaintext |
| `POST /v1/uploads/{intent}/finalize` with body `{}` | Publishes a staged server-mode upload, for instance once its approval is given |

**Upload steps**

1. **Begin.** The same checks as a client-mode begin: `create-object` for a new key, `new-version` for an existing one.
2. **Seal.** The keys role seals a data key for the intent (`storage.key.seal-create` or `seal-version`).
3. **Stage.** Admitted by a single-use decision (`storage.object.stage-create` or `stage-version`) and run under the upload lease.
4. **Publish.** `storage.object.publish-server-create` (with `-labeled` for an explicit label) or `publish-server-version`. The checks are the write's, without envelope checks, and the operation carries a plan.

The answer is `200` with the published version, or `202` with `approval_id` and `intent_id` when the publication needs an approval.

Stat, listing, labels, deletion and approvals are shared with client mode. Stat now also reports `encryption` and, for a server-mode version, the plaintext `length`.

Each route serves its own mode only (ENC-002). After authorization, a client-mode route answers `409 ENCRYPTION_MODE` for a server-mode bucket or version, and a server-mode route does the same for a client-mode one.

## Payload

The cipher is `internal/payload`: Tink's streaming AEAD AES-256-GCM-HKDF with 1 MiB segments, keyed with the data key. The associated data binds tenant, object, logical version, crypto version and blob under the domain `fga-server-payload/v1`. Versions record suite 1 and format 2. The byte layout is in the [crypto format companion](../spec/crypto-format-profile.tex).

**Upload**

- The body is encrypted as it arrives into the staged blob, whose exact size `payload.CiphertextSize` gives in advance. No plaintext reaches a blob, temporary file or spill (SSE-005).
- The intent records the ciphertext digest and length and the plaintext length. Publication moves the sealed data key from the intent to the version.
- A server-mode version has no client signer or descriptor. Migration 0017 adds `plaintext_length`.

**Read**

- The blob is opened against its recorded digest and decrypted segment by segment under the read lease.
- A failed authentication, digest, truncation or lease makes the stream fail, and the HTTP handler aborts the response instead of completing a shorter one (V-164, V-165).
- The data key is cleared when the stream is set up; Tink holds its own copy for the stream.

## Retries and approvals

- **Retry with the same `Idempotency-Key`.** It answers with the attempt's outcome: the committed version, or the publication of a staged upload. The body is then ignored.
- **Retry after an unfinished attempt.** If the attempt got its data key but did not finish staging, it cannot get the key again; the client begins again under a new key (CRY-007, SSE-005).
- **Approval.** If publication needs one, the staged upload is kept. The client repeats with `Fga-Approval`, either by finalizing the intent (`fga finalize -intent I -approval A`) or by sending the same `PUT` again.

## SDK and CLI

**SDK.** `client.BucketEncryption`, `PutPlain`, `GetPlain` and `ExportPlain`. `FinalizeUpload(intent, nil)` sends `{}`.

**CLI.**

- `fga put` asks for the bucket's mode. In server mode it uploads plaintext and refuses `-to` and `-sources`; derived outputs in server mode come with S4.
- `fga get` stats the version and uses its mode, so a bucket that changed mode still reads older versions through their own route.
- A caller who may not list or stat is answered as for client mode, and the server still refuses the wrong route.

## Roles and imports

The storage role links `internal/payload` and Tink's `streamingaead`, and no KEK code. The keys and decision roles may not link the payload cipher (`depcheck.PayloadCipher`), and only the keys role links the KEK code (`depcheck.KeyEncryption`).

## Tests

| Test | Covers |
|---|---|
| `internal/payload` | Exact ciphertext size across segment boundaries; key and identity binding; corruption and truncation |
| `internal/content` `TestServerObjects` | Round trip, a read by policy alone, a retry, overwrite, history, stat, export, delete, conditions, and each route refusing the other mode (V-155, V-156) |
| `TestServerObjectRetry` | A short body; an unfinished attempt is not retried under the same key |
| `TestServerApprovals` | A publication held for an approval, publishing nothing, then finalized (with derived outputs, server-documents.md) |
| `TestServerPayloadAtRest` | No plaintext in blobs or the catalog and no data key in audit records (V-168); a corrupted blob (V-164) and another version's ciphertext (V-165) do not read |
| `internal/nativeapi` `TestServerModeHTTP` | The routes and SDK over HTTP, with data keys over the keys role's internal route; the stream is aborted on corruption |
| `scripts/smoke.sh` | Server-mode upload and a read by another member; a bucket switched to client mode reading both versions; no plaintext in blobs |

## Later stretches

Server-mode documents, units, originals, collections and derived outputs (S4, [server-documents.md](server-documents.md)), share grants (S5, [share-grants.md](share-grants.md)) and the recovery of server-mode data (S6, [server-keys.md](server-keys.md)) are built.
