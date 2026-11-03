# Server-mode documents, text collections and derived outputs (D-12, stretches S4a and S4b)

In a server-mode bucket, the client sends UTF-8 text and reads units as plaintext. The storage role does what the client SDK does in client mode:

- it splits the text under the same profile (`fga.text/nfc-paragraphs-v1`, now `internal/textunits`, which the SDK also uses), so both modes split the same text into the same units;
- it encrypts each unit under its own data key, which the keys role seals ([server-keys.md](server-keys.md));
- it builds the manifest and publishes the version.

Unit-level access is unchanged: each unit is read alone, under its own checks and its own key release (DOC-006, DOC-007). Policy alone decides who reads; there are no envelopes.

## Upload

Readings of sources take the same steps ([mcp-data-tools.md](mcp-data-tools.md)): `POST /v1/sources/{source}/readings` splits a JSON reading under the profile `fga.json/groups-v1`, one unit per field group with the group's label from the source's active version, assigned without a label decision, and stores no original. The manifest records the profile as its normalization version and `fga.source/v1:<source>:<version>` as its extraction version. Each step is its reading twin, which decides `post-reading` in place of `create-object` or `new-version`, and the keys role seals a reading's keys only under the reading's seal (ING-012).

`POST /v1/buckets/{b}/documents/text?key=[&collection=1|&append=1]`

The body is the text (`Content-Length` required, at most 64 MiB), with an optional `Idempotency-Key`. The SDK calls are `PutDocumentText` and `AppendText`; in the CLI, `fga put-document [-collection]` and `fga append` follow the bucket's mode.

1. **Begin.** The document's checks: `create-object` on the bucket for a new key, `new-version` on the document otherwise. For an append, the begin keeps every entry of the collection's current version as a reused unit. If an entry is no longer LIVE, the append is refused rather than dropping that entry. The append names that version as its base, and the begin refuses it (`409 CONFLICT`) unless the version is still current when the begin reads the generation that the publication checks. So an append committed in between is not dropped; the caller begins again under a new idempotency key (review v2 finding 3). A conflict the keys role finds in its fence while sealing, because another append committed after the seal decision, is likewise `409 CONFLICT`.
2. **Seal.** One decision for the keys role, `storage.key.seal-document-create` or `seal-document-version`, carries the document's write check. In one fenced transaction the keys role seals a data key for every new unit intent of the document intent, each bound to its unit's identity. Reused units keep their keys.
3. **Stage.** One single-use staging decision admits the upload (as for client units). Each paragraph is encrypted into its unit's blob (`internal/payload`), and each unit intent records its digest, ciphertext length and plaintext length.
4. **Publish.** The storage role builds the manifest. `cryptowire.MarshalServer` gives it the client manifest's shape, with every unit in suite 1 and the server format. Nobody signs it, and the client parser refuses it.
   - **Decisions:** the client-mode ones. `document.publish-create` or `-version` carries the plan, so a policy can require an approval. Explicit unit labels and reused units are decided in batches. There are no share or envelope checks.
   - **Staged ciphertext:** before deciding, the storage role checks every staged unit and the original in the blob store by length and digest, as in client mode, so a version whose ciphertext was lost or altered while it waited, for instance for an approval, is refused (`409`) and never published (review v5 F08).
   - **Commit:** the same fenced transaction as client mode. The document version stores no signature or signer, units store no descriptor (migration 0018), and each unit version receives its sealed data key from its intent.

**Answers**

- **Success:** `200` with the published version.
- **Approval needed:** `202` with `approval_id` and `intent_id`. Finalize with `POST /v1/document-uploads/{intent}/finalize` and body `{}` (`fga finalize -document`).
- **Retry under the same idempotency key:** it answers with that attempt's outcome. An attempt whose units got their keys but were not all staged cannot be finished; begin again under a new key.

## Read

`GET /v1/buckets/{b}/document/unit/content?key=&unit=[&version=]`

1. **Admission.** The unit read's checks (`document.read-unit` or `collection.entry.read`: `read-units` on the version, `read` on the unit) admit it like a ciphertext unit read.
2. **Release.** The keys role releases that unit's data key against `storage.key.release-unit` or `release-entry`, with the same checks. It checks that the unit is a member of that document version at the unit version named, and that both are LIVE. A version that is not current needs the history twins, with `read-history` on the document; under the plain operations the keys role releases only while the version is still current (DOC-009).
3. **Stream.** The plaintext streams under the read's lease.

The unit listing (`/document/units`) now names the document version it lists, so that `GetDocument` reads every unit from that version. The SDK reads a unit without a client descriptor through the server route. In server mode the content is the server's word (N-09).

## Modes

- **Client-mode routes** refuse server-mode units, after authorization (`409 ENCRYPTION_MODE`): unit ciphertext, unit packages and client finalize.
- **Server-mode routes** refuse client-mode buckets and units in the same way.
- **Unit reuse** stays within one mode.

## Original files and exports (S4b)

**Original files**

- **Upload.** The same route takes `multipart/form-data`: a `text` part, then an optional `original` part streamed straight into encryption (SDK `PutDocumentTextWithOriginal`, CLI `fga put-document -original`). The begin reserves an original intent. The document seal gives it its own data key, it is encrypted into its own blob with no length known in advance, and the manifest names it. A collection has none.
- **Read.** `GET .../document/original/content` (SDK `GetOriginalPlain`, CLI `fga get-original`, which tries the server route first and falls back on `ENCRYPTION_MODE`) needs `raw-read` on the version and `read` on every unit (CNT-003).
  1. The storage role's own complete-content decisions admit the read.
  2. A second set is made for the keys role and goes with the release decision (`storage.key.release-original`).
  3. The keys role checks in `internal/keycheck` that the second set names every unit of the version exactly once. That is the code envelope delivery now uses too. It admits them in the fence of the release, so a unit changed between the storage role's checks and the release yields no key (review finding 3, V-163).

**Exports.** `POST .../document/export/content` with `{"units": [...]}` (SDK `ExportUnitsPlain`) needs `export` and `read-units` on the version and `read` and `export-key` on every unit, all allowed or none (`document.export`). The admission is recorded. Each unit's key is then released under its read checks, and the plaintext returns as JSON, bounded like client exports (32 MiB). Text entries cannot be exported.

## Derived outputs (S4b)

**Upload.** `POST /v1/buckets/{b}/derived/content?key=` takes `multipart/form-data`: a `lineage` part, `{"sources": [{"type", "id", "version"}, ...]}`, then a `content` part streamed straight into encryption with no length known in advance. `Idempotency-Key`, `If-Match`, `If-None-Match` and `Fga-Label` (a proposal that can only raise the label the lineage gives) work as for objects. The SDK call is `PutPlain` with `PutOptions.Lineage`; `fga put -sources` follows the bucket's mode.

1. **Begin and seal.** The derived begin (`create-object` on the bucket, or `new-version` on the output). The keys role seals the version's data key (`storage.key.seal-create` or `seal-derived-version`), and the content is encrypted like an object payload.
2. **Lineage.** The storage role records the declared lineage with the version in the client lineage's shape (`cryptowire.Lineage.MarshalServer`), unsigned. The lineage is bound to the caller's publication decision instead, whose plan names its digest. It is dated when the upload began, so a publication repeated with an approval presents the plan that was approved. The client-mode checks apply:
   - every source exists in the tenant and is LIVE;
   - the bounds hold and there is no cycle;
   - the caller may read every direct source (deliver for a derived source).

   The label is the lineage maximum (DRV-007).
3. **Publish.** `derived.publish-server` or `derived.publish-server-version`: the client-mode checks without envelopes.

**Approval.** `202` with `approval_id` and `intent_id`. Finalize with `POST /v1/uploads/{intent}/finalize` and body `{"sources": [...]}`, the same lineage. The CLI saves that request in the key directory for `fga finalize -request`. Another lineage is another plan, which the approval does not cover.

**Read.** `GET .../derived/content?key=&version=` (SDK `GetDerivedPlain`). `fga get-derived` tries this route first and falls back to the client route on `ENCRYPTION_MODE`. There is no recipient key. The reader needs `deliver` on the output and a reader path of their own (DRV-002), either of:
- read (deliver for derived sources) on every source of the transitive lineage;
- failing that, `derived.declassify-reader`: `deliver` and `declassify` on this output version.

The storage role admits the read with those decisions. The keys role then releases the data key against `storage.key.release-derived`, with a second reader path decided for it. `internal/keycheck` (`ReaderPath`) checks that this path covers exactly the transitive lineage, or is a declassification of this very version, and the keys role admits it in the fence of the release. A source change while the output's own authority holds ends the stream (V-145), as in client mode.

So in server mode a member who may read every source reads the output with no sharing step. A member who loses a source loses the output (DRV-009) unless it is declassified for them.

## Tests

| Test | Covers |
|---|---|
| `internal/content` `TestServerDocument` | Splitting, sealing and publishing without signatures or descriptors; reads by policy alone; a unit raised to `restricted` leaving another member's view while the owner still reads it; a retry; a second version; mode refusals in both directions |
| `TestServerCollection` | Create, append keeping entries, an append retry, a member without `new-version`, appending to a document, a withdrawn entry |
| `TestConcurrentServerAppends` | Two writers appending concurrently, beginning again on conflict: every acknowledged entry is kept |
| `internal/datakeys` `TestReleaseUnit` | A unit's decision opens no other unit; a unit outside the version; another operation; audit |
| `TestServerOriginal` | Original upload and read, a member without `raw-read`, V-163, exports |
| `internal/datakeys` `TestReleaseOriginal` | A release without every unit, or with a unit named twice, is refused |
| `internal/nativeapi` `TestServerDocumentsHTTP` | The routes and SDK end to end, including a multipart upload with an original and an export |
| `TestServerDerived` | Lineage recorded unsigned; the label from the lineage; a member reads by their own path and loses it when a source is restricted; a lead reads by declassification, and her stream ends when a source changes; a retry; mode refusals |
| `TestServerApprovals` | An approved publication finalized with its lineage; another lineage is not covered (objects too) |
| `TestServerDocumentVerifiesStagedBlobs` | A document held for an approval whose staged unit, or original, is gone from the blob store is not published (review v5 F08) |
| `TestExportSizeAfterAuthorization` | An export over 32 MiB is too large only to a caller who may export it; to anyone else not found, as a missing key (review v5 F07) |
| `internal/datakeys` `TestReleaseDerived` | A path over another source, no path, or another output's declassification releases no key |
| `internal/nativeapi` `TestServerDerivedHTTP` | A multi-segment output streamed with its lineage and read by another member; a repeated finalize by sources; malformed uploads |
| `scripts/smoke.sh` | A server-mode document and an appended collection read by another member; an original the owner reads and another member may not; a derived output another member reads through their own read of the source |
