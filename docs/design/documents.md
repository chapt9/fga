# Documents and text units (DOC-001 to DOC-008, CNT-003, DSC-001 to DSC-005, SRH-001 to SRH-004)

Status: design record, 31 October 2026. Our own design; no upstream mapping. Default deny (ruling 7) applies to every operation below. Publication of text units and the original file, and their disclosure, are implemented (R1-C steps 3 and 4, see "Implementation" below). Export, search and text entries follow in step 6.

## Model

| Concept | Catalog | Resource type (policy) |
|---|---|---|
| Document | An `objects` row of kind `document` under its bucket and key | `storage.object` (create-object on the bucket, new-version, delete, delete-version, approve) |
| Document version | A `document_versions` row: signed manifest, its digest, signer, optional original, extraction and normalization versions, state | `document.version` (read-units, raw-read, discover, share, export, approve) |
| Unit | An `objects` row of kind `unit` with one immutable `object_versions` row: its own ciphertext and keyset | `document.text_unit` (read, share, use-in-model, export-key, label, relabel, approve), or `text.entry` for entries of a text collection (DOC-005) |
| Original file | An `objects` row of kind `original` with one version: the whole encrypted original, under its own keyset | Guarded through its document version |
| Membership | `document_units`: document version, position, unit, unit version, signed unit descriptor | |

Objects of kind `unit` and `original` never appear in object listings or the object API; a key of kind `document` is read only through the document API. Units carry their own protected label (LAB-001) and are ordinary encrypted objects in the blob store (KEY-001).

## Formats (client encryption wire profile 2)

- **Manifest core** (`fga.manifest/v1`, strict JSON, signed with a detached JWS of type `fga-manifest+jws`): tenant, document, document version, extraction and normalization versions, the original's version and digest if present, and the ordered unit entries (unit, unit version, crypto version, ciphertext digest and length, suite, format). The manifest digest is SHA-256 of `"fga.manifest/v1"`, a zero byte and the core bytes, computed before descriptors or signatures exist (DOC-001).
- **Unit descriptor** (`fga.unit-descriptor/v1`, type `fga-unit-descriptor+jws`): tenant, document, document version, manifest digest, unit, unit version, crypto version, blob, ciphertext digest and length, suite, format, signer. A client given a subset verifies each unit through its descriptor without the full manifest.
- **Envelope context, profile 2:** the profile-1 fields 1 to 14 with `profile_version = 2`, plus field 15 document, 16 document version and 17 manifest digest, all required. Profile 1 keeps rejecting fields 15 to 17. An envelope for a unit therefore names exactly one unit version, one recipient and one document version; two document versions that reuse a unit have distinct envelope contexts (RCP-005, V-152). The HPKE plaintext is the unit's single-keyset key package (DOC-007).

## Publication (DOC-002, DOC-003, DOC-004)

1. **Begin:** a document intent allocates the document version and one unit intent per new unit (and one for the original if any). It needs `create-object` on the bucket or `new-version` on the document. Bounds: 1,000 units per document version.
2. **Client:** splits bounded UTF-8 text or Markdown at paragraph boundaries after NFC normalization (recorded as `normalization_version`), encrypts each unit with a fresh keyset, stages each unit's ciphertext through its unit intent, and signs the manifest and the unit descriptors and envelopes. Parsing and splitting never happen on the server.
3. **Finalize:** the server verifies every signature and binding and reuses existing units only with `read` on them. It obtains decisions for:
   - the document;
   - each explicit label;
   - per recipient, `share` on the document version and the recipient's `read-units` on it;
   - per unit and recipient, `share` on the unit, `create` on the planned envelope, and the recipient's `read` and `receive-key`.

   Checks are split into batches of at most 50 (DEC-009).
4. **Commit:** one transaction under the authority fence consumes every batch's decision and publishes all new unit versions, the original, the manifest, membership, envelopes and the document's current version together. If anything is missing, nothing is visible (V-063).

**References.** A unit version referenced by a live document version cannot be withdrawn or reclaimed (V-064); reclamation checks membership as well as retirements.

## Disclosure (DOC-006, DOC-007, DSC-001 to DSC-005, CNT-003)

| Request | Checks | Result |
|---|---|---|
| Explicit unit IDs | `read-units` on the document version and `read` on every named unit | All named units, or a generic denial if any is denied (V-054) |
| Authorized subset | `read-units` on the document version; `read` per unit, decided one by one | Only permitted units, with an opaque continuation; no hidden IDs, positions or counts (V-055, V-070) |
| Unit package | The unit's checks plus GetRecipientEnvelope for the caller's key | Ciphertext, unit descriptor and the caller's existing envelope |
| Full manifest | `read-units` and `read` on every unit | The signed manifest, only when every entry may be disclosed |
| Original file | `raw-read` on the document version and `read` on every unit (complete content) | The original's ciphertext and envelope; never inferred from unit reads (CNT-003, V-052, V-053) |

"Every unit" for the full manifest and the original file means every unit the version lists, whatever its state: a unit quarantined after a restore is still named by the manifest and still in the original, so it is still checked. A check set is never empty; the version's own check is always decided (review v3 F05).

Deliveries are audited with unit, version, recipient and digests, never plaintext (DSC-003).

## Export (Table "Compound operations", V-132 to V-136)

Remote package export delivers ciphertext and existing envelopes to another recipient. It needs `export` on the document version (or object), `export-key` on each selected unit, the applicable read checks and the full GetRecipientEnvelope set for the target recipient. The target must already have an envelope; the server never creates or rewraps one. A decision lacking any required check, such as `receive-key`, is refused (V-136).

## Metadata search (SRH-001 to SRH-004)

Search filters documents by permitted catalog metadata only: bucket, key prefix, project, label rank. Each candidate gets an exact `discover` decision on its document version, so results, order and totals depend only on what the caller may see. There is no plaintext, snippet or embedding search on the server. Clients search plaintext locally after decrypting.

## Text entries (DOC-005)

A text collection or conversation is a document whose units have type `text.entry` (read, use-in-model, update). An update is a new document version that replaces or appends entries; there is no separate transcript store.

## Implementation (step 3)

**Catalog.**
- `objects.kind` is `object`, `document` or `unit`.
  - Keys are unique among objects and documents only. A unit has an empty key and is reached only through a document version.
  - The object API, listings and sharing select `kind = 'object'`, so a document key is invisible to them. An object upload over a document key, and a document over an object key, conflict.
- A document is a `storage.object` resource with `kind: document`. Its head is `objects.current_document_version`, which is deferrable like the object head so that restore can load it.
- `document_versions`, `document_units` (position, unit version, document-specific descriptor) and `envelopes.document_version` hold the rest. Envelope uniqueness includes the document version, so a reused unit gets envelopes of its own per document version (V-152).

**Intents.** `document_intents` reserves the document version and records the unit plan per position. Each new unit gets an `upload_intents` row of kind `unit`, which the client stages with the ordinary ciphertext route. Staging needs the document's right (`create-object` on the bucket, or `new-version` on the document), decided fresh and consumed in the fence like any upload. Object finalize refuses unit intents. A reused unit's plan carries its ciphertext digest and length, its blob and its crypto version, so begin first decides `document.reuse-units` (`read` on each reused unit, below) and returns nothing of a unit the caller may not read; a retry under the same idempotency key decides it again (review v5 F06).

**Decisions.** Finalize verifies:
- the manifest's signature by an active signing key of the caller, and that it names exactly the intent's document version and units in order;
- each unit's staged receipt (or, for a reused unit, its LIVE version);
- each unit descriptor, signed by the same key and bound to the manifest digest;
- each profile-2 envelope, with generation 1, distinct recipients and the recipient's current key version.

It then asks for these registered operations, packing check groups into batches of at most 50 checks without splitting a group:

| Operation | Checks |
|---|---|
| `document.publish-create` or `document.publish-version` | `create-object` on the bucket or `new-version` on the document |
| `document.label-units` | `label` on each new unit with an explicit label |
| `document.reuse-units` | `read` on each reused unit |
| `document.share-version` | Per recipient: `share` on the planned document version, and the recipient's `read-units` on it |
| `document.share-units` | Per unit and recipient: `share` on the unit, `create` on the planned envelope, the recipient's `read` on the unit and `receive-key` on its key |

**Commit.** The fence admits all batches together (`fence.RunAll`): every decision's facts are checked in one lock order and every decision is consumed in the same transaction. The commit then:
- creates or advances the document;
- inserts the document version, the new units (objects, resources and LIVE versions) and the membership;
- inserts the envelopes and moves the head;
- consumes the intents;
- checks that reused unit versions are still LIVE.

One `DOCUMENT_PUBLISHED` audit event names the document, the version and every unit version. Envelopes are not listed in it individually.

**Labels.**
- A new unit takes the document's label, or an explicit label in the order and not below the bucket's floor (checked with `label`).
- A reused unit keeps its label.
- A new document takes the bucket's default.
- The decision and release sentinels see the computed ranks, so a policy can keep restricted units from a recipient. A document with such a unit cannot be published to that recipient at all (V-063).

**Approvals.** Publication sends its plan on the document's create-object or new-version check ([labels-and-approvals.md](labels-and-approvals.md)). Its other batches (unit labels, reused units) send none, so a policy that holds them for an approval denies them.

**Client.** `crypto.SplitText` normalizes to NFC and splits at blank lines (`fga.text/nfc-paragraphs-v1`, at most 64 MiB and 1,000 units). Each unit is encrypted with its own keyset (`crypto.EncryptUnit`). `crypto.SealDocument` signs the manifest, the descriptors and the envelopes. `crypto.DecryptUnit` verifies one unit from its descriptor without the manifest. `client.PutDocument` and `fga put-document` run the whole flow.

**API.** `POST /v1/buckets/{bucket}/documents` (begin), then `PUT /v1/uploads/{unit intent}/ciphertext` per new unit, then `POST /v1/document-uploads/{intent}/finalize`. The finalize body may be up to 48 MiB.

## Implementation (step 4: disclosure of units)

| Route | Operation and checks | Result |
|---|---|---|
| `POST /v1/buckets/{b}/document/units/select?key=&version=` with `unit_ids` (at most 100, distinct) | `document.select-units`: `read-units` on the version and `read` on every named unit, in batches | All named units, or `404` if any is absent or denied, with no hint which (V-054) |
| `GET /v1/buckets/{b}/document/units?key=&version=&limit=&continuation=` | Per batch of members the same operation; on a denial, one decision per unit | Permitted units in document order. The continuation is sealed and bound to the caller, its identity revision and the document version; no positions or totals (V-055, V-070) |
| `GET …/document/manifest` | `document.manifest`: `read-units` and `read` on every unit | The signed manifest, only if every unit may be disclosed |
| `GET …/document/unit/package?unit=&recipient=` | `document.unit.read` (`read-units`, `read`), then for the keys role `document.unit.get-envelope`: those two, the envelope's `release`, and the recipient's `read-units`, `read` and `receive-key` | The unit's descriptor for this document version and the recipient's existing envelope with a delivery receipt. The keys role delivers a unit envelope only for this operation, bound to the envelope's document version, unit, version and recipient, and only while unit and document version are LIVE |
| `GET …/document/unit/ciphertext?unit=` | `document.unit.read`, single use, admitted under the fence with a read lease | The unit's exact ciphertext |

Entries carry the unit ID, unit version, ciphertext length and signed descriptor, never a position. `client.GetDocument` and `fga get-document` fetch the permitted units and verify each with `crypto.DecryptUnit`. A document key is never served by the object routes.

## History (DOC-009 to DOC-011)

Older versions of a document are a right of their own, as for objects ([mcp-data-tools.md](mcp-data-tools.md)):
- **Checks.** Disclosing a version that is not the document's current one also needs `read-history` on the document, its `storage.object`. Every disclosure has a history twin, named after it with `-history`, that adds this check last: unit listings and selections, the manifest, unit reads and packages, the original, exports, and the keys role's releases and envelope deliveries, in both modes. A unit listing of an older version needs `discover-history` for its gate.
- **Mid-read.** A read decided for the current version is admitted only while that version is still current: the storage role rechecks it in its admission fence (`409 CONFLICT`), and the keys role in its release fence. A history read binds the document, so a newer version makes it stale too, and the reader reads again.
- **Listing.** `GET /v1/buckets/{b}/document/versions?key=&limit=&continuation=` lists LIVE versions newest first, each with `document_version_id`, `published_at` and `current`. `discover` on the current version admits it; every entry needs `discover` on its version, and older entries also `discover-history` on the document. Others are left out without a count. The continuation is sealed and bound as for object version listings, and the listing starts again when the head moves.
- **Publication time.** Every new document version carries `published_at`, the server's commit time in RFC 3339 UTC, as a protected attribute. Rules may compare it with a fixed date, guarded with `has()`. A window relative to `request.now` is refused by the engine, which bounds a decision's validity only by timestamp literals (POL-008).

## Implementation (step 4: the original file, CNT-003)

**Publication.** A document intent may reserve an original (`"original": true`): an upload intent of kind `original` staged like a unit. The manifest's `original` entry names its object, version, digest and length. Finalize carries its object descriptor (`fga.descriptor/v1`) and profile-2 envelopes, which name the document version and manifest. Per recipient, `document.share-original` decides:
- `share` on the version;
- `create` on the envelope (planned as `docintent:<intent>|<fingerprint>|<envelope>`);
- the recipient's `raw-read` on the version;
- the recipient's `receive-key`.

The original is an `objects` row of kind `original` without a key or a resource of its own, linked from `document_versions.original`. Its key is its own: no unit envelope opens it (the AAD and context name the original).

**Disclosure.** `GET …/document/original/package?recipient=` and `GET …/document/original/ciphertext` need `document.raw-read`: `raw-read` on the version and `read` on every unit, in batches. The read is admitted under the fence over all batches together, with a read lease over their merged binding. The keys role then releases the original's envelope against `document.original.get-envelope`:
- `raw-read` for the caller and the recipient;
- the envelope's `release`;
- `receive-key`.

The keys role delivers it only if the envelope is that version's original, and never a unit envelope under this operation. For the package, the complete-content decisions are issued for the keys role and sent with the release. The keys role checks that they are single-use `document.raw-read` decisions of the same actor on this version and that together they name every unit version exactly once. It admits them in the same fence as the release, so a unit change between the storage role's checks and the release blocks it (review finding 3). A member who may read some units but not all, or who lacks `raw-read`, gets no original (V-052, V-053) and can still read the units it may. `client.GetOriginal`, `fga put-document -original` and `fga get-original` use these routes.

## Implementation (step 6: export and metadata search)

**Export.** `POST /v1/buckets/{b}/document/export?key=&version=` with `unit_ids` (at most 100, distinct) and the target `recipient`.
- The storage role decides `document.export` in batches: `export` and `read-units` on the version, `read` and `export-key` on each unit.
- For each unit, the keys role releases the target's existing envelope against `document.export-envelope`. That decision carries the same caller checks plus the envelope's `release` and the target's `read-units`, `read` and `receive-key`.
- The keys role accepts only that exact check set, bound to the envelope's document version, unit, version and recipient. A decision of any other operation, or one lacking a check such as `receive-key`, is refused (V-136).
- The ciphertext is admitted under the fence over all storage decisions and returned inline, at most 32 MiB per package. The size is compared with that bound only after the storage role's decisions, so a caller who may not export the units gets the generic `404` whatever their size (review v5 F07). Object exports and server-mode unit exports do the same.
- The target must already have an envelope: the server never creates or rewraps one. Any denial, or a missing envelope, is a generic `404` (V-132 to V-135).
- Releasing someone else's envelope needs a `release` rule. The fixture and example policies let an owner release envelopes of its own content for export.

**Object export.** `POST /v1/buckets/{b}/object/export?key=&version=` with the target `recipient` exports one object version. It uses `storage.object.export`: `export` and `read` on the object, plus `read-history` for a version that is not current. `export` on `storage.object` is our addition to the spec's action table, approved by the owner. After the decision the selected head is rechecked (review finding 2). The keys role releases the target's existing envelope only against `storage.object.export-envelope`: the same checks plus the envelope's `release` and the target's `read` and `receive-key`. Without the history check it releases only the current version's envelope. The keys role's exact-match check now allows optional roles to be left unfilled. `client.ExportObject` fetches the package.

**Metadata search.** `GET /v1/buckets/{b}/documents/search?prefix=&project=&max_label=&limit=&continuation=` needs `list` on the bucket. It considers documents with a LIVE current version that match the key prefix and project; the label filter uses the stored label's rank. Each candidate's current version gets a `discover` decision (`document.search`, one batch, then one per candidate if the batch is denied). Results are in key order with a sealed continuation bound to the caller, its identity revision, the policy epoch, the incarnation and the query. There are no totals, scores or plaintext (SRH-001 to SRH-004, V-070). `fga search` and `client.SearchDocuments` use it; `client.Export` fetches an export package.

## Implementation (step 6: text entries, DOC-005)

A text collection or conversation is a document key begun with `"collection": true`. A key keeps its kind: a collection takes no ordinary version, and a document becomes no collection. Its units are `text.entry` resources (actions `read`, `use-in-model`, `update`) instead of `document.text_unit`. The entry operations (`collection.reuse-entries`, `collection.share-entries`, `collection.select-entries`, `collection.entry.read`, `collection.manifest`, `collection.entry.get-envelope`) are derived in the registry from the unit operations: the same checks on `text.entry`, with `update`, the entry's write action, in place of the writer's `share`. Appending or replacing entries is a new document version that reuses the entries it keeps (with `read` on each) and adds new ones, so there is no separate transcript store. Entries take the collection's label. A collection has no original file, and entries cannot be exported (text.entry has no `export-key`). An entry cannot be reused in an ordinary document, nor a unit in a collection. Disclosure, packages and ciphertext use the same routes as units. `client.PutCollection` and `fga put-document -collection` create a collection with one entry per paragraph. `client.AppendCollection` and `fga append` add paragraphs: the client fetches the manifest, which the server returns only to a caller who may read every entry, so no entry is dropped silently. The begin names the manifest's version as `base_version`. A new collection version that keeps entries must name one, and the begin refuses it unless that version is still current, so an append committed in between is not dropped (review v2 finding 3, `TestConcurrentAppends`). It recovers each kept entry's key from the caller's own envelope (`crypto.UnitFromPackage`, which verifies the descriptor and envelope signatures and the key package's binding to the entry before using the key). It then seals the kept entries again with the new ones for the recipients. Whoever appends must hold an envelope for every entry; the server checks `read` on each reused entry and `new-version` on the document.

## Implementation (withdrawal, PUB-005 and DOC-002)

`DELETE /v1/buckets/{b}/document?key=` (`document.delete`, `delete` on the document) clears the key's head. Its versions stay as they are and remain readable by version ID with `read-units`. A new version may be published later.

`DELETE …/document?key=&version=` (`document.delete-version`, `delete-version` on the document) withdraws one version:
- the version becomes WITHDRAWN, its resource generation advances, and its envelopes are retired;
- the version's unit versions are locked first, so a concurrent publication that reuses one is either seen or fails on the withdrawn state;
- each unit version, and the original, that no other LIVE version references is withdrawn too: its envelopes are retired and its blob is scheduled for reclamation (`retirements`);
- units still referenced stay LIVE (V-064), and reclamation keeps refusing referenced unit versions;
- withdrawing the current version clears the head; it never restores an older version.

Units are withdrawn only this way, never alone while a version needs them. Both operations take a plan, so a policy can require an approval. `fga rm -document` uses them.
