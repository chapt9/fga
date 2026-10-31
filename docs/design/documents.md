# Documents and text units (DOC-001 to DOC-008, CNT-003, DSC-001 to DSC-005, SRH-001 to SRH-004)

Status: design record, 31 October 2026. Our own design; no upstream mapping. Default deny (ruling 7) applies to every operation below.

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

Deliveries are audited with unit, version, recipient and digests, never plaintext (DSC-003).

## Export (Table "Compound operations", V-132 to V-136)

Remote package export delivers ciphertext and existing envelopes to another recipient. It needs `export` on the document version (or object), `export-key` on each selected unit, the applicable read checks and the full GetRecipientEnvelope set for the target recipient. The target must already have an envelope; the server never creates or rewraps one. A decision lacking any required check, such as `receive-key`, is refused (V-136).

## Metadata search (SRH-001 to SRH-004)

Search filters documents by permitted catalog metadata only: bucket, key prefix, project, label rank. Each candidate gets an exact `discover` decision on its document version, so results, order and totals depend only on what the caller may see. There is no plaintext, snippet or embedding search on the server. Clients search plaintext locally after decrypting.

## Text entries (DOC-005)

A text collection or conversation is a document whose units have type `text.entry` (read, use-in-model, update). An update is a new document version that replaces or appends entries; there is no separate transcript store.
