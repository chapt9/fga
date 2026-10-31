# D-12: Encryption modes (server-side by default, client-side opt-in)

- **Status:** decided by the owner, 31 October 2026, including share grants (part 4). Server-side encryption is always on and client-side encryption is opt-in; the mode is set per bucket and visible to policy; a server-encrypted object is shared by policy and the server decrypts for the reader. The requirements are in specification 2.6, whose text the owner approved on 31 October 2026 (stretch S0 done).
- **Why:** under 2.5, every reader needs client key custody (recipient keys, pinned signers, envelopes), and generic clients such as MCP cannot read anything. The owner wants other users to read shared encrypted data without that, with access control as the protection.

## 1. Modes

| Mode | Who encrypts | Who can decrypt | Sharing |
|---|---|---|---|
| `server` (default) | the storage role, with a fresh data key per version | the platform, for a reader whose request a fresh signed decision allows | policy decides who reads; nothing else is needed |
| `client` (opt-in) | the uploading client, as today | only clients holding a recipient envelope | as today: policy allows the reader, and the client publishes an envelope to the reader's key |

- There is no plaintext mode: every stored payload is encrypted.
- A bucket has exactly one mode (`buckets.encryption`), chosen at creation. Changing it is the registered operation `bucket.set-encryption` (action `manage` on `storage.bucket`, approval-capable), and it applies to new versions only.
- Each version records the mode it was published under (`object_versions.protection`), and that never changes. A version moves to another mode only as a new version: an authorized client reads it and uploads it again.
- The mode is visible to policy as `resource.attributes.encryption` on the bucket and on everything in it (objects, documents, units, entries, derived outputs). A rule or ceiling can therefore require client mode, for example: no label at or above `restricted` in a `server` bucket.
- There is no fallback across modes (KEY-015 is kept). A client-mode version is never served through a server key, and a server-mode version never takes a client envelope. Routes of one mode refuse buckets of the other with `409 ENCRYPTION_MODE`.
- In client mode, the blob is stored as the client sent it, with no second server layer: it is already encrypted, and the server cannot add confidentiality.
- Migration: existing buckets become `client`, so data already published is unchanged. New buckets default to `server`.

## 2. Server-mode keys

- **Data keys.** Each object version, unit version, original file and derived version gets its own data key, using the same streaming AEAD primitive as client payloads. Its AAD binds tenant, object, logical version, crypto version, blob and mode, so copying bytes to another object yields nothing readable (CRY-008).
- **Key-encryption keys (KEKs).** Each tenant has a versioned KEK held only by the keys role. The catalog stores each data key wrapped under a KEK, together with that KEK's version. Rotation adds a KEK version and rewraps data keys in the keys role, without touching blobs.
- **Role separation.**
  - The keys role holds KEKs and never sees blobs or plaintext.
  - The storage role holds blobs, and a data key only for the duration of one stream. It never holds a KEK.
  - The decision role holds neither.
  - No role persists, logs or caches an unwrapped data key; key buffers are cleared after use (best effort, as KEY-007).
- **Write.** The storage role obtains the signed decision for the write and sends it to the keys role. The keys role checks it (audience and exact checks, as for envelope delivery), generates the data key and returns it with its wrapped form. The storage role encrypts the incoming stream into the blob, then discards the key, and the wrapped key is stored with the version at publication.
- **Read.**
  1. The storage role obtains the read decision, with the same operations and checks as today, and sends it to the keys role.
  2. The keys role verifies it inside the fence with the same bindings as envelope delivery: policy epoch, approval, current-head state for current reads (review finding 2), and all unit checks for originals (review finding 3).
  3. The keys role unwraps the data key, and the storage role streams the decrypted plaintext under the read lease. An AEAD failure aborts the stream; it never ends as a shorter "complete" response.
  - Every read needs a fresh decision and unwrap, so revoking access takes effect on the next read, with no envelopes to retire.
- **KEK custody** is a new open decision, D-13, which gates production in the same way D-08 does. Development uses a KEK file protected like the backup key (Argon2id passphrase and Tink AEAD).
- **Deletion.** When a server-mode version is finally removed, its wrapped data key is destroyed. The blob is then unreadable once no backup still holds that wrapped key.

## 3. Content in server mode

- **Objects.** Plaintext upload and download go over TLS, with the same operations, checks, conditional writes (PUB-007), idempotency and history rules as today. Range reads stay out of scope.
- **Documents and text collections.** The server splits text under the same `fga.text/nfc-paragraphs-v1` profile, encrypts each unit or entry under its own data key and builds the manifest.
  - Unit-level access is unchanged: a reader gets only the units it may read, and an original file only with the complete-content checks (CNT-003).
  - Appending to a collection needs no client keys.
- **Derived outputs.** The client uploads plaintext and declares lineage in the request. The server binds that lineage to the caller's decision instead of to a client signature. The lineage rules themselves are unchanged.
- **Signatures.** There are no client signatures in server mode. Origin is the authenticated uploader recorded in the catalog, and integrity is the server AEAD bound to the catalog identity.
- **Search** stays metadata-only (SRH-001 to SRH-003). The server keeps no plaintext index; server-side text search would be a separate decision.
- **MCP (R2)** returns plaintext of server-mode content to an authorized caller, and ciphertext and envelopes for client-mode content (MCP-005 narrowed).

## 4. Share grants

- Today, and in server mode, a user can read only what a policy rule already allows. This optional part lets a user share an object with a named person:
  - A principal with `share` on a resource records a grant: resource, grantee, actions (`read`, `stat`) and expiry. `unshare` removes it.
  - Unexpired grantees appear to policy as `resource.attributes.shared_with`.
- A grant does nothing by itself (default deny). It takes effect only where a rule honors it, for example `principal.id in resource.attributes.shared_with`. Ceilings and clearance still apply.
- Grants work in both modes. In client mode, the honored grant is what lets the recipient-read check pass before the client publishes an envelope.

## 5. What changes in the threat model

- **Server mode.** Server-mode content is readable by the platform. Someone who controls the keys role and either the catalog and blobs or the storage role can read it. The protection is the access decision, enforced in the fence at every unwrap.
- **Client mode** keeps 2.5's guarantee: a platform compromise does not reveal the content. Policy can require client mode for chosen labels or buckets.

## 6. Specification 2.6: requirements affected

**Rewritten for two modes.** The 2.5 text either becomes the client-mode rule or is replaced:

| Area | Requirements |
|---|---|
| Custody | CRY-001, BKD-005, CRY-005, KEY-001, KEY-011, KEY-013, KEY-014, KEY-015, KEY-016, KEY-017, D-09, RCP-010 |
| Format | CRY-004, CRY-006, CRY-007, CRY-008, CRY-009 |
| Content | CNT-001, PUB-002, DOC-003, DOC-004, DSC-001, DSC-002, DSC-003, DRV-001, DRV-003, DRV-005, SRH-002 |
| R2 | MCP-005, DRV-004, DRV-006, FLW-002, FLW-003 |
| Engineering | MOD-002, MOD-004, SIZ-001, SIZ-002, DAT-006, AUD-004, GATE-004; test families T-09 to T-12 |
| Narrative | `main.tex` structure line; p03 native API, derived-output and MCP paragraphs; p06 role table; scenario appendix |

**New requirements:** ENC-001 to ENC-003 (bucket mode, version mode, no fallback, migration), SSE-001 to SSE-006 (data keys and AAD, KEK custody and rotation, decision-bound wrap and unwrap in the fence, key lifetime, stream integrity, deletion), SHR-001 and onward (grants), with fixture vectors for each.

Changing normative text makes this 2.6 (TEST-003). The text is drafted from this list and approved by the owner before it replaces 2.5.

## 7. Build stretches

Each stretch ends with `make check-pg`, the smoke run, a commit, and a stop for the owner.

| # | Stretch | Needs |
|---|---|---|
| S0 | Specification 2.6 text, errata 2.5 to 2.6 and new vectors | this record |
| S1 | Bucket mode: column, `fga-admin` flag, `bucket.set-encryption`, policy attribute, version mode, `409 ENCRYPTION_MODE` on client routes; existing buckets become `client` | S0 |
| S2 | Keys role: KEK store (development file), wrap and unwrap API under signed decisions in the fence, rotation command, import allowlists (MOD-004) | S0 |
| S3 | Server-mode objects: plaintext put, get, stat, list, history, delete and export; the SDK and CLI pick the route by bucket mode | S1, S2 |
| S4 | Server-mode documents, units, originals, collections and derived outputs | S3 |
| S5 | Share grants (part 4) | S1 |
| S6 | Recovery: wrapped keys in backups, restore requires the KEK, reconcile proves unwrap, key destruction on final removal; README and documentation | S3, S4 |

MCP (R2) and the executor stack follow S6.
