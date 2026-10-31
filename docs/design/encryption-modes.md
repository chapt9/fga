# Encryption modes: bucket mode (D-12, stretch S1)

Specification 2.6 (decision [D-12](../decisions/D-12-encryption-modes.md)) puts every bucket in **server mode** (the default) or **client mode** (ENC-001). Stretch S1 builds the mode itself. The server-mode data path comes with S2 (keys role KEKs) and S3 (server-mode objects). Until then every content route serves client mode only.

## State

| Where | What |
|---|---|
| `buckets.encryption` | The bucket's mode. `fga-admin bucket create -encryption server` or `-encryption client` sets it; `server` is the default. The column has no SQL default, so every insert names a mode |
| `upload_intents.encryption`, `document_intents.encryption` | The mode the upload began under |
| `object_versions.encryption`, `document_versions.encryption` | The mode the version was published under. It never changes (ENC-002). A delete marker has none |
| `resources.attributes.encryption` | What policy sees, on the bucket and on every resource in it: objects, documents, document versions, units, entries, originals and derived outputs. It is the bucket's current mode, the mode new uploads get. Open intents carry it in their planned attributes, and every resource a publication creates takes it (document versions and derived outputs did not before review v3 F08; migration 0023 backfills them). Envelopes keep the attributes of the version they were made for |

Migration 0015 puts all existing buckets, intents and versions in client mode, because data published before modes was client-encrypted (ENC-003).

## Changing the mode

`PUT /v1/buckets/{bucket}/encryption` (`fga set-encryption`) is the registered operation `storage.bucket.set-encryption`. It works as follows:

1. **Decision.** It needs `manage` on the bucket. The check resolves the proposed change `change.encryption` (`<bucket>|<mode>`): the bucket as it is, plus `new_encryption`. The operation carries a plan, so a policy can require an approval.
2. **Fence.** The change locks the bucket row (`FOR UPDATE`) and commits only if the mode is still the one the request was decided against.
3. **Effects.** It updates the bucket and the attribute of every resource in the bucket, advancing their metadata revisions, so decisions bound to the old mode fail (DEC-006). It also updates the planned attributes of open intents.

An upload's begin runs its fence with the bucket row locked `FOR SHARE` and checks that the mode is the one it was decided under. So an upload either begins before a change commits, keeping the old mode (V-159), or after it, with the new one.

One window is accepted. An upload begun before a change publishes in its old mode, but the publication decision sees the bucket's new mode. That can only add denials, for example a ceiling that requires client mode.

## Routes and the client-mode guard

Every current route is a client-mode route. After the caller is authorized, it answers `409 ENCRYPTION_MODE` for a server-mode target (ENC-002). A caller without authorization gets the usual `404 NOT_FOUND` (CNT-004).

| Where | Guard |
|---|---|
| Upload begin: objects, derived outputs, documents and collections | The bucket is in client mode |
| Staging, finalize, document finalize | The intent is in client mode |
| Unit reuse | Only client-mode unit versions can be reused |
| Ciphertext streams; package, original, derived and export envelope delivery | The version is in client mode. A package route checks it after the caller's read checks and before it looks up the recipient's envelope, which a server-mode version never has |
| Keys role: envelope publication | The version is in client mode (`409 ENCRYPTION_MODE`) |
| Keys role: envelope delivery | The envelope's version is in client mode, else the decision does not authorize the delivery |

Stat, listing, search, labels, deletion and approvals do not depend on the mode.

## Tests

| Test | Covers |
|---|---|
| `internal/content/encryption_test.go` `TestEncryptionModeRefusals` | V-155 on all upload routes; `NOT_FOUND` for unauthorized callers; nothing reserved |
| `TestVersionModeGuards` | ENC-002 at the read, delivery and envelope-publication points |
| `TestServerModePackages` | The object, unit, original and derived package routes answer `ENCRYPTION_MODE` for a server-mode version to a caller who may read it, and `NOT_FOUND` to one who may not |
| `TestSetBucketEncryption` | ENC-001, V-159, attributes and revisions, `manage` required |
| `TestEncryptionCeiling` | V-158: a ceiling that requires client mode for a label |
| `internal/catalog/encryption_test.go` | ENC-003: migration of existing data |
| `scripts/smoke.sh` | The HTTP route, `fga set-encryption`, `409 ENCRYPTION_MODE` |
