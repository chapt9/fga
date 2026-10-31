# Client encryption wire profile 1 (RCP-006, RCP-007, CRY-002 to CRY-004, KEY-006)

Status: design record, 31 October 2026. Implemented by `internal/cryptowire` (formats shared by clients and servers, no key handling) and `sdk/go/crypto` (client only, uses Tink). Not qualified: the interoperability tests below run one implementation against itself (RCP-007 needs independent implementations or pinned external examples before enablement in production; D-08 still gates production payloads).

## Suite and format registry

| Value | Meaning |
|---|---|
| Suite 1 | Payload: Tink streaming AEAD AES-256-GCM-HKDF, HMAC-SHA256 HKDF, 32-byte derived keys, 1 MiB ciphertext segments, one key, raw output. Envelopes: Tink HPKE `DHKEM_X25519_HKDF_SHA256` / `HKDF_SHA256` / `AES_256_GCM`, variant NO_PREFIX. Content signatures: Ed25519 in JWS (EdDSA). Digests: SHA-256. |
| Format 1 | Payload AAD and key package of [crypto-format-profile.tex](../spec/crypto-format-profile.tex); Tink's own streaming ciphertext framing. |

Any other suite or format value rejects (CRY-001). A new value needs a new reviewed profile, never an implicit fallback.

## Identifiers and encodings

- Tenant, object, logical-version, crypto-version, blob, attempt and envelope IDs are random UUIDs (RFC 9562 version 4). Binary form: the 16 bytes in RFC order. Text form: lowercase `8-4-4-4-12`. Tenants keep their text name for routing; the catalog assigns each tenant a UUID used in AAD and contexts.
- Timestamps in binary messages: signed 64-bit Unix milliseconds. In JSON: RFC 3339 UTC with `Z`.
- Digests in binary messages: 32 raw bytes. In JSON and text: `sha256:` followed by 64 lowercase hex digits.
- Public keys in JSON: standard base64 with padding of the raw 32-byte key.

## Fingerprints

| Key | Fingerprint input to SHA-256 |
|---|---|
| Recipient (X25519) | `"fga.recipient-key/v1"` ‖ `0x00` ‖ suite (uint16 BE) ‖ raw public key (32 bytes) |
| Content signing (Ed25519) | `"fga.signing-key/v1"` ‖ `0x00` ‖ raw public key (32 bytes) |

A fingerprint identifies a key; it grants nothing (RCP-001, CRY-005).

## Payload binding and key package

Exactly as [crypto-format-profile.tex](../spec/crypto-format-profile.tex): the 60-byte AAD `FGAAD001` ‖ tenant UUID ‖ object UUID ‖ crypto-version UUID ‖ suite (uint16 BE) ‖ format (uint16 BE), and the key package `format=1` (uint16) ‖ `60` (uint16) ‖ binding ‖ keyset length (uint32) ‖ Tink binary keyset. The client rejects inconsistent lengths, trailing bytes, unknown versions, keysets above 64 KiB, a keyset with other than exactly one enabled primary AES-256-GCM-HKDF-1MB key, and a binding that differs from the context's.

## `RecipientEnvelopeContextV1`

Protobuf wire format, written and parsed with `google.golang.org/protobuf/encoding/protowire` (no generated code, no `protoc`).

| Field | No. | Wire type | Rule |
|---|---|---|---|
| `profile_version` | 1 | varint | `1` |
| `tenant_id` | 2 | bytes | 16 |
| `object_id` | 3 | bytes | 16 |
| `logical_version_id` | 4 | bytes | 16 |
| `crypto_version_id` | 5 | bytes | 16 |
| `suite` | 6 | varint | registered suite |
| `format` | 7 | varint | registered format |
| `ciphertext_sha256` | 8 | bytes | 32 |
| `ciphertext_length` | 9 | varint | ≥ 1 |
| `recipient_fingerprint` | 10 | bytes | 32 |
| `recipient_key_version` | 11 | varint | ≥ 1 |
| `envelope_generation` | 12 | varint | ≥ 1 |
| `sharer_signing_key` | 13 | bytes | 32 (fingerprint of the signing key) |
| `created_at_unix_ms` | 14 | varint (int64) | > 0; informational, never evidence (RCP-011) |
| reserved | 15–17 | | document, document version and manifest digest for R1-C units; rejected in profile 1 |

Strict parsing (RCP-006): every field appears exactly once, in ascending field order, with its wire type and exact length; no unknown, duplicate, reserved or aggregate fields; total size ≤ 512 bytes; and re-encoding the parsed values must reproduce the input byte for byte, which rejects overlong varints and any other non-canonical form. Signatures are always checked over the received bytes, never over a re-serialization.

HPKE `contextInfo` = SHA-256(`"fga.envelope-hpke-info/v1"` ‖ `0x00` ‖ context bytes).

## Envelope

An envelope is the triple (context bytes, HPKE ciphertext, origin signature). The HPKE plaintext is one key package. Limits: HPKE ciphertext ≤ 66,000 bytes. The origin signature is a detached compact JWS:

- header `alg` EdDSA, `kid` the sharer's signing-key fingerprint (text form), `typ` `fga-envelope+jws`;
- payload `"fga.envelope-signature/v1"` ‖ `0x00` ‖ uint32 BE length of the context ‖ context ‖ SHA-256(HPKE ciphertext).

The envelope digest, used in receipts and audit, is SHA-256(`"fga.envelope-digest/v1"` ‖ `0x00` ‖ uint32 length ‖ context ‖ uint32 length ‖ HPKE ciphertext).

## Ciphertext descriptor

Strict JSON (unknown fields, duplicate fields and trailing data reject), at most 4 KiB, signed exactly as transmitted with a detached JWS (`typ` `fga-descriptor+jws`, `kid` the signer fingerprint):

```json
{"version":"fga.descriptor/v1","tenant_id":"…","object_id":"…","logical_version_id":"…",
 "crypto_version_id":"…","blob_id":"…","attempt_id":"…","suite":1,"format":1,
 "ciphertext_sha256":"sha256:…","ciphertext_length":1234,"signer":"sha256:…",
 "created_at":"2026-10-31T12:00:00Z"}
```

The server checks every identifier against the upload intent, the digest and length against the durable receipt, and the signer against the content-signing registry (RCP-008, RCP-011). It cannot check the AEAD tag or the plaintext (KEY-003, BKD-005).

## Delivery receipt

The keys role signs each envelope delivery with its own receipt key (a separate key purpose, RCP-001). Strict JSON, JWS `typ` `fga-receipt+jws`: version `fga.delivery-receipt/v1`, envelope ID and digest, tenant, object and version, recipient fingerprint, decision and operation IDs, audience (the recipient principal), recovery incarnation, issue time and `valid_until`. Expiry is not a self-destructing key (KEY-010).

## Enrollment proofs (RCP-002)

The server issues a one-use challenge (ID, 32-byte nonce, expiry ≤ 5 minutes) bound to tenant, principal and fingerprint.

- Content-signing key: the client returns a detached JWS (`typ` `fga-signing-proof+jws`) over `"fga.signing-key-proof/v1"` ‖ `0x00` ‖ challenge ID ‖ `0x00` ‖ tenant ‖ `0x00` ‖ principal ‖ `0x00` ‖ fingerprint ‖ `0x00` ‖ nonce. The server verifies it with the submitted public key.
- Recipient key: the challenge also carries an ephemeral X25519 public key generated by the server with Go's `crypto/ecdh`. The client computes the X25519 shared secret with its recipient private key and returns HMAC-SHA256 under key HKDF-SHA256(secret, salt = nonce, info = `"fga.recipient-proof/v1"`) over challenge ID ‖ `0x00` ‖ tenant ‖ `0x00` ‖ principal ‖ `0x00` ‖ fingerprint. The server recomputes it with the ephemeral private key, which it stores only until the challenge is used or expires. This proves possession without the server holding any HPKE decryption code (MOD-004). It is a composition of standard primitives and needs cryptographic review before qualification.

Possession proof does not establish the intended recipient: the publishing client must also pin the fingerprint from an owner-approved source (RCP-002). The SDK refuses to encrypt to a fingerprint that is not in its local trust store.

## Examples (RCP-007)

`internal/cryptowire` tests hold the frozen positive example (a fixed context and its exact hex encoding) and negative examples: an unknown field, a duplicate field, fields out of order, a wrong wire type, a short UUID, an overlong varint, a reserved field, trailing bytes and an oversized message. `sdk/go/crypto` tests cover round trips and wrong AAD, wrong recipient, truncated, reordered and forged ciphertext (CRY-006).

## Profile 2: document units (R1-C)

Profile 2 is profile 1 extended for units of a document ([documents.md](documents.md)); profile 1 stays as it is for ordinary objects.

| Change | Rule |
|---|---|
| `profile_version` | `2` |
| Fields 15, 16, 17 | `document_id` (16 bytes), `document_version_id` (16 bytes), `manifest_digest` (32 bytes), all required, in this order after field 14 |
| Strictness | Same as profile 1; a profile-1 context must not carry fields 15 to 17, and a profile-2 context must carry all of them |
| HPKE info, signing input, digest | As in profile 1, over the profile-2 context bytes |
| Manifest | `fga.manifest/v1` strict JSON core; digest = SHA-256(`"fga.manifest/v1"` ‖ `0x00` ‖ core); detached JWS of type `fga-manifest+jws` |
| Unit descriptor | `fga.unit-descriptor/v1` strict JSON; detached JWS of type `fga-unit-descriptor+jws` |

Frozen examples (`internal/cryptowire` tests): the profile-2 golden encoding (profile 1's golden example with profile version 2 and fields 15 to 17 appended), and negative examples for a profile-1 context with document fields, a profile-2 context without them, a missing field 17, reordered document fields and profile 3. Object paths (finalize, share, the SDK's object decryption) reject profile-2 contexts, so a unit envelope never opens an ordinary object and the reverse.

Manifest limits: at most 512 KiB and 1,000 units, unit IDs distinct, a normalization version required (at most 64 bytes).
