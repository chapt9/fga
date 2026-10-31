# Envelope service (keys role) and enrollment (KEY-002, KEY-011, KEY-012, RCP-001, RCP-002, RCP-005, TRU-005)

Status: design record, 31 October 2026. Mechanism-matrix row "Client-side envelope keys" applies (MinIO's server-side envelope keys studied; decision Adapt: the server never holds or unwraps a key).

## What the role holds

| Record | Content | Never |
|---|---|---|
| `recipient_keys` | Tenant, principal, fingerprint, raw X25519 public key, suite, key version, purpose `encryption`, status PENDING / ACTIVE / REVOKED, revision | A private key |
| `signing_keys` | Tenant, principal, fingerprint, raw Ed25519 public key, status PENDING / ACTIVE / RETIRED / COMPROMISED, revision, status history | A private key |
| `envelopes` | Tenant, envelope ID, object, logical and crypto version, recipient fingerprint, key version, generation, context bytes, HPKE ciphertext, origin signature, signer, status ACTIVE / RETIRED, revision | An unwrapped keyset |
| `enrollment_challenges` | One-use challenges with expiry; for recipient keys, the server's ephemeral X25519 private key until use | Anything after use or expiry |

`fga-keys` links no Tink, no HPKE and no payload decryption code; its import allowlist enforces that (MOD-004). Its cryptography is JWS verification, SHA-256, `crypto/ecdh` for possession proofs and its own receipt signatures.

## Operations

| Operation | Caller | Authority | Effect |
|---|---|---|---|
| Enroll recipient | Client | Decision for `crypto.recipient` `enroll` (planned resource: the caller's own new key) | PENDING record and challenge |
| Activate recipient | Client | Decision for `activate` on the PENDING record, valid proof, unused unexpired challenge | ACTIVE, revision + 1; challenge deleted |
| Revoke recipient | Client or `fga-admin` | `revoke` decision, or local administrator | Security-journal entry first, then REVOKED, revision + 1 (fence step 5) |
| Provision / retire signing key | `fga-admin` | Local administrator, trusted provisioning (RCP-002); no registered resource type exists for self-service | ACTIVE or RETIRED; history kept for verification (RCP-011) |
| Mark signer compromised | `fga-admin` | Local administrator (ADM-003) | Journal entry, then COMPROMISED |
| PublishRecipientEnvelope | Client (sharer) | Fresh decision with the `PublishRecipientEnvelope` checks of Table "Compound operations"; fence | Envelope ACTIVE, generation = previous for this (version, recipient) + 1, audit |
| GetRecipientEnvelope | Storage role (TB3) | Decision signed for audience `fga-keys` whose checks are exactly the `GetRecipientEnvelope` mapping, bound to the object, version and recipient (TRU-005); fence with consumption | Returns the stored envelope and a signed delivery receipt; audit `ENVELOPE_DELIVERED` |
| RetireEnvelope | Client | `retire` on the envelope | RETIRED, revision + 1; client copies are not erased (KEY-010) |

Initial envelopes are not published through this role: they are written by the storage role's publication transaction, which already holds the complete check set and must publish them atomically with the version (PUB-003, KEY-012).

## Delivery rule (GetRecipientEnvelope)

The role verifies, in this order: workload identity of the storage role; the decision signature, audience `fga-keys`, expiry and incarnation; that the decision's registered operation is `storage.envelope.get` and that its checks are exactly caller `read` on the object, `release` on the envelope, recipient `read` on the object and recipient `receive-key` on the recipient key, all ALLOW and all bound to the requested object, version and fingerprint. Then, inside the fence: consumption, current revisions of the caller, recipient principal and key, object generation and metadata revision, version LIVE, envelope ACTIVE. It returns only the envelope stored for that exact (version, fingerprint); it never selects another recipient, never accepts a key-server URL and cannot manufacture a missing envelope (RCP-005, KEY-015).

## Enrollment protocol

1. `POST /v1/recipients` with the raw public key. The role computes the fingerprint, validates that the key is a canonical X25519 point (32 bytes, accepted by `crypto/ecdh`, not all-zero output), allocates the next key version for the principal, stores PENDING, and returns a challenge ([proofs](crypto-wire-profile.md#enrollment-proofs-rcp-002)).
2. `POST /v1/recipients/{fp}/activate` with the proof over the authenticated session of the same principal. A wrong, reused or expired proof leaves the key PENDING.
3. Publishing clients pin recipient fingerprints out of band (owner-approved provisioning). `GET /v1/recipients/{fp}` is a directory lookup only, allowed only by a `discover` rule; the SDK never trusts it alone (RCP-002).

Content-signing keys are provisioned by the local administrator in R1 (trusted provisioning); the JWS possession proof of the wire profile is defined for a later self-service operation. A retired key keeps verifying historical content; a compromised key fails verification of every signature it made unless an object-specific reviewed disposition exists (none can be recorded in R1, so all fail closed) (RCP-011).
