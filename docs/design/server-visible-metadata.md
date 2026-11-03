# Server-visible metadata (DAT-006)

Status: design record, 31 October 2026. Specification 2.5 says the server may read only the minimum authorization and routing metadata "declared in the schema" but has no single list. This is that list for R1-B. Anything not listed is either client ciphertext or absent. Policy conditions can use only the protected attributes marked "policy".

| Record | Server-visible fields | Use |
|---|---|---|
| Tenant | Name, UUID | Routing, AAD |
| Identity | ID, revision, status, expiry, roles, attributes | Policy, fence |
| Delegation | ID, actor, subject, audience, grants, expiry, parent, revision, revoked | Gate, fence |
| Bucket | Name, UUID, policy scope, default project and label, revision | Routing, policy (`scope`, `attributes.project`, `attributes.label`) |
| Object | UUID, bucket, exact key, owner, project, label, generation, metadata revision | Routing, policy (`attributes.owner`, `attributes.project`, `attributes.label`, `attributes.bucket`) |
| Version | UUID, crypto-version, blob ID, state, ciphertext length and SHA-256, suite, format, signer fingerprint, signed descriptor bytes, created time, delete-marker flag | Publication, integrity, delivery |
| Upload intent | IDs, principal and delegation, expected generation and current version, planned protected attributes, preconditions, idempotency key, state, expiry | Publication |
| Recipient key, signing key | Fingerprint, principal, raw public key, suite, key version, status, revision | Fence, verification |
| Envelope | IDs, recipient fingerprint, key version, generation, status, signer, context bytes, opaque HPKE ciphertext, origin signature | Delivery |
| Audit outbox | IDs, tenant, kinds, outcomes, resource identities, digests | Evidence (AUD-001) |

Readings of sources ([mcp-data-tools.md](mcp-data-tools.md)) add protected attributes, all for policy: `source` on the source's bucket and on each reading's document, versions and units, `group` on units, and `source_version` on document versions. The source record itself (owner, key rule, groups with their fields, labels and client-mode recipients) is catalog metadata, as a bucket's defaults are.

Not visible to the server: plaintext, plaintext digests, payload keysets, private keys, titles and any descriptive text. Object keys are visible routing metadata, so clients should use opaque keys for sensitive names (Part 3, "Catalog records and ownership"). No log line contains an object key, token, envelope bytes or descriptor; logs carry IDs only.

Hidden fields cannot become server-evaluated policy attributes or search predicates: the policy engine sees only the attributes above.
