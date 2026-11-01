# D-13: production custody of key-encryption keys

Status: decided by the owner, 31 October 2026; built 1 November 2026.

## Decision

A separate local key management role, `fga-kms`, alone holds the server-mode key-encryption keys. They are sealed at rest under a master secret: the existing ring file, passphrase-protected with Argon2id and AES-256-GCM. The role seals and opens data keys for the keys role over mutual TLS. Everything stays local; no cloud KMS or HSM.

## Consequences

- The keys role holds no KEK in production. It configures `kms` and refuses `kek_file` ([server-keys.md](../design/server-keys.md)).
- `fga-kms` decides nothing. It trusts only the workloads in its `clients`, and the keys role authorizes every release under its fence before it asks.
- Rotation stays `fga-admin kek rotate` on the ring's host. Backups still never hold the ring, which is recovered apart from them.
