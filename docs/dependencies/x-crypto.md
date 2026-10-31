# Dependency record: golang.org/x/crypto (LIB-002)

| Field | Record |
|---|---|
| Module | `golang.org/x/crypto` v0.56.0 (pinned in `go.mod` and `go.sum`); a direct dependency since 31 October 2026, previously indirect through Tink. No new download was needed. |
| Owner | `internal/keyfile` (`argon2` only). Tink also links `chacha20poly1305`, `curve25519` and `hkdf`. |
| License | BSD-3-Clause, from the module's `LICENSE` file. |
| Why | Argon2id derives the key that protects key files from a passphrase ([key-files.md](../design/key-files.md)). The standard library has no memory-hard password KDF. |
| Alternatives | scrypt from the same module; PBKDF2 from the standard library, rejected as not memory-hard. |
| Maintainers | The Go team. |
| Advisories | See [vulnerability-scan.md](vulnerability-scan.md): the reachable findings of 31 October 2026 are fixed; `openpgp` (unfixed, unmaintained) is not linked. |
| Our evidence | `internal/keyfile` tests: round trip, wrong passphrase, bound header, parameter bounds. |
| Transitive footprint | `golang.org/x/sys`. |
| Replacement path | Confined to `internal/keyfile`. |
