# Dependency record: Tink for Go (LIB-002)

| Field | Record |
|---|---|
| Module | `github.com/tink-crypto/tink-go/v2` v2.9.0, released 15 October 2026, pinned in `go.mod` and `go.sum` (`go mod verify` passes). Downloaded from proxy.golang.org with the owner's approval on 31 October 2026 (module zip 5,329,292 bytes). |
| Owner | Client SDK (`sdk/go/crypto`), and backup encryption in `fga-admin` (`internal/backupcrypt`, streaming AEAD only). No server role may link it (MOD-004); the storage, keys and decision roles' import allowlists exclude it. |
| License | Apache-2.0, from the `LICENSE` file of the downloaded module. The module ships no `NOTICE` file. The license text is to be carried in `LICENSES/` before distribution. |
| Why | CRY-002 and RCP-004 name Tink: streaming AEAD AES-256-GCM-HKDF with 1 MiB segments for payloads, and HPKE `DHKEM_X25519_HKDF_SHA256` / `HKDF_SHA256` / `AES_256_GCM` for recipient envelopes. The SDK frames and signs what Tink produces and implements no cipher. |
| HPKE support | Verified on 31 October 2026: v2.9.0 has `hybrid/hpke` with KEM `DHKEM_X25519_HKDF_SHA256`, KDF `HKDFSHA256`, AEAD `AES256GCM` and variant `NO_PREFIX`, key objects from raw public key bytes (`hpke.NewPublicKey`), and `keyset.Manager.AddKey`. `sdk/go/crypto` tests encrypt and decrypt with it. This is a functional check against our own code only, not cryptographic interoperability evidence (RCP-007). |
| Alternatives | Go's `crypto/hpke` and our own chunked AEAD framing. Rejected: CRY-002 forbids reproducing chunked encryption, and the specification names Tink. |
| Maintainers | Google's Tink team (tink-crypto organization). |
| Advisories | Scanned with govulncheck on 31 October 2026: no finding in Tink; see [vulnerability-scan.md](vulnerability-scan.md). |
| Our evidence | `sdk/go/crypto` tests: round trips across several segments and for an empty payload, two recipients, unpinned or substituted recipients, untrusted signers, truncation, corruption (also under a re-signed descriptor), swapped envelopes, other-object bytes, a key package binding another object and a keyset with two keys. |
| Transitive footprint | `golang.org/x/crypto` v0.56.0 (BSD-3-Clause), `golang.org/x/sys` v0.47.0 (BSD-3-Clause), `google.golang.org/protobuf` v1.36.11 (BSD-3-Clause). Tink's test-only module `github.com/c2sp/wycheproof` is recorded in `go.sum` but not linked. Adding Tink upgraded `golang.org/x/sync` and `golang.org/x/text`; the vulnerability scan later moved them to v0.22.0 and v0.41.0. |
| Unused surface | The SDK links Tink's AEAD, deterministic AEAD and PRF registries through Tink's own init code; it uses only streaming AEAD and HPKE. |
| Replacement path | All Tink calls are in `sdk/go/crypto/crypto.go`. The wire formats (`internal/cryptowire`) do not depend on Tink except for the keyset bytes inside the key package, which a replacement would have to read. |
