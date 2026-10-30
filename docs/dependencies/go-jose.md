# Dependency record: go-jose (LIB-002)

| Field | Record |
|---|---|
| Module | `github.com/go-jose/go-jose/v4` v4.1.7 (pinned in `go.mod` and `go.sum`) |
| Owner | Signed decisions (`internal/signing`) |
| License | Apache-2.0, from the `LICENSE` file of the downloaded module. Notices are to be carried in `LICENSES/` before distribution. |
| Why | Detached JWS (EdDSA) for signed decisions (DEC-008). ID-007 requires one JOSE implementation for every token and envelope signature, and this is it. |
| Alternatives | Ed25519 from the standard library with our own envelope format. Rejected: that would be a custom security format, and the specification names JWS. |
| Maintainers | The go-jose project, successor to the square/go-jose repository. |
| Advisories | None checked yet. `govulncheck` must run in CI before release (LIB-003). |
| Our evidence | `internal/signing` tests: round trip, tampering, unknown and revoked keys, key validity, audience, expiry, strict record parsing, single-use consumption under concurrency and rotation overlap. |
| Transitive footprint | No dependencies outside the standard library. |
| Replacement path | JWS handling is confined to `Signer.signBytes` and `Verifier.Verify`. |
