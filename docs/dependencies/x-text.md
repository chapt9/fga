# Dependency record: golang.org/x/text (LIB-002)

| Field | Record |
|---|---|
| Module | `golang.org/x/text` v0.41.0 (pinned in `go.mod` and `go.sum`); a direct dependency since 31 October 2026, previously indirect through cel-go. No new download was needed. |
| Owner | `sdk/go/crypto` (`unicode/norm` only), client side. No server role uses it directly; the decision role already linked it through cel-go. |
| License | BSD-3-Clause, from the module's `LICENSE` file. |
| Why | Document ingestion normalizes text to NFC before splitting it into units and records the scheme in the manifest (DOC-004, `fga.text/nfc-paragraphs-v1`). The standard library has no Unicode normalization. |
| Alternatives | No normalization (rejected: equal text could split and digest differently), or our own normalization tables (rejected: error-prone). |
| Maintainers | The Go team. |
| Advisories | Covered by [vulnerability-scan.md](vulnerability-scan.md); re-run the scan before qualification. |
| Our evidence | `internal/content` document tests and the smoke run split, encrypt, publish and decrypt units. |
| Transitive footprint | None beyond the module. |
| Replacement path | Confined to `crypto.SplitText`. |
