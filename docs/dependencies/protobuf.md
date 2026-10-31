# Dependency record: Go protocol buffers runtime (LIB-002)

| Field | Record |
|---|---|
| Module | `google.golang.org/protobuf` v1.36.11 (pinned in `go.mod` and `go.sum`); a direct dependency since 31 October 2026, previously indirect through cel-go. |
| Owner | `internal/cryptowire` (`RecipientEnvelopeContextV1`). |
| License | BSD-3-Clause, from the `LICENSE` file of the downloaded module. |
| Why | RCP-006 requires the envelope context to be a versioned Protobuf message. Only `encoding/protowire` is used, to write and parse the wire format by hand, so no code generator (`protoc`) is needed and the parser can reject what generated code would accept (unknown, duplicate or out-of-order fields, non-canonical varints). |
| Alternatives | Generated code with `protoc`: needs a further download and a generator pin (LIB-003), and generated parsers are permissive. |
| Maintainers | The Go team at Google. |
| Advisories | Not checked; `govulncheck` must run before release (LIB-003). |
| Our evidence | `internal/cryptowire` tests: the frozen golden encoding and thirteen negative wire examples. |
| Transitive footprint | None beyond the standard library for `encoding/protowire`. |
| Replacement path | Confined to `internal/cryptowire/context.go`. |
