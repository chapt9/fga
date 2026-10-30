# Dependency record: cel-go (LIB-002)

| Field | Record |
|---|---|
| Module | `cel.dev/cel-go` v0.33.2 (pinned in `go.mod` and `go.sum`) |
| Owner | Policy engine (`internal/policy/engine`) |
| License | Apache-2.0, from the `LICENSE` file of the downloaded module. Notices are to be carried in `LICENSES/` before distribution. |
| Why | Evaluates policy conditions written in CEL (decision D-01, `docs/design/policy-format-v1.md`). It provides type checking, cost limits and context cancellation, which POL-009 requires. |
| Alternatives | A small expression language of our own (rejected when the format was approved), or the standard library alone (no expression evaluator). |
| Maintainers | The CEL project (Google). The module path moved from `github.com/google/cel-go` to `cel.dev/cel-go`. |
| Advisories | None checked yet. `govulncheck` must run in CI before release (LIB-003). |
| Our evidence | `internal/policy/engine` tests: typed compilation, the cost limit as a refusal, cancellation, and concurrent evaluation under the race detector. |
| Transitive footprint | About 70 non-standard packages in the engine's import graph, mainly the ANTLR runtime, the Protobuf runtime, `cel.dev/expr` and `golang.org/x/exp`. |
| API stability | Pre-1.0 version numbers. Upgrades are reviewed, and the engine tests must pass before any upgrade. |
| Replacement path | Conditions sit behind the engine's compile step. Replacing CEL changes the `when` language of policy format v1, so it would need a format version change. |
