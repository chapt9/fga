# fga: Fine-Grained Access Platform

An implementation of the Fine-Grained Access Platform specification 2.1 (draft), which is kept in [docs/spec](docs/spec) together with its test vectors and consistency check. `fga` is a placeholder name (decision D-11).

## Status

Phase R1-A (decision core) has started. So far:

- **Evaluator contract** (`internal/policy`, POL-001).
- **Batch decision** (`internal/decision`): the platform gate, then the ceiling set, then the business set, combined so that a ceiling denial always wins and nothing is allowed without an explicit business allow (POL-003, POL-007, DEC-002 to DEC-004).

The Cerbos adapter, identity and delegation, the resource registry and signed decisions are not written yet. Decision records are in [docs/decisions](docs/decisions).

## Layout

| Path | Contents |
|---|---|
| `internal/policy` | Evaluator contract |
| `internal/decision` | Batch decision |
| `docs/spec` | Specification sources, PDF, vectors, `tools/check_spec.py` |
| `docs/decisions` | Phase 0 decision records |

## Checks

Go 1.27.3 (Homebrew).

```bash
make check
```

`make check` runs gofmt, `go vet` and `go test -race`. `make spec` runs the specification consistency check.
