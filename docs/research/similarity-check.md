# Code similarity checks against Cerbos and MinIO (D-03, SRC-001)

Status: done 31 October 2026, at the owner's request. The owner asked whether any of our code was copied from the two projects studied for ideas: Cerbos for the policy engine, MinIO for storage. Our policy format and engine share Cerbos's vocabulary (principal, resource, action, role, effect, condition) and some of its ideas, and our storage design took ideas from MinIO ([mechanism-matrix.md](mechanism-matrix.md)). MinIO is AGPL-3.0, so copied MinIO code would bring its copyleft into our code base.

**Result: no Cerbos or MinIO code was found in this repository.** Our code shares fewer identical token runs with each of them than with unrelated Go code of the same size and kind. The longest identical runs, 34 tokens against MinIO and 31 against Cerbos (about four lines), are general Go idioms, and nothing of 40 tokens or more is identical. With names blanked, the only long matches are declarations (lists of constants and error variables, structs with JSON tags, import blocks) with at most two lines of logic each, a shape any Go code has. No 8-word comment phrase occurs in both.

## What was compared

| | |
|---|---|
| Ours | Every `.go` file of this repository except `papers/`, at commit `f50f8b0`: 215 files, 388,258 tokens |
| Cerbos | `github.com/cerbos/cerbos` at `ae014ba2ea919771216bc666c4f654d18a1c1a52`, the revision the mechanism matrix pins: GitHub source tarball, 1.7 MB, SHA-256 `eea6e9eabfae229cf8ef2b307338b6530112d3fb72a00d44898d77fa615a917e`, 543 `.go` files, 1,576,090 tokens |
| MinIO | `github.com/minio/minio` at `7aac2a2c5b7c882e68c1ce017d8256be2feea27f`, the pinned revision: GitHub source tarball, 24 MB, SHA-256 `71794c2df26aad0cc99e8421c58b7aa2dd55969f979b0e7d1e931042e9fabcd6`, 902 `.go` files, 1,889,392 tokens |
| Controls | Unrelated Go code: the MCP Go SDK v1.8.0, pgx v5.11.0 and go-jose v4.1.7 from the module cache, and, as a control of MinIO's size and kind (HTTP servers, cryptography, files), the Go 1.27.3 standard library's `net/http`, `crypto`, `os`, `database` and `encoding`: 1,091 files, 2,436,171 tokens |

The upstream snapshots, the comparison program and its outputs were kept in a temporary directory outside the repository and are not part of the code base (SRC-002).

## Method

The comparison program, written for this check, reads two trees as Go tokens, without comments, and counts the share of our tokens that lie in a run of *k* consecutive tokens that also occurs anywhere in the other tree. Two modes:

- **raw:** names and literals are kept. This finds copied code.
- **norm:** every name is `I`, every number `N` and every string `S`. This finds copies whose names were changed, at the price of matching any code of the same shape.

It also counts the 8-word phrases that occur in comments of both trees. Its test validated the detector: an exact copy is found in both modes, a copy with every name changed and its comment rewritten is found by norm (at least 95% of its tokens), and unrelated code is not found at all.

**How to read the percentages.** A shared token is one that lies inside *some* run of *k* tokens found somewhere in the other tree. It does not mean that a share of our code is the same as theirs. Every Go project has the same short runs: `if err != nil { return nil, err }` is 12 tokens, and a table-driven test loop is about 20. The controls show what that background is: a score within their range shows nothing beyond it.

**Run length decides.** Copied code, renamed or not, keeps matching as the run length grows, since a copied function is a hundred tokens or more of the same shape. Background matches are short and vanish as *k* grows.

## Whole repository

| Compared with | raw, k 15 | norm, k 30 |
|---|---|---|
| **Cerbos** | **3.36%** | **7.92%** |
| **MinIO** | **5.79%** | **13.62%** |
| Go standard library (control) | 6.50% | 14.60% |
| MCP Go SDK | 5.21% | 8.08% |
| pgx | 4.29% | 5.31% |
| go-jose | 4.24% | 5.23% |

By run length:

| k (tokens) | raw: MinIO | raw: Go std | raw: Cerbos | norm: MinIO | norm: Go std | norm: Cerbos |
|---|---|---|---|---|---|---|
| 20 | 0.85% | 1.75% | 0.33% | 54.07% | 53.58% | 39.08% |
| 30 | 0.02% | 0.11% | 0% | 13.62% | 14.60% | 7.92% |
| 40 | 0% | 0.01% | 0% | 3.27% | 4.35% | 2.09% |
| 60 | 0% | 0% | 0% | 0.61% | 0.42% | 0.37% |
| 100 | 0% | 0% | 0% | 0.13% | 0% | 0.16% |

In raw mode both lie at or below the control at every length, and nothing of 40 tokens or more is identical to either. In norm mode, from 60 tokens, both match a little more than this control: 33 runs against MinIO (3 of them 100 tokens or more) and 15 against Cerbos. Each was read on our side, and each is a declaration with at most two lines of logic (below). A copied function would carry its logic with it.

## Cerbos

Policy and decision code (`internal/policy`, `internal/decision`, `internal/decisionsvc`, `internal/release`: 17 files, 32,568 tokens) against Cerbos's engine (`internal/engine`, `conditions`, `compile`, `ruletable`, `policy`: 94 files, 152,689 tokens):

| Compared with | raw, k 12 | norm, k 20 |
|---|---|---|
| **Cerbos's engine** | **3.16%** | **20.27%** |
| MCP Go SDK | 6.25% | 33.53% |

**Why 20% in norm mode is background.** With names and strings blanked, any two Go projects share many 20-token shapes. Unrelated projects score more against each other than our policy code does against Cerbos:

| norm, k 20 | Shared |
|---|---|
| go-jose against pgx | 42.23% |
| go-jose against the MCP Go SDK | 37.45% |
| the MCP Go SDK against pgx | 37.37% |
| Cerbos's engine against the MCP Go SDK | 28.87% |
| **our policy code against Cerbos's engine** | **20.27%** |

Our policy code by run length, norm mode:

| k (tokens) | Cerbos's engine | MCP Go SDK | pgx | go-jose |
|---|---|---|---|---|
| 20 | 20.27% | 33.53% | 30.10% | 22.16% |
| 30 | 3.74% | 9.93% | 7.03% | 4.07% |
| 40 | 0.29% | 2.08% | 1.13% | 0.44% |
| 60 | 0% | 0% | 0.24% | 0% |
| 100 | 0% | 0% | 0% | 0% |

Cerbos is the lowest of the four at every length, and nothing of 60 tokens or more matches it.

What the shared runs are:

- **raw, whole repository:** the longest are 31 tokens, the closing of a table-driven test (`}` `for _, tt := range tests {` `t.Run(…, func(t *testing.T) {`), an HTTP call followed by an error check, and an `http.HandlerFunc` middleware wrapper.
- **raw, policy code:** 37 runs in non-test files, 12 to 20 tokens each. They are error checks (`x, err := f(…); if err != nil { return …, err }`), `if err := ctx.Err(); err != nil`, a type switch, nil-map defaults, and cel-go calls (`env.Compile`, `env.Program(… cel.CostLimit …)`, `program.ContextEval`, `val.Value().(bool)`, `celast.NavigateAST`), a library both projects use.
- **norm:** 15 runs of 60 tokens or more, none with a line of logic: lists of constants and error variables, structs, import blocks, and a chain of `errors.Is` alternatives.
- **Comments:** 0 of our 55,740 comment phrases occur in Cerbos.
- **Names:** none of Cerbos's own names or keys appear in our code (`EFFECT_ALLOW`, `derivedRoles`, `resourcePolicy`, `policyVersion`, `request.principal`, `P.attr`, its copyright holder).

## MinIO

MinIO's tree is the largest compared, and it is an HTTP server with many tests, as ours is. Against the whole repository it scores below the Go standard library control in both modes (table above).

- **raw:** the longest identical runs are 34, 31 and 30 tokens: a helper that returns a map's keys sorted, an HTTP call followed by an error check, and a test-table loop. Nothing of 40 tokens or more matches.
- **norm:** 33 runs of 60 tokens or more match. Each was read on our side: every one is a declaration (the list of operation names, error variables, a map from errors to reason codes, structs with JSON tags, struct literals filling many fields, an import block), with at most two lines of logic. Their MinIO counterparts are scattered over unrelated files (metrics, SQL value types, a ring buffer, storage data types), as shape matches are.
- **Comments:** 0 of our 55,740 comment phrases occur in MinIO.

Our storage and encryption code (`internal/content`, `datakeys`, `blob`, `catalog`, `envelope`, `fence`, `kek`, `payload`, `cryptowire`, and `sdk/go/crypto`: 170,366 tokens) against MinIO's storage and encryption code (`cmd/xl-storage*`, `erasure*`, `encryption-v1*`, `bitrot*`, `object-api*`, `bucket-versioning*`, and `internal/crypto`, `kms`, `hash`: 116 files, 382,064 tokens):

| | raw k 12 | raw k 20 | raw k 30 | norm k 20 | norm k 40 | norm k 60 |
|---|---|---|---|---|---|---|
| **MinIO storage** | **8.31%** | **0.68%** | **0%** | **40.24%** | **1.52%** | **0.14%** |
| Go standard library (control) | 10.56% | 1.84% | 0.06% | 55.50% | 3.97% | 0.28% |

The longest identical run there is 24 tokens, in our tests: `p, err := alice.Put(…); if err != nil { t.Fatal(err) }`. The control is about six times larger, so the lower figures against MinIO partly reflect size. What decides is the run length: no identical run reaches 30 tokens, and the shape matches of 60 tokens or more are among the 33 declarations above.

## Limits

Token runs find copied and renamed code. They do not find a rewrite of the same algorithm in another structure. The design-level likeness is deliberate and recorded row by row in the mechanism matrix. Cerbos's own engine mechanisms (its bitmap rule index, its query planner, derived roles, principal policies, lenient condition errors) and MinIO's own storage mechanisms (erasure coding and quorum, the per-object metadata journal, distributed locking, the metacache) have no counterpart here, by decision.

## Licenses at the pinned revisions

- **Cerbos:** the `LICENSE` file is the Apache License 2.0 text, `NOTICE.txt` starts "Copyright 2020-2026 Zenauth Ltd." followed by third-party notices, and every one of the 441 Go files under `internal/`, `cmd/` and `pkg/` carries `SPDX-License-Identifier: Apache-2.0`.
- **MinIO:** the `LICENSE` file is the GNU Affero General Public License, version 3.

Both confirm the expectations in D-03. The specification's references appendix still calls them unverified; an erratum can update it. The license record still needs the qualified review that SRC-004 and GATE-001 ask for before distribution.

## Upstream source seen during these checks

The mechanism matrix records that no upstream source file was opened during the study. These checks read both trees mechanically. To judge the longest Cerbos matches, about 80 lines of Cerbos were displayed, all ordinary Go and none used for implementation:

| Cerbos file | Lines |
|---|---|
| `cmd/cerbos/healthcheck/healthcheck.go` | 256-260 |
| `cmd/cerbos/repl/internal/repl.go` | 860-870 |
| `internal/util/filesystem_test.go` | 29-32 |
| `internal/conditions/cerbos_lib_test.go` | 330-333 |
| `internal/conditions/cerbos_lib.go` | 1-3, 267-270, 519-522, 595-597 |
| `internal/conditions/cel.go` | 48-55 |
| `internal/server/middleware.go` | 120-121 |
| `internal/audit/kafka/publisher.go` | 25-34 |
| `internal/storage/index/index.go` | 22-31 |
| `internal/engine/engine.go` | 162-168 |
| `LICENSE`, `NOTICE.txt` | the first lines |

No MinIO source line was displayed: its matches were judged from our side only. Of MinIO, only the top-level file listing and the first lines of `LICENSE` were shown.

Code continues to be written from the specification and this project's records, never from upstream files (SRC-001).

## Repeating the checks

Download each pinned revision's source tarball (`https://codeload.github.com/cerbos/cerbos/tar.gz/<commit>`, `https://codeload.github.com/minio/minio/tar.gz/<commit>`) into a temporary directory outside the repository, write the comparison described under Method there, and run it in both modes over a series of run lengths, against the upstream tree and against a control of similar size and kind. Delete the temporary directory afterwards.
