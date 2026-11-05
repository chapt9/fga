# Go code cleanup scan: unused, legacy and duplicated code

Date: 3 November 2026. Scope: every `.go` file in this repository, measured at commit `b63ff0b` (branch `data-tools`). Nothing in the repository was changed by the scan; this record is the only file added.

| | Lines |
|---|---|
| Go code (non-test) | 41,278 |
| Go tests | 23,382 |
| Total | 64,660 |

## Summary

| Category | Lines that could go | Status |
|---|---|---|
| A. Dead code: nothing calls it, tests included | **84** (30 server, 14 test, 40 SDK) | Verified: deleted in a copy, then `go build`, `go vet` and the full suite (57 packages, database tests required) pass |
| B. Server code that only tests call | up to ~560 | Needs a decision per item; most are test conveniences, three are spec features never wired |
| C. Legacy compatibility path (MCP "experimental" capability) | ~30 | Needs a protocol decision |
| D. Near-duplicate server code, reusable through a shared function | ~330 hand-checked, ~85 more from the detector only | Refactor, not deletion; several touch import allowlists |
| E. Duplicated test code | ~95 hand-checked, ~210 more from the detector only | Refactor of test helpers |

A is safe to delete now. B to E change structure or behaviour and each needs its own agreement before coding.

## How it was measured

All tools ran from a temporary directory against an exported copy of `b63ff0b`; no tool, binary or output was written into the repository.

- `deadcode` (golang.org/x/tools v0.52.0, built offline from the local module cache): functions unreachable from the eight `cmd/` binaries, and separately unreachable even from tests.
- A type-checked scan (`golang.org/x/tools/go/packages`): constants, variables, types, functions, methods and untagged struct fields with no use, or with uses only in `_test.go` files and the test-support packages `r1test`, `mcptest`, `executortest`, `pgtest` and `conformance`.
- A token clone detector (identifiers and literals normalized, runs of at least 100 tokens, import blocks skipped) and a function-similarity pass (Jaccard over 8-token shingles, at least 0.6).
- Requirement IDs in test doc comments, to find requirements tested in more than one package.

Detector figures are upper bounds. Every finding in A and every "hand-checked" estimate in D and E was read in the source.

Note: another session committed `8dd681a` (time windows, including changes to `internal/policy/engine/engine.go`) during the scan. The dead-code scans of A were rerun on `8dd681a` and found the same items; only `Engine.Digest` moved, to engine.go:335. Line numbers below are those of `b63ff0b`.

## A. Dead code (verified, 84 lines)

Each item has no caller anywhere, tests included. The set was deleted in a copy of `b63ff0b`; `go build ./...`, `go vet ./...` and `go test ./...` with `FGA_TEST_REQUIRE_DB=1` against `fga_test` all passed, and `deadcode -test` then reported nothing.

### Server code (30 lines)

| Item | Lines | What it affects |
|---|---|---|
| `nativeapi.Storage` (internal/nativeapi/nativeapi.go:188) | 5 | Wrapper around `StorageWith`; `fga-storage` calls `StorageWith` directly. None. |
| `catalog.(*Store).GetDelegation` (internal/catalog/catalog.go:176) | 5 | No caller. None. |
| `kek.(*Ring).Tenants` (internal/kek/kek.go:154) | 5 | Includes the `maps` and `slices` imports it alone used. None. |
| `content.Prepared.Decision` (internal/content/write.go:558) | 3 | Accessor nobody reads. None. |
| `engine.(*Engine).Digest` (internal/policy/engine/engine.go:226, 335 at `8dd681a`) | 3 | No caller at either commit; the engine is under active change, so check again before deleting. |
| `rpc.ErrDelivery` (internal/rpc/rpc.go:145) | 3 | Error value never returned or compared. None. |
| `gate.ReasonDelegationChanged`, `ReasonResourceChanged`, `ReasonPolicyEpochSuperseded` (internal/gate/gate.go:36-40) | 3 | Leftovers of the 2.2 gate, which rechecked bindings itself; the fence does that now. No code emits them and no document names them. |
| `audit.KindApprovalConsumption`, `KindExternalDelivery` (internal/audit/audit.go:25-26) | 2 | Audit kinds no code writes. If the parked executor is meant to write `external_delivery` later, keep that one. |
| `approval.ErrNotUsable` (internal/approval/approval.go:31) | 1 | Never returned; the package returns `ErrNotPending`, `ErrExpired` or `ErrSelfApproval`, and `content` has its own `ErrApprovalNotUsable`. None. |

### Test code (14 lines)

| Item | Lines | What it affects |
|---|---|---|
| `(*Fixture).unbound` (internal/conformance/harness_test.go:113) | 7 | Helper for a case "this implementation cannot express"; no case uses it now. |
| `epochs` type, its `RequiredEpoch` method and the fixture field (internal/gate/gate_test.go:25-36) | 7 | The gate fixture still builds a policy-epoch source the gate never reads (same leftover as the three reasons above). |

### Public SDK methods nothing calls (40 lines)

Not used by `cmd/fga`, by any test, or by `fga-console` (a separate module that does not import the SDK). Deleting them narrows the SDK's public API, so this is the owner's call even though nothing breaks.

| Item | Lines |
|---|---|
| `(*Client).ExportObject` (sdk/go/client/document.go:699) | 14 |
| `(*Client).PutDocument` (sdk/go/client/document.go:35) | 10 |
| `(*Client).GetUnit` (sdk/go/client/document.go:504) | 8 |
| `(*Client).ExportPlain` (sdk/go/client/client.go:428) | 5 |
| `crypto.MaxText` (sdk/go/crypto/document.go:26) | 3 |

## B. Server code that only tests call (up to ~560 lines)

None of this is reachable from the binaries; tests keep it alive. Deleting any of it means changing the tests that use it.

### Spec features implemented but not wired into any role (64 lines)

These look like missing wiring, not dead code. Decide per item whether to wire it or delete it.

| Item | Lines | Requirement |
|---|---|---|
| `registry.(*Operations).Plan` (internal/registry/registry.go:511) | 31 | RES-001, RES-006; the decision service plans by role instead |
| `release.EffectChanges` (internal/release/release.go:476) | 21 | REL-005: the reviewer acknowledges effect changes before activation. No activation path calls it. |
| `registry.(*Resolver).Revalidate` (internal/registry/registry.go:349) | 12 | RES-004, DAT-003 |

### In-memory stand-ins in production packages (~260 lines)

`delegation/memory.go` (65), `registry/memory.go` (76), `audit.MemoryOutbox` (77), `identity.MemoryStore` (29), `gate.MemoryRecipients` (13). Their comments say "for tests and the development profile", but no role uses them any more; the development profile runs on PostgreSQL. They are used by the `gate`, `decisionsvc`, `registry`, `delegation` and `audit` tests.

- Deleting them requires moving those tests onto the PostgreSQL stores through `pgtest`, which makes the tests slower and database-dependent.
- Moving them into a test-support package saves no lines but takes them out of production packages.
- At the least, the "development profile" wording in their comments is stale.

### Test conveniences (~200 lines)

| Item | Lines | Note |
|---|---|---|
| `catalog.(*Store)` setup methods: `PutIdentity`, `AddRecipientKey`, `EnableMCP`, `PutDelegation`, `CreateBucket`, `GrantCapabilities`, `TouchIdentity`, `DisableIdentity`, `RevokeDelegation` | 83 | Production writes go through `adminops`, which records an audit event and a journal entry through `catalog.(*Store).Administer`. These methods write directly, with neither, and exist for test setup. Moving them to `r1test` saves no lines but keeps an unaudited write path out of the production package. |
| `recovery.Backup`, `Restore`, `Reconcile`, `NotBackedUp` | 30 | Wrappers of `BackupWith`, `RestoreWith`, `ReconcileWith`, which `fga-admin` uses. Deleting them means passing empty options at 54 test call sites. |
| `jsonunits.ParseUnit` 18, `blob.(*Store).Put` 12, `content.(*Service).PreparePublish` 11 (conformance only), `approval.(*Store).Decide` 8, `cryptowire.ParseReceipt` 8, `delegation.Chain.Revisions` 8, `journal.State.Head` 7, `release.(*Manager).History` 6, `authn.NewVerifier` 4, `decision.CheckNotEvaluated` 3, `mcpbridge.(*Bridge).Server` 2, `mcpsvc.Tools` 2 | 89 | Small helpers kept for tests. Low value either way. |
| SDK: `(*Client).Units`, `ExportUnitsPlain`, `Export` | 30 | Public SDK API with tests but no CLI use. Keep unless the SDK surface is being trimmed. |

### Kept by ruling, not counted

- Parked executor stack (`invocation`, `reservation`, `toolstore`, plus `catalog.(*Store).RegisterDestination`): 47 lines used only by tests or unused. Kept per the 31 October 2026 ruling that this stack is not removed or extended before R2.
- `depcheck` (33 lines): a test helper by design, living in a non-test file so every role test can import it.

## C. Legacy compatibility path (~30 lines)

The MCP client capability is still read from, and sent under, the older `experimental` key (`mcpwire.Capability`, `ClientCapability.Experimental`, the fallback in `ParseCapability`, `mcptest.Conn.LegacyCapability` and one test block in `mcpsvc_test.go`). fga's own bridge (`internal/mcpbridge/bridge.go:66`) still sends both forms.

- Removing it drops clients that only declare the capability under `experimental`, and older servers that only read it there.
- It is a protocol decision, not dead code.

The legacy action alias in `registry` (`storage.object.read` to `read`) is not dead: the decision service canonicalizes every action through it.

## D. Near-duplicate server code (reuse through a shared function)

Estimates count lines removed after adding the shared function and its calls.

| # | Where | Duplicated | Est. saving | What it affects |
|---|---|---|---|---|
| D1 | `content.ExportUnits` (export.go:68-183) and `ExportUnitsPlain` (serveroriginals.go:110-191) | Selection checks, decision batching and the fence admission are the same apart from the audit recipient and the encryption-mode check | ~60 | Both export paths. The client path releases envelopes between deciding and admitting, so the helper must keep that order. |
| D2 | 11 copies of "parse stored digest, open blob" and 4 of "decrypt, close on error" in `internal/content` | 8 and 5 lines each | ~40 | Every content read path; a mechanical change. |
| D3 | `nativeapi`: 5 streamed routes with the same parse, call, close, write shape | 14 lines each | ~45 | Five routes, made table-driven. The other 43 routes are ordinary per-route code and not counted. |
| D4 | `cmd/fga-mcp` `Peer.client` copies `roleconfig.Peer.Client`; `loopback` exists 3 times (fga-kms, fga-decision, fga-mcp); `fga-kms workload` copies `decisionsvc.AdapterFromClientCert`; `fga-decision httpServer` copies `roleconfig.Common.Server` | 24 + 3×8 + 13 + 18 lines | ~50 | The copies exist because fga-mcp and fga-kms may not link `roleconfig` (it imports `decisionsvc`). Reuse needs a standard-library-only package that every role's `allowed-imports.txt` admits. |
| D5 | Role start-up in fga-keys, fga-storage, fga-tools, fga-decision and `fga-admin serve` | Load and validate config, signal context, open pool, migrate, readiness ping | ~35 | Five binaries; `roleconfig` would gain the `pgxpool` and `catalog` imports, which those roles already link. |
| D6 | Tink single-key keyset construction in `backupcrypt`, `kek`, `keyfile`, `payload` and `sdk/go/crypto` (2) | 6 × ~12 lines | ~40 | Five security packages and the allowlists of the roles that link them. |
| D7 | `envelope.recipientPath` (envelope.go:440) and `keycheck.ReaderPath` (keycheck.go:136) | Lineage set comparison and fence bindings, ~25 lines | ~25 | The derived-output delivery paths. Merging also removes one divergence: `keycheck` refuses an empty lineage, `envelope` does not. That case is unreachable through the API (creation requires at least one source), so it is a defense-in-depth gap, not a verified defect. |
| D8 | `decisionsvc/http.go`: `/v1/decide`, `/v1/decide-batch`, `/v1/check` | Admit, read body, strict decode, answer | ~20 | The decision API handlers. |
| D9 | SDK download and decrypt tail (client.go:482-502, document.go:602-622) | 21 lines | ~18 | SDK `Get` and derived reads. |
| | Hand-checked total | | **~330** | |
| D10 | `sdk/go/crypto/document.go` (169-214, 216-285), `cryptowire` descriptor marshal and parse pairs, `datakeys` release tails | Detector only, not read in full | ~85 | Crypto wire formats and key release. Read before planning. |

Not worth changing: the three `classify` functions in `nativeapi`, `keysapi` and `datakeysapi` map different error sets; `ceilingName` and `effectName` map different types; flag declarations, error-variable lists and `String` switches only look alike.

The detector puts 3,697 server lines inside some duplicated region. Most of that is the explicit `if err != nil` handling and per-route handlers that Go code normally repeats, so it is not counted above.

## E. Duplicated test code

| # | Where | Est. saving | What it affects |
|---|---|---|---|
| E1 | `internal/recovery` tests repeat one preamble (stack, bucket, client, put, backup): 4 exact copies and about 15 close variants around the 19 backup calls | ~30 | Recovery tests only. |
| E2 | `fence_test.go`: `TestFenceOrdersAgainstRevocation` and `TestFirstEpochRaiseIsOrdered` share a 35-line "hold the fence, run a concurrent change, check the order" scaffold | ~30 | Two tests. |
| E3 | `cmd/*/deps_test.go`: five files hand-write a "must not link" loop over `depcheck.Deps`, and fga-mcp and fga-tools rebuild `CheckForbidden` inline with a trimmed list | ~35 | Import tests of six roles; `depcheck` would gain one option for the trimmed list. |
| | Hand-checked total | **~95** | |
| E4 | `internal/content` tests: 819 lines inside duplicated setup regions (bucket, clients, publish) | ~150 | Detector only. Helpers would go in `r1test`. |
| E5 | `auditexport` (3 × 15), `history_test.go` (3 × 14), `mcpsvc` (4 × 17) | ~60 | Detector only. |

### Overlapping tests

436 test functions; 149 name a requirement in their doc comment. 36 requirements are tested in more than one package, for example APR-001 in 8 tests and POL-011 in 5. These are layered (a unit test plus an end-to-end or conformance test), not redundant, and no test was found that only repeats another's assertions. Worth one look:

- V-142: `TestV142` (conformance), `TestRevocationBeforePublish` (content) and `TestFenceOrdersAgainstRevocation` (fence).
- INV-002, 003, 006, 007 and 009 are each tested in both `executor` and `invocation` (parked stack, so not to be changed now).

## False positives excluded

- `Unwrap` and `Is` methods (`content.StagedApproval`, `jsonunits.ReadingError`): called by the `errors` package.
- Struct fields of map keys in `delegation/memory.go` and `registry/memory.go`: set positionally.
- `decision.OutcomeUnknown`: the zero value that never authorizes; it is meant to be unused.
- `approval.StateConsumed`: the fence writes the same state as the literal `'CONSUMED'` (fence.go:199). Using the constant there is better than deleting it.
- Test-support packages (`r1test`, `mcptest`, `executortest`, `pgtest`, `conformance`): only tests use them, by design.

## Applied on 4 November 2026

At the owner's request ("run this", with the rule that the cleanup must not alter any functionality of the main system), only part A was applied, on branch `data-tools` after the data tools stops, rechecked first with `deadcode` v0.52.0 on that branch:

- Deleted (no caller anywhere, tests included): `nativeapi.Storage`, `catalog.(*Store).GetDelegation`, `kek.(*Ring).Tenants` with the two imports only it used, `content.Prepared.Decision`, `rpc.ErrDelivery`, `gate.ReasonDelegationChanged`, `ReasonResourceChanged` and `ReasonPolicyEpochSuperseded`, `approval.ErrNotUsable`, and in tests `(*Fixture).unbound` and the gate fixture's `epochs`.
- Kept, with the reason:
  - `engine.(*Engine).Digest`: the engine's `digest` field is read only by it, so deleting it leaves a field nothing reads, and deleting the field too changes `Compile`'s required-digest check, which is behaviour.
  - `audit.KindApprovalConsumption` and `KindExternalDelivery`: AUD-002 names approval consumption and external delivery as distinct events. The code records a consumed approval as a target of the mutation event (authority-fence.md, step 9), and nothing writes an external delivery yet. Both constants name that vocabulary; the difference from AUD-002 is worth a look on its own, not in a cleanup.
  - The public SDK methods (`ExportObject`, `PutDocument`, `GetUnit`, `ExportPlain`, `crypto.MaxText`): removing them changes the SDK's API, which the scan already left to the owner.
- Not applied: B to E. They change structure or behaviour, and the scan itself leaves each to its own agreement.

The full suite passed afterwards, the database tests required.
