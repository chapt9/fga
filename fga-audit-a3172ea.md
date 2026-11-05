# Code audit: `fga` at a3172ea (INITIAL_FULL)

Code-only security, correctness and code-quality audit. Evidence comes from the committed tree at the review commit, from running the existing tests and binaries against disposable state, and from static tracing. READMEs, design documents, specifications, OpenAPI files and commit messages were not used as evidence. Comments and test names were used only for navigation.

---

## A. Review metadata

| Field | Value |
|---|---|
| mode | **INITIAL_FULL** |
| repository | `/Volumes/workdata/new_idea` (remote `origin` = `git@github.com:chapt9/fga.git`) |
| branch | `main` (`refs/heads/main`), not detached |
| review_commit | `a3172ead39b95d512c9e930a11adbbbd79a3ac56`: "MCP conformance: protocol 2026-07-28, resource metadata, origins, extensions" (2026-10-31 23:41 +0100) |
| base_commit | `null` (INITIAL_FULL) |
| parent-selection rule | First parent. Not applied in this mode; first parent `e2f7f4140f494721a301e12966710921ed4cd24a` is recorded for the next incremental run. |
| audit timestamp | 2026-11-01, 00:14–00:45 CET (snapshot, tests, reproductions); report written afterwards |
| excluded uncommitted / later work | The working tree has uncommitted deletions of `README.md` and every `docs/**` file. The untracked `.local/` and the empty `papers/` were not inspected. All evidence comes from `git archive a3172ea` extracted to a disposable directory outside the repository. |
| gap since last recorded review | None. No earlier review was recorded, so this run is the baseline. |
| Git state | Unchanged. Only read-only commands were used (`rev-parse`, `log`, `ls-tree`, `cat-file`, `archive`). No fetch, checkout, reset, stash or clean. |

---

## B. Scope and implementation inventory

**Size at a3172ea:** 216 Go files (84 of them tests); 36,127 non-test and 16,136 test lines. There are 25 catalog migrations and 2 tool-store migrations, plus a smoke script and an example policy bundle.

### B.1 Programs and entry points

| Program | Role and entry points (from code) |
|---|---|
| `cmd/fga-decision` | The only policy authority. `POST /v1/decide-batch` takes an adapter request; the adapter is identified by a TLS client certificate (URI SAN, else CN) or, in the development profile without TLS, is the configured dev adapter for any loopback caller. `POST /v1/check` is the public facade (bearer token, public projection only). Also `GET /healthz` and `/readyz`. It signs ALLOW decisions as detached EdDSA JWS with a lifetime of at most 5 min, appends one audit-outbox row per decision, and activates one signed bundle at start. |
| `cmd/fga-storage` | The native API: about 45 routes for objects, documents, derived outputs, labels, grants, approvals and server-mode plaintext. Callers authenticate with a bearer token (aud `fga-storage`) or, from configured MCP workloads, with the `Fga-Decision` header. It holds the content service, blob store and security journal. |
| `cmd/fga-keys` | Recipient enrolment, activation, revocation and lookup; envelope publication and retirement; `POST /internal/v1/deliver`; and the server-mode `POST /internal/v1/data-keys/*` routes (storage workload only). It holds the KEK ring file. |
| `cmd/fga-mcp` | MCP server (go-sdk v1.8.0, streamable HTTP, stateful and stateless). It obtains decisions for `mcp.tool.invoke` on the user's token and presents them to the storage and tools roles. |
| `cmd/fga-tools` | Executor for registered HTTP tools: invocations, leases, budget reservations and a 30 s reconciliation loop. Its admin subcommands are `tool add`, `tool review`, `destination add` and `budget set`. |
| `cmd/fga-admin` | Operator CLI that works directly on the database, journal and blobs: identities, delegations, capabilities, keys, epochs, backup, restore, reconcile, reclaim, audit export and KEK rotation. |
| `cmd/fga` | Client CLI and the stdio MCP bridge. |
| `sdk/go/client`, `sdk/go/crypto` | Client-side encryption (Tink streaming AEAD and HPKE), descriptor and envelope signatures, and download verification. |

### B.2 Identity propagation and trust boundaries

* **Users to storage, keys and tools:** `authn.Verifier` requires an `at+jwt` token signed with EdDSA, with the `kid` from configuration and no embedded keys. It checks `iss`, `aud`, `exp` and `iat` with 30 s skew and a lifetime of at most 1 h, and requires `sub`, `jti` and `fga_tenant`. The caller is `(tenant, sub)`. There is no revocation list, but disabled identities are refused by the gate and the fence.
* **Workloads:** in production, decision-role connections need a verified client certificate. The storage, keys and tools roles accept a client certificate if one is presented, and internal routes compare `AdapterOf` with a configured name.
* **MCP gateway (TB3):** the storage and tools roles accept a decision signed for their own audience when it was requested by a configured MCP workload for operation `mcp.tool.invoke`. The decision role accepts such a decision as first-hop evidence (`chained`).
* **Delegations:** only `fga-admin` creates them. A request without evidence but with a delegation is accepted from any non-public adapter, and the gate requires the delegation's audience to be the presenting adapter (or the gateway via `Via`).

### B.3 End-to-end trace of a protected operation

input (strict JSON with size caps, path and query validation) → authentication (token or gateway decision) → per-tenant admission → **selection** (bucket, object, version or intent read from the catalog *before* the decision) → `enforce.AuthorizeWith` (actor and subject revisions read from the catalog; checks; operation digest or plan) → decision role (gate: identity, revision, disabled and expiry state, delegation chain, actor capability, recipient keys; resource resolution by alias, ID, planned or changed; CEL ceiling then business evaluation; approvals; `Bind`; sign; append the audit row *before* responding) → `enforce.bound` (signed record against the request) → **fence** (one transaction locking `authority_state`, `tenant_epochs`, identities, delegations, recipient keys, resources (`FOR UPDATE` when mutated) and the approval; the operation's own rows; consumption of the approval and the single-use decision; time recheck; audit row in the same transaction) → redacted response → retry through idempotency keys or intents.

### B.4 Values selected before authorization and how they are bound

| Pre-authorization value | Later use | Bound or rechecked? | Code |
|---|---|---|---|
| Object head and version (`target`) | read, stat, package, ciphertext | Checks carry the version. The fence rechecks the object's generation and metadata revision, and `headHolds` rechecks currentness under lock for admitted reads. | `content/catalog.go:138-161`, `read.go:356-383` |
| Bucket encryption mode | begin, upload | `modeHolds` runs in the fence; a mismatch is `ErrEncryptionMode`, returned after authorization | `content/catalog.go:76-89`, `write.go:240-246` |
| Planned attributes at begin (owner, label, project) | planned object for the decision; **envelope resources of a new version** | The planned object comes from the intent. For an *existing* object, envelope resources copy the attributes as they were at **begin** (stale after a relabel) | `write.go:224,232,824-829`, `envelope.go:137-141` (**F-11**) |
| Label vs relabel classification | `setLabel` | Rechecked in the fence (current label and order generation) | `labels.go:184-200` |
| Grantee revision | grant record | Rechecked in the fence (`grantHolds`) | `grants.go:251-289` |
| Recipient key version | envelope or publish | Revision bound through recipient checks (fence step 5) | `fence.go:349-361` |
| Approval | decision → commit | ID and revision bound; consumed in the fence | `fence.go:185-195, 386-403` |
| Tool record (executor) | dispatch | The decision and fence bind the `agent.tool` generation; the tool is loaded at plan time | `executor.go:132-182` |
| **Destination row (executor)** | HTTP call | **Read after the fence commit; not bound** | `executor.go:264-270` (**F-16**) |
| **Tool and destination at reconciliation** | status query | **Current rows are read, not those used at dispatch** | `reconcile.go:138-157` (**F-04**) |
| **MCP tool named in a gateway decision** | any storage or tools route | **Not bound by the enforcing roles** | `httpapi.go:129-131`, `decisionsvc/service.go:568-571` (**F-06**) |

---

## C. Audit matrix

The status columns separate evidence level from outcome:

* **Evidence level:** NONE, STATIC_TRACE, EXISTING_TEST_INSPECTED, EXISTING_TEST_EXECUTED or SCENARIO_REPRODUCED.
* **Outcome:** UNASSESSED, SUPPORTED_FOR_LISTED_CASES, DEFECT_OBSERVED, SOURCE_SUPPORTED_FINDING, COVERAGE_GAP, AMBIGUOUS_INTENT or NOT_APPLICABLE.

Every row references commit a3172ea. The "Tests" column names existing tests that exercise the path; "executed" means they ran and passed in this audit.

### A01 Entry points and identity

| ID | Operation / path | Observed behaviour → invariant (basis) | Enforcement / refs | Tests (assertions) | Uncovered scenario → proposed test and oracle | Evidence / outcome / priority |
|---|---|---|---|---|---|---|
| A01-1 | `POST /v1/decide-batch` adapter identity | Adapter comes only from the connection: the verified certificate's URI SAN, else CN. The dev profile requires loopback and a single dev adapter (executable config checks). | `decisionsvc/http.go:23-35`; `fga-decision/main.go:186-203`; `config.go:108-181` | `cmd/fga-decision` TestValidate (rejects prod without TLS and dev on non-loopback); roleconfig TestRolesOverMutualTLS; executed | A certificate with no URI SAN but a CN equal to another adapter's name. **Test A:** issue certificates with CN-only and URI-only names; oracle: only the configured adapter names get non-401 responses and audience mapping. | EXECUTED / SUPPORTED_FOR_LISTED_CASES / P3 |
| A01-2 | Bearer tokens (all user-facing roles) | Token fields as in B.2; the claimed tenant and subject *are* the identity. | `authn/authn.go:71-113` | authn TestVerify asserts `ErrInvalid` for: JWT or missing type, other audience, other issuer, expired, lifetime >1 h, missing tenant, sub or jti, wrong key, garbage; executed | **Not tested:** other `alg` values (only EdDSA is accepted by `ParseSigned`), embedded `jwk`/`jku`/`x5c`, future `iat`/`nbf`. Disabled identities are refused by the gate (traced). No `jti` replay control (by design, ≤1 h). **Test A:** those three negative cases, plus a tenant-A token against a tenant-B resource ID giving 404 with no audit target in B. | EXECUTED / SUPPORTED / P3 |
| A01-3 | Decision request without evidence but with a delegation | Accepted from any non-public adapter; the gate checks presenter = delegation audience. The adapter vouches for the agent's identity (executable). | `service.go:524-527`; `gate.go:277-306` | decisionsvc TestFirstHopEvidence; executed | It is ambiguous whether every non-gateway adapter may assert agent identities. **Test A:** adapter X presents a delegation whose audience is Y; oracle: DENY `DELEGATION_AUDIENCE_MISMATCH`. | EXECUTED / AMBIGUOUS_INTENT / P3 |
| A01-4 | Gateway decision accepted by storage and tools | Checks: workload in MCPAdapters, signature, own audience, validity, `operation == mcp.tool.invoke`, `rec.Adapter` = caller. **The MCP tool is not checked.** | `httpapi.go:120-139`; `fga-tools/main.go:158-165` | nativeapi TestMCPGatewayHTTP, TestChainedEvidence; executed | **F-06.** **Test A:** obtain a `resources.list` MCP decision and call `DELETE /v1/buckets/b/object` and `POST /v1/invocations` with it; oracle: refused (currently expected to succeed). | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A01-5 | `POST /v1/check` public facade | Takes an admission slot (shared key `fga-public`) **before** verifying the token, and appends an audit row per request even on authentication failure. In production the decision role uses `RequireAndVerifyClientCert` for every route, so the "public" facade needs a workload certificate. | `decisionsvc/http.go:68-91`; `service.go:265-292, 580-587`; `fga-decision/main.go:201` | decisionsvc TestPublicProjection, TestAdmission; executed | **F-12** and an ambiguity about the facade's reachability. **Test B:** hold 128 slow-body `/v1/check` requests with junk bearer tokens; oracle: valid public callers are not refused. | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |

### A02 Tenant and ownership isolation

| ID | Path | Observed → invariant | Refs | Tests | Gap → proposed test | Status |
|---|---|---|---|---|---|---|
| A02-1 | Catalog schema and queries | Composite keys and foreign keys include the tenant, and every query filters on tenant (migrations are executable constraints). | migrations 0001, 0006, 0010-0020; `catalog/*.go` | catalog TestIdentitiesAreTenantScoped, TestCrossTenantReferenceIsRejected; executed | Global tables couple tenants: `audit_outbox` capacity, `consumed_decisions`, `label_orders`, `authority_state`, `journal_state`. Availability coupling is **F-07**. | EXECUTED / SUPPORTED (data) + finding (availability) / P2 |
| A02-2 | Keys internal routes | Tenant taken from the verified decision (`rec.Tenant`); envelope and version lookups scoped to it. | `envelope.go:224-371`; `datakeys.go` | envelope TestDeliveryRules, TestDeliveryNeedsTheExactEnvelope; datakeys TestRoutes; executed | **Test A:** a decision for tenant A with an envelope ID of tenant B; oracle: NotFound. | EXECUTED / SUPPORTED / P3 |
| A02-3 | Idempotency keys | Intents are unique per (tenant, principal, key). **Invocations are unique per (tenant, key)**, so another principal's reuse gets 409 instead of its own fresh invocation (a small oracle on keys in use). | `toolstore/migrations/0001_executor.sql` (`UNIQUE (tenant, idempotency_key)`); `invocation.go:117-141` | invocation TestCreateIsIdempotentPerOperation; executed | Two principals with the same key; oracle under the current code: 409, not cross-user data. | EXECUTED / SOURCE_SUPPORTED (low) / P4 |
| A02-4 | Admission keys | Storage and keys roles key admission on the tenant; the decision role on the adapter; the MCP role on (tenant, sub, *delegation header*). | `admission.go`; `mcpsvc.go:278-305` | admission TestLimits; mcpsvc TestMCPLimits; executed | **F-03.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |

### A03 Authorization and policy evaluation

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A03-1 | Ceiling and business combination | ALLOW only with a ceiling PASS and an explicit business ALLOW; any error or missing result denies; a deny overrides; stopping the engine is an ERROR. | `decision/decide.go:241-302, 410-427`; `engine.go:252-310` | decision TestCombinationOfCeilingAndBusinessSets, TestNothingIsAllowedWhenEvaluationStops; engine TestEvaluateCannotDecide; executed | None found. **F (mutation):** flip `ceiling.Effect != EffectAllow` and confirm the tests catch it. | EXECUTED / SUPPORTED / P3 |
| A03-2 | Time conditions | `request.now` may only appear in a direct comparison with a `timestamp()` literal; next-change bounds the validity window. | `engine.go:156-203, 264-268`; `service.go:466-468` | engine TestTimeRule, TestNextChange; decisionsvc TestTimeConditionBoundsValidity; executed | **E (fuzz):** a CEL AST fuzzer for `request.now` in macros; oracle: rejected at compile time or bounded. | EXECUTED / SUPPORTED / P3 |
| A03-3 | Operation shape | Checks must exactly fill the registered roles (types, actions, kinds); tool operations are read from the catalog and validated. | `service.go:320-336, 670-685` | registry TestPlanCompoundOperation; decisionsvc tests; executed | None found. | EXECUTED / SUPPORTED / P3 |
| A03-4 | Release activation | Ed25519 over the epoch and digest; environment match; ceiling declared; sentinels hold. The higher-epoch rule holds **within one process only**. | `release.go:294-382` | release TestRollbackIsANewHigherEpoch, TestSnapshotRequiresEpoch, TestCeilingDeclaration; executed | An older signed bundle activates after a restart unless tenant required epochs were raised (**AMB-4**). | EXECUTED / AMBIGUOUS_INTENT / P3 |
| A03-5 | Label ranks | Ranks are computed from the signed order; unknown or missing labels rank highest; stored rank attributes are dropped. | `labels/labels.go:51-79` | labels TestLabelRanks; executed | None found. | EXECUTED / SUPPORTED / P4 |

### A04 Signed and chained authority

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A04-1 | Decision verification | Detached JWS; key known, not revoked, issued within its validity; strict JSON; digest bindings; every check an unconditional allow; audience; issue and expiry times; obligations applied. The JWS `typ` is not checked, unlike content signatures. | `signing.go:367-457` vs `cryptowire/signed.go:59` | signing TestVerifyRejects, TestRecordContentRules, TestObligations; executed | Q-6 (inconsistency). Verifier keys are static (`roleconfig.go:189-199`), so revoking a decision key needs a configuration change and restart (**AMB-5**). | EXECUTED / SUPPORTED + AMB / P3 |
| A04-2 | `enforce.bound` | Tenant, actor, subject, delegation, operation, digest, single-use and each check's ID, version and binding must match; the resource is compared when it was requested by ID. | `enforce.go:199-219` | content and envelope tests; executed | **F (mutation):** drop the `OperationDigest` comparison; is it detected? (not run) | EXECUTED / SUPPORTED / P3 |
| A04-3 | Gateway decision as evidence | Bound to tenant, actor, subject and delegation; the audience must be one the gateway may address and the adapter serves; the incarnation is compared. **Not bound to the MCP tool or the downstream operation**, and reusable until it expires. | `service.go:558-575`, `httpapi.go:120-139` | TestChainedEvidence, TestGatewayRevision; executed | **F-06.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A04-4 | Key-release extras | Complete-content, reader-path and recipient-path decisions must exactly cover the units or lineage, be single-use, come from the same actor, and be admitted in one fence. | `keycheck.go:30-155`; `envelope.go:373-453` | datakeys TestReleaseOriginal, TestReleaseDerived; content TestDerivedDelivery, TestOriginalFile; executed | **C (property):** random lineage DAGs; oracle: the release succeeds only with the exact closure. | EXECUTED / SUPPORTED / P3 |

### A05 Delegations, approvals and grants

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A05-1 | Delegation chains | Each link is checked for tenant, revocation, expiry, cycles, depth ≤ 4 and narrowing (subject, expiry, grants). Every link must cover the action. The leaf is admitted on actor, subject and audience. `ValidateChild` does **not** constrain the child's audience or relate the child to the parent's actor. | `delegation.go:77-166` | delegation TestChildCannotWiden, TestRevokingParentDisablesChild; executed | **AMB-2** (only `fga-admin` creates delegations). **Test C:** generate chains; oracle: no allow beyond the intersection. | EXECUTED / SUPPORTED + AMB / P3 |
| A05-2 | Approval separation of duties | The storage role refuses deciders for whom `c.Is(requester or actor)` holds, which covers the same subject acting through *another agent*. The store refuses `approver ∈ {requested_by, actor}`, and the decision role checks again. Consumed by revision in the fence. | `content/approvals.go:102-146`; `approval.go:198-225`; `service.go:768-775`; `fence.go:185-195` | content TestPublicationApprovals, TestShareApproval; executor TestInvokeApproval; executed | **Test A:** user U requests directly; agent A2 acting for U approves; oracle: 409 (traced to `c.Is`, not executed). | EXECUTED / SUPPORTED / P3 |
| A05-3 | Share grants | Grantee revision bound; expiry ≤ grantor identity and delegation; replacements and removals journaled before commit; at most 100 per resource. | `content/grants.go:169-342`; `catalog/grants.go:90-165` | content grants tests; recovery TestRestoreKeepsGrantRemoval; executed | Expired grants removed in `RecordGrant` are not journaled (harmless: they are already expired). | EXECUTED / SUPPORTED / P4 |
| A05-4 | Executor resolve and write-off | Neither the actor nor the subject (including through another delegation) may settle an invocation. | `executor.go:324-365`; `invocation.go:291-348` | executor TestResolution; executed | None found. | EXECUTED / SUPPORTED / P4 |

### A06 Selection and version consistency

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A06-1 | Object reads | Version bound in the checks; the head is rechecked in the fence; a plain server-mode key release requires the head. | `read.go:193-255, 356-383`; `datakeys.go:222-290` | content race_test (concurrent overwrite); datakeys TestRelease; executed | None found. **B:** a deterministic overwrite between decision and fence (partly covered by race_test). | EXECUTED / SUPPORTED / P3 |
| A06-2 | SDK multi-request download | Package then ciphertext pinned to the claimed version; descriptor signature, digest and AAD verified before decryption. **For a current-version read the client cannot bind the object to the requested key**, because the descriptor holds the object UUID but not the bucket or key. | `sdk/go/client/client.go:45-55, 458-489`; `cryptowire/signed.go:74-88` | client TestGetChecksRequestedVersion; executed | **AMB-3.** **Test A:** a storage stub returns a correctly signed package of object B for key A. | EXECUTED / AMBIGUOUS_INTENT / P3 |
| A06-3 | Begin → finalize attributes | Envelope resources take the begin-time snapshot for existing objects, while the decision saw current attributes (`planned.go:56-61`). | `write.go:224-232, 824-829` | none | **F-11.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |
| A06-4 | Executor tool and destination | See B.4. | `executor.go:264-270`; `reconcile.go:138-157` | executor TestReconcile (no re-registration) | **F-04, F-16.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A06-5 | Listing continuation | Sealed AES-GCM token bound to tenant, principal, revision, bucket, prefix, epoch, incarnation and expiry; every candidate decided. Not bound to delegation or subject (only the start position is affected). | `list.go:39-127, 345-387` | content list tests; executed | None. | EXECUTED / SUPPORTED / P4 |

### A07 Publication and durable state

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A07-1 | Publish commit | In one transaction: the fence, intent state STAGED and unexpired, preconditions, generation compare-and-set, version, head, envelopes, intent result and audit row. | `write.go:638-676, 747-837` | content TestRoundTrip and others; executed | None found. | EXECUTED / SUPPORTED / P3 |
| A07-2 | Blob durability | Exclusive temp file, length and SHA-256 checked, fsync, link without replace, directory fsync. Staging happens under the intent row lock. | `blob.go:134-162`; `write.go:436-467` | blob tests; recovery TestReclaimDuringUpload; executed | **D:** crash between link and directory fsync (process kill does not prove power-loss durability). | EXECUTED / SUPPORTED / P3 |
| A07-3 | Journal before commit | Admin path: append, then `RecordJournal`, then change. Keys revoke and grant removal: append, then `RecordJournal` inside the fence. | `fga-admin/main.go:211-229`; `envelope/registry.go:209-244`; `grants.go:144-158` | journal TestChain, TestConcurrentAppends; recovery TestJournalHistoryContinuity; executed | Coverage of journal kinds: **AMB-1**. | EXECUTED / SUPPORTED + AMB / P2 |
| A07-4 | `DeleteVersion` envelope retirement | Envelopes set to RETIRED, but their `crypto.envelope` resources keep `status: ACTIVE` and their generation. Delivery is still blocked by the envelope row status. | `delete.go:129-131` | content delete tests; executed | Q-7 (policy-visible state drifts from row state). | STATIC_TRACE / SOURCE_SUPPORTED (low) / P4 |

### A08 Disclosure

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A08-1 | Absent vs denied | Both give `ErrNotFound`/404. Absent targets return before any decision; denied ones cost a decision round trip and an audit row. | `content/catalog.go:138-161`; `envelope/registry.go:270-289` | content TestDeniedDocumentLooksAbsent; executed | **AMB-6 (timing).** **Test A:** latency distribution for absent vs denied keys. | EXECUTED / AMBIGUOUS_INTENT / P4 |
| A08-2 | Listing | Hidden entries omitted; the cursor skips invisible keys and stays sealed. | `list.go:62-203` | content list tests; executed | Amplification: **F-07**. | EXECUTED / SUPPORTED / P3 |
| A08-3 | Stat projection obligation | Applied only for stat operations; any other obligation is refused. | `content.go:166-168`; `read.go:98-106` | content obligations_test; decisionsvc TestApplyObligations; executed | None. | EXECUTED / SUPPORTED / P4 |
| A08-4 | Document units, manifest and original | read-units plus read on every selected unit; whole-document disclosures are checked against all members, quarantined ones included. | `disclosure.go:101-230, 488-654` | TestExplicitSelection, TestAuthorizedSubset, TestQuarantinedUnitsStayGuarded, TestOriginalFile; executed | None found. | EXECUTED / SUPPORTED / P3 |
| A08-5 | Public projection | Only ALLOW, DENY DENIED, DENY INVALID_REQUEST or ERROR UNAVAILABLE. | `public.go:38-52` | TestPublicProjection; executed | None. | EXECUTED / SUPPORTED / P4 |
| A08-6 | `SearchDocuments` | Traced in part only. | `export.go:219-380` | content search tests (not inspected in detail) | Not completed. | STATIC_TRACE (partial) / UNASSESSED / P3 |

### A09 Cryptography and custody

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A09-1 | Content signatures | JWS separated by `typ`; the signer must be an ACTIVE key of the uploader at finalize and again in the fence. | `cryptowire/signed.go:50-70`; `catalog/storagecontrol.go:159-167`; `write.go:646` | cryptowire TestSignatures; content tests; executed | None. | EXECUTED / SUPPORTED / P3 |
| A09-2 | Client crypto | HPKE envelope with checked context binding; descriptor digest checked before streaming decryption; AAD bound to tenant, object, crypto version, suite and format. | `sdk/go/crypto/crypto.go:411-470` | sdk crypto TestDecryptFailures, TestKeyPackageChecks; executed | **AMB-3.** | EXECUTED / SUPPORTED / P3 |
| A09-3 | Server-mode data keys | 32-byte key sealed under the KEK (AES-GCM; AAD = domain, KEK version, version identity). Released only against a single-use keys-audience decision in the fence. The key is cleared after use, though Tink keeps a copy until garbage collection. | `kek.go`; `datakeys.go:121-638`; `payload.go:78-121` | datakeys tests; payload TestBindingAndIntegrity; kek tests; executed | None found. | EXECUTED / SUPPORTED / P3 |
| A09-4 | KEK ring and key files | Argon2id with bounded parameters; atomic writes; the development ring is refused in production. | `keyfile.go`; `fga-keys/main.go:63-65` | keyfile tests; TestProductionRefusesDevelopmentKEKs; executed | None. | EXECUTED / SUPPORTED / P4 |
| A09-5 | Key destruction at reclaim | `sealed_key → NULL` and `key_destroyed_at` constrained by a CHECK. `Reclaim` was **not** read in full. | migration 0021; `recovery/reclaim.go` | recovery TestReclaim; executed | Partial trace. | EXECUTED / UNASSESSED (code) / P3 |

### A10 Concurrency and locking

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A10-1 | Fence lock order | authority_state → tenant_epochs → identities → delegations → recipient keys → resources (sorted by type and ID) → approval. | `fence.go:286-405` | fence TestFenceOrdersAgainstRevocation, TestFirstEpochRaiseIsOrdered; content race_test; executed under `-race` | Operation rows locked inside `fn` are outside the fixed order; not every pair was analysed. | EXECUTED / SUPPORTED_FOR_LISTED_CASES / P2 |
| A10-2 | Recipient revoke through the keys API | Locks `resources(fp)` FOR UPDATE, then updates `recipient_keys`. The opposite order is used by recipient-check fences and by admin revoke and replay. | `envelope/registry.go:225-243`; `fence.go:349-383`; `catalog/control.go:40-54` | envelope TestRevokeRecipient; executed | **F-09.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |
| A10-3 | Connector `written` flag | Written by the transport's trace callback and read after `Do` returns, without synchronisation. | `connector.go:149-158` | connector TestNotSentIsFailed; executed under `-race` (window not exercised) | **F-14.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P4 |

### A11 Backup and recovery

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A11-1 | `ReconcileWith` integrity scan | **A query error mid-iteration ends the loop silently; admission then reopens.** | `recovery.go:683-723` | recovery TestReconcileQuarantines (no fault injection); executed | **F-01, reproduced.** | **SCENARIO_REPRODUCED / DEFECT_OBSERVED / P1** |
| A11-2 | Backup table set | `recovery.Tables` omits the catalog table `tool_operations` (migration 0025). | `recovery.go:47-53` | none compare `Tables` with the schema | **F-02, reproduced.** | **SCENARIO_REPRODUCED / DEFECT_OBSERVED / P3** |
| A11-3 | Restore table list | Restore deletes the fixed `Tables` but COPYs whatever the manifest lists. | `recovery.go:512-531` | recovery TestBackupIntegrity; executed | **F-17.** | STATIC_TRACE / SOURCE_SUPPORTED (low) / P4 |
| A11-4 | Journal continuity and unproven gate | Admission stays closed on a broken or short chain, a different journal, or (without `-journal-complete`) a missing catalog record. | `recovery.go:117-122, 461-569, 595-648` | TestLostJournalFailsClosed, TestRestoreWithoutCatalogRecord, TestJournalHistoryContinuity; executed | Journal coverage: **AMB-1**. | EXECUTED / SUPPORTED + AMB / P2 |
| A11-5 | KEK check at reconcile | Every sealed key must open under the ring, or its version is quarantined; `rows.Err()` is checked here. | `recovery.go:738-788` | recovery serverkeys_test; executed | None. | EXECUTED / SUPPORTED / P3 |

### A12 External effects and accounting

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A12-1 | Dispatch commit | In the fence: lease check (token and expiry), DISPATCHING, reservation hold, consumption of the decision and approval, audit row. | `executor.go:237-262`; `invocation.go:190-243` | executor TestDispatchFence, TestInvokeReservation; executed | None. | EXECUTED / SUPPORTED / P2 |
| A12-2 | Reconciliation target | Queries the **current** tool and destination. | `reconcile.go:138-157` | executor TestReconcile; executed | **F-04.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A12-3 | "404 = never received" and stalled workers | A destination 404 maps to FAILED and releases the reservation. Nothing stops a worker whose lease expired from sending later. | `connector.go:196-222`; `executor.go:244-270` | connector TestStatus; executed | **F-05.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A12-4 | Outcome audit | The outcome event is appended *after* `Complete`, outside the transaction; a failure is only logged. | `executor.go:274-283`; `reconcile.go:159-165` | none | **F-18.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |
| A12-5 | SSRF controls | Resolved address must be inside the allowed CIDRs at dial time; no proxy; redirects not followed; credential read from the destination's file. | `connector.go:89-127, 176-186` | TestAddressPolicy, TestRedirectIsNotFollowed; executed | None found. | EXECUTED / SUPPORTED / P3 |

### A13 Progress and resource bounds

| ID | Path | Observed → invariant | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A13-1 | MCP sessions and calls | Per-user limits keyed by the client-chosen delegation header. | `mcpsvc.go:278-374` | TestMCPLimits (never varies the header) | **F-03.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A13-2 | Audit outbox | One global capacity; `count(*)` per append; drained only by `fga-admin audit export`; List amplification. | `catalog.go:300-328`; `list.go:93-203` | audit TestFullOutboxRefusesInsteadOfDropping; executed | **F-07.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P2 |
| A13-3 | Retention | Several tables are never pruned. | grep: only 3 `DELETE` sites | none | **F-08.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |
| A13-4 | UNKNOWN reconciliation | The oldest 100 UNKNOWN invocations are re-polled forever; newer ones starve. | `invocation.go:366-373`; `reconcile.go:105-127`; `fga-tools/main.go:179` | none | **F-10.** | STATIC_TRACE / SOURCE_SUPPORTED_FINDING / P3 |
| A13-5 | Slow upload bodies | No ReadTimeout or WriteTimeout on storage, keys, tools or MCP servers; an upload lease runs to the year 9999. | `roleconfig.go:232`; `read.go:271-274` | nativeapi TestTenantStreamLimit; executed | **F-13.** | STATIC_TRACE / SOURCE_SUPPORTED (low) / P3 |
| A13-6 | Request and response size bounds | JSON 1 MiB (documents 48 MiB), ciphertext 256 MiB, decide-batch 64 KiB, MCP request 1 MiB, MCP response caps. | `httpapi.go:20, 163`; `content.go:117`; `mcpsvc.go:95, 225` | nativeapi TestHTTPBoundaries; executed | None. | EXECUTED / SUPPORTED / P4 |

### A14 Protocol and client compatibility

| ID | Path | Observed | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A14-1 | MCP protocol selection | Lexicographic `Mcp-Protocol-Version >= "2026-07-28"`; any larger string takes the stateless path without session accounting. | `mcpsvc.go:228-234, 293` | TestMCPTransport; executed | Low. **Test A:** version `"9"`. | STATIC_TRACE / SOURCE_SUPPORTED (low) / P4 |
| A14-2 | Strict parsing | `strictjson` rejects unknown, duplicate and trailing fields for configs, requests, records and manifests. The MCP role's decision response is decoded tolerantly but carries no authority. | `strictjson.go`; `mcpsvc/decision.go:96` | format TestParseRejectsAmbiguousInput; decision role TestLoadConfigRejectsUnknownFields; executed | None. | EXECUTED / SUPPORTED / P4 |
| A14-3 | OpenAPI coverage | `TestOpenAPICoversRoutes` regex-matches `nativeapi.go` against `docs/...openapi.yaml`. It is a documentation-sync check, not behavioural evidence, and it fails in the current working tree because `docs/` is deleted there. | `openapi_test.go` | executed on the snapshot (passes) | Q-8. | EXECUTED / NOT_APPLICABLE (doc) / P4 |

### A15 Audit and error handling

| ID | Path | Observed | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A15-1 | Decision audit | The audit row is appended before the response; a failure turns the answer into ERROR AUDIT_UNAVAILABLE and the signature is discarded. | `service.go:288-291` | TestNoDecisionWithoutAudit; executed | None. | EXECUTED / SUPPORTED / P3 |
| A15-2 | Mutation audit | Audit row in the same transaction as the change (fence `fn`). | e.g. `write.go:670`, `delete.go:146` | content tests; executed | None. | EXECUTED / SUPPORTED / P3 |
| A15-3 | Ignored errors | `rows.Err()` missing in the reconcile scan (F-01; the only such loop in the tree, found by script). Executor outcome audit only logged (F-18). `_ = json.NewEncoder(w).Encode` on response writes is acceptable. | see findings | — | — | REPRODUCED + STATIC_TRACE / DEFECT + FINDING / P1–P3 |

### A16 Test fidelity and code quality

See D.4. Summary: tests exercise production-unused parallel paths (`gate.Recheck`; `invocation.BeginDispatch` with `approval.ConsumeTx` and `Usable`), one test is a regex documentation-sync check, and several public SDK functions have no tests. Whole-suite coverage is 70.3%, with `cmd/fga`, `cmd/fga-admin` and `cmd/fga-storage` at 0%.

### A17 Build, configuration and migrations

| ID | Path | Observed | Refs | Tests | Gap | Status |
|---|---|---|---|---|---|---|
| A17-1 | Build reproducibility | `go mod verify` passes; gofmt, vet and build are clean offline with `-mod=readonly` and `GOPROXY=off`; go 1.27.3. | `go.mod`, `go.sum` | — | No vulnerability scanner was available (govulncheck absent, offline). | EXECUTED / SUPPORTED (build) / UNASSESSED (CVE) |
| A17-2 | Migrations | Each runs in its own transaction under an advisory lock; tests apply them twice (idempotent); toolstore migrations use a prefix. | `catalog.go:91-142`; `pgtest.go:47-51` | every DB test via `pgtest.Pool`; executed | Upgrade from real old data not tested (migrations 0015, 0016 and 0023 rewrite rows). | EXECUTED / SUPPORTED / P3 |
| A17-3 | Unsafe configuration | Production requires TLS, refuses the dev issuer, the dev KEK ring and `dev_adapter_id`; development without TLS requires loopback. Peer `CAFile` is optional in production (falls back to system roots). | `roleconfig.go:101-140, 203-226`; per-role `Validate` | TestValidate in cmd packages; executed | **AMB-5** (system roots). | EXECUTED / SUPPORTED + AMB / P3 |
| A17-4 | Role import allowlists | Every role's transitive imports are checked against `allowed-imports.txt` with `go list`. | `depcheck.go` | TestImportAllowlist ×5; executed | None. | EXECUTED / SUPPORTED / P4 |

---

## D. Prioritized findings

Severity reflects impact under the code's own trust model. Every finding was challenged by searching for an overlooked guard; the counter-checks are listed with each. No independent parallel reviewer was available in this session, so agreement between reviewers was not used as evidence.

### D.1 Reproduced defects

#### F-01: Reconcile reopens admission after an incomplete integrity scan (Medium, P1), SCENARIO_REPRODUCED

* **Where:** `internal/recovery/recovery.go:683-707` (scan loop) and `:723` (`store.SetAdmission(ctx, true, 0)`).
* **Preconditions:** a restore has left admission closed. `fga-admin reconcile` runs, and the scan query fails mid-stream (connection reset, statement cancel, failover, `statement_timeout`).
* **Sequence:** `pool.Query(...)` → `for rows.Next()` ends early because of the error → `rows.Close()` with **no `rows.Err()` check** → only the versions seen so far are quarantined → admission reopens → exit 0 with an understated count.
* **Consequence:**
  * The deployment is admitted again although not every LIVE or WITHDRAWN version was checked against its blob.
  * Versions with missing or altered ciphertext stay LIVE: they are listed, reads return 503 instead of 404, and later backups fail with `ErrIncomplete` unless `-allow-missing` is used.
  * The operator is told the reconcile succeeded.
  * Confidentiality is not affected: clients verify digests and AEAD, and the server decrypts with AEAD.
* **Why the guards don't help:**
  * `ReconcileWith` never rescans.
  * `checkKeys` checks `rows.Err()` only for its own queries.
  * `SetAdmission` is unconditional.
  * This is the only `rows.Next()` loop in the tree without `rows.Err()` (script `rowscheck.py`).
* **Reproduction:**
  * Setup: committed `fga-admin` built from the snapshot, two disposable databases, 300,000 LIVE client-mode versions whose blobs are absent.
  * Control (uninterrupted): `quarantined 300000 versions; admission is open`, exit 0, 31.8 s.
  * Interrupted (`pg_cancel_backend` on the scan backend 0.3 s after it started; the server logged `ERROR: canceling statement due to user request`): `quarantined 35533 versions; admission is open`, **exit 0**; final state `LIVE=264467, QUARANTINED=35533`, `admission_open=t`.
* **Proposed regression test (D, fault):** a pgx pool whose connection is cancelled after N rows (or `pg_cancel_backend` at a synchronisation point). Oracle: reconcile returns an error, `admission_open` stays false, and nothing is partially reported.

#### F-02: Backups omit `tool_operations`, so a restore drops tool registrations (Low, P3), SCENARIO_REPRODUCED

* **Where:** `internal/recovery/recovery.go:47-53`; table created in `internal/catalog/migrations/0025_tool_operations.sql`; read in `catalog/tools.go:77-91`.
* **Sequence:** register a tool (a `tool_operations` row plus an `agent.tool` resource) → `fga-admin backup` → `fga-admin restore` onto an empty catalog.
* **Reproduction:** source `tool_operations=1, agent.tool resources=1`; the manifest lists 31 tables and no `tool_operations`; restored `tool_operations=0, agent.tool resources=1` (restore exit 0).
* **Consequence:** after restore and reconcile, every registered tool call is denied with `UNKNOWN_OPERATION` until each tool is reviewed again. This fails closed, but tool availability is lost after recovery. An in-place restore instead keeps post-backup `tool_operations` next to backup-era resources.
* **Counter-check:** no test compares `recovery.Tables` with the catalog schema (`TestCoreMigrationsHaveNoExecutorTables` only checks the opposite direction).
* **Proposed regression test (A):** compare `recovery.Tables` with `pg_tables` of the migrated catalog, minus a documented exclusion list (`enrollment_challenges`, `schema_migrations`), and round-trip a registered tool through backup and restore. Oracle: `ToolOperation()` is unchanged.

### D.2 Source-supported findings (not executed; reasoning from code)

#### F-03: One MCP token can exhaust the MCP role's global session and call limits (Medium, P2)

* **Where:** `internal/mcpsvc/mcpsvc.go:363-374` (`UserID` includes the `Fga-Delegation` header); `:278-305` (`bound` keys the limiter and sessions on `UserID`); `resources.go:20-64` (`initialize` is never decided).
* **Sequence:** the holder of one valid token sends `initialize` requests with different syntactically valid `Fga-Delegation` values (`[A-Za-z0-9-_.:]{1,128}`). Each value is a new "user" with a fresh quota of `UserSessions=8` and `UserRequests=8`. Values are not checked against the catalog before a session opens. 128 values reach `TotalSessions=1024`, and 32 values reach `TotalRequests=256` concurrent calls.
* **Consequence:** every other MCP user gets 429 until sessions time out (30 min idle, which the attacker can keep alive).
* **Counter-checks:**
  * Origin checking only applies to browsers.
  * The decision role would deny the bogus delegations, but only on tool calls; `initialize`, `ping` and listing do not reach it.
  * Whether the SDK caps sessions could not be checked: its source is outside the catalogue.
* **Proposed test (A/B):** `mcptest` with `Limits{UserSessions:2, TotalSessions:3}`; one token opens sessions with delegation values `a`, `b` and `c`. Oracle: the third distinct value is refused and another user can still connect.

#### F-04: Reconciliation consults the current tool and destination, not the ones dispatched to (Medium, P2)

* **Where:** `internal/executor/reconcile.go:138-157`. The `invocations` row stores `tool` and `tool_version`, but neither the destination nor its URL (`toolstore/migrations/0001_executor.sql`).
* **Sequence:**
  1. An invocation of tool T is dispatched to destination D1 and ends DISPATCHING (stalled) or UNKNOWN.
  2. An administrator runs `tool add` and `tool review` for T pointing at D2, or `destination add D1 -url <new>`.
  3. The reconciler calls `Status` on the new destination with the old idempotency key.
  4. The new destination has no record and returns 404 → FAILED → `ReleaseTx` releases the reservation (`invocation.go:271-279`), although D1 executed the call.
* **Consequence:** budget accounting understates spending, the invocation is recorded as failed though it took effect, and a user may retry and cause a second effect.
* **Counter-checks:** `status()` never compares `t.Version` with `inv.ToolVersion` and never pins the destination; UNKNOWN invocations can stay open for a long time, so the window is wide.
* **Proposed test (B, deterministic):** in `executortest`, a destination stub never answers (UNKNOWN); re-register the tool pointing at a second stub that answers 404 to status; run `Reconcile`. Oracle: the invocation stays UNKNOWN and the reservation stays HELD.

#### F-05: "Destination 404 = never received" is not established; a stalled worker can still send (Medium-Low, P2)

* **Where:**
  * `internal/tools/connector/connector.go:196-222` (404 → `Failed`).
  * `executor.go:237` (the lease is taken *before* the fence), `:244-262` (dispatch commit), `:264-270` (destination DB read, then `Do`, with no lease check in between).
  * `reconcile.go:94-104` (stalled → status → Complete).
* **Sequence A (stalled worker):** W1 commits DISPATCHING near the end of its lease (fence lock waits count against it), then stalls (slow destination read, GC or VM pause) beyond the lease. W2 reconciles: status 404 → FAILED → reservation released. W1 resumes and sends the request with the same idempotency key, and the destination executes it.
* **Sequence B (in flight):** the request was sent; `Do` times out (UNKNOWN). The destination has not yet recorded the key when the reconciler asks, gets 404, and the call is marked FAILED and released; the destination then processes it.
* **Consequence:** as in F-04.
* **Counter-checks:**
  * `Complete` with a stale fencing token fails, but the external effect has already happened, and the invocation stays FAILED (the reconciler only rescans DISPATCHING and UNKNOWN).
  * Defaults are lease 60 s and connector timeout 30 s, which narrows but does not remove the window.
* **Proposed tests:**
  * **B:** inject a pause hook between `DispatchTx` and `Do` (test-only) and advance the clock past the lease; oracle: no send after expiry, or no FAILED without positive evidence.
  * **G (model):** states {PREPARED, DISPATCHING, SENT?, DEST_RECORDED, FAILED, …} with lossy timing.

#### F-06: Gateway decisions are not bound to the MCP tool at the enforcing roles (Medium-Low, P2; defense in depth)

* **Where:** `internal/httpapi/httpapi.go:129-131` checks only operation, adapter and subject consistency; `internal/decisionsvc/service.go:568-571` (`chained`) does the same.
* **Sequence:** the MCP workload, which is trusted but could be compromised or buggy, obtains a user's decision for `invoke` on `mcp.tool:resources.list`. It presents that decision in `Fga-Decision` to any storage route (DELETE object, grants, approvals, export) or to the tools role's `POST /v1/invocations`. Each is decided with the user's native permissions.
* **Consequence:** MCP-tool-level policy (for example "member may list via MCP but not `documents.export` or `tools.call`") is enforced only by the MCP role. A gateway bug or compromise acts with the user's full native authority for the decision's validity (≤ 5 min, reusable).
* **Counter-checks:** limited to configured `mcp_adapters` workloads; the decision's audience must be the receiving role.
* **Proposed test (A):** a test-only HTTP client with the MCP workload identity replays a `resources.list` decision against `DELETE /v1/buckets/vault/object?key=…`. Oracle with the fix: 401 or 403.

#### F-07: One global audit-outbox capacity can halt every tenant, with high per-request amplification (Medium, P2; availability)

* **Where:**
  * `internal/catalog/catalog.go:300-328`: global `count(*) … WHERE delivered_at IS NULL < capacity` on every append.
  * `decisionsvc/service.go:288-291`: an append failure gives ERROR.
  * `content/list.go:93-118, 166-203`: up to 100 batches × (1 + 50) decisions ≈ 5,100 decisions, audit rows and fence checks per `List` call when candidates are hidden.
  * `auditexport` is used only by `fga-admin audit export`, so no role drains the outbox.
  * The public facade appends a row even for failed authentication (`service.go:265-292`).
* **Consequence:** without a continuously running exporter, the platform stops deciding (fail closed, all tenants) after `outbox_capacity` decisions in normal use. With one, an authenticated user can still drive it toward capacity with `List` on buckets of hidden objects. Appends cost O(backlog).
* **Proposed test (A/C):** a small `outbox_capacity` with a hidden-object bucket. Oracle: a bounded number of audit rows per List call, and per-tenant fairness (tenant B's decisions still succeed).

#### F-08: No retention for consumption, admission and audit tables (Low, P3)

* **Where:** `DELETE` appears only at `envelope/registry.go:189`, `catalog/labels.go:28` and restore `recovery.go:517`.
* **What grows without bound:** `consumed_decisions` (every single-use decision), `read_admissions` (every admitted read), delivered `audit_outbox` rows, expired `enrollment_challenges` with PENDING `recipient_keys`, expired approvals, aborted intents and `label_proposals`. All of these are copied into every backup (`recovery.Tables`).
* **Consequence:** unbounded growth of the database and of backups. Consumption rows are needed only until `valid_until`.
* **Proposed test (C):** after N single-use reads, table sizes stay bounded once their windows pass, assuming pruning is added.

#### F-09: Lock-order inversion between recipient revocation and recipient-bound operations (Low, P3)

* **Where:**
  * `envelope/registry.go:225-243`: fence step 6 `resources(fp) FOR UPDATE`, then `UPDATE recipient_keys`.
  * `fence.go:349-383` (publish, deliver): `recipient_keys FOR SHARE` (step 5), then `resources(fp) FOR SHARE` (step 6).
  * `catalog/control.go:40-54` (admin) and reconcile replay: `recipient_keys`, then `resources`.
* **Consequence:** concurrent revoke and publish or deliver for the same key can deadlock (`40P01`); PostgreSQL aborts one of them. The revoke may fail after its journal entry was written (the design allows replaying it). This causes spurious failures, not a bypass.
* **Proposed test (B):** two connections with an advisory-lock barrier that hold the step-5 and step-6 locks in opposite orders. Oracle: no `40P01`.

#### F-10: Old UNKNOWN invocations starve reconciliation of newer ones (Low, P3)

* **Where:** `invocation.go:366-373` (`ORDER BY dispatched_at LIMIT 100`); `fga-tools/main.go:179` (limit 100).
* **Consequence:** with 100 or more UNKNOWN invocations at destinations without a reconcile path, every pass re-polls the same 100, and newer UNKNOWN invocations are never resolved or escalated.
* **Proposed test (A):** 101 UNKNOWN invocations, the oldest 100 unresolvable. Oracle: the 101st is reconciled or escalated within one or two passes.

#### F-11: Envelope resources snapshot the object's attributes at upload begin (Low, P3)

* **Where:** `content/write.go:224, 232` store the object's attributes at begin; `:824-829` insert envelopes with `in.attributes`; `envelope.go:137-141` copies owner, project, label and bucket. The decision about the planned envelope used *current* attributes (`catalog/planned.go:56-61`). `catalog.SetLabel` does not propagate to envelopes (`catalog/labels.go:82-91`).
* **Consequence:** after a relabel between begin and finalize, or any later relabel, `crypto.envelope` resources carry a stale label or owner. Policies that test `resource.attributes.label` on `release` see the stale value; the example policy does not.
* **Proposed test (A):** begin, raise the label, finalize. Oracle: the envelope resource's label equals the object's.

#### F-12: Public facade takes an admission slot before authentication (Low, P3)

* **Where:** `decisionsvc/http.go:68-91`.
* **Consequence:** any connection presenting `Authorization: Bearer x` can hold one of the 128 `fga-public` slots for up to `ReadTimeout` (10 s) with a slow body. In production this needs a workload client certificate (`fga-decision/main.go:201`), which is also why the facade is not truly public there (AMB).

#### F-13: Storage, keys, tools and MCP servers have no read or write timeouts (Low, P3)

* **Where:** `roleconfig.go:232`; `fga-mcp/main.go:292`; `read.go:271-274` (upload lease until 9999).
* **Consequence:** a slow upload body holds a tenant stream slot (8 per tenant) and a total slot (512) indefinitely; that is self-DoS per tenant and erodes the shared total.

#### F-14: Data race on the connector's `written` flag (Low, P4)

* **Where:** `connector.go:149-158`. The flag is written in `httptrace.WroteRequest`, which runs on the transport goroutine, and read after `Do` returns, possibly early on timeout.
* **Consequence:** a narrow-window misclassification of FAILED versus UNKNOWN, which settles the reservation the wrong way.

#### F-15: `budget set` can change a budget's currency while amounts are held (Low, P4; admin)

* **Where:** `toolstore/store.go:190-196`.
* **Consequence:** reserved and spent minor units are reinterpreted in the new currency.

#### F-16: Destination row is not bound to the decision, and `destination add` is not atomic (Low, P3; admin-triggered)

* **Where:** `executor.go:264` reads the destination after the fence; `cmd/fga-tools/main.go:261-266` runs `PutDestination` and `RegisterDestination` in separate transactions.
* **Consequence:** a call decided under the old destination's generation can be sent to the new URL, CIDRs and credential.

#### F-17: Restore follows the manifest's table list (Low, P4)

* **Where:** `recovery.go:512-531` deletes the fixed `Tables` but copies `m.Tables`.
* **Consequence:** a manifest that omits a table empties it, and one that names an extra table writes into it. Exploiting this requires the backup key, because the manifest is AEAD-sealed.

#### F-18: Executor outcome audit is outside the outcome transaction (Low-Medium, P3)

* **Where:** `executor.go:274-283` and `reconcile.go:159-165`. `Complete` commits SUCCEEDED, FAILED or UNKNOWN, then `Catalog.Append` runs separately; an error is only logged.
* **Consequence:** an external effect can complete with no outcome audit event, for example when the outbox is full (F-07). Every other mutation writes its audit row inside its own transaction.

### D.3 Ambiguities (product intent needed)

* **AMB-1, journal coverage.** The journal records identity disable, delegation and recipient revocation, signer compromise, epoch raises, grant removals and incarnations (`journal.go:35-47`). It does not record role or attribute *reductions* (`fga-admin identity put`, `main.go:266-274`), signing-key *retirement* (`main.go:309-313`) or identity expiry changes, and there is no capability-removal command at all. A restore from an older backup silently restores those privileges. Is "security-critical" meant to include them?
* **AMB-2, delegation narrowing.** A child delegation's audience (presenter) is not constrained by its parent's, and the model has no "delegator" (`delegation.go:113-130`).
* **AMB-3, client verification of current-version reads.** The SDK and MCP bridge cannot bind a package to the requested bucket and key, since the descriptor carries only object and version UUIDs (`client.go:45-55`). A malicious storage role could substitute another object's, or an older, correctly signed version. Explicit version reads are pinned.
* **AMB-4, policy rollback across restarts.** `Activate` enforces higher epochs per process only (`release.go:309-313`); rollback across restarts relies on operators raising tenant required epochs.
* **AMB-5, decision-key custody.** Verifier keys are static (`roleconfig.go:189-199`), so revocation needs a restart. A peer client without `ca_file` trusts system roots in production (`roleconfig.go:203-226`).
* **AMB-6, existence timing oracle.** Absent targets return before any decision, while denied ones cost a decision and an audit row (`content/catalog.go:138-161`).
* **AMB-7, reusable gateway evidence.** Gateway evidence can be reused for its whole validity across operations (see F-06).

### D.4 Code-quality issues ("AI slop": concrete maintenance or correctness consequences only)

| ID | Observation | Consequence | Refs |
|---|---|---|---|
| Q-1 | **Parallel, drifted re-check implementation.** `gate.Recheck` is unused in production but tested; it lacks the incarnation, admission, recipient-key and approval checks the fence performs. | Gives false confidence; anyone calling it gets weaker semantics than the fence. | `gate.go:359-401`; `gate_test.go:160` TestRecheck |
| Q-2 | **Dead dispatch and approval-consumption path.** `invocation.BeginDispatch`, `MarkReserved`, `approval.ConsumeTx` and `Usable` consume approvals *by digest*; production consumes in the fence *by revision*. | Tests `TestLeaseAndFencing`, `TestDispatchConsumesTheApproval`, `TestNoRedispatch`, `TestApprovalIsBoundToTheOperation` and `TestConsumedOnce` validate code production never calls, so they are **redundant tests that bypass the real path**. | `invocation.go:149-151, 207-226`; `approval.go:229-252` |
| Q-3 | **Duplicate single-use consumption.** `signing.Verifier.Verify` plus `Consumption` and `catalog.Store.Consume` (which omits the `incarnation` column) are never used in production; roles pass `MemoryConsumption` (per process). | Maintenance hazard: one future `Verify` call gives per-replica, non-transactional single use. | `signing.go:300-348`; `catalog.go:269-277`; `roleconfig.go:198` |
| Q-4 | **Dead authentication path.** Agent API keys (`IssueKey`, `Authenticate`, `RevokeKey`, table `agent_keys` with a non-deferrable FK to `identities`) have no production caller. | Unused credential store; if ever populated, `DELETE FROM identities` in restore would fail on the FK. | `toolstore/store.go:55-91`; migration `0001_executor.sql` |
| Q-5 | **Unused exported duplicate type.** `nativeapi.EnvelopeBody` duplicates `httpapi.EnvelopeBody`, with a mislabeled comment; there are no references. | Dead code. | `nativeapi.go:157-162` |
| Q-6 | **Inconsistent JWS type checks.** Content signatures check `typ`; decision records do not. | Weaker domain separation for decisions, mitigated by strict record parsing. | `signing.go:368` vs `cryptowire/signed.go:59` |
| Q-7 | **Policy-visible state drifts from row state.** Withdrawn versions' envelopes become RETIRED but their resources keep `status: ACTIVE`. | Policies reading `status` see stale data. | `delete.go:129-131` |
| Q-8 | **Documentation-sync test.** `TestOpenAPICoversRoutes` regex-scans the source file and a YAML file in `docs/`. | Not behavioural evidence; fails whenever `docs/` is absent (as in the current working tree). | `openapi_test.go` |
| Q-9 | **Merged and misplaced doc comments.** `unitsOf`'s comment is attached to `kind()`. | Cosmetic, misleading. | `content/units.go:24-35` |
| Q-10 | **Untested public SDK API.** `PutDocument`, `GetUnit`, `ExportPlain` and `crypto.ProveSigningKey` have no references in production or tests; `cmd/fga`, `cmd/fga-admin` and `cmd/fga-storage` have 0% coverage. | Behaviour of client-facing and operator code is unverified. | coverage profile |
| Q-11 | **Test-only release tooling.** `release.EffectChanges` and `History` are not wired to any command. | Unused feature surface. | `release.go:445-492` |

Not counted as slop: long files, verbose comments, Go error handling, and the deliberate re-checks in the fence, decision role and keys role.

---

## E. Testing plan

### E.1 Existing tests run, and results obtained (snapshot a3172ea)

| Step | Command (in snapshot, env below) | Result |
|---|---|---|
| Format | `gofmt -l .` | no files; exit 0 |
| Module integrity | `go mod verify` | all modules verified; exit 0 |
| Build | `go build ./...` | exit 0 |
| Static | `go vet ./...` | exit 0 |
| Tests without a database | `go test -count=1 -json ./...` | exit 0; **246 pass, 200 skip** (PostgreSQL-backed tests skip silently when `FGA_TEST_DATABASE_URL` is unset); 50 packages pass, 16 have no tests |
| Tests with a database and the race detector | `FGA_TEST_DATABASE_URL=<disposable> go test -race -count=1 -json ./...` | exit 0; **446 pass, 0 skip, 0 fail** |
| Coverage | `FGA_TEST_DATABASE_URL=… go test -count=1 -coverpkg=./... -coverprofile=cover.out ./...` | exit 0; merged **70.3% of 13,821 statements** (includes the test-helper packages r1test, mcptest, executortest and pgtest) |

**Low-coverage packages:**

| Package | Coverage |
|---|---|
| `cmd/fga`, `cmd/fga-admin`, `cmd/fga-storage` | 0% |
| `cmd/fga-tools` | 5.8% |
| `cmd/fga-keys` | 9.7% |
| `cmd/fga-decision` | 27.5% |
| `cmd/fga-mcp` | 37.5% |
| `internal/keysapi` | 37.8% (`classify` and `fail` at 0%) |
| `sdk/go/client` | 44.7% |
| `internal/roleconfig` | 48.1% |
| `internal/nativeapi` | 55.7% |

Coverage measures executed statements, not assertions. The A11 and A12 paths are covered without fault injection.

### E.2 Runtime reproductions (existing binaries against disposable state)

1. **F-01:** reconcile with a cancelled scan query; control run versus interrupted run (see D.1).
2. **F-02:** backup and restore round trip of a registered tool (see D.1).

### E.3 Missing tests (proposed; not written, since test authoring was not authorized)

| Target invariant | Method | Setup and sequence | Synchronisation or fault | Oracle | Why existing tests miss it |
|---|---|---|---|---|---|
| A query error never reopens admission (F-01) | D | Restored catalog with N≥10⁵ versions, admission closed | Cancel the scan after k rows (pgx wrapper or `pg_cancel_backend`) | Error returned; `admission_open=false`; no partial quarantine report | TestReconcileQuarantines has no fault |
| Backup holds every catalog table (F-02) | A | Migrated catalog | — | `Tables` = `pg_tables` minus documented exclusions; `tool_operations` round-trips | No schema comparison |
| Per-user MCP limits cannot be multiplied (F-03) | A | `mcptest` with small limits | One token, distinct delegation headers | Third distinct header refused; other users still served | TestMCPLimits uses distinct users only |
| Reconciliation uses the dispatched destination (F-04) | B | `executortest` with two destination stubs | Re-register the tool between dispatch and `Reconcile` | Stays UNKNOWN; reservation HELD | TestReconcile has no re-registration |
| No send after lease loss; 404 alone is not FAILED (F-05) | B, G | Pause hook between `DispatchTx` and `Do`; clock past the lease | Concurrent `Reconcile` | Zero sends after expiry, or outcome stays UNKNOWN; budget correct | No timing control |
| Gateway decision bound to its tool (F-06) | A | MCP workload client replays a `resources.list` decision | — | Mutating storage and tools routes refuse it | Tests use the matching tool only |
| Outbox fairness and amplification (F-07) | A/C | `outbox_capacity` = 1,000; bucket of hidden objects | Repeated `List` | Audit rows per call bounded; another tenant unaffected | Only "full outbox refuses" is tested |
| Lock order without deadlock (F-09) | B | Two sessions with advisory-lock barriers | Revoke through the keys API against publish or deliver for the same key | No `40P01`; deterministic winner | Not exercised |
| Envelope attributes follow the object (F-11) | A | Begin, relabel, finalize | — | Envelope label = object label | Not exercised |
| Audit and outcome atomic (F-18) | D | Full outbox at `Complete` | — | No outcome without an audit row | Not exercised |
| Policy engine time rule (A03-2) | E | CEL AST fuzzer, cost-limited | Seeds from TestTimeRule | Accepted expressions yield a finite NextChange or are rejected | Example-based only |
| Delegation and approval model (A05) | C | Random chains, agents and approvals against an independent set model | Revocation, expiry, re-delegation | No allow outside the intersection; no self-approval through any agent | Example-based only |
| Fence critical comparisons (A04-2, A10-1) | F | Remove one comparison at a time (`OperationDigest`, `Revision`, `admission_open`) in a test-only copy | — | At least one test fails per mutation | Not run |
| Executor outcome model (A12) | G | Small TLA+ or PlusCal model: worker, reconciler and destination with message delay and pause | Fairness on the reconciler | "Effect at destination ⇒ not FAILED" holds | No model exists |

---

## F. Validation ledger

| Item | Value |
|---|---|
| Snapshot | `git archive a3172ead39b95d512c9e930a11adbbbd79a3ac56 \| tar -x` into the scratchpad (unchanged files) |
| Go | go1.27.3 darwin/arm64; `GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local GOCACHE=<scratchpad>` (offline; no module downloads) |
| OS | macOS 26.6.1 (25G76), Darwin 25.6.0 arm64 |
| Database | PostgreSQL 18.6 (Homebrew), throwaway cluster created for this audit in the scratchpad; listens on 127.0.0.1 at a random port, SCRAM password, `fsync=off`, `LC_ALL=C`. Test schemas are created and dropped by `pgtest.Pool`. Repro databases: `fga_repro`, `fga_ctrl`, `fga_bk1`, `fga_bk2`. The user's own PostgreSQL on :5432 was not touched. |
| Dependencies | `go.mod`: cel-go 0.33.2, go-jose 4.1.7, pgx 5.11.0, mcp go-sdk 1.8.0, tink-go 2.9.0, x/crypto 0.56.0, x/text 0.41.0, protobuf 1.36.11 (`go list -m all` saved) |
| Skipped | `scripts/smoke.sh`: it runs `dropdb`/`createdb fga_smoke` on `localhost:5432`, which is not an isolated target without modifying the script. `make spec` / docs validation: excluded by the brief. |
| Analyzers not available | govulncheck, staticcheck, golangci-lint, gosec are not installed. Nothing was downloaded, so no CVE or dataflow scan was performed. Two ad-hoc scripts were used: missing `rows.Err()` (`rowscheck.py`) and production-unused exported functions (`deadcheck.py`, a heuristic). |
| Not read (outside the catalogue) | Dependency sources (go-sdk, Tink, go-jose, pgx). SDK behaviour such as MCP session binding and Tink key copying was taken from this repository's tests and comments, as noted. |
| Artifacts (scratchpad) | `logs/{gofmt,modverify,build,vet}.txt`, `logs/test_nodb.json`, `logs/test_db_race.json`, `logs/cover.out`, `logs/cover_func.txt`, `logs/repro_reconcile.txt`, `logs/postgres.log`, `repro/fixture.sql`, `repro/interrupt.py`, `repro/bk/`, `notes/` |
| Timings | Race and DB suite ≈ 80 s; coverage run ≈ 70 s; F-01 control 31.8 s |

---

## G. Completion statement

**Covered:**

* The full committed tree at `a3172ea`: build, vet, format, module integrity, the full test suite with and without PostgreSQL, the race detector and whole-suite coverage.
* All seventeen matrix areas.
* Detailed static tracing of the decision role (`decisionsvc`, `gate`, `decision`, policy engine, release, `signing`), `enforce`, the fence, catalog control, migrations, the content read, upload, publish, label, grant, approval, list, delete and selection paths, the keys role (registry, delivery, data keys, keycheck, KEK, keyfile), roleconfig, `httpapi`, `authn`, admission, guard, the MCP role core (handler, limits, decision, storage, resources), the executor (invoke, reconcile, connector, invocation store, tool store, `fga-tools` admin), recovery (backup, restore, reconcile), blob store and journal.
* Two defects reproduced at runtime with the committed binaries.

**Traced only in part or not at all (remaining unverified):**

* `content/documents.go`, `derived.go`, `export.go` (including `SearchDocuments`), `serverdocuments.go`, `serveroriginals.go`, `serverderived.go`, `encryption.go`, `withdraw.go`.
* `recovery/reclaim.go` and `catalog/serverkeys.go` (KEK rotation).
* `mcpsvc` tools, export, packages and registered tools; `mcpbridge`; `cmd/fga` client.
* `sdk/go/client/document.go` and most of `sdk/go/crypto`; `cryptowire` parsers (context, document, lineage).
* `policy/format` and `registry/operations.go` in detail; the test-helper packages.

**Remaining limitations:**

* Source-supported findings F-03 to F-18 were not executed. Their tests are proposed in E.3, but writing them was not authorized.
* No mutation, fuzzing or model checking was run.
* No dependency CVE scan was run.
* Process-level fault tests do not establish power-loss durability.
* Behaviour that depends on the MCP SDK and Tink internals was not verified at source level.

This audit does not establish that all issues were found, that the system is secure, or that it is production-ready.
