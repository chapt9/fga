# The MCP role (R2 stretches M2 and M3; MCP-001 to MCP-008)

Status: design record, 31 October 2026. Our own design; no upstream mapping. The hop from the MCP role to the storage role is [mcp-gateway.md](mcp-gateway.md).

`fga-mcp` is an MCP server, on the official MCP Go SDK (MCP-001), that maps MCP requests onto the storage role's native API. It holds no permission rules, catalog, blob store, keys or user database, and decrypts nothing (MCP-002, MCP-006, MCP-008). Whatever a user reads through it is what the storage role lets that user read over the native API, through the same routes and checks.

## Components

| Part | Where | Job |
|---|---|---|
| Transport | SDK `mcp.NewStreamableHTTPHandler` at `/mcp` | MCP over streamable HTTP; JSON responses; stateful sessions |
| User authentication | SDK `auth.RequireBearerToken`, `mcpsvc` `verify` | Each request carries the user's token for audience `fga-mcp`, verified with `authn`; the session is bound to the token's tenant and user (below) |
| Decision client | `mcpsvc` `decide`, `authorize` | Asks the decision role for `mcp.tool.invoke` (or `mcp.tool.discover`) with the user's token as evidence, addressed to the storage role |
| Storage client | `mcpsvc` `storageGet` | Calls native API routes as the MCP workload, with the decision in the `Fga-Decision` header (TB3) |
| Operations | `mcpsvc` tools and resources | Below |
| Bounds and containment | `mcpsvc` `bound`, `contain`; `internal/guard` | Below and [fault-isolation.md](fault-isolation.md) |
| Command | `cmd/fga-mcp` | Configuration and startup |

The role links only the SDK and its dependencies, plus `authn`, `signing`, `strictjson`, `admission` and `guard` (`cmd/fga-mcp/allowed-imports.txt`). It does not link `decisionsvc` or `registry`, which carry the policy engine and catalog code. It keeps its own copies of the wire format and the shared names, which `TestSharedNames` and `TestWireFormat` pin.

## One MCP request

1. The SDK checks the bearer token (`401` otherwise) and the session (`403` for a session opened by another user).
2. The role asks the decision role for `invoke` on the tool, an `agent.tool` resource such as `mcp.tool:documents.read`. A refusal is "not allowed". Discovery and invocation are decided apart from content (MCP-003).
3. It calls the native API with that decision. The storage role makes its own decisions for every resource and unit, accepting the MCP decision as the user's evidence.
4. It returns what the storage role returned, in MCP form.

The role keeps no identity store, so it cannot name the user's identity revision. It asks with revision 0, and for a configured gateway's own MCP operations the decision role binds the user's current revision (`gate.CurrentRevision`). Every other adapter and operation must still name the revision (ID-004).

## Operations

| MCP | Tool decided | Native API | Returns |
|---|---|---|---|
| `tools/list` | `discover` on each served tool, one batch; with the tools role configured, also `tools.list` | `GET {tools}/v1/tools` | The tools the user may discover, then the registered tools the tools role lets the user discover, as `tool.<id>`; none of either on any failure |
| `resources/list` | `resources.list` | `GET …/objects`, then `GET …/documents/search`, per configured bucket (`buckets`) | `fga://bucket/key` references. A bucket the user may not list is passed over; the cursor walks buckets and storage pages |
| `resources/read` `fga://bucket/key[?version=][&unit=]` | `resources.read` | `GET …/object/content`; for a key that is not a readable object, `GET …/document/units` and `GET …/document/unit/content` per unit; with `unit`, that unit through `POST …/document/units/select` | An object as text or a blob; a document's or collection's readable units joined by blank lines |
| `documents.search` | `documents.search` | `GET …/documents/search` | Keys, document version IDs and references: catalog metadata only (SRH-001) |
| `documents.read` | `documents.read` | `GET …/document/units` (`kind` must be `document`), `GET …/document/unit/content`; with `units` (at most 100), the all-or-nothing selection `POST …/document/units/select` (DOC-007) | The readable units in document order, as text and as structured output. With `units`, exactly those, or "not found" |
| `text.read` | `text.read` | The same, with `kind` `collection` | The readable entries |
| `tool.<id>` (a registered tool) | `tools.call` | `POST {tools}/v1/invocations` with `Fga-Approval` when given | The tools role decides the call's own operation for its exact plan and carries it out ([executor.md](executor.md)). The input is the tool's arguments, its version, an idempotency key, and optionally an approval ID and a note. An approval that is needed answers with its ID, not an error |
| `documents.export` | `documents.export` | Server mode: `GET …/object/export`, `POST …/document/export/content`. Client mode: `POST …/object/export`, `POST …/document/export` for a recipient. Each route refuses the other mode (`409 ENCRYPTION_MODE`), and the tool then takes the other | A complete export or nothing: server-mode plaintext, or ciphertext and the recipient's existing envelopes. Storage decides `export` on the version and `export-key` on every unit besides the reads; the server never rewraps or decrypts. Text collections are not exported (DOC-005) |

The configured buckets choose what `resources/list` goes through, never what may be read. `tools.list` and `tools.call` are gates only: the MCP role's decision sees no plan, so the tools role decides discover and invoke on each registered tool itself.

- **Unit filtering (V-169).** A unit the user may not read is left out without a trace: no text, ID or count.
- **One tool, one kind.** `documents.read` refuses a text collection and `text.read` a document. A tool permission therefore stays what it names. The unit listing's `kind` field tells them apart.
- **Client-mode content** never comes back as plaintext (MCP-005). A generic client gets an explicit capability error (V-170). A client that declares the encrypted-package capability gets the encrypted package (below).
- **Not cached.** Every result is marked cache scope `private` with TTL 0: it is for one user, now (the SDK default is `public`).
- **Untrusted content (MCP-004).** Text read from storage is returned as data, and the role acts on none of it. Its only effects are reads. Nothing a document says reaches the tool registry, a delegation or an identity: those change only through their own authorized operations, which the MCP role does not offer. A follow-up the text asks for is an ordinary request, decided as any other (V-029, V-120).

## Client mode (M3, MCP-005)

**Capability.** A client that verifies and decrypts client-mode content itself declares the experimental capability `fga.encrypted-package` at initialize: `{"version": 1, "recipient": "sha256:…"}`, naming the recipient key it decrypts with. The profile is `internal/mcpwire`, which the MCP role and a client-side bridge share; it holds formats only, no keys or cryptography.

**Reads.** For such a client, a client-mode object or document read returns a `Package`:
- an object version: its signed descriptor, the envelope the keys role delivered for the recipient with its receipt, and the exact ciphertext (`GET …/object/package`, then `GET …/object/ciphertext` of that version);
- a document version: the same for each readable unit (`GET …/document/unit/package`, `…/unit/ciphertext`). Units the user may not read are left out, ID and all.

`resources/read` returns the package as JSON text of type `application/vnd.fga.encrypted-package+json`. The read tools return it in their structured output, with a short text saying what it is. Binary fields are base64, as the native API sends them, and are passed through unchanged.

The storage role decides the read and the envelope delivery exactly as for a native client. The delivery decision takes the MCP decision as the user's evidence (TB3), and the MCP role holds nothing that opens an envelope. A recipient without an envelope gets nothing, since the server never creates or rewraps one. A package counts against `max_bytes` by its ciphertext; larger content is for a native client until authenticated links exist.

**Export.** `documents.export` exports for the `recipient` argument, or the declared key when it is absent, so a generic client may also export for someone else: it receives ciphertext it cannot open.

**The local bridge.** `fga mcp-bridge` is the client that declares the capability and opens the packages with the user's keys ([mcp-bridge.md](mcp-bridge.md)).

## Sessions (MCP-007, V-115)

A session is bound to the tenant and user of the token that opened it, via the SDK's `TokenInfo.UserID`. A request carrying the session ID with another user's token is refused `403`. The session ID alone is never authority: every request is authenticated again, and every call is decided again. An idle session closes after `session_timeout` (default 30 minutes).

## Bounds and containment

| Bound | Default | Over it |
|---|---|---|
| Concurrent calls per user, and in total | 8, 256 | `429` at once |
| Open sessions per user, and in total | 8, 1024 | `429` for the opening request. A session counts from the request that opens it, so concurrent opens cannot overshoot. Closed sessions are forgotten |
| Content returned per request; units per document read | 4 MiB, 1,000 | "read selected units" |
| Request body | 1 MiB | `413` |

The SDK runs handlers in its own goroutines, outside the HTTP server's panic recovery. The role's outermost SDK middleware (`contain`) therefore turns a panic into an error for that request only. `guard.Handler` covers the HTTP layer.

## Configuration

`cmd/fga-mcp` reads a strict JSON file:

| Setting | Meaning |
|---|---|
| `profile`, `listen`, `tls` | As for the other roles. Production needs TLS, a real token issuer and mutual TLS to both peers |
| `token_issuer`, `audience` | The users' tokens, for `fga-mcp` |
| `storage_audience` | `fga-storage`: the decisions it asks for are addressed there |
| `decision`, `storage` | URLs and the client certificate that is the MCP workload's identity |
| `tools`, `tools_audience` | Optional: the tools role and `fga-tools` |
| `buckets` | For `resources/list` |
| `max_bytes`, `max_units`, `user_requests`, `total_requests`, `user_sessions`, `total_sessions`, `session_timeout` | Bounds; absent keeps the default |

The decision role needs the MCP workload in `adapter_audiences` (for `fga-mcp`) and in `gateways` (for `fga-storage`, and `fga-tools` with the tools role), and the storage role and the tools role need it in `mcp_adapters` ([mcp-gateway.md](mcp-gateway.md)). `fga-admin mcp enable` registers the tools for a tenant.

## Tests

The tests deploy through `internal/mcptest`: a decision role and a storage role over HTTP, and the MCP role calling both as its workload, which the bridge's tests share.

| Test | Covers |
|---|---|
| `internal/mcpsvc` `TestMCPReads` | Nothing before the tenant enables MCP; tools; object, document, unit and collection reads; V-169 filtering; V-002 and V-050: the native API, `resources/read` and the read tool return the same unit, and the storage role decides the same operation and checks for each; one kind per tool; search; `resources/list` with a forged cursor refused; private cache scope |
| `TestMCPNoPermissionFromTools` | MCP-003, MCP-002: a member of another project may use every tool and reads nothing; a user without tool permissions sees and calls none |
| `TestMCPSessions` | V-115: another user's token in a session `403`; a token for another audience or none `401` |
| `TestMCPPanicContained` | A panic in one request fails only that request; other sessions go on. Without `contain` it ends the test process |
| `TestMCPLimits` | Session and call bounds per user and in total; a closed session frees its place |
| `TestMCPClientMode` | V-170: a generic client gets a capability error and no plaintext; a capable client gets packages that the recipient's key opens to the original object and units; no plaintext in the response; a restricted unit is left out, ID and all; another project's member gets nothing |
| `TestMCPExport` | Server-mode export of an object and a document; export needs its own permission (a reader who may not export gets "not found"); client-mode export for another recipient, which only that recipient opens; none without a recipient, or for a recipient without an envelope |
| `TestMCPRegisteredTools` | AGT-002, AGT-003 through MCP: a member lists the registered tool with its schema and calls it; the tools role carries it out once with the member as actor; a required approval is asked for, then used; a user who may use MCP but not the tool sees and calls nothing; arguments outside the schema, another version and an unknown field are refused |
| `TestGatewayRevision` | Revision 0 is filled in only for a gateway's own MCP operations |
| `TestMCPUntrustedContent` | V-029: a document that tells the agent to register a tool and widen its delegation is read as data, and no tool, delegation or identity changes; V-120: the follow-up calls it asks for are refused |
| `TestSharedNames`, `TestWireFormat`, `TestResourceURIs` | The copied names and wire format; `fga://` URIs round trip, and malformed ones are refused |
| `internal/mcpwire` `TestCapability` | The capability round trips; another version or a missing recipient is not the capability |
| `cmd/fga-mcp` `TestImportAllowlist`, `TestValidate` | MCP-008 and MOD-004: no catalog, blob, key, payload, policy or decision-service package; configuration rules |
| `scripts/smoke.sh` | A generic MCP client (JSON-RPC over HTTP): tools, a server-mode document and object equal to the native reads, another project's member refused, client-mode content refused, a session bound to its user; a client that declares its recipient key gets the client-mode object as a package |

## R2 validation vectors

| Vector | Requirement | Covered by |
|---|---|---|
| V-002, V-050 | RES-002, RES-003, CNT-001 | `TestMCPReads`: the native API, `resources/read` and the read tool return the same unit under the same storage decision |
| V-028 | TRU-003 | `internal/nativeapi` `TestMCPGatewayHTTP`: the MCP workload's own claims are refused |
| V-029, V-120 | MCP-004 | `TestMCPUntrustedContent`. Tool registration is the executor's (stretch E1), whose tests repeat V-120 against it |
| V-114 | FLW-008 | Not built: the optional managed-client profile, which comes with delegated agents |
| V-115 | MCP-007 | `TestMCPSessions` |
| V-137 | MOD-004 | `cmd/fga-decision` `TestAllowlistCatchesForbiddenImports`, and every role's `TestImportAllowlist` |
| V-169 | MCP-005 | `TestMCPReads` (server mode), `TestMCPClientMode` (client mode) |
| V-170 | MCP-005 | `TestMCPClientMode`; `internal/mcpbridge` `TestBridge` for the capable client |

