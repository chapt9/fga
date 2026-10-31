# The MCP role (R2 stretch M2; MCP-001 to MCP-008)

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
| `tools/list` | `discover` on each served tool, one batch | none | The tools the user may discover; none on any failure |
| `resources/list` | `resources.list` | `GET …/objects`, then `GET …/documents/search`, per configured bucket (`buckets`) | `fga://bucket/key` references. A bucket the user may not list is passed over; the cursor walks buckets and storage pages |
| `resources/read` `fga://bucket/key[?version=][&unit=]` | `resources.read` | `GET …/object/content`; for a key that is not a readable object, `GET …/document/units` and `GET …/document/unit/content` per unit; with `unit`, that unit through `POST …/document/units/select` | An object as text or a blob; a document's or collection's readable units joined by blank lines |
| `documents.search` | `documents.search` | `GET …/documents/search` | Keys, document version IDs and references: catalog metadata only (SRH-001) |
| `documents.read` | `documents.read` | `GET …/document/units` (`kind` must be `document`), `GET …/document/unit/content`; with `units` (at most 100), the all-or-nothing selection `POST …/document/units/select` (DOC-007) | The readable units in document order, as text and as structured output. With `units`, exactly those, or "not found" |
| `text.read` | `text.read` | The same, with `kind` `collection` | The readable entries |

The configured buckets choose what `resources/list` goes through, never what may be read.

- **Unit filtering (V-169).** A unit the user may not read is left out without a trace: no text, ID or count.
- **One tool, one kind.** `documents.read` refuses a text collection and `text.read` a document. A tool permission therefore stays what it names. The unit listing's `kind` field tells them apart.
- **Client-mode content** is refused with an explicit error, never returned as plaintext (MCP-005). Returning it as the encrypted package for a local bridge is stretch M3, together with `documents.export`.
- **Not cached.** Every result is marked cache scope `private` with TTL 0: it is for one user, now (the SDK default is `public`).
- **Untrusted content.** Text read from storage is returned as data. The role acts on none of it (MCP-004).

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
| `buckets` | For `resources/list` |
| `max_bytes`, `max_units`, `user_requests`, `total_requests`, `user_sessions`, `total_sessions`, `session_timeout` | Bounds; absent keeps the default |

The decision role needs the MCP workload in `adapter_audiences` (for `fga-mcp`) and in `gateways` (for `fga-storage`), and the storage role needs it in `mcp_adapters` ([mcp-gateway.md](mcp-gateway.md)). `fga-admin mcp enable` registers the tools for a tenant.

## Tests

| Test | Covers |
|---|---|
| `internal/mcpsvc` `TestMCPReads` | Nothing before the tenant enables MCP; tools; object, document, unit and collection reads; V-169 filtering; V-002 and V-050: the native API, `resources/read` and the read tool return the same unit, and the storage role decides the same operation and checks for each; one kind per tool; search; `resources/list` with a forged cursor refused; private cache scope |
| `TestMCPNoPermissionFromTools` | MCP-003, MCP-002: a member of another project may use every tool and reads nothing; a user without tool permissions sees and calls none |
| `TestMCPSessions` | V-115: another user's token in a session `403`; a token for another audience or none `401` |
| `TestMCPPanicContained` | A panic in one request fails only that request; other sessions go on. Without `contain` it ends the test process |
| `TestMCPLimits` | Session and call bounds per user and in total; a closed session frees its place |
| `TestGatewayRevision` | Revision 0 is filled in only for a gateway's own MCP operations |
| `TestSharedNames`, `TestWireFormat`, `TestResourceURIs` | The copied names and wire format; `fga://` URIs round trip, and malformed ones are refused |
| `cmd/fga-mcp` `TestImportAllowlist`, `TestValidate` | MCP-008 and MOD-004: no catalog, blob, key, payload, policy or decision-service package; configuration rules |
| `scripts/smoke.sh` | A generic MCP client (JSON-RPC over HTTP): tools, a server-mode document and object equal to the native reads, another project's member refused, client-mode content refused, a session bound to its user |
