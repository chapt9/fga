# The local MCP bridge (R2 stretch M3; MCP-005, T-10)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

`fga mcp-bridge` lets an MCP application on the user's machine read client-mode content as plaintext, which the server never sees. The MCP role returns client-mode content only as encrypted packages ([mcp-role.md](mcp-role.md), "Client mode"). The bridge sits on the client side of the custody boundary, holds the user's keys and opens those packages, as `fga get` does for the native API.

## How it runs

The user configures the application to start `fga mcp-bridge` as its MCP server command. The bridge then:

- **serves that one application** over the process's stdin and stdout (the SDK's stdio transport). It opens no network listener, so nothing else can talk to it. Starting it with the user's key directory is the user's explicit authorization of that application (MCP-005);
- **connects to the MCP role** as the user with the user's `fga-mcp` token. It declares the encrypted-package extension (`io.github.chapt9/fga-encrypted-package`, and the earlier `experimental` form for older servers) with the fingerprint of the user's recipient key, at the newest protocol both sides speak;
- **forwards** `tools/list`, `tools/call`, `resources/list`, `resources/templates/list` and `resources/read`, and answers `initialize` and `ping` itself.
  - It forwards only each request's own fields (cursor, tool name and arguments, URI), never the application's `_meta`. Under protocol 2026-07-28 that `_meta` carries the client's own protocol version and capabilities.
  - It drops the MCP role's tool output schemas, since its results hold plaintext where the MCP role's held packages.
- **opens** every package addressed to the user's key, and passes everything else through unchanged: server-mode plaintext, errors, and an export made for another recipient.

Every authorization is still the MCP role's and the storage role's. The bridge decides nothing, and it cannot read anything the user could not read with `fga get`.

## Opening a package

`Bridge.Open` verifies a package as the native client does, all of it or nothing:

1. **Profile and recipient:** `fga.encrypted-package/v1`, for this key.
2. **Signature and signer:** the descriptor's signature by a signer the user trusts (the key directory's trust store). The signer must be one the keys role still reports as `ACTIVE` or `RETIRED`, checked with the user's keys token as `fga get` does (RCP-011).
3. **Envelope and ciphertext:** the envelope opens with the user's private key, and the ciphertext authenticates against the descriptor (CRY-006).
4. **Identity:**
   - For an object, the signed descriptor names the version the package claims, and the asked-for version if any.
   - For a document, each unit's signed descriptor names the unit, unit version and document version the package claims. A package names each unit once. When the application asked for units (`units` of a tool call, `?unit=` of a resource), the package holds exactly those: another unit of the same version, though signed and encrypted for this key, is refused (review v5 F09).

A package that fails any step is an error with no plaintext: a tool error for `tools/call`, a JSON-RPC error for `resources/read`. Plaintext and keys stay in memory; nothing is written to disk.

## Configuration

| Setting | Meaning |
|---|---|
| `-dir` or `FGA_KEY_DIR` | The user's key directory, as for every `fga` command |
| `FGA_KEY_PASSPHRASE` or `-passphrase-file` | The passphrase of protected keys |
| `-mcp-url` or `FGA_MCP_URL` | The MCP role's endpoint |
| `FGA_MCP_TOKEN` | The user's token for `fga-mcp` |
| `FGA_MCP_DELEGATION` | For an agent: the delegation it acts under, sent as `Fga-Delegation` ([delegated-agents.md](delegated-agents.md)) |
| `FGA_KEYS_URL`, `FGA_KEYS_TOKEN` | The keys role, for signer status |

Stdout carries MCP only; diagnostics go to stderr.

## Not covered

- **Token refresh.** The token is read once at start. A production identity provider's refresh flow comes with D-04.
- **Large content.** Content over the MCP role's `max_bytes` is for the native client until authenticated links exist.

## Tests

| Test | Covers |
|---|---|
| `internal/mcpbridge` `TestBridge` | T-10 MCP client interoperability: the application reads a client-mode object and document as plaintext; server-mode content passes through; an export made for another recipient passes through unopened; a user without an envelope gets nothing; the MCP role's output schemas are dropped |
| `TestOpenRefusesBadPackages` | Altered, truncated or swapped ciphertext, a unit claimed as another, another version claimed or asked for, another recipient, a compromised signer and an untrusted signer each fail with no plaintext; so do a unit not asked for, a unit asked for and missing, a unit twice, and units asked of an object |
| `TestBridgeBindsRequestedUnits` | An upstream that answers a request for unit A with unit B's package, or for units A and B with B alone, gets an error and no plaintext, by resource and by tool; B asked for and given opens (review v5 F09) |
| `cmd/fga` `TestNoServerCode` | The CLI and bridge link no server-side catalog, content, payload, key-encryption, envelope, fence, decision-service or MCP-role code |
| `scripts/smoke.sh` | A Python application starts `fga mcp-bridge` and reads bob's client-mode object and document over stdio, equal to the originals |
