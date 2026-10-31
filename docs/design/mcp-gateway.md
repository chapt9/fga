# MCP gateway hop (R2 stretch M1, TB3, MCP-003, TRU-003)

Status: design record, 31 October 2026, owner ruling 8. Our own design; no upstream mapping.

The MCP service (R2) is a separate role, `fga-mcp`. It holds no permission rules, catalog, blob or key access (MCP-002, MCP-006, MCP-008). It turns MCP requests into calls on the storage role's native API, which checks them as for any other client. This record covers how the storage role knows which user a call from the MCP role is for. The MCP role itself is stretch M2.

## The hop

1. **The user's client to the MCP role.** The MCP client presents the user's token for audience `fga-mcp`, and the MCP role verifies it.
2. **The MCP role to the decision role.** For each MCP tool call, the MCP role asks the decision role for `mcp.tool.invoke`: `invoke` on the tool, an `agent.tool` resource such as `documents.read`. It sends the user's token as evidence (TB2), and the decision role verifies the token for audience `fga-mcp` (the MCP adapter's `adapter_audiences`). The decision is addressed to the storage role (`fga-storage`), so policy can allow or deny MCP use apart from content access (MCP-003).
3. **The MCP role to the storage role (TB3).** The MCP role calls the native API with its workload identity (its client certificate) and the decision in the `Fga-Decision` header, in `signing.Evidence` form. It sends no bearer token. The storage role accepts the call (`httpapi.Gateway`) only if all of these hold:
   - the workload is one of its `mcp_adapters`;
   - the decision verifies for its own audience and is still valid;
   - it is for `mcp.tool.invoke` and was requested by that same workload;
   - it names no delegation or subject.

   The caller is then the decision's actor.
4. **The storage role's own checks.** The storage role decides every content check as for a native client, passing the gateway's decision as the user's evidence. The decision role accepts its own earlier decision (`decisionsvc` `chained`) only if all of these hold:
   - it verifies under the role's own key;
   - it is for `mcp.tool.invoke`;
   - it was requested by a configured gateway (`gateways`) and addressed to an audience that gateway may address and the requesting adapter serves;
   - it is for the same tenant and user, acting for themself;
   - it is still valid and from the current recovery incarnation.

The user's MCP token never leaves the MCP role. Neither the MCP workload's own claims about a user nor a forwarded MCP token is accepted (V-028). A decision is not single-use: one MCP call may need several storage requests. It is short-lived, though (the decision role's maximum age), and bound to the MCP role's workload.

## MCP tools

`agent.tool` (discover, invoke, and the executor's later actions) is in the core type set (`registry.CoreTypes`, `release.CoreEnvironment`). Policy bundles are therefore signed against a schema that includes it; the executor's other types stay optional.

- **Registration.** `fga-admin mcp enable -tenant T` registers the tools of `registry.MCPTools` for a tenant: `resources.list`, `resources.read`, `documents.search`, `documents.read`, `text.read` and `documents.export`. Each is a resource `mcp.tool:<name>`, aliased in the `mcp.tool` namespace with attributes `name` and `kind: "mcp"`. A tenant without them has no MCP access.
- **Policy.** Tools are allowed by ordinary rules on `agent.tool`, as in the example bundle's `tools.json` (members may discover and invoke MCP tools). Users need the capabilities `discover` and `invoke` on `agent.tool`, which the storage preset now includes.
- **Operations.** `mcp.tool.invoke` (one tool) and `mcp.tool.discover` (tools/list, several tools).

## Configuration

| Role | Setting | Example |
|---|---|---|
| decision | `adapter_audiences` for the MCP adapter | `"mcp-1": ["fga-mcp"]` |
| decision | `gateways`: the audiences each gateway's decisions may be addressed to | `"mcp-1": ["fga-storage"]` |
| storage | `mcp_adapters`: the MCP role's workload identities | `["mcp-1"]` |

In the development profile without TLS, every caller has the one development adapter identity, as for the other roles. There, the decision is what binds a call to its user.

## Not yet

- The `fga-mcp` role and its operations (M2), client mode and the local bridge (M3).
- Agents acting for users through delegations (the decision may then name a delegation and subject).

## Tests

| Test | Covers |
|---|---|
| `internal/nativeapi` `TestMCPGatewayHTTP` | A read for the user through the gateway; no decision before the tenant enables MCP; refusals (V-028): the MCP workload's own claim, a forwarded MCP token, the decision from another workload, a decision another adapter requested, a decision for another operation, a broken signature, an expired decision |
| `TestChainedEvidence` | The decision role's side: another user, a non-gateway's decision, a forwarded MCP token, a decision from an earlier recovery incarnation |
