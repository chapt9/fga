# The tools role: the executor (R2 stretch E1; AGT-001 to AGT-006, INV-001 to INV-009, APR-004, APR-006)

Status: design record, 31 October 2026. Our own design; no upstream mapping. The packages `tools`, `toolstore`, `invocation`, `reservation` and `tools/connector` were built for specification 2.2 and parked; this stretch connects them to today's authority.

`fga-tools` carries out a registered tool's call on an external destination for an authorized user: a payment, a ticket, a notification. It is an optional role and a process of its own. It has no payload, key-encryption, client-decryption, storage-content or MCP code (`cmd/fga-tools/allowed-imports.txt`).

## Registering a tool (AGT-001)

A tool is administered out of band with `fga-tools` subcommands. Nothing an agent or a document says can register or change one (MCP-004, V-120).

| Command | Effect |
|---|---|
| `tool add -tenant T -file tool.json` | Stores the record: ID, version, destination, endpoint, strict argument schema, budget and amount argument, maximum hold age. The tool is unusable until reviewed |
| `tool review -tenant T -id ID` | Marks the current record reviewed and registers it in the catalog: the `agent.tool` resource `tool:<id>` (alias namespace `tool`, attributes `kind: executor`, destination, version) and the operation `tool:<id>` with exactly its checks (`tool_operations`). A changed registration advances the resource's generation, so earlier decisions fail at their fence |
| `destination add -tenant T -id D -url U -cidrs … [-credential-file F] [-approved]` | Registers the destination: the base URL, allowed address ranges, the destination's own credential, and a `network.destination` resource `destination:<id>` whose `approved` attribute policy may test |
| `budget set -tenant T -id B -currency C -limit N` | A budget in integer minor units (DAT-005) |

A record changed after its review is unusable, because its digest no longer matches the reviewed one (V-034).

## The decision role

A tool's operation `tool:<id>` is decided like a registered operation (DEC-001). The decision role reads its checks from the catalog, since it links no tool code (MOD-004), and validates them against the core types:

- `invoke` on the tool;
- `send` on its destination;
- the declared action on every resource argument, by alias (RES-006).

The executor's resource types (`network.destination`, `business.record`, `ai.model`) are part of the core types, so one signed release governs the executor too. A verified plan's arguments and amount are visible to conditions as `request.operation`, for example `request.operation.amount_minor > 5000`. A tool can be an approval target (`agent.tool.approve`), decided in the same approval inbox as every other approval. `agent.tool.resolve` and `agent.tool.write-off` are core operations.

## One call (AGT-003)

`POST /v1/invocations {tool, version, arguments, idempotency_key, note}`, with the user's token for `fga-tools`:

1. **Who:** the token's subject, acting for itself. Delegated agents are a later stretch.
2. **Which tool:** the reviewed record at exactly the requested version (AGT-004), with the arguments validated against its strict schema.
3. **What exactly:** the call becomes its checks and its canonical plan (`opplan`), whose digest is the operation digest. The invocation is created under the idempotency key. The same key with the same plan and actor returns the same invocation; another plan or another actor is a conflict (INV-004).
4. **May it:** the decision role decides the operation for the plan. A policy may require:
   - an approval, which opens one for exactly that plan (the call answers 202 with its ID and is repeated with `Fga-Approval`);
   - a reservation, which the release's obligation mapping turns into a signed `reservation` obligation ([obligations.md](obligations.md)). Without the mapping the call is refused.
5. **Before sending:** one transaction, the authority fence of the decision (INV-002), which:
   - rechecks every bound fact;
   - consumes the decision and the approval;
   - moves the invocation to DISPATCHING under the worker's lease and fencing token;
   - holds the reservation on the tool's budget, which the database bounds whatever the concurrency (APR-004);
   - records the audit event.

   A revocation that commits first leaves the call unsent (DAT-007).
6. **Send once:** the connector calls the destination with its own credential, the invocation's ID as the idempotency key, only at allowed addresses checked at connection time, and without following redirects (AGT-005, AGT-006). The outcome is recorded:
   - SUCCEEDED (2xx) charges the reservation;
   - FAILED (not sent, or 4xx) releases it;
   - UNKNOWN (anything else after sending) keeps it held (INV-007).

## Unknown outcomes (INV-006, INV-009)

`POST /v1/invocations/{id}/resolve {outcome, evidence}` closes an UNKNOWN invocation as SUCCEEDED, FAILED (with evidence) or ABANDONED. `POST …/write-off {note}` releases an ABANDONED call's charge as an accepted risk. Both:

- need `resolve` or `write-off` on the tool;
- need a principal other than the call's actor;
- run in the fence of their decision.

ABANDONED keeps the charge and the consumed approval, and its idempotency key never dispatches again. `GET /v1/invocations/{id}` shows an invocation to its actor, or to a principal who may resolve it.

## Example bundle

`tools.json`: members invoke `kind == "executor"` tools; leads approve, resolve and write off. `destinations.json`: members send only to approved destinations.

## Not yet (stretch E2)

- MCP tool calls of registered tools through the MCP role;
- a reconciliation worker for stalled DISPATCHING and long-held UNKNOWN invocations, with escalation after the maximum hold age;
- delegated agents.

## Tests

| Test | Covers |
|---|---|
| `internal/executor` `TestInvoke` | AGT-003 end to end against a recording destination: one dispatch with the destination's credential and the invocation as key; retry without redispatch; another plan or actor under the key; unknown tool, other version, extra argument, a user without rights, and a record changed after review, all refused |
| `TestInvokeApproval` | A policy reading `request.operation.amount_minor` requires an approval for large payments; another plan is not covered; the approval is consumed with the dispatch |
| `TestInvokeReservation` | Reserved in the dispatch's transaction; charged on success, released on refusal, held while unknown; a payment beyond the budget sent nowhere; no reservation without the mapping |
| `TestResolution` | The actor cannot resolve; evidence is required; ABANDONED keeps the charge and never redispatches; another lead writes it off |
| `TestDispatchFence` | A revocation between decision and dispatch leaves the call unsent |
| `cmd/fga-tools` `TestImportAllowlist`, `TestValidate` | MOD-004 and the configuration |
| `scripts/smoke.sh` | A tool added and reviewed with `fga-tools`; refused before review; called once for bob with the destination's credential; a retry answered without a second call; a guest refused |
