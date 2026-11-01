# Delegated agents (R2; DLG-001 to DLG-007, MCP-006, MCP-007, AGT-003, INV-006)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

An agent is an identity of its own, with its own token and capabilities. It acts for a user (the subject) only under a delegation: a record that names the agent, the user, the workload that presents it, the resource types and actions it covers, and an expiry. The decision core has checked delegations since R1-A. This stretch lets an agent use one through the MCP role, into the storage role and the tools role.

## What decides

For every check of a delegated request (DLG-003, DLG-004):

- business policy is evaluated for the **subject**: the agent can do no more than the user;
- the **delegation chain** must cover the resource type and action, every link of it, and be unrevoked and unexpired (DLG-002, DLG-005);
- the **agent's own capability** must allow the action.

The effective authority is the intersection of the three. The agent's own roles play no part.

## Creating and ending a delegation

`fga-admin delegation add -tenant T -id ID -actor AGENT -subject USER -audience WORKLOAD -grants 'type:a,b;type:c' -expires 24h [-parent ID]`

- The grants name core resource types and their actions, or `*`.
- The audience is the workload that presents the delegation: for an agent using MCP, the MCP role's workload identity.
- A child (`-parent`) must narrow its parent: the same subject, no later expiry, and no grant its parent lacks.
- A delegation is never changed. `fga-admin delegation revoke` ends it, journaled, and every decision bound to it fails at its fence (DLG-005).
- Actor and subject must differ and be known identities.

Delegations are created out of band. Nothing an agent reads or says can create or widen one (MCP-004).

## Through the MCP role

1. **The agent connects** with its own MCP token and names its delegation in the `Fga-Delegation` header (`mcpwire.DelegationHeader`). It never names the subject. With `fga mcp-bridge`, `$FGA_MCP_DELEGATION` sets the header.
2. **The session is bound** to the token's tenant and identity and the delegation together (MCP-007). A request in that session under another delegation, or none, is refused `403`.
3. **The MCP role asks the decision role** as for a user: the agent's token as evidence, revision 0, and the delegation. The MCP role keeps no catalog, so it names no subject. The decision role reads the subject from the delegation record, at its current revision, and admits the whole chain (`gate.DelegatedSubject`). The delegation must name the MCP workload as its audience.
4. **The storage role and the tools role** accept the MCP role's decision as before (`httpapi.Gateway`, [mcp-gateway.md](mcp-gateway.md)). The caller now carries the actor, the subject and the delegation (`enforce.Caller`), and every decision they ask for names all three.
5. **The decision role accepts its earlier decision** as evidence only for the same actor, subject and delegation. The delegation is then checked against the gateway that requested that decision (`decision.Envelope.Via`), since it names the MCP workload, not the role behind it.

## What a delegated caller is in each role

| Where | The agent (actor) | The user (subject) |
|---|---|---|
| Decisions, audit | Actor, with its revision and capability | Principal of business policy, with its revision |
| New objects and documents | | Owner |
| Share grants, label proposals | | Grantor, proposer |
| Approvals | Recorded as the deciding actor | Never decides an approval it requested, nor one its own agent requested |
| Client-mode recipient and signing keys | Its own keys: an agent that decrypts must be an eligible recipient itself (FLW-002) | |
| Tool invocations | Actor | Subject; sees what its agents did |
| Resolving or writing off a call | Recorded as resolver | Never settles its own call, through any agent (INV-006) |
| An idempotency key | The same key under another actor, subject or delegation is a conflict (INV-004) | |

## Without the MCP role

A role may also present a delegation itself, with no token: the request names the agent, the subject and the delegation, and the delegation must name that role's workload as its audience (TRU-003: a delegation verified against authoritative state, never caller-asserted identity alone).

## Not yet

- The optional managed-client profile and context marks (FLW-003 to FLW-008, V-114).
- Self-service delegation by a user for their own agents; for now an administrator records them.
- Delegated calls on the native API from an agent's own client.

## Tests

| Test | Covers |
|---|---|
| `internal/mcpsvc` `TestMCPDelegatedAgent` | Through the MCP role: the agent reads the user's document; a delegation without read grants, another agent with the user's delegation, and no delegation all refuse; a registered tool call recorded with actor, subject and delegation, visible to the user; a session reused under another delegation `403`; a revoked delegation refused |
| `internal/nativeapi` `TestChainedEvidence` | The decision role names the subject from the delegation; the gateway's decision is evidence only for the same actor, subject and delegation |
| `internal/executor` `TestResolution` | An agent for a lead resolves another's call, never the lead's own |
| `internal/catalog` `TestPutDelegation` | Creation: a child narrows its parent in actions and lifetime; no overwrite, no self-delegation, no past expiry, no unknown actor, no empty grant |
| `internal/catalog` `TestParentInTheTransaction` | A child delegation recorded by an administration resolves its parent through that transaction, on a pool of one connection (audit F4) |
| `scripts/smoke.sh` | An agent under a delegation reads the user's document through MCP; without it, nothing; its session is bound to it |
