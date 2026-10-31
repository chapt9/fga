# Fault isolation (MOD-002, AVL-006)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

## Problem

A failure in one part of the system must not stop the rest. A panic while serving an MCP user, for example, must not end the storage role. Within a role, one bad request must not end the requests of other users.

## One process per role

Each role is a program and an operating-system process of its own: `fga-decision`, `fga-keys`, `fga-storage` and, in R2, `fga-mcp`. The roles share no memory. They have separate configurations and credentials (MOD-002, MOD-003), and they call each other only over authenticated HTTP. A role that ends takes no other role's state with it.

No role links C code (cgo); `go list` shows none. A nil pointer or an index out of range is therefore a Go panic, not a segmentation fault. A Go process can fail in two ways:

- **A panic** unwinds one goroutine. Unless something recovers it, it ends the whole process. `internal/guard` recovers it where our code serves a request or starts a goroutine (below).
- **A fatal runtime error** (out of memory, a concurrent map write, stack exhaustion, every goroutine blocked) ends the process and cannot be recovered. This is why the process is the unit of isolation: the role's supervisor restarts it, and the other roles go on.

## Inside a process (`internal/guard`)

A caught panic is logged with its stack and fails closed: the request is refused, or the work the goroutine guarded counts as failed.

| Where | How | On a panic |
|---|---|---|
| The HTTP server of the storage and keys roles (`roleconfig.Serve`) and of the decision role | `guard.Handler` | The request is answered `500 UNAVAILABLE`; a response that had already begun is aborted, so the client sees a broken response rather than a short one. The role serves the next request. |
| The storage role's stream lease recheck (`content` `leased.watch`) | `guard.Go` | The stream ends as on a failed recheck: no byte is delivered without a passing recheck (CNT-008). |
| The MCP role's HTTP handler, and every MCP request inside the SDK (`mcpsvc` `contain`, the outermost SDK middleware) | `guard.Handler`, `guard.Recover` | The request fails with an internal error; the SDK runs handlers in its own goroutines, beyond the HTTP server's recovery, so without this one request's panic would end every user's session. |

Not guarded:
- goroutines inside third-party code that we do not start, such as the MCP SDK's transport;
- the Go SDK client's upload goroutines, which run in the user's own process.

The guard does not undo work. Code releases locks and transactions with `defer`, so a panic leaves nothing held.

## When a role is down

| Down | Effect on the others |
|---|---|
| decision | Every enforcing role fails closed: requests are refused (`503 UNAVAILABLE`), and nothing is allowed |
| keys | Server-mode reads and writes and client-mode envelope delivery fail; listings and decisions go on |
| storage | No content is stored or delivered; decisions go on; the MCP role answers that a backing service is unavailable |
| mcp | Its sessions end and MCP clients reconnect; nothing else is affected, and it keeps no state to lose |
| a user's `fga mcp-bridge` | Only the application that started it loses its MCP server; it is a client process on the user's machine, guarded like the MCP role (`guard.Recover` around every request) |
| PostgreSQL | Every role fails closed |

## Deployment

- One supervisor per role (a systemd unit or a Kubernetes deployment) restarts it when it ends; `/healthz` and, where present, `/readyz` report its state.
- Each role has a memory cap (cgroup or container limit), with `GOMEMLIMIT` set somewhat below it, so the garbage collector works harder before the kernel ends the process.
- Each role runs as its own operating-system user, and only that user can read its configuration and key files.
- In the local profile, `scripts/smoke.sh` starts each role as a process of its own.

## Load

One caller must not be able to exhaust a role that others depend on.

| Role | Bound |
|---|---|
| storage, keys | Concurrent requests per tenant and in total, concurrent streams per tenant (`internal/admission`, AVL-006); a request over a bound is answered `429 OVERLOADED` |
| decision | Request size, checks per request and time per decision (DEC-009). Concurrent requests per calling workload (the public facade counts as one) and in total: `admission` in the role's configuration, `adapter_requests` 128 and `total_requests` 512 when absent, so no workload holds more than a quarter of the role. A request over a bound is answered `429` at once, and its connection closed; callers treat it as the role being unavailable, so nothing is allowed |

| mcp | Concurrent calls and open sessions per user and in total, content per request, units per read, request body (see [mcp-role.md](mcp-role.md)); over a bound, `429` at once |

Not yet: a bound per calling workload at the storage role. The MCP role's own bounds and the decision role's bound per workload limit what a runaway MCP role can send.

## Tests

| Test | Covers |
|---|---|
| `internal/guard` `TestHandler`, `TestGo`, `TestRecover` | A panicking request is answered 500 and logged, a panic after the response began aborts it, streaming flushes through the guard, a goroutine's panic reaches its fail-closed handler |
| `internal/roleconfig` `TestServeGuardsPanics` | The storage and keys roles' server answers a panicking request 500 and serves the next |
| `internal/content` `TestLeaseCheckPanic` | A panicking recheck ends the stream; without the guard it ends the process |
| `internal/decisionsvc` `TestAdmission` | The decision role's bounds per workload and in total; a slow request body holds its slot; a refused request is answered before its body is read; slots are freed |
| `cmd/fga-decision` `TestValidate` | Bad bounds are refused; without an `admission` section the defaults apply |
| `internal/mcpsvc` `TestMCPPanicContained`, `TestMCPLimits` | A panicking MCP request fails alone, and without the guard ends the test process; the MCP role's session and call bounds |
