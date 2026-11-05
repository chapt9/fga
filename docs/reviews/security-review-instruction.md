# Instruction: security review of fga, beyond SQL injection

## Context

fga is the owner's own fine-grained access control firewall. It is written in Go.
It has its own default-deny policy engine based on CEL. It uses PostgreSQL through pgx v5.
Its roles are fga-decision, fga-storage, fga-keys, fga-kms, fga-mcp, fga-tools
and the admin API (`fga-admin serve`).

- Repository: `/Volumes/workdata/new_idea`. It is local only.
- Web console: a separate repository at `/Volumes/workdata/fga-console`.

Review the branch the owner names. When this was written (3 November 2026), it was
`data-tools` at commit `d702513`, based on main `7a5c33f`. Line numbers below are
from that day and may have moved.

## Rules

- Treat both repositories as read-only. Do not edit, add or commit files, and do
  not change their git state. Another session may be working in the same checkout.
- Keep tools, downloads and outputs in your scratchpad, never in the repositories.
- Do not open `code_review_v5.txt`, `fga-audit-a3172ea.md` or `papers/` in the
  repository root unless the owner says so.
- Do not run the PostgreSQL-backed tests unless the owner says the shared test
  database is free. `go vet`, and `go test` without `FGA_TEST_DATABASE_URL`, are fine.
- If a check needs a running system, ask the owner first. Then use the real fga.
  Never use stand-ins, fake data or fake calls. Do not touch the running demo
  without the owner's go-ahead.
- Report verified findings only. Do not fix anything. Fixes come later, after the
  owner agrees. Each fix stays narrow and comes with a regression test.
- Write in plain, short sentences.

## Already done

SQL injection was reviewed on 3 November 2026. It had no findings: every SQL text is
constant, and all input is bound as `$n`. Do not repeat that review.

That review noticed one point outside its scope. It is not yet confirmed. Restore joins
the manifest's `file` paths to the backup folder without checking that they stay
inside it (`internal/recovery/recovery.go:467`, `:472`, `:553`, `:591`). Confirm or
dismiss it under area 9.

Earlier reviews (v1 to v5, the fga audit, and the full-tree audit of `8b52b0c`) covered:
- decision binding;
- races and lock order;
- the security journal, backup and restore;
- approvals and grants;
- labels;
- the limits on the audit outbox;
- a govulncheck scan (commit `fbf1930`, `docs/dependencies/vulnerability-scan.md`).

Do not redo them, unless an area below needs one of them.

## How to review

For each area:

1. Name the attacker. It may be a user of a tenant, an agent working through MCP,
   a user of another tenant, a client-mode uploader, the administrator of one
   tenant, or someone on the network.
2. Find each place where that attacker's input or action reaches the code in
   question. Trace it from the HTTP handler, MCP call or CLI flag.
3. Confirm that the attacker really controls it, and what happens then. Read the
   code. Run a Go test without the database if that helps.
4. Keep only what you confirmed.

## Areas, in this order

1. **Who can set what the rules read.** For each attribute that a policy reads
   (of the caller, object, bucket, envelope or delegation), find who can set or
   change it. A user who can set a value that a rule trusts can grant themselves
   access. Start at `internal/envelope/envelope.go:148`, which copies `owner`,
   `project`, `label` and `bucket` from the object. Check the policies in
   `examples/local/bundle/policies`. `principal.self` lets a user read their own
   record (`internal/content/self.go`). Check that no route lets a user change
   their own roles or attributes.
2. **Stored script in the console.** A key may hold any UTF-8 text except NUL
   (`internal/content/write.go:99`). Find every place where the console shows a
   stored value: keys, names, labels, attributes and audit events. Check that each
   one is inserted as text, never as HTML. Check the console's
   Content-Security-Policy and frame headers. fga sets none itself.
3. **Tenant isolation.** Check that:
   - no lookup, cache or map works without the tenant;
   - a token, decision, approval or envelope from one tenant is refused in another;
   - the tables that are global, such as the label order in
     `internal/catalog/labels.go`, are meant to be.
4. **An agent misled through MCP.** Content that an agent reads can tell it to
   misuse rights it really has. Check that the flow rules (origin-bound flows are
   denied by default) stop:
   - data read from one origin being written to another tool;
   - allowed calls chained to do what one call may not;
   - tool answers that are very large or that carry values instead of references.

   Start at `internal/mcpsvc` and `internal/mcpbridge`.
5. **Look-alike and hidden characters.** Keys are compared byte by byte, with no
   Unicode normalization. Check what this allows:
   - two keys that look the same;
   - newlines or terminal escape codes in names that reach logs or CLI output;
   - right-to-left marks that change what an administrator or reviewer sees.

   Check identity, bucket, tenant and source names too.
6. **Crypto design.** For each kind of ciphertext, check:
   - what its associated data binds (tenant, object, version);
   - how nonces are made;
   - whether keys are cleared after use.

   Check the edge cases of KEK rotation. Check one point in particular. If the
   content cipher does not commit to its key, a client-mode uploader could give
   two recipients different keys that open one ciphertext to different contents.
   Check whether a signed digest of the plaintext prevents this.
7. **Tokens.** Algorithms are pinned and matched to the key type
   (`internal/authn/authn.go:82-108`). Check:
   - the audience and issuer for each role;
   - the maximum lifetime and the clock skew (`internal/authn/issuer.go`);
   - what an unknown key ID does (it must not force a JWKS fetch each time);
   - how fast a disabled identity loses access while its token is still valid.
8. **Answers that leak.** Check that timing, error text, status codes, page sizes,
   scan budgets and audit views do not tell a caller what exists or what someone
   else holds. Review v3 F04 fixed one such case for grant lookups. Look for
   others like it.
9. **Files and paths.** Confirm or dismiss the backup manifest point above.
   Check symlinks and file modes in the journal, blob, key, KEK and audit export
   folders, and in paths given as `fga-admin` flags.
10. **Load one caller can force.** Many limits exist:
    - the CEL cost limit (`internal/release/release.go:172`);
    - body and slow-client limits (`internal/guard`);
    - list scan budgets;
    - per-tenant outbox limits.

    Check what is left:
    - a PostgreSQL statement timeout;
    - the batch size of decide-batch;
    - locks that one request can hold over many rows;
    - slow tool servers holding workers.
11. **Policy bundles.** Check that:
    - a bundle that fails verification keeps the role closed;
    - an older bundle cannot be loaded again (epochs only grow, see `RaiseEpoch`
      in `internal/catalog/control.go`);
    - only the right people can sign a bundle.
12. **Clocks.** Decisions, leases, tokens, approvals and challenges use the local
    clock. Check that each comparison has a margin and an upper bound. Check that
    roles whose clocks disagree fail closed.
13. **Dependencies.** Run govulncheck on the current tree if the owner allows the
    download, and compare with `docs/dependencies/vulnerability-scan.md`. Check
    the console's JavaScript dependencies.

These looked guarded at a first look. Confirm them, but do not redo them:
- The JWKS URL comes from config, not from the token.
- Tool paths come from reviewed tool records (`internal/executor/executor.go:308`).
- Outbound HTTP clients refuse redirects. The exception is the audit export client
  (`internal/auditexport/auditexport.go:142`).
- Plain HTTP is allowed only on loopback, with a dev setting
  (`internal/roleconfig/roleconfig.go:111`, `cmd/fga-admin/serve.go:85`).
- Strict JSON rejects duplicate and unknown fields (`internal/strictjson`).
- MCP checks the `Origin` header (`internal/mcpsvc/mcpsvc.go:294`).

## Report

Write one Markdown file in your scratchpad, and give its full path. Use this order:

1. **Findings**, most severe first. For each one, give:
   - the `file:line`;
   - the input that reaches it;
   - an example input and what it does;
   - who the attacker is;
   - the severity;
   - the smallest fix.

   If the same fix also applies to other roles, say so.
2. **Checked and found safe**, area by area, so the coverage is visible.
3. **Not checked**, and why.

If you find nothing in an area, say so plainly. Put the findings in your final
message too. If time runs short, finish the area you are in, report the areas you
covered, and list the rest as not reviewed.
