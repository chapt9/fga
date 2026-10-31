# Authority fence (DAT-007, DEC-006, DEC-011, AVL-008)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

## Problem

A signed decision is evaluated outside any database transaction (POL-003, DAT-007: policy evaluation stays outside held locks). Between evaluation and the protected effect, authority can change: an identity is disabled, a delegation or recipient key is revoked, a stricter policy release raises the tenant's required epoch, the object is overwritten, or the catalog is restored from a backup. Before this record, `gate.Recheck` re-read those facts with plain reads and `catalog.Consume` consumed the decision in its own statement. Neither formed one ordering point with the protected transition, so a revocation could commit between the recheck and the effect and go unnoticed.

## Contract

Every protected transition or durable admission (publish a version, write a delete marker, withdraw a version, publish or deliver an envelope, admit a ciphertext read) runs inside **one** PostgreSQL transaction, the *fence*, which:

1. takes row locks on every authority fact the signed decision is bound to, in the fixed order below;
2. compares each locked row with the revision bound in the decision;
3. records single-use consumption of the decision;
4. performs the operation's own catalog transition or admission record;
5. appends the audit-outbox event;
6. checks `now + clock_margin < valid_until` and commits.

Every change to a fact that a fence checks updates that fact's row and advances its revision. An `UPDATE` takes the row's exclusive lock, which conflicts with the fence's `FOR SHARE`:

- If the change commits first, the fence's locking read waits for it and then sees the new row (READ COMMITTED re-reads the latest committed version for locking reads), finds a revision mismatch and rolls back. A stale operation cannot commit.
- If the fence locks first, the change waits until the fence commits. Only that exact admitted operation proceeds, and later fences see the change.

Snapshot reads alone are not used for any fenced fact.

## Lock order

All fences and all authority changers acquire rows in this order. A transaction skips categories it does not need but never goes back to an earlier one.

| # | Rows | Lock | Checked against the record |
|---|---|---|---|
| 1 | `authority_state` (one row) | `FOR SHARE` | `admission_open` is true; `incarnation` equals the record's recovery incarnation |
| 2 | `tenant_epochs` (the tenant's row) | `FOR SHARE` | The row exists (every tenant gets one, at required epoch 0, when it first appears; without it nothing orders a first epoch raise, so the fence refuses) and `required_epoch` is not above the record's policy epoch |
| 3 | `identities`: actor, subject and every check principal, sorted by id | `FOR SHARE` | Same revision; not disabled; not expired |
| 4 | `delegations`: every link of the chain, sorted by id | `FOR SHARE` | Same revision; not revoked; not expired |
| 5 | `recipient_keys`: every recipient fingerprint, sorted | `FOR SHARE` | Same revision; status ACTIVE |
| 6 | `resources`: every bound resource, sorted by (type, id) | `FOR UPDATE` when the operation changes it, otherwise `FOR SHARE` | Same generation and metadata revision |
| 6a | `approvals`: the approval the record binds (`context_revisions.approval`), if any | `FOR UPDATE` in a transition, `FOR SHARE` in a read-only check | State APPROVED, same revision, unexpired (APR-002) |
| 7 | Operation rows: object heads, then versions, then upload intents, then envelopes, each sorted by id; for a label decision, the active label order (`FOR SHARE`), whose generation must be the record's; for a publication or share, the content-signing key's row (`FOR SHARE`), which must still be ACTIVE and the caller's | `FOR UPDATE` | Operation-specific expected state (PUB-003, PUB-007, D-06) |
| 7a | `approvals` | update | The bound approval becomes CONSUMED, revision + 1, in the operation's transaction (APR-002, APR-003) |
| 8 | `consumed_decisions` | insert | The decision ID was not consumed before (DEC-011) |
| 9 | `audit_outbox` | insert | Capacity (AUD-002); a full outbox rolls the fence back. The mutation event names the consumed approval |

Authority changers lock one fact row each (an identity, a delegation, a recipient key, the tenant epoch or the authority state), so they cannot deadlock with a fence that takes rows in this order. A fence that loses a deadlock or serialization race is retried by the caller with the same operation identity; it never retries with a different decision.

## What changes a fenced fact

| Change | Row updated | Effect on open fences |
|---|---|---|
| Identity disabled, roles, attributes or capabilities changed | `identities.revision` + 1 (capability changes also advance the actor's revision) | Mismatch on step 3 |
| Delegation revoked | `delegations.revoked`, `revision` + 1 | Mismatch on step 4 |
| Recipient key revoked or compromised | `recipient_keys.status`, `revision` + 1 | Mismatch on step 5 |
| Policy activation with a higher required epoch | `tenant_epochs.required_epoch` | Mismatch on step 2 |
| Object overwritten, deleted, relabeled | `resources.generation` or `metadata_revision` + 1 | Mismatch on step 6 |
| Restore or recovery | `authority_state.incarnation` + 1, `admission_open` false | Mismatch on step 1 |

## Recovery incarnation (AVL-008, DEC-011)

`authority_state` holds the deployment's current recovery incarnation and whether admission is open. The decision role refuses to decide while admission is closed and binds the current incarnation into every signed decision. A restore closes admission, restores the backup, issues a new incarnation that is higher than both the backup's and every incarnation recorded in the security journal, reconciles security-critical changes made after the backup (see [storage-r1b](storage-r1b.md), "Backup and restore"), and only then reopens admission. A decision signed before the restore names the old incarnation and fails step 1 even if its consumption record was lost with the restored database.

## Single-use consumption

`consumed_decisions` gains the incarnation. Consumption is an insert inside the fence, so it commits or rolls back with the protected transition (DEC-011). Every storage and envelope decision is single-use: the storage and keys roles request a fresh decision for each operation they enforce. Expiry during a durability wait does not extend validity; a consumed decision stays consumed.

## Read admission and stream leases (CNT-008)

A ciphertext read runs the fence with an admission record (`read_admissions`: decision, version, lease expiry) instead of a catalog transition, then streams outside the transaction. While streaming, the storage role re-runs steps 1 to 6 as a read-only locked check at least every `T_check` (5 s). A failed or overdue check (no completion within `2 T_check`) aborts the connection. No byte is emitted at or after `valid_until`. Cancellation ends the lease.

## Time

The fence compares `valid_until` with the enforcing process's clock plus a configured clock margin (default 1 s). In the `local` profile every role reads the same host clock. An uncertain clock is not modeled in R1; the margin is the only allowance (POL-008 qualification remains open).

## Owning code

- `internal/fence`: the binding type, the lock order and the checks of steps 1 to 6a, 7a, 8 and the time check, over a `pgx.Tx`.
- `internal/content` and `internal/envelope`: the operation rows of step 7 and the audit event.
- Authority changers in `internal/catalog` (control functions) and `cmd/fga-admin` advance revisions as listed above.

## Acceptance invariants

- V-142: a revocation that commits between prepare and publish makes the publication fail with no version, head change or success audit event.
- A fence that holds its locks makes a concurrent revocation wait, and the revocation then applies to the next fence.
- Replaying a consumed decision fails at step 8; a decision from an older incarnation fails at step 1.
- An expired decision fails the time check even when every revision still matches.
