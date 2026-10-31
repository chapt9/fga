# Labels and approvals (LAB-001 to LAB-005, FLW-004, APR-001 to APR-007)

Status: design record, 31 October 2026. Decisions: [D-06](../decisions/D-06-labels.md) and ruling 6 of [the owner's rulings](../decisions/rulings-2026-10-31.md). Our own design; no upstream mapping.

## Labels

**Where labels live.** Every storage object, document unit and derived output carries a protected `label` attribute in its `resources` row. A client field never sets it directly (DAT-002). A label change advances the resource's metadata revision (its access revision, LAB-005), so every decision, plan and stream lease bound to the old revision fails at the authority fence; payload bytes and envelopes are unchanged.

**Order in policy.** The release manifest carries the order and its generation (D-06). Before evaluation, the decision role adds trusted, platform-computed attributes:

- `resource.attributes.label_rank`: the label's position in the order, from 0; a missing or unknown label gets the highest rank (FLW-004);
- `principal.attributes.clearance_rank`: the position of the principal's `clearance` attribute, when it has one. A policy that uses `clearance_rank` for a principal without one fails the condition and therefore denies (POL-005).

With an empty order (generation 0) no ranks are added. Policies compare ranks, for example `resource.attributes.label_rank <= principal.attributes.clearance_rank`. The ranks are computed from authoritative attributes and the signed release, never taken from a request.

**Setting a label.**

| Situation | Label | Checks |
|---|---|---|
| Upload without a label | The bucket's default (also its floor) | None beyond the upload's |
| Upload with a label | That label, if not below the floor | `label` on the planned resource |
| Label change to an equal or higher rank | New label | `label` |
| Label change to a lower rank | New label, never below the floor | `relabel`; a policy may require an approval (`"requires": ["approval"]`), which is how LAB-004's default approval is expressed |
| Classifier proposal | Unchanged | None; stored as advisory (`label_proposals`), `authoritative: false` |

Registry additions: `label` and `relabel` on `storage.object` and `document.text_unit`; `label` on `document.derived` (which already has `relabel`).

## Approvals

**Authority.** Ruling 6: an `approve` action on the resources themselves (`storage.object`, `storage.bucket`, `document.version`, `document.text_unit`, `document.derived`). Approvers are granted by ordinary policy rules on those resources. The approval store separately forbids self-approval by the requester or acting agent (APR-002).

**Operation digest.** An approval is bound to one exact operation, so the digest must not change between the request and the retry. The enforcing role renders the operation as a neutral plan (`opplan.Summary`: operation, action, exact targets and versions, changes such as the new label or recipients, preconditions). The digest is SHA-256 of that plan's canonical encoding. It excludes identifiers allocated per attempt, such as planned envelope IDs. The approver is shown the same plan (APR-005).

**Flow.**

1. The decision role answers `NEEDS_APPROVAL`: every check holds once an approval is given.
2. The enforcing role records a pending approval with the plan, its digest, the requester and the acting agent, and a lifetime of 24 hours. It answers `202 APPROVAL_REQUIRED` with the approval ID. This tells the caller only that they could do this with an approval, which is information they are entitled to; any other non-ALLOW outcome stays `404`.
3. An approver lists pending approvals (`GET /v1/approvals`), each shown only if the approver's `approve` checks on its targets allow it, and decides (`POST /v1/approvals/{id}`). Every decision is a fresh `approve` decision under the authority fence.
4. The requester repeats the operation with the approval ID. The decision role verifies the approval (approved, unexpired, same tenant and digest, not consumed, given by someone else), treats the `approval` prerequisite as satisfied, and binds the approval's ID and revision into the signed decision (DEC-002, DEC-008).
5. The enforcing role consumes the approval inside the fence, in the same transaction as the operation (APR-002, APR-003). A changed operation has a different digest and needs a new approval (APR-001).

**Scope in R1-C.** Approvals cover the storage role's operations: deletion, version deletion, publication and label changes. A `NEEDS_APPROVAL` outcome on a keys-role operation stays a denial until that role gets the same flow.
