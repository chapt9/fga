# Labels and approvals (LAB-001 to LAB-005, FLW-004, APR-001 to APR-007)

Status: design record, 31 October 2026, updated with the implementation of R1-C step 2. Decisions: [D-06](../decisions/D-06-labels.md), and rulings 6 and 7 of [the owner's rulings](../decisions/rulings-2026-10-31.md). Our own design; no upstream mapping. Default deny applies throughout: every action below needs an allowing rule, and owner status grants nothing by itself.

## Labels

**Where labels live.** Every storage object carries a protected `label` attribute in its `resources` row (document units and derived outputs follow in steps 3 and 5). A client field never sets it directly (DAT-002). A label change advances the resource's metadata revision (its access revision, LAB-005), so every decision, plan and stream lease bound to the old revision fails at the authority fence. Payload bytes and envelopes are unchanged.

**The order.** The signed release manifest carries the order and its generation (D-06; the example bundle uses `public` < `internal` < `confidential` < `restricted`, generation 1). Two parts use it:

- *The decision role* adds trusted attributes before evaluation (`internal/decision`, `ranked`). The ranks are integers from 0:
  - `resource.attributes.label_rank` for the label; a missing or unknown label ranks highest (FLW-004);
  - `new_label_rank` and `floor_rank` when the resource carries `new_label` and `floor` (below);
  - `principal.attributes.clearance_rank` when the principal's `clearance` attribute is in the order. A principal without a known clearance has no `clearance_rank`, so a condition on it errors and denies (POL-005).

  Stored attributes with these names are dropped first, so a policy only ever sees computed ranks. With no order (generation 0), no ranks are added. A release's sentinels are evaluated with the same ranks (`labels.Ranked`), so they test what the decision role decides.
- *The enforcing roles* need the order to tell a raise from a lowering and to apply the floor. On activation, the decision role publishes the release's order to the catalog (`label_orders`, `label_order_active`); an order never changes within its generation. The storage role reads it. Inside the fence, it checks that the active generation equals the generation the signed decision binds (`context_revisions.label_order_generation`); otherwise the operation fails with a conflict.

**Proposed changes.** A label change is decided on the namespace `change.label`, named `<resource ID>|<new label>`. It resolves to the existing object with its current binding and attributes, plus:
- `new_label`;
- `floor`, the bucket's default label.

An explicit label at upload resolves the same way on the planned object. A policy can therefore bound labels by clearance, for example `resource.attributes.new_label_rank <= principal.attributes.clearance_rank`.

**Setting a label.**

| Situation | Label | Checks |
|---|---|---|
| Upload of a new key without a label | The bucket's default (also its floor) | None beyond the upload's |
| Upload of a new key with a label | That label, if in the order and not below the floor | `label` on the planned object (operation `storage.object.publish-create-labeled`) |
| Upload of a new version with another label | Refused | Labels of existing keys change only through the label operation |
| Label change to an equal or higher rank | New label | `label` (`storage.object.label`) |
| Label change to a lower rank | New label, never below the floor | `relabel` (`storage.object.relabel`). A policy may require an approval (`"requires": ["approval"]`), which is how LAB-004's default approval is expressed. The example and fixture policies do |
| Classifier proposal | Unchanged | `propose-label` (`storage.object.propose-label`). The proposal is stored as advisory (`label_proposals`, `authoritative` always false, V-147) |

Document units and derived outputs are labelled the same way: `PUT …/document/unit/label?key=&unit=` with `document.unit.label` or `document.unit.relabel`, and `PUT …/derived/label?key=` with `derived.label` or `derived.relabel` (`fga label -unit` or `-derived`). A unit's label is the unit's, in every document version that includes it. Text entries take their collection's label and are not labelled alone. Lowering a derived output, also below its lineage maximum, is relabel (LAB-004, DRV-007). Approvals can target units and derived outputs (`document.unit.approve`, `derived.approve`). A change advances the resource's metadata revision, so derived outputs that name a relabelled unit lose their admitted authority (LAB-005, DRV-009).

A label outside the order, or below the floor, is refused before any decision. The audit record of a change names the object and its new metadata revision, with outcome `LABEL_RAISED` or `RELABELED`; the label values are not written to audit (AUD-003).

**Registry.**
- `label`, `relabel`, `propose-label` and `approve` on `storage.object`;
- `approve` on `storage.bucket` and `document.version`;
- `label`, `relabel`, `propose-label` and `approve` on `document.text_unit`;
- `label` and `approve` on `document.derived`, which already had `relabel`.

`propose-label` is our addition: under default deny, storing a proposal is an action like any other. There is no registry of trusted classifiers (D-06 leaves it open), so every proposal is advisory.

## Approvals

**Authority.** Ruling 6: an `approve` action on the resources themselves. Ordinary policy rules grant approvers. The fixture and example policies let a principal with role `lead` approve in its projects, and `fga-admin grant -preset approver` grants the capability. The requester and the acting agent can never decide their own approval (APR-002), whatever the policy says.

**Plan and digest.** The enforcing role renders each operation that can need an approval as a neutral plan (`opplan.Summary`). Operations: finalize, delete, version delete and label changes. The plan holds:
- the operation and action;
- the targets with exact versions; the first target is the approval target, an object or (for a new key) its bucket;
- changes, such as the new label, the previous label and the recipients;
- preconditions, and the bucket and key as details.

The operation digest is SHA-256 over `fga.opplan/v1`, a zero byte and the plan's JSON without its digest field (`opplan.Digest`). It excludes identifiers allocated per attempt, such as planned envelope IDs. The decision role refuses a request whose plan is not the one its digest names, or names another operation, so the approver is shown exactly what the decision binds (APR-005).

**Flow.**

1. The storage role asks for a decision with the plan. Every check holds only with an approval, so the decision is `NEEDS_APPROVAL`.
2. The decision role opens a pending approval, or returns the caller's existing pending one for the same digest. The approval records:
   - the plan, digest, requester and acting agent;
   - the approval target;
   - the policy epoch and the generation and metadata revision of every existing bound resource (APR-001);
   - a lifetime of 24 hours.

   The storage role answers `202 APPROVAL_REQUIRED` with the approval ID. This tells the caller only that they could do this with an approval, which they are entitled to know. Every other non-ALLOW outcome stays `404`.
3. An approver lists pending approvals (`GET /v1/approvals`). Each one is shown only if a fresh `approve` decision on its target allows it. The approver decides with `POST /v1/approvals/{id}`. That is a single-use `approve` decision, and the approval's transition commits in the same fenced transaction. The approval's revision advances on every state change.
4. The requester repeats the operation with `Fga-Approval: <id>`. The decision role accepts the approval only if all of these hold:
   - it is APPROVED and unexpired;
   - it has the same operation, digest, requester and actor;
   - someone else decided it;
   - it was requested under the current policy epoch and the same resource revisions.

   The decision role then removes the `approval` prerequisite, binds the approval's ID and revision into the signed decision (`context_revisions.approval`, DEC-008), and limits the decision's validity to the approval's expiry. A pending approval answers `202` again. Anything else answers `409 APPROVAL_NOT_USABLE`.
5. Verifiers accept a check whose only prerequisite is `approval`, and only when the record binds an approval; a reservation is never satisfied by a record. The fence locks the bound approval (step 6a), requires it APPROVED at that revision, and consumes it in the operation's own transaction (step 7a, APR-002, APR-003). The mutation's audit event names the approval. A changed operation has another digest and needs a new approval (APR-001).

**Scope in R1-C.** Approvals cover the storage role's finalize, delete, version delete and label changes. A `NEEDS_APPROVAL` outcome on a keys-role operation stays a denial, because those operations send no plan.
