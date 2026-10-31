# Derived outputs and lineage (DRV-001 to DRV-003, DRV-007 to DRV-009)

Status: design record, 31 October 2026. Our own design; no upstream mapping. These controls rely on cooperating clients declaring their inputs truthfully; the server cannot see the computation (Part 3, "Derived outputs").

## Registration

A derived output is an encrypted object of kind `derived` whose resource type is `document.derived` (deliver, declassify, label, relabel, approve). At publication the client supplies signed lineage: the exact source resources (objects, units, other derived outputs) and versions its computation received (DRV-001). The server checks:
- the signer's authority;
- that every source exists in the tenant and is LIVE;
- the bounds: at most 1,000 direct sources and a transitive depth of 32;
- that no cycle exists.

It stores the lineage edges in `lineage(derived, source)`.

## Effective label (DRV-007, LAB-004)

The effective label is the maximum, under the label order, of the collection default and every source's effective label. A proposed lower label is ignored unless the same request carries a `relabel` allow for this output (V-148). The effective label is stored as the derived resource's protected label.

## Delivery (DRV-002)

Delivering a derived output needs `deliver` on it, the usual envelope checks, and one of:
- `read` for the recipient on every source in its transitive lineage; or
- `declassify` for this exact output, version and recipient.

The owner's client must already have created the recipient's envelope. A `declassify` allow authorizes that delivery only; it does not change the stored label (DRV-008).

## Freshness (DRV-009, V-145)

Every lineage source's resource binding (generation and metadata revision) is a check of the delivery decision, so the authority fence and the stream lease recheck them. A label change, deletion or other change to any transitive source invalidates the decision and aborts an admitted stream at its next lease check. The reported reason is `LINEAGE_AUTHORITY_CHANGED` when the changed resource is a lineage source rather than the output itself. The traversal is bounded by the limits above.
