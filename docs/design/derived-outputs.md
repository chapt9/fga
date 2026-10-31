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

The effective label is the maximum, under the label order, of the collection default and every source's effective label. A proposed lower label is ignored unless the same request carries a `relabel` allow for this output (V-148). The effective label is stored as the derived resource's protected label. A new version also keeps at least the output's current label: it never lowers it implicitly (lowering is relabel).

The label is computed once to plan the publication, and again in the fence from current state. The second computation uses the output's current label, the sources' labels with their rows held by the fence, and the active label order. If the two differ, because a raise of the output or of a source committed in between, the publication is refused with `409 CONFLICT`; a retry plans again at the higher label (review v3 F06). The fence locks an existing output for update from the start, since the commit updates it.

## Delivery (DRV-002)

Delivering a derived output needs `deliver` on it, the usual envelope checks, and one of:
- `read` for the recipient on every source in its transitive lineage; or
- `declassify` for this exact output, version and recipient.

The owner's client must already have created the recipient's envelope. A `declassify` allow authorizes that delivery only; it does not change the stored label (DRV-008).

## Freshness (DRV-009, V-145)

Every lineage source's resource binding (generation and metadata revision) is a check of the delivery decision, so the authority fence and the stream lease recheck them. A label change, deletion or other change to any transitive source invalidates the decision and aborts an admitted stream at its next lease check. The reported reason is `LINEAGE_AUTHORITY_CHANGED` when the changed resource is a lineage source rather than the output itself. The traversal is bounded by the limits above.

## Server mode (D-12, S4b)

In a server-mode bucket the lineage is declared in the authenticated upload request and bound to the caller's publication decision rather than signed. A reader has no recipient key and reads under `deliver` and their own reader path, which the keys role checks again when it releases the data key. See [server-documents.md](server-documents.md), "Derived outputs".

## Implementation (R1-C step 5)

**Publication.** A derived output is a new key of kind `derived`, begun with `"derived": true` and staged like an object. Finalize also carries a signed lineage: `fga.lineage/v1`, strict JSON, JWS type `fga-lineage+jws`, signed by the same active key as the descriptor. It names this output and version and 1 to 1,000 distinct sources (`storage.object`, `document.text_unit` or `document.derived`, each at an exact LIVE version of the tenant). Bounds: transitive depth at most 32. Cycles cannot arise, because a lineage names only existing versions and an output is new.

The caller needs:
- `create-object` on the bucket (`derived.publish`, with the planned envelopes' `create` and `receive-key`);
- `read` on each direct object or unit source, and `deliver` on each derived source (`derived.sources`; the three source roles are optional, a new `Optional` flag of registered operations).

Initial envelopes are for the caller's own keys only. The commit, under the fence over all decisions:
- rechecks the signer;
- rechecks that every source is still LIVE;
- stores `derived_versions` (lineage bytes, signature, label, depth) and the `lineage` edges.

**Label.** The stored label is the maximum of the bucket's default (the floor) and every direct source's label. A proposed label above it applies, with `label` on the planned output. A proposal below it is ignored (V-148). A derived source contributes its own stored label, which already includes its lineage.

**Delivery.** `GET /v1/buckets/{b}/derived/package?key=&recipient=`, `GET …/derived/ciphertext?key=&recipient=` and sharing (`POST …/derived/envelopes?key=&version=`) need `deliver` on the output plus the recipient path. The recipient path (`recipientPath`) is either of:
- `derived.recipient-sources`: the recipient's `read` on every object or unit source in the transitive lineage and `deliver` on every intermediate derived output, in batches;
- `derived.declassify`: `deliver` and the recipient's `declassify` on this output and version.

Package and ciphertext are for one of the caller's own keys. For a package, the recipient-path decisions are issued for the keys role and sent with the release (`derived.get-envelope`). The keys role verifies that they are either one declassify decision for this output, version and recipient, or recipient-source decisions covering the version's transitive lineage exactly. It admits them in the same fence as the release. Sharing commits the caller's re-wrapped envelope at the next generation.

**Freshness.** The ciphertext read is admitted over the merged binding of all decisions, and its lease rechecks that binding. If a recheck fails while the output's own binding still holds, the stream ends with `LINEAGE_AUTHORITY_CHANGED` (`content.ErrLineageChanged`, V-145).

**Relabelling.** `PUT …/derived/label?key=`: raising is `label`, lowering (also below the lineage maximum) is `relabel`, never below the bucket floor (labels-and-approvals.md). `derived_versions.effective_label` keeps the label computed at publication; the resource's label is the current one.

**Versions.** Begin with `"derived": true` on an existing derived key starts a new version.
- `document.derived` gains `new-version`, our addition to the spec's action table. Begin and staging need it on the output (`derived.begin-version`, `derived.stage-version`), and so does finalize (`derived.publish-version`).
- Each version carries its own signed lineage, recorded in `derived_versions` and `lineage`. Delivery of a version follows that version's transitive lineage.
- The output's label is one resource label. A version raises it to the maximum of the bucket floor, the current label and the version's sources (and a higher proposal). It never lowers it; lowering is `relabel`.
- An object or document key cannot take a derived version, nor a derived key an object version.

**Not yet.** A recipient-bound declassify record for managed clients beyond the decision itself (DRV-008's reported label).
