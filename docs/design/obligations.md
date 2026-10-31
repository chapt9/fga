# Policy outputs and obligations (POL-011, APR-007, DEC-002, DEC-008)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

Policy outputs are data. They become platform obligations only through a release's explicit, versioned obligation mapping. An obligation is signed into the decision with its parameters. An enforcement point accepts the decision only if it can apply every obligation it carries.

## Policy outputs

An allow rule of the business set may carry `outputs`: at most eight values under identifier names. A value is a string, an integer, a boolean, or a list of up to 64 strings.

```json
{"id":"members-stat-projected","effect":"allow","actions":["stat"],"roles":["member"],
 "when":"resource.attributes.project in principal.attributes.projects",
 "outputs":{"projection":["version_id","etag"]}}
```

The engine reports, per allowed action, the outputs of every allow rule that matched. The decision role returns them with each check result, as data (DEC-003). On their own they authorize and restrict nothing.

## The obligation mapping

A release's manifest (`release.Info`) may carry `obligation_mapping`. It is part of the signed manifest, so only a publisher changes it:

```json
"obligation_mapping": {
  "version": "fga.obligations/v1",
  "outputs": {"projection": "metadata_projection"},
  "prerequisites": {"reservation": "reservation"}
}
```

| Part | Meaning | Validated when the bundle loads |
|---|---|---|
| `version` | The mapping version: `fga.obligations/v1` | The only version |
| `outputs` | Output name to obligation type | Only `metadata_projection` can come from an output, and every mapped output in the bundle must be a non-empty list of field names |
| `prerequisites` | Allow prerequisite to obligation type | Only `reservation` to `reservation`. An approval is never mapped: the decision role always resolves approvals before signing |

Without a mapping, no decision carries an obligation (`fga.obligations/none-v1`). That is the behavior of every release made before this record.

## In a decision

After the approval step, the decision role applies the mapping:

- **A reservation prerequisite**, if mapped, becomes a `reservation` obligation, and a decision that would otherwise wait for a reservation is signed as an allow. The enforcing role must reserve the operation's budget and commit the reservation with the operation (APR-004). Unmapped, the outcome stays `NEEDS_RESERVATION`, with no signed decision.
- **Mapped outputs** of every allowed check become obligations, merged restrictively (APR-007). Several `metadata_projection` outputs allow only the fields they all name. A check whose allow has no projection adds no restriction.

Each obligation carries its parameters (canonical JSON) and their digest. The record names the mapping version, and the record's obligations digest covers them all (DEC-008). Changing the transmitted obligation set without a new signature fails verification (V-141).

## At an enforcement point

`signing.Verifier.Applying(f)` declares, per operation, which obligation types an enforcement point applies. The verifier accepts:

- `fga.obligations/none-v1` with no obligations;
- `fga.obligations/v1` only if every obligation's parameters match their digest and `f` applies its type to the decision's operation.

Anything else is `ErrObligation`, so an obligation nobody applies fails closed (DEC-002). A check that requires a reservation is an unconditional allow only if the record carries a `reservation` obligation.

| Enforcement point | Applies |
|---|---|
| Storage role (`content.Applies`) | `metadata_projection` on `storage.object.stat` and `storage.object.stat-history`: the stat response shows only the named fields (`VersionInfo.Projection`, `Wire`) |
| Executor (R2 stretch E1) | `reservation` on tool operations |
| Every other verifier | Nothing |

## Not covered

Projections of listings and searches are not applied. A policy that attaches a projection to them makes those operations fail closed until they are.

## Tests

| Test | Covers |
|---|---|
| `internal/signing` `TestObligations` | Accepted only where applied and for the operation; parameters bound to their digest; a reservation obligation satisfies a reservation prerequisite, and nothing else does |
| `internal/decisionsvc` `TestApplyObligations` | No mapping, no obligations; a mapped reservation becomes an obligation; an approval never does; projections intersect; unmapped outputs and denials yield none |
| `internal/content` `TestMetadataProjection` | A stat shows only the projected fields; unmapped outputs change nothing; a projection on a read fails closed |
| `internal/conformance` `TestV141` | The fixture: the original grant verifies, a removed or widened obligation set does not |
| `internal/policy/format` (bundle validation) | Outputs only on business allow rules, with identifier names and output values |
