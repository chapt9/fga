# Share grants (D-12 stretch S5, SHR-001 to SHR-003)

Status: design record, 31 October 2026. Our own design; no upstream mapping. Specification 2.6.1 (the grant targets and grantable actions of SHR-001).

A share grant lets a principal name another principal of the same tenant who may read a resource, within what policy allows. A grant is an authority fact that rules can test. It is never a permission by itself: without a rule that honors it, a grant has no effect (default deny, V-171). It works in both encryption modes.

## Targets and actions

A grant names one resource and the actions it may allow, taken from that resource type's read set (`registry.GrantableActions`):

| Target | Resource type | Grantable actions |
|---|---|---|
| A bucket (no key) | `storage.bucket` | `list` |
| An object at a key | `storage.object` | `read`, `stat`, `discover` |
| A document at a key (its current version, or `version`) | `document.version` | `read-units`, `discover` |
| A unit of that version (`unit`) | `document.text_unit` | `read` |
| An entry of a text collection (`unit`) | `text.entry` | `read` |
| A derived output at a key | `document.derived` | `deliver` |

An object's or derived output's grant covers the resource, not one version. A document version's grant covers that version only; a new version needs its own grant.

## What policy sees

The decision role adds `resource.attributes.shared_with` to every resource of these types it resolves. It maps each grantable action of the type to the IDs of the principals whose unexpired grants name it, with empty lists when there are none. A rule honors grants by testing it:

```json
{"id":"grantees-read","effect":"allow","actions":["read"],"roles":["*"],
 "when":"principal.id in resource.attributes.shared_with.read"}
```

The attribute is always present on resolved resources. A policy sentinel or test fixture that lacks it fails evaluation, so the example bundle guards with `has(resource.attributes.shared_with) && ...`.

- **Ceilings still apply.** An honored grant does not lift a ceiling, a label rule or a clearance (V-175). A grant on a document reaches its units only where a unit rule says so, and unit checks stay per unit (SHR-003).
- **Server mode.** An honored `read` is enough for the storage role to decrypt for the grantee after the ordinary checks (V-172).
- **Client mode.** The grant makes the grantee pass the target-recipient `read` check, so the owner can now share an envelope, but it supplies no key. Until an envelope exists, the grantee gets nothing (V-178).

## Operations

Each grantable type has three registered operations, each with one check, `share` on the resource (role `target`):

- `<type>.record-grant`. The check resolves the proposed change `change.grant` (`<resource>|<grantee>|<grantee identity revision>|<actions>|<expiry>`): the resource as it is, plus `grantee`, `grantee_attributes`, `grant_actions` and `grant_expires_at`. `grantee_attributes` are the grantee identity's attributes at exactly the named revision; they are empty for an unknown or disabled principal or another revision. A policy can therefore limit whom and what may be granted, for example to grantees of the same project. The operation carries a plan, so a policy can require an approval.
- `<type>.remove-grant`. Carries a plan as well.
- `<type>.list-grants`. Returns the unexpired grants.

**Recording** (`content.RecordGrant`):

1. The actions must come from the type's read set. Duplicates are dropped and the actions are sorted. The expiry must be in the future; it is stored to the microsecond.
2. The decision is made.
3. If the grantee already has a grant on the resource, its removal is journaled (below), because the new grant replaces it.
4. In the authority fence:
   - the grantee must be a known, enabled and unexpired principal of the tenant, still at the identity revision the decision saw. Its row stays locked until the commit, so a grantee who changed project after the decision is refused (`409 CONFLICT`, review v2 finding 2);
   - the expiry must not pass the expiry of the grantor's identity, of the subject it acts for, or of its delegation;
   - the grantee's earlier grant must still be the one that was journaled;
   - the resource must have fewer than 100 unexpired grants.

   Then the earlier grant and any expired grants of the resource are marked removed, the new grant is inserted, and the resource's metadata revision advances.
5. Audit: a `mutation` event `SHARE_GRANT_RECORDED` names the resource and the grant.

Any check that fails rejects the grant (`400 INVALID`, V-177). A caller without `share` gets `404 NOT_FOUND` (V-176). Before the caller's `share` is decided, nothing reveals what a key holds: a version or unit selector on an object or derived output answers like an absent key, and whether the actions fit the target's type is checked only after the decision (review v3 F04).

**Removing** (`content.RemoveGrant`) decides `share`, journals the removal, then in the fence marks the grant removed and advances the resource's metadata revision (`SHARE_GRANT_REMOVED`).

## Freshness (SHR-002)

- **Recording or removing a grant** advances the resource's metadata revision. Every decision, plan, key release and stream lease bound to the earlier state fails at its next fence or lease check. A stream the grantee opened under a removed grant aborts (V-174).
- **Expiry** works through validity (DEC-005). Each decision's `valid_until` is capped at the earliest expiry among the unexpired grants on every resource it resolved, whichever rule allowed it. Leases end at `valid_until`, so a stream opened under a grant ends when the grant does (TH-29). A decision made after the expiry no longer sees the grant (V-173). This has the effect the specification asks of an advance at expiry, with no background job.

## Recovery (AVL-008)

A grant's removal is a revocation. The storage role, which now opens the security journal (`journal_dir` in its configuration, shared with the keys role), journals `grant-removed` with the grant ID before the removal commits. This also covers a grant replaced by a new one. Reconcile replays it after a restore: the grant is marked removed by `recovery`, and its resource's metadata revision advances. So a restore from a backup taken before the removal does not give the access back. A grant recorded after the backup is simply absent after the restore, which only removes access. `share_grants` is in every backup.

## Interfaces

| Interface | Record | Remove | List |
|---|---|---|---|
| Native API | `POST /v1/buckets/{b}/grants?[key=&version=&unit=]` `{"grantee","actions","expires_at"}` | `DELETE /v1/buckets/{b}/grants?[key=…]&grantee=` | `GET /v1/buckets/{b}/grants?[key=…]` |
| SDK | `RecordGrant` | `RemoveGrant` | `Grants` |
| CLI | `fga grant -grantee P -actions read,stat -expires 24h` | `fga ungrant -grantee P` | `fga grants` |

Record and remove answer `202` with the approval's ID when a policy requires one; repeat with `-approval` once it is given.

## Not covered

- A grant survives the grantor losing `share` or being disabled; only its expiry (bounded by the grantor's at recording), a removal or a recovery ends it.
- There is no grant on a collection as a whole, and no grant that carries over to a document's later versions.

## Tests

| Test | Covers |
|---|---|
| `internal/content` `TestGrantDefaultDeny` | V-171 |
| `TestGrants` | V-172 to V-177, listing, a stream ending at removal and at expiry, replacement, journaled removals |
| `TestGrantOutlivingGrantor` | An expiry beyond the grantor's identity is rejected |
| `TestGrantClientMode` | V-178: eligible as a recipient, no key until an envelope is shared |
| `TestGrantBindsGrantee` | Review v2 finding 2: a grantee who left the project between the decision and the commit is refused |
| `TestGrantTargets` | Each target type and its read set |
| `internal/recovery` `TestRestoreKeepsGrantRemoval` | A removal after the backup survives restore and reconcile |
| `internal/nativeapi` `TestGrantsHTTP` | The routes and SDK |
| `scripts/smoke.sh` | A member of another project reads a server-mode object only while granted |
