# Errata: specification 2.6.1 to 2.6.2

Date: 31 October 2026. Version 2.6.2 corrects 2.6.1 in two places, after code review v3
(findings F02 and F03), with the owner's decisions of the same day. Changing normative text
changes the specification version (TEST-003), so 2.6.1 was not edited in place. No
requirement or test family is added or removed (289 requirements, 24 families); case
V-179 is added (140 cases).

## Recovery onto a catalog without a journal record (F02)

G-03 promises that recovery cannot silently restore revoked grants, while N-08 accepts that
the local profile loses changes made after the last backup. When the catalog that recorded
how far the security journal reached survives, a restore compares the journal with that
record. When it does not survive, for example after a restore onto an empty catalog, only
the backup's own record is left: it shows the journal complete up to the backup, not after
it. A journal copy missing a later revocation then looked complete, and a reconcile
reopened access the revocation had removed.

| Where | Change |
|---|---|
| AVL-008 | When the restored catalog keeps no record of how far the separately protected recovery record reached, admission reopens only after an explicit, audited operator statement that the record is complete, or an explicit acceptance of its loss |
| V-179 (T-16) | Such a restore without the statement: fresh delivery stays closed (`DENY`) |

## Approvals for collection entries (F03)

SHR-001 lets a grant name a collection entry, and a policy may require an approval for it,
but `text.entry` had no `approve` action, so no approval could be opened or decided.

| Where | Change |
|---|---|
| Part 1, resource type table | `approve` added to `text.entry`, as on `document.text_unit` |

## Also changed

Title page, running head, review appendix (a 2.6.2 section) and companions name 2.6.2.

## Verification (31 October 2026)

See `VALIDATION.txt`.
