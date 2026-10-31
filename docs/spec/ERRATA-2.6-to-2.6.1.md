# Errata: specification 2.6 to 2.6.1

Date: 31 October 2026. Version 2.6.1 corrects 2.6 in one place, approved by the owner
before share grants (D-12 stretch S5) were built. Changing normative text changes the
specification version (TEST-003), so 2.6 was not edited in place; it stays in git history.
No requirement, test family or case is added or removed (289 requirements, 24 families,
139 cases).

## What was inconsistent

SHR-001 lets a grant name a bucket, object, document version, unit, entry or derived output
and requires `share` on it, but:

- the resource type table (Part 1) gave `storage.bucket`, `text.entry` and
  `document.derived` no `share` action, so a grant on them could never be recorded;
- its grantable actions (`read`, `stat`, `discover`) are object actions. A bucket is read
  with `list`, a document version with `read-units`, and a derived output with `deliver`.

## Changes

| Where | Change |
|---|---|
| Part 1, resource type table | `share` added to `storage.bucket`, `text.entry` and `document.derived` |
| SHR-001 | A grant's actions come from its target type's read set: `read`, `stat` and `discover` on an object; `read-units` and `discover` on a document version; `read` on a unit or entry; `deliver` on a derived output; `list` on a bucket |
| V-177 note | Names the target type's read set instead of read, stat and discover |
| Title page, running head, review appendix, companions | Version 2.6.1; the review appendix gains a 2.6.1 section |

## Verification (31 October 2026)

See `VALIDATION.txt`.
