# Errata: specification 2.4 to 2.5

Date: 31 October 2026. Version 2.5 is 2.4 with the changes below. No requirement
identifier was added or removed (277 before and after). Changing normative text changes
the specification version (TEST-003), so 2.4 was not edited in place.

## Why 2.4 needed correcting

Version 2.4 descends from the pre-2.2 lineage. It silently reverted two decisions that
the project owner had recorded on 30 October 2026 (`docs/decisions/D-01`, `D-02` in the
implementation repository), and its vectors, fixtures and test text depended on that
reversal. The owner reaffirmed both decisions on 31 October 2026:

- **D-01.** The policy format is our own `fga.policy/v1`. A matching deny overrides an
  allow across roles and scopes. No upstream format, reference or oracle.
- **D-02.** R1 uses our own single-node local blob store. Local only; no external store.

## Changes made

| # | Area | Change | Where |
|---|---|---|---|
| 1 | D-01 | Decision rows D-01 and D-03 restored; D-01 states `fga.policy/v1`, deny-overrides, no oracle | p00 decisions table |
| 2 | D-01 | POL-001, POL-002, POL-003, POL-005, POL-006, POL-012, POL-014, TEST-004, SRC-004 rewritten for the own format; the upstream-format listing, the role-path hazard paragraph and the oracle wording removed | p01, p06 |
| 3 | D-01 | New subsection "Policy format" (`sec:policyformat`): document shape, evaluation steps, conditions, plus the ceiling declaration and time-condition rules below | p01 |
| 4 | D-01 | Mechanism table, first row: upstream precedence is recorded as **Reject**, with our deny-overrides design | p06 |
| 5 | D-01 | Vectors V-001, V-003, V-004, V-005 (**now DENY**), V-006, V-008, V-010, V-011, V-012, V-014, V-017 rewritten; every `oracle` mark removed; fixture `v-001.json` rewritten in `fga.policy/v1` and uses `document.text_unit` | vectors/ |
| 6 | D-02 | Decision row D-02 restored; BKD-001 and BKD-002 rewritten for the single-node store; SMALL-003, Part 5 intro, scenarios and the review appendix no longer assume an external store | p00, p03, p05, p06, appendices |
| 7 | D-02 | Two deployment profiles: `local` (R1) and `ha` (multi-node, qualified only when deployed). AVL-001, AVL-003, AVL-004, AVL-005, AVL-007 and the AVL intro say which profile each obligation belongs to. New non-guarantee **N-08** | p00, p01 |
| 8 | D-02 | New checker feature `ha` (available from R1-B). Test family T-16 and vectors V-123, V-124 require it; V-144 (restore) stays core | tools/check_spec.py, vectors/ |
| 9 | Clarity | Ceiling declaration: a manifest must declare its ceiling set; an explicitly empty set passes, an omitted declaration is rejected. New vector V-153 | p01, vectors/ |
| 10 | Clarity | Time conditions: `request.now` is accepted only against a timestamp literal, and `valid_until` is bounded by the earliest literal later than the request time among the candidate rules. New vector V-154. Fixture V-143 now uses `request.now` | p01, vectors/ |
| 11 | Clarity | Decision API: check kinds `OPERATION` and `RECIPIENT_ELIGIBILITY` and the meaning of `principal_binding` defined (they were used by RES-009 but never defined) | p01 |
| 12 | Consistency | Eight requirements cited tests that were not scheduled for their phase. T-01 and T-19 now also apply in R1-B, T-03 in R1-B and R2, and the R1-B exit list gains T-01, T-03 and T-19. ENF-006 becomes a review item (REV) | p00, p02, p06 |
| 13 | Clean room | "Inspiration, not transcription" paragraph added under SRC-002, naming `docs/research/mechanism-matrix.md` as the SRC-002 record | p06 |
| 14 | Housekeeping | Version strings, review appendix section for 2.5, BUILD.txt, VALIDATION.txt, vectors README | various |

## Deliberately not changed (owner decisions still needed)

| Item | Why it was left |
|---|---|
| D-04 identity providers, D-05 HA design, D-06 label order, D-08 client key custody, D-09 recipient hierarchy, D-10 limits, D-11 name and license | Open decisions. They gate work (GATE-002), so the paper must not pre-empt them |
| DEC-001 says "versioned gRPC for internal services"; the code has a JSON facade only | Needs an owner ruling: JSON-only in R1, or gRPC required |
| Retention and legal hold | PUB-005 and REP-008 mention "retention" guards, but no requirement defines retention. Proposal: R1 has reference guards only and no time-based retention, until defined |
| Server-visible metadata | DAT-006 says "declared in the schema", but no single table lists the fields the server may read |
| Fixture operations (`decide_read`, `admit_read`, `emitted_bytes`) | The harness binding is unspecified. Only 10 of 115 cases have fixtures |
| The crypto wire profile and the native API contract | RCP-006/007 and CNT-009 say these are "frozen before qualification" but they do not exist. They are design deliverables, not errata |
| Provenance discrepancy | Part 6 and `engineering-notes.tex` say six upstream source excerpts (158 lines) were inspected; the repository's mechanism matrix says no upstream source file was opened. Implementation work follows the stricter reading |

## Corrections to the first review

Counts reported earlier used a pattern that skipped the nine `S3P-*` requirements. The
corrected figures: 260 requirement IDs in 2.2, 277 in 2.4 and 2.5; 99 of the 260 shared
requirements changed phase between 2.2 and 2.4. S3P phases did not change.

## Verification (31 October 2026)

- `python3 -I tools/check_spec.py`: PASS, 277 requirements, 22 test families, 115 cases (10 fixture-ready, 105 scenario-only), 85 mapping rows checked against the 1.3 source.
- `python3 -I tools/test_check_spec.py`: 15 tests, OK.
- Qualification mode still rejects absent evidence: 74 errors for `--qualify R1-B --features core`, 77 with `core,ha`.
- Standalone source compiled with Tectonic: 99 pages, 0 overfull and 0 underfull boxes, no unresolved references, all 277 requirement markers present in the PDF text. Pages 14 and 15 (policy format) were inspected visually. The remaining pages were not.
- Not verified: any implementation, cryptographic interoperability, or the code's conformance to 2.5. This revision supplies no execution evidence.
