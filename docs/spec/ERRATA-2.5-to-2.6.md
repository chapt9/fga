# Errata: specification 2.5 to 2.6

Date: 31 October 2026. Version 2.6 is 2.5 with the changes below, made to record the
owner's decision D-12 (`docs/decisions/D-12-encryption-modes.md` in the implementation
repository). Changing normative text changes the specification version (TEST-003), so 2.5
was not edited in place; it stays in git history.

## Why 2.5 needed changing

Specification 2.5 makes client-side encryption the only payload custody profile
(CRY-001, BKD-005): every reader needs client key custody, and no platform role may
decrypt. The owner decided on 31 October 2026 that client-side encryption is not
mandatory:

- Every payload is still encrypted; there is no plaintext mode.
- A bucket is in **server mode** (the default) or **client mode** (opt-in), and policy can
  see the mode.
- In server mode the storage role encrypts under per-version data keys. They are wrapped
  by tenant KEKs held only by the keys role and released only under fresh signed
  decisions.
- Server-encrypted content is shared by policy: the server decrypts for an authorized
  reader. Share grants let a user name a reader where a rule honors them.
- Client mode keeps the 2.5 custody model unchanged.

## Requirements added (12; 277 before, 289 after)

| Requirements | Subject | Where |
|---|---|---|
| ENC-001, ENC-002, ENC-003 | Bucket mode, visible to policy; versions keep their mode; no cross-mode fallback; documentation and upgrade (existing buckets become client mode) | p04 "Encryption modes" |
| SSE-001 to SSE-006 | Per-version data keys and AAD; tenant KEKs only in the keys role; wrap and release only under exact decisions in the fence, with audit; key lifetime; stream integrity and retries; backup, restore and key destruction | p04 "Server mode: platform-held keys" |
| SHR-001, SHR-002, SHR-003 | Recording and removing share grants; grants visible to policy as `resource.attributes.shared_with` and effective only where a rule honors them; per-mode effect | p03 "Share grants" |

New test families T-23 (encryption modes and server-side keys) and T-24 (share grants), both
with feature `core`. New scenario-only cases V-155 to V-178. New guarantee G-09,
non-guarantee N-09, threats TH-28 and TH-29, and decision rows D-12 (decided) and D-13
(server key custody, open; gates production payloads in server mode).

## Requirements changed

The text either becomes the client-mode rule or names both modes. Phases and tests are
unchanged except MCP-005, which gains T-23.

| Area | Requirements |
|---|---|
| Custody (p04) | CRY-001, CRY-002, CRY-004, CRY-005, CRY-007, CRY-008, CRY-009, KEY-001, KEY-010, KEY-011, KEY-013, KEY-014, KEY-015, KEY-016, KEY-017, RCP-010 |
| Content (p03) | CNT-001, PUB-002, BKD-005, DOC-001, DOC-002, DOC-003, DOC-004, DOC-006, DOC-007, LAB-005, DSC-001, DSC-002, DSC-003, DSC-004, DSC-006, DRV-001, DRV-002, DRV-004, DRV-005, DRV-006, SIZ-001, SIZ-002 |
| Authority and audit (p01) | DAT-006, AUD-004 |
| MCP (p02) | MCP-005; wording in MCP-003, MCP-008, FLW-002, FLW-003, FLW-007 and the flow-control introduction |
| S3, R3 (p05) | S3P-001, S3P-002, S3P-007 and the profile paragraph |
| Engineering (p06) | GATE-004; wording in MOD-001, MOD-002, MOD-004, PERF-001, GATE-002; test rows T-09, T-10, T-11, T-12, T-18, T-20, T-22; the role table and the MinIO encryption row of the mechanism table (now Adapt with server custody of our own shape) |

Small wording changes inside requirements whose substance is unchanged: CNT-003 (server-mode original read), CNT-008 (emitted plaintext), PUB-007 (checksums in either mode), BKD-002 (ciphertext from either mode), SRH-001 (search after an authorized read).

## Narrative changes

- **Title page and Part 0.** Central principle, version and structure lines, product
  statement, release table (T-23 and T-24 in the R1-B, R1-C and R2 exit lists), guarantees
  G-07 and G-09, non-guarantees N-02, N-03, N-04, N-07 and N-09.
- **Threat model.** Assets A1 and A2, adversary E10, TH-13, TH-28 and TH-29.
- **Architecture.** Architecture text and figure, role table, decisions D-09, D-12 and D-13.
- **Part 4.** Retitled "Payload encryption, key custody and authorized delivery". It opens
  with both modes; the client-custody subsections are marked client mode. The key-event
  table gains KEK rotation and KEK or role compromise. The cryptographic-choices table
  gains the server-mode row.
- **Part 3.** Introduction, `ContentService` sketch, native API paragraph and operations
  table (a share-grants row), document, disclosure, derived-output and MCP introductions,
  MCP table and sizing table.
- **Appendices.** The review appendix gains a 2.6 section. The scenarios appendix now
  says which mode each scenario uses and adds a server-mode sharing scenario.
- **Implementation repository.** The mechanism matrix (`docs/research/mechanism-matrix.md`)
  rows on server-side encryption, rewrapping and KMS were changed to match, as the
  adoption rule in Part 6 requires.

## Deliberately not changed

| Item | Why |
|---|---|
| D-06 label order | Decided in the implementation repository, but the paper still lists it as open. That is outside D-12; a separate revision can record it |
| `crypto-format-profile.tex` byte layout | It covers the client-mode wire format, which is unchanged. The server-mode AAD encoding and wrapped-key record are specified with the implementation (stretches S2 and S3 of D-12) and added to this companion then |
| Server-side text search, server classifiers | Server mode could support them, but D-12 does not decide them; SRH-001 to SRH-003 and LAB-002 are unchanged |
| Executor access to server-mode plaintext (R2) | Not decided; FLW-002 keeps the executor without any data key, and an executor reads only as an ordinary authorized client |
| Fixtures | The new cases are scenario-only; none is fixture-ready yet |

## Verification (31 October 2026)

See `VALIDATION.txt`.
