# Fixture binding (TEST-003)

Status: design record, 31 October 2026.

Specification fixtures (`docs/spec/vectors/fixtures/*.json`, schema `fga.fixture/v1`) name semantic operations, not API paths. The harness `internal/conformance` binds each operation name to one function at our public or internal boundary, runs the schedule in order and evaluates the assertions. It never invents a fact that the fixture does not state; a fixture whose facts are insufficient for our boundary is reported as `UNBOUND` with the missing fact, not run with a guess.

| Fixture operation | Bound to | Notes |
|---|---|---|
| `evaluate` | `decision.Decider.DecideBatch` over a snapshot compiled from the fixture's policies | V-001 |
| `issue_signed_decision`, `verify_transmitted_grant`, `alter_transmitted_grant` | `decisionsvc.Service.Decide`, `signing.Verifier.Verify` on the transmitted bytes | V-141 |
| `prepare_publish`, `revoke_principal`, `publish` | `content.Service` begin and finalize; `catalog` identity disable | V-142, needs PostgreSQL |
| `decide_read`, `admit_read` | Decision for `storage.object.read` and the fence's read admission at the fixture's `now` | V-143 |
| `delete_key`, `delete_version`, `read_version` | `content.Service` | V-146, needs PostgreSQL |
| `retire_content_signing_key`, `mark_content_signer_compromised`, `verify_historical_content` | `envelope` signing-key registry and `cryptowire` verification | V-149 |
| `propose_label` | `content.Service.ProposeLabel` on a storage object standing in for the unit until document units exist; `collection_floor` is the bucket's default label, `access_revision` our metadata revision | V-147, needs PostgreSQL |
| `admit_recipient_envelope`, `take_catalog_backup`, `revoke_recipient_and_record_recovery`, `restore_backup`, `reconcile_security_journal`, `get_recipient_envelope` | `envelope.Service`, `cmd/fga-admin` backup/restore/reconcile functions | V-144, needs PostgreSQL |

Fixture-only facts that our model expresses differently are mapped explicitly in the harness, one line per mapping, for example a fixture `access_revision` to our `metadata_revision`, and a fixture version label (`v1`) to a generated UUID kept in a name table.

Assertion paths address the result of a named input (`decide.outcome`) or a named state probe (`object.current_version`, `emitted_bytes`, `envelopes_delivered`) that the harness implements by reading the catalog or counting bytes.

## Evidence

A harness run prints one line per case: case ID, fixture SHA-256, result. It does not write `vectors/execution-evidence.json`: that file binds a reviewed immutable release manifest (GATE-001), and no release manifest exists yet. Passing harness runs are therefore development evidence only, not qualification.
