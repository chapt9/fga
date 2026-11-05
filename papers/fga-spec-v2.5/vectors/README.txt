Specification 2.5 acceptance inputs

The catalogue separates scenario_only obligations from fixture_ready cases.
A fixture is concrete input for an implementation test harness, not evidence that
the implementation passed. Schedule entries run in order; must_complete_before
is a required synchronization relationship. Assertions name observable outcomes
or protected state. Operation names describe semantics, not mandatory API paths.
The harness must bind these operations to its reviewed public/internal boundary
and must not infer missing policy, identity or authority facts. Required setup
success is asserted before a regression's adversarial transition is exercised.

Run structural validation:
  python3 -I tools/check_spec.py
Run checker regressions:
  python3 -I tools/test_check_spec.py
Require release evidence for a feature configuration, supplying the SHA-256 of
its reviewed immutable release manifest as RELEASE_MANIFEST_SHA256:
  python3 -I tools/check_spec.py --qualify R1-C --features core \
    --release-manifest-sha256 "$RELEASE_MANIFEST_SHA256"

Qualification intentionally fails for this document-only revision: scenario
cases still need concrete fixtures and execution-evidence.json records no
implementation runs. A passing structural check is not a release
gate pass. Missing or malformed release-manifest selection also rejects.

Execution evidence uses schema fga.evidence/v2. Every case_runs and test_runs
entry binds release_manifest_sha256, the selected phase, the complete enabled
features, result PASS and a run_record reference. A case additionally binds
case_id and fixture_sha256.
A family additionally binds test_id. All applicable records must match the
selected manifest and configuration; records from different builds or feature
configurations cannot be combined into a passing release. Duplicate records
reject. The older implementation_digest field and fga.evidence/v1 schema do not
satisfy this contract.

The immutable release manifest identifies the source/build revision, each role's
binary digest, harness revision and security-relevant configuration, including
its policy bundle digest. It can therefore cover separately built
roles without requiring every role to be the same binary. The checker compares
manifest hashes; independent release review verifies the referenced manifest,
run records, provenance and correspondence to the candidate deployment. These
are reviewable evidence references, not self-authenticating attestations.

Family prerequisites are declared in test-families.json using
fga.test-families/v1. Every defined family has one feature declaration; its phases
remain defined by the paper's test matrix. T-07 requires s3 and T-17 requires
replication. A disabled optional family requires no run. Enabling its feature
requires passing evidence in addition to the applicable individual cases; the
remaining shared families continue to cover the core obligations.
