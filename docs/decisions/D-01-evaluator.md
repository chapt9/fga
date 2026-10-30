# D-01: Policy evaluator

- **Status:** decided, 30 October 2026
- **Decision:** the open-source Cerbos PDP is the R1 business-policy evaluator. It runs as a pinned sidecar behind the evaluator contract (`internal/policy`, POL-001). Platform ceilings, signed decisions, the resource registry and enforcement stay in project code.
- **Not chosen:** a native Go evaluator over cel-go. It remains the fallback if the open items below cannot be met.
- **Scope:** the open-source policy decision point only. Hosted or commercial Cerbos components are out of scope.

## Open before the Cerbos adapter is written

1. **License record (D-03, SRC-004).** Record the license of the pinned Cerbos release and of what ships with it, and confirm the sidecar distribution model. A reviewer reported Apache-2.0 for the pinned source; this has not been verified here.
2. **Pin.** Exact release, checksum and image or binary digest, recorded at dependency admission (LIB-002, LIB-003).
3. **Epoch binding (REL-001 to REL-004).** The PDP must serve exactly the activated bundle digest. Candidate approach: an immutable policy directory per digest, and a readiness check that refuses decisions until the PDP reports that bundle.
4. **Ceiling set mapping (POL-007).** Cerbos denies an action that no rule allows, so a deny-only policy set evaluated on its own would deny everything. Proposed mapping:
   - ceiling policies use a reserved policy version;
   - each carries a platform-generated wildcard allow baseline plus authored deny rules;
   - a ceiling ALLOW therefore means "no objection";
   - principal policies are rejected in that version;
   - a resource kind with no ceiling policy is denied (fail closed).

   This contradicts the current text of POL-007 ("rejects an allow rule"), which needs an amendment that permits the generated baseline only.
5. **Production profile (POL-005).** Set strict evaluation and schema rejection in the PDP configuration, and reject a configuration that differs.
6. **Oracle vectors (TEST-004).** With the upstream engine in production, the oracle-marked vectors confirm configuration and mapping rather than a reimplementation. They still need to be run before being frozen.
