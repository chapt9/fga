# D-01: Policy evaluator

- **Status:** decided 30 October 2026; this record replaces the same day's first version.
- **Decision:** our own evaluator, written in Go, for our own policy format. The proposed format is in [policy-format-v1](../design/policy-format-v1.md).
- **Cerbos:** studied for ideas only. No Cerbos code, binary or container is used, in the product or in tests, and there is no compatibility promise with its policy format.
- **Why:** licensing and ownership. Ideas may be reused, upstream code may not (D-03).

## Withdrawn

The first version of this record chose the upstream Cerbos PDP as a sidecar. That came from reading "use Cerbos" as "run Cerbos". It is withdrawn, together with its open items: the Cerbos license record for distribution, the pin, the ceiling-baseline workaround and the oracle runs.

## Consequences for specification 2.1

- **Requirements to replace in 2.2:** POL-002 (compatible format), POL-012 (reference oracle), POL-014 (upstream scope modes), TEST-004 (oracle freezing), the Cerbos examples in Section 1.4.2 and the oracle marks on vectors V-001, V-004, V-005, V-008 and V-012.
- **Ceilings:** POL-007 is implemented natively. The ceiling set is evaluated by our engine, which can report "no ceiling rule matched" directly, so no generated allow baseline is needed.
- **Unchanged:** the evaluator contract (`internal/policy`) and the batch decision (`internal/decision`).
