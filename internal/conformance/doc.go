// Package conformance runs the specification's fixture-ready acceptance
// cases (docs/spec/vectors/fixtures) against this implementation, as
// designed in docs/design/fixture-binding.md (TEST-003). Each case binds
// the fixture's semantic operations to our boundary, runs its schedule in
// order and evaluates its own assertions. A case whose facts cannot be
// expressed by this implementation is reported UNBOUND with the reason,
// never run with invented facts.
//
// Passing runs are development evidence only: no reviewed release manifest
// exists, so nothing here is written to execution-evidence.json and nothing
// here is qualification (GATE-001).
package conformance
