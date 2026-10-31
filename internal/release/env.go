package release

import (
	"fga/internal/policy/engine"
	"fga/internal/registry"
)

// AudienceDecision is the audience of releases for the decision role.
const AudienceDecision = "fga-decision"

// CoreEnvironment is the environment of a decision role built from this
// source tree: the core resource types and operations (R1 and the MCP
// service's tools), this evaluator build and the cost limit of DEC-009.
func CoreEnvironment() Environment {
	types := registry.CoreTypes()
	return Environment{Schema: types, SchemaDigest: types.Digest(), OperationsDigest: registry.CoreOperations(types).Digest(),
		Audience: AudienceDecision, MaxCostLimit: engine.DefaultOptions.CostLimit}
}
