package release

import (
	"fga/internal/policy/engine"
	"fga/internal/registry"
)

// AudienceDecision is the audience of releases for the decision role.
const AudienceDecision = "fga-decision"

// R1Environment is the environment of an R1 decision role built from this
// source tree: the R1 resource types and operations, this evaluator build
// and the cost limit of DEC-009.
func R1Environment() Environment {
	types := registry.R1Types()
	return Environment{Schema: types, SchemaDigest: types.Digest(), OperationsDigest: registry.R1Operations(types).Digest(),
		Audience: AudienceDecision, MaxCostLimit: engine.DefaultOptions.CostLimit}
}
