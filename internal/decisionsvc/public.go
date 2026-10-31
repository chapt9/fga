package decisionsvc

import "fga/internal/decision"

// PublicResponse is the projection of a decision that a caller outside the
// enforcement audience may see (DEC-010). An absent target and a target the
// policy denies get the same representation; only request-shape errors and
// dependency failures stay distinguishable, because they reveal nothing
// about a target. It carries no signature, results, policy outputs or
// diagnostics, so it can never authorize execution.
type PublicResponse struct {
	DecisionID string `json:"decision_id"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
}

// Public reasons.
const (
	PublicDenied      = "DENIED"
	PublicInvalid     = "INVALID_REQUEST"
	PublicUnavailable = "UNAVAILABLE"
)

// requestShape are the denial reasons that depend only on the request's
// own form, never on the state of a target.
var requestShape = map[string]bool{
	string(ReasonInvalidRequest):            true,
	string(ReasonUnknownOperation):          true,
	string(ReasonOperationMismatch):         true,
	string(decision.ReasonEmptyBatch):       true,
	string(decision.ReasonDuplicateCheckID): true,
	string(decision.ReasonMalformedCheck):   true,
}

// Public projects r. An ALLOW stays ALLOW so that the caller learns its
// own permission; every other denial becomes DENY DENIED, and every
// service failure ERROR UNAVAILABLE.
func (r Response) Public() PublicResponse {
	p := PublicResponse{DecisionID: r.DecisionID}
	switch r.Outcome {
	case decision.OutcomeAllow.String():
		p.Outcome = r.Outcome
	case decision.OutcomeError.String():
		p.Outcome, p.Reason = r.Outcome, PublicUnavailable
	default:
		p.Outcome, p.Reason = decision.OutcomeDeny.String(), PublicDenied
		if requestShape[r.Reason] {
			p.Reason = PublicInvalid
		}
	}
	return p
}
