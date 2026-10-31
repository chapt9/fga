package mcpsvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"fga/internal/signing"
)

// decisionRequest is a DecideBatch request (decisionsvc.Request) as the
// MCP role sends it: the user acting for themself, with the user's MCP
// token as evidence. The actor revision is 0: the role keeps no identity
// store, and the decision role binds the user's current revision (TB3).
type decisionRequest struct {
	RequestID   string      `json:"request_id"`
	Tenant      string      `json:"tenant"`
	Operation   string      `json:"operation"`
	OperationID string      `json:"operation_id"`
	Audience    string      `json:"audience"`
	Actor       actorRef    `json:"actor"`
	Evidence    string      `json:"evidence"`
	Checks      []toolCheck `json:"checks"`
}

type actorRef struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

type toolCheck struct {
	ID       string    `json:"id"`
	Role     string    `json:"role"`
	Action   string    `json:"action"`
	Resource toolAlias `json:"resource"`
}

type toolAlias struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// decisionResponse is the part of a DecideBatch response the role reads.
type decisionResponse struct {
	Outcome string `json:"outcome"`
	Results []struct {
		CheckID string `json:"check_id"`
		Effect  string `json:"effect"`
	} `json:"results"`
	Signed *struct {
		Payload string `json:"payload"`
		JWS     string `json:"jws"`
	} `json:"signed"`
}

// maxDecision bounds a decision response.
const maxDecision = 1 << 20

// decide asks the decision role for action on each MCP tool, as one batch
// of operation op addressed to the storage role.
func (s *Service) decide(ctx context.Context, c caller, op, action string, tools []string) (decisionResponse, error) {
	return s.decideFor(ctx, c, op, action, s.d.StorageAudience, tools)
}

// decideFor is decide addressed to audience.
func (s *Service) decideFor(ctx context.Context, c caller, op, action, audience string, tools []string) (decisionResponse, error) {
	req := decisionRequest{RequestID: newID(), Tenant: c.tenant, Operation: op, OperationID: newID(), Audience: audience,
		Actor: actorRef{ID: c.principal}, Evidence: c.token}
	for i, t := range tools {
		req.Checks = append(req.Checks, toolCheck{ID: fmt.Sprintf("tool-%d", i), Role: roleTool, Action: action,
			Resource: toolAlias{Namespace: toolNamespace, Name: t}})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return decisionResponse{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.d.Decision.URL+"/v1/decide-batch", bytes.NewReader(body))
	if err != nil {
		return decisionResponse{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := s.d.Decision.HTTP.Do(hreq)
	if err != nil {
		return decisionResponse{}, errUnavailable
	}
	defer resp.Body.Close()
	var out decisionResponse
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxDecision)).Decode(&out) != nil {
		return decisionResponse{}, errUnavailable
	}
	return out, nil
}

// authorize returns the decision that the caller may invoke tool, in the
// form the storage role accepts in the Fga-Decision header.
func (s *Service) authorize(ctx context.Context, c caller, tool string) (string, error) {
	return s.authorizeFor(ctx, c, tool, s.d.StorageAudience)
}

// authorizeFor is authorize presented to the role of audience: the MCP
// tools to the storage role, tools.list and tools.call to the tools role
// (TB3).
func (s *Service) authorizeFor(ctx context.Context, c caller, tool, audience string) (string, error) {
	resp, err := s.decideFor(ctx, c, opInvoke, "invoke", audience, []string{tool})
	if err != nil {
		return "", err
	}
	if resp.Outcome != "ALLOW" || resp.Signed == nil {
		return "", errNotAllowed
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	if err != nil {
		return "", errUnavailable
	}
	return signing.Signed{Payload: payload, JWS: resp.Signed.JWS}.Evidence(), nil
}

// discoverable returns the tools the caller may discover; on any failure,
// none (MCP-003).
func (s *Service) discoverable(ctx context.Context, c caller, tools []string) map[string]bool {
	out := map[string]bool{}
	resp, err := s.decide(ctx, c, opDiscover, "discover", tools)
	if err != nil {
		return out
	}
	for _, r := range resp.Results {
		var i int
		if _, err := fmt.Sscanf(r.CheckID, "tool-%d", &i); err == nil && i >= 0 && i < len(tools) && r.Effect == "ALLOW" {
			out[tools[i]] = true
		}
	}
	return out
}

// newID returns a random UUID (version 4).
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
