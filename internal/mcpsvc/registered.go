package mcpsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisteredPrefix names a registered tool of the tools role among the MCP
// tools: "tool.<id>" (R2 executor, stretch E2).
const RegisteredPrefix = "tool."

// approvalHeader carries an approval to the tools role
// (httpapi.ApprovalHeader).
const approvalHeader = "Fga-Approval"

// registeredTool is a tool as the tools role lists it.
type registeredTool struct {
	Name        string         `json:"name"`
	Version     int            `json:"version"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// registeredTools returns the registered tools the caller may discover,
// as MCP tools. The listing is the tools role's, which decides discover on
// each for the user; the MCP role asks it only with a decision that the
// user may invoke tools.list (TB3). Any failure shows none.
func (s *Service) registeredTools(ctx context.Context, c caller) []*mcp.Tool {
	if s.d.Tools.URL == "" {
		return nil
	}
	ev, err := s.authorizeFor(ctx, c, ToolToolsList, s.d.ToolsAudience)
	if err != nil {
		return nil
	}
	var list struct {
		Tools []registeredTool `json:"tools"`
	}
	resp, err := s.toolsCall(ctx, http.MethodGet, ev, "", "/v1/tools", nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxListing)).Decode(&list) != nil {
		return nil
	}
	out := make([]*mcp.Tool, 0, len(list.Tools))
	for _, t := range list.Tools {
		out = append(out, &mcp.Tool{Name: RegisteredPrefix + t.Name, Description: t.Description +
			" A registered tool: it acts on an external system for you, decided per call; a call may need an approval.",
			InputSchema: callSchema(t)})
	}
	return out
}

// callSchema is a registered tool's MCP input: its arguments, its version
// (which binds the call to the reviewed record), an idempotency key, and an
// optional approval and note.
func callSchema(t registeredTool) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"arguments", "version", "idempotency_key"},
		"properties": map[string]any{
			"arguments":       t.InputSchema,
			"version":         map[string]any{"type": "integer", "const": t.Version},
			"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"approval":        map[string]any{"type": "string", "description": "the approval given for this exact call"},
			"note":            map[string]any{"type": "string", "maxLength": 500, "description": "shown to an approver; not verified"},
		}}
}

// callRegistered calls a registered tool for the caller: the decision
// that the user may call registered tools (tools.call), addressed to the
// tools role, and the call there, which the tools role decides for the
// call's exact plan and carries out (AGT-003). The MCP role's decision
// sees no plan, so it never decides the tool itself. An approval the call
// needs is an answer, not an error.
func (s *Service) callRegistered(ctx context.Context, c caller, name string, raw json.RawMessage) *mcp.CallToolResult {
	toolErr := func(err error) *mcp.CallToolResult {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
	}
	if s.d.Tools.URL == "" {
		return toolErr(errNotFound)
	}
	var in struct {
		Arguments      json.RawMessage `json:"arguments"`
		Version        int             `json:"version"`
		IdempotencyKey string          `json:"idempotency_key"`
		Approval       string          `json:"approval"`
		Note           string          `json:"note"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(in.Arguments) == 0 {
		return toolErr(errInvalid)
	}
	id := strings.TrimPrefix(name, RegisteredPrefix)
	ev, err := s.authorizeFor(ctx, c, ToolToolsCall, s.d.ToolsAudience)
	if err != nil {
		return toolErr(err)
	}
	resp, err := s.toolsCall(ctx, http.MethodPost, ev, in.Approval, "/v1/invocations", map[string]any{"tool": id, "version": in.Version,
		"arguments": in.Arguments, "idempotency_key": in.IdempotencyKey, "note": in.Note})
	if err != nil {
		return toolErr(errUnavailable)
	}
	defer resp.Body.Close()
	var out map[string]any
	decoded := json.NewDecoder(io.LimitReader(resp.Body, maxListing)).Decode(&out) == nil
	field := func(name string) string {
		v, _ := out[name].(string)
		return v
	}
	// A success is reported only from an answer that says what happened:
	// an unreadable one is the tools role's failure, not a result (review
	// v4 F14).
	switch resp.StatusCode {
	case http.StatusOK:
		if !decoded || field("invocation_id") == "" || field("state") == "" {
			return toolErr(errUnavailable)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("invocation %s: %s", field("invocation_id"), field("state"))}},
			StructuredContent: out}
	case http.StatusAccepted:
		if !decoded || field("approval_id") == "" {
			return toolErr(errUnavailable)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
			"approval required: call again with approval %s once it is given", field("approval_id"))}}, StructuredContent: out}
	case http.StatusNotFound:
		return toolErr(errNotFound)
	case http.StatusBadRequest:
		return toolErr(errInvalid)
	case http.StatusConflict:
		return toolErr(fmt.Errorf("refused: %v", out["error"]))
	case http.StatusTooManyRequests:
		return toolErr(errOverloaded)
	}
	return toolErr(errUnavailable)
}

// toolsCall calls the tools role as the MCP workload with the user's
// decision (TB3), and an approval if given.
func (s *Service) toolsCall(ctx context.Context, method, evidence, approval, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.d.Tools.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set(decisionHeader, evidence)
	if approval != "" {
		req.Header.Set(approvalHeader, approval)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.d.Tools.HTTP.Do(req)
	if err != nil {
		return nil, errors.Join(errUnavailable, err)
	}
	return resp, nil
}
