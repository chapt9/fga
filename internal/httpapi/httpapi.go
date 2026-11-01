// Package httpapi holds what the storage and keys roles' HTTP APIs share
// (docs/design/native-api.md): bearer-token authentication of users (TB1,
// ADP-001), strict bounded JSON, redacted error codes and health probes.
package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"fga/internal/admission"
	"fga/internal/authn"
	"fga/internal/enforce"
	"fga/internal/registry"
	"fga/internal/signing"
	"fga/internal/strictjson"
)

// MaxJSONBody bounds JSON request bodies.
const MaxJSONBody = 1 << 20

// Error codes of the native API.
const (
	CodeInvalid      = "INVALID_REQUEST"
	CodeUnauth       = "UNAUTHENTICATED"
	CodeNotFound     = "NOT_FOUND"
	CodeConflict     = "CONFLICT"
	CodePrecondition = "PRECONDITION_FAILED"
	CodeTooLarge     = "TOO_LARGE"
	CodeUnavailable  = "UNAVAILABLE"
	CodeOverloaded   = "OVERLOADED"
	// CodeApprovalRequired answers 202: the operation needs an approval,
	// named in the body. CodeApprovalNotUsable answers 409: the presented
	// approval does not cover this operation.
	CodeApprovalRequired  = "APPROVAL_REQUIRED"
	CodeApprovalNotUsable = "APPROVAL_NOT_USABLE"
	// CodeEncryptionMode answers 409: the target is in the other
	// encryption mode than the route serves (ENC-002).
	CodeEncryptionMode = "ENCRYPTION_MODE"
)

// ApprovalHeader carries the approval a caller presents when repeating an
// operation that needed one (APR-001).
const ApprovalHeader = "Fga-Approval"

// TokenVerifier verifies access tokens; authn.Verifier implements it.
type TokenVerifier interface {
	Verify(token, audience string) (authn.Claims, error)
}

// WriteError writes a redacted error body.
func WriteError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// WriteJSON writes v as JSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Fail writes the redacted response for err: classify maps known service
// errors to a status and code; anything else is logged without protected
// detail and answered UNAVAILABLE.
func Fail(w http.ResponseWriter, r *http.Request, err error, classify func(error) (int, string, bool)) {
	if status, code, ok := classify(err); ok {
		WriteError(w, status, code)
		return
	}
	slog.Warn("request failed", "method", r.Method, "route", r.Pattern, "error", err.Error())
	WriteError(w, http.StatusServiceUnavailable, CodeUnavailable)
}

// Authenticate verifies the bearer token for audience and returns the
// caller (TB1, ADP-001).
func Authenticate(tokens TokenVerifier, audience string, r *http.Request) (enforce.Caller, bool) {
	token, ok := authn.Bearer(r.Header.Get("Authorization"))
	if !ok {
		return enforce.Caller{}, false
	}
	c, err := tokens.Verify(token, audience)
	if err != nil {
		return enforce.Caller{}, false
	}
	approval := r.Header.Get(ApprovalHeader)
	if len(approval) > 64 {
		return enforce.Caller{}, false
	}
	return enforce.Caller{Tenant: c.Tenant, Principal: c.Subject, Token: token, Approval: approval}, true
}

// Authed wraps h with bearer-token authentication for audience.
func Authed(tokens TokenVerifier, audience string, h func(http.ResponseWriter, *http.Request, enforce.Caller)) http.HandlerFunc {
	return AuthedVia(tokens, audience, nil, h)
}

// DecisionHeader carries a gateway's decision for the user's MCP tool
// call, in signing.Evidence form (TB3).
const DecisionHeader = "Fga-Decision"

// Gateway authenticates calls a gateway (the MCP role) makes for its users
// (TB3): the calling workload must be one of Adapters, and it presents its
// decision for the user's call, for Operation, addressed to this role
// (Verifier's audience), requested by that same workload, and still valid.
// The decision is for one MCP tool and stands for the user only on the
// routes that tool uses (registry.MCPToolRoutes).
// The caller is the decision's actor, acting for themself or, under a
// delegation the decision admitted, for its subject; the decision goes on
// to the decision role as the caller's evidence. A gateway's own claims
// about the user are never accepted (TRU-003, V-028).
type Gateway struct {
	AdapterOf func(*http.Request) (string, error)
	Adapters  map[string]bool
	Operation string
	Verifier  *signing.Verifier
}

func (g *Gateway) authenticate(r *http.Request) (enforce.Caller, bool) {
	signed, ok := signing.ParseEvidence(r.Header.Get(DecisionHeader))
	if g == nil || !ok {
		return enforce.Caller{}, false
	}
	adapter, err := g.AdapterOf(r)
	if err != nil || !g.Adapters[adapter] {
		return enforce.Caller{}, false
	}
	rec, err := g.Verifier.Check(signed)
	if err != nil || rec.Operation != g.Operation || rec.Adapter != adapter || (rec.Delegation == "") != (rec.Subject.ID == "") ||
		len(rec.Checks) != 1 || rec.Checks[0].ResourceType != "agent.tool" {
		return enforce.Caller{}, false
	}
	tool, ok := strings.CutPrefix(rec.Checks[0].ResourceID, registry.MCPToolNamespace+":")
	if !ok || !slices.Contains(registry.MCPToolRoutes[tool], r.Pattern) {
		return enforce.Caller{}, false
	}
	approval := r.Header.Get(ApprovalHeader)
	if len(approval) > 64 {
		return enforce.Caller{}, false
	}
	return enforce.Caller{Tenant: rec.Tenant, Principal: rec.Actor.ID, Subject: rec.Subject.ID, Delegation: rec.Delegation,
		Token: signed.Evidence(), Approval: approval}, true
}

// AuthedVia is Authed that also accepts gateway calls: a request without a
// bearer token that carries a gateway's decision is authenticated by gw.
func AuthedVia(tokens TokenVerifier, audience string, gw *Gateway, h func(http.ResponseWriter, *http.Request, enforce.Caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c enforce.Caller
		var ok bool
		if r.Header.Get("Authorization") == "" && r.Header.Get(DecisionHeader) != "" {
			c, ok = gw.authenticate(r)
		} else {
			c, ok = Authenticate(tokens, audience, r)
		}
		if !ok {
			WriteError(w, http.StatusUnauthorized, CodeUnauth)
			return
		}
		h(w, r, c)
	}
}

// MaxDocumentJSONBody bounds a document finalize request: up to 1,000
// units, each with its descriptor and up to 16 envelopes, plus the
// manifest.
const MaxDocumentJSONBody = 48 << 20

// DecodeJSON reads a bounded, strict JSON body into v.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return DecodeJSONLimit(w, r, v, MaxJSONBody)
}

// DecodeJSONLimit is DecodeJSON with another bound.
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		WriteError(w, http.StatusRequestEntityTooLarge, CodeTooLarge)
		return false
	}
	if err := strictjson.Decode(body, v); err != nil {
		WriteError(w, http.StatusBadRequest, CodeInvalid)
		return false
	}
	return true
}

// Health serves the liveness and readiness probes (REL-006).
func Health(mux *http.ServeMux, ready func() bool) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			WriteError(w, http.StatusServiceUnavailable, CodeUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// EnvelopeBody is an envelope on the wire.
type EnvelopeBody struct {
	Context    []byte `json:"context"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// Admitted wraps an authenticated handler with the tenant admission limits
// (AVL-006): a request over a bound gets 429 OVERLOADED at once. A stream
// holds its slot until the handler returns, that is until the body is
// sent or received.
func Admitted(l *admission.Limiter, stream bool, h func(http.ResponseWriter, *http.Request, enforce.Caller)) func(http.ResponseWriter, *http.Request, enforce.Caller) {
	return func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		release, ok := l.Acquire(c.Tenant, stream)
		if !ok {
			w.Header().Set("Retry-After", "1")
			WriteError(w, http.StatusTooManyRequests, CodeOverloaded)
			return
		}
		defer release()
		h(w, r, c)
	}
}
