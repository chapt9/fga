// Package httpapi holds what the storage and keys roles' HTTP APIs share
// (docs/design/native-api.md): bearer-token authentication of users (TB1,
// ADP-001), strict bounded JSON, redacted error codes and health probes.
package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"fga/internal/admission"
	"fga/internal/authn"
	"fga/internal/enforce"
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
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
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
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := Authenticate(tokens, audience, r)
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
