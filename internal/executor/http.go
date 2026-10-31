package executor

import (
	"errors"
	"net/http"

	"fga/internal/admission"
	"fga/internal/enforce"
	"fga/internal/httpapi"
	"fga/internal/invocation"
)

// CodeBudget answers 409 when the budget cannot cover a call (APR-004).
const CodeBudget = "BUDGET"

// Handler serves the tools role's API, authenticated by users' tokens for
// Audience, or by the MCP role's gateway decision when gw is set (TB3):
//
//	GET  /v1/tools                        the tools the caller may discover, with input schemas
//	POST /v1/invocations                  {tool, version, arguments, idempotency_key, note}
//	GET  /v1/invocations/{id}
//	POST /v1/invocations/{id}/resolve     {outcome, evidence}
//	POST /v1/invocations/{id}/write-off   {note}
//
// A call that needs an approval answers 202 with the approval's ID;
// repeating it with that ID in the Fga-Approval header, once given,
// carries it out (APR-001).
func Handler(svc *Service, tokens httpapi.TokenVerifier, ready func() bool, limiter *admission.Limiter, gw *httpapi.Gateway) http.Handler {
	mux := http.NewServeMux()
	auth := func(h func(http.ResponseWriter, *http.Request, enforce.Caller)) http.HandlerFunc {
		return httpapi.AuthedVia(tokens, Audience, gw, httpapi.Admitted(limiter, false, h))
	}
	reply := func(w http.ResponseWriter, r *http.Request, res Result, err error) {
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, res)
	}
	mux.HandleFunc("POST /v1/invocations", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var req Request
		if !httpapi.DecodeJSON(w, r, &req) {
			return
		}
		res, err := svc.Invoke(r.Context(), c, req)
		reply(w, r, res, err)
	}))
	mux.HandleFunc("GET /v1/tools", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		list, err := svc.List(r.Context(), c)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"tools": list})
	}))
	mux.HandleFunc("GET /v1/invocations/{id}", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		res, err := svc.Get(r.Context(), c, r.PathValue("id"))
		reply(w, r, res, err)
	}))
	mux.HandleFunc("POST /v1/invocations/{id}/resolve", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var body struct {
			Outcome  string `json:"outcome"`
			Evidence string `json:"evidence"`
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		res, err := svc.Resolve(r.Context(), c, r.PathValue("id"), invocation.State(body.Outcome), body.Evidence)
		reply(w, r, res, err)
	}))
	mux.HandleFunc("POST /v1/invocations/{id}/write-off", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var body struct {
			Note string `json:"note"`
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		res, err := svc.WriteOff(r.Context(), c, r.PathValue("id"), body.Note)
		reply(w, r, res, err)
	}))
	httpapi.Health(mux, ready)
	return mux
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	var need *enforce.ApprovalRequired
	if errors.As(err, &need) {
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{"status": httpapi.CodeApprovalRequired, "approval_id": need.ID})
		return
	}
	httpapi.Fail(w, r, err, func(err error) (int, string, bool) {
		switch {
		case errors.Is(err, ErrNotFound):
			return http.StatusNotFound, httpapi.CodeNotFound, true
		case errors.Is(err, enforce.ErrApprovalNotUsable):
			return http.StatusConflict, httpapi.CodeApprovalNotUsable, true
		case errors.Is(err, ErrInvalid):
			return http.StatusBadRequest, httpapi.CodeInvalid, true
		case errors.Is(err, ErrBudget):
			return http.StatusConflict, CodeBudget, true
		case errors.Is(err, ErrConflict):
			return http.StatusConflict, httpapi.CodeConflict, true
		}
		return 0, "", false
	})
}
