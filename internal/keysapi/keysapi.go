// Package keysapi is the keys role's HTTP API (specification 2.5, KEY-002,
// RCP-002, TB1, TB3; docs/design/native-api.md): recipient enrollment and
// revocation, directory lookups, envelope publication and retirement, and
// the internal delivery endpoint only the storage workload may call.
package keysapi

import (
	"encoding/base64"
	"errors"
	"net/http"

	"fga/internal/admission"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/httpapi"
	"fga/internal/signing"
)

// classify maps keys-role errors to redacted responses.
func classify(err error) (int, string, bool) {
	switch {
	case errors.Is(err, envelope.ErrNotFound):
		return http.StatusNotFound, httpapi.CodeNotFound, true
	case errors.Is(err, envelope.ErrInvalid):
		return http.StatusBadRequest, httpapi.CodeInvalid, true
	case errors.Is(err, envelope.ErrConflict):
		return http.StatusConflict, httpapi.CodeConflict, true
	case errors.Is(err, envelope.ErrDecision):
		return http.StatusForbidden, httpapi.CodeInvalid, true
	case errors.Is(err, enforce.ErrApprovalNotUsable):
		return http.StatusConflict, httpapi.CodeApprovalNotUsable, true
	}
	return 0, "", false
}

// fail writes err; an operation that needs an approval answers 202 with
// the pending approval's ID (APR-001), as the storage API does.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	var need *enforce.ApprovalRequired
	if errors.As(err, &need) {
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{"status": httpapi.CodeApprovalRequired, "approval_id": need.ID})
		return
	}
	httpapi.Fail(w, r, err, classify)
}

// wire types of the keys API.
type (
	enrollBody struct {
		PublicKey []byte `json:"public_key"`
	}
	proofBody struct {
		ChallengeID string `json:"challenge_id"`
		Proof       string `json:"proof"`
	}
	shareBody struct {
		Bucket   string               `json:"bucket"`
		Key      string               `json:"key"`
		Version  string               `json:"version"`
		Envelope httpapi.EnvelopeBody `json:"envelope"`
	}
	// DeliverBody is the storage role's internal delivery request (TB3).
	DeliverBody struct {
		Payload    []byte `json:"payload"`
		JWS        string `json:"jws"`
		EnvelopeID string `json:"envelope_id"`
		// Extra holds further decisions the release needs, such as the
		// complete-content decisions of an original file.
		Extra []SignedBody `json:"extra,omitempty"`
	}
	// SignedBody is one signed decision.
	SignedBody struct {
		Payload []byte `json:"payload"`
		JWS     string `json:"jws"`
	}
	// DeliveredBody is the internal delivery response.
	DeliveredBody struct {
		EnvelopeID       string               `json:"envelope_id"`
		Envelope         httpapi.EnvelopeBody `json:"envelope"`
		Receipt          []byte               `json:"receipt"`
		ReceiptSignature string               `json:"receipt_signature"`
	}
)

// Keys returns the keys role's handler. adapterOf identifies the workload
// calling the internal delivery endpoint, which only storage may call
// (TB3); its decision is verified as well (TRU-005).
func Keys(svc *envelope.Service, tokens httpapi.TokenVerifier, adapterOf func(*http.Request) (string, error), storageAdapter string, ready func() bool,
	limiter *admission.Limiter) http.Handler {
	mux := http.NewServeMux()
	httpapi.Health(mux, ready)
	auth := func(h func(http.ResponseWriter, *http.Request, enforce.Caller)) http.HandlerFunc {
		return httpapi.Authed(tokens, enforce.KeysAudience, httpapi.Admitted(limiter, false, h))
	}
	mux.HandleFunc("POST /v1/recipients", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var b enrollBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		ch, err := svc.EnrollRecipient(r.Context(), c, b.PublicKey)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, ch)
	}))
	mux.HandleFunc("POST /v1/recipients/{fp}/activate", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var b proofBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		proof, err := base64.StdEncoding.DecodeString(b.Proof)
		if err != nil {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		rec, err := svc.ActivateRecipient(r.Context(), c, r.PathValue("fp"), b.ChallengeID, proof)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("GET /v1/recipients/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		rec, err := svc.Recipient(r.Context(), c, r.PathValue("fp"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("DELETE /v1/recipients/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		if err := svc.RevokeRecipient(r.Context(), c, r.PathValue("fp")); err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"fingerprint": r.PathValue("fp"), "status": "REVOKED"})
	}))
	mux.HandleFunc("GET /v1/signing-keys/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		rec, err := svc.SigningKey(r.Context(), c, r.PathValue("fp"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("POST /v1/envelopes", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		var b shareBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		ref, err := svc.Publish(r.Context(), c, b.Bucket, b.Key, b.Version,
			envelope.EnvelopeIn{Context: b.Envelope.Context, Ciphertext: b.Envelope.Ciphertext, Signature: b.Envelope.Signature})
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, ref)
	}))
	mux.HandleFunc("DELETE /v1/envelopes/{id}", auth(func(w http.ResponseWriter, r *http.Request, c enforce.Caller) {
		ref, err := svc.Retire(r.Context(), c, r.PathValue("id"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, ref)
	}))
	mux.HandleFunc("POST /internal/v1/deliver", func(w http.ResponseWriter, r *http.Request) {
		if a, err := adapterOf(r); err != nil || a != storageAdapter {
			httpapi.WriteError(w, http.StatusUnauthorized, httpapi.CodeUnauth)
			return
		}
		var b DeliverBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		var extra []signing.Signed
		for _, x := range b.Extra {
			extra = append(extra, signing.Signed{Payload: x.Payload, JWS: x.JWS})
		}
		d, err := svc.Deliver(r.Context(), signingSigned(b), b.EnvelopeID, extra...)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, DeliveredBody{EnvelopeID: d.EnvelopeID, Envelope: httpapi.EnvelopeBody{Context: d.Context,
			Ciphertext: d.Ciphertext, Signature: d.Signature}, Receipt: d.Receipt, ReceiptSignature: d.ReceiptSignature})
	})
	return mux
}

func signingSigned(b DeliverBody) signing.Signed {
	return signing.Signed{Payload: b.Payload, JWS: b.JWS}
}
