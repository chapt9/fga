// Package nativeapi is the storage role's native HTTP API (specification
// 2.5, CNT-009, ADP-001, TB1; docs/design/native-api.md). It authenticates
// the caller, validates the request and delegates to the content service;
// it never decides access itself (CNT-002). Errors are redacted to a code.
package nativeapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"fga/internal/admission"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/httpapi"
)

// classify maps content service errors to redacted responses. Absent and
// denied targets are both NOT_FOUND (CNT-004, DEC-010).
func classify(err error) (int, string, bool) {
	switch {
	case errors.Is(err, content.ErrNotFound):
		return http.StatusNotFound, httpapi.CodeNotFound, true
	case errors.Is(err, content.ErrApprovalNotUsable):
		return http.StatusConflict, httpapi.CodeApprovalNotUsable, true
	case errors.Is(err, content.ErrInvalid):
		return http.StatusBadRequest, httpapi.CodeInvalid, true
	case errors.Is(err, content.ErrPrecondition):
		return http.StatusPreconditionFailed, httpapi.CodePrecondition, true
	case errors.Is(err, content.ErrConflict):
		return http.StatusConflict, httpapi.CodeConflict, true
	case errors.Is(err, content.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, httpapi.CodeTooLarge, true
	}
	return 0, "", false
}

// fail writes err. An operation that needs an approval answers 202 with
// the pending approval's ID; repeating it with that ID in the Fga-Approval
// header once the approval is given performs it (APR-001).
func fail(w http.ResponseWriter, r *http.Request, err error) {
	var need *content.ApprovalRequired
	if errors.As(err, &need) {
		httpapi.WriteJSON(w, http.StatusAccepted, approvalRequiredBody{Status: httpapi.CodeApprovalRequired, ApprovalID: need.ID})
		return
	}
	httpapi.Fail(w, r, err, classify)
}

// wire types of the storage API.
type (
	beginBody struct {
		Key            string `json:"key"`
		IdempotencyKey string `json:"idempotency_key"`
		IfMatch        string `json:"if_match,omitempty"`
		IfNoneMatch    string `json:"if_none_match,omitempty"`
		Label          string `json:"label,omitempty"`
	}
	approvalRequiredBody struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
	}
	labelBody struct {
		Label string `json:"label"`
	}
	proposalBody struct {
		Label      string `json:"label"`
		Classifier string `json:"classifier"`
	}
	approvalDecisionBody struct {
		Decision string `json:"decision"`
	}
	approvalsBody struct {
		Approvals []content.ApprovalView `json:"approvals"`
		Next      string                 `json:"next,omitempty"`
	}
	intentBody struct {
		IntentID            string `json:"intent_id"`
		TenantID            string `json:"tenant_id"`
		ObjectID            string `json:"object_id"`
		LogicalVersionID    string `json:"logical_version_id"`
		CryptoVersionID     string `json:"crypto_version_id"`
		BlobID              string `json:"blob_id"`
		AttemptID           string `json:"attempt_id"`
		Suite               uint16 `json:"suite"`
		Format              uint16 `json:"format"`
		MaxCiphertextLength int64  `json:"max_ciphertext_length"`
		ExpiresAt           string `json:"expires_at"`
	}
	// httpapi.EnvelopeBody is an envelope on the wire.
	EnvelopeBody struct {
		Context    []byte `json:"context"`
		Ciphertext []byte `json:"ciphertext"`
		Signature  string `json:"signature"`
	}
	finalizeBody struct {
		Descriptor          []byte                 `json:"descriptor"`
		DescriptorSignature string                 `json:"descriptor_signature"`
		Envelopes           []httpapi.EnvelopeBody `json:"envelopes"`
	}
	receiptBody struct {
		BlobID           string `json:"blob_id"`
		CiphertextLength int64  `json:"ciphertext_length"`
		CiphertextSHA256 string `json:"ciphertext_sha256"`
	}
	packageBody struct {
		Version             content.VersionInfo  `json:"version"`
		Descriptor          []byte               `json:"descriptor"`
		DescriptorSignature string               `json:"descriptor_signature"`
		EnvelopeID          string               `json:"envelope_id"`
		Envelope            httpapi.EnvelopeBody `json:"envelope"`
		Receipt             []byte               `json:"receipt"`
		ReceiptSignature    string               `json:"receipt_signature"`
	}
)

// Storage returns the storage role's handler.
func Storage(svc *content.Service, tokens httpapi.TokenVerifier, ready func() bool, limiter *admission.Limiter) http.Handler {
	mux := http.NewServeMux()
	httpapi.Health(mux, ready)
	auth := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return httpapi.Authed(tokens, content.Audience, httpapi.Admitted(limiter, false, h))
	}
	stream := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return httpapi.Authed(tokens, content.Audience, httpapi.Admitted(limiter, true, h))
	}
	mux.HandleFunc("POST /v1/buckets/{bucket}/uploads", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b beginBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		if b.IfNoneMatch != "" && b.IfNoneMatch != "*" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		in, err := svc.Begin(r.Context(), c, content.BeginRequest{Bucket: r.PathValue("bucket"), Key: b.Key,
			IdempotencyKey: b.IdempotencyKey, IfMatch: b.IfMatch, IfNoneMatch: b.IfNoneMatch == "*", Label: b.Label})
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, intentBody{IntentID: in.IntentID.String(), TenantID: in.Tenant.String(), ObjectID: in.Object.String(),
			LogicalVersionID: in.LogicalVersion.String(), CryptoVersionID: in.CryptoVersion.String(), BlobID: in.Blob.String(),
			AttemptID: in.Attempt.String(), Suite: in.Suite, Format: in.Format, MaxCiphertextLength: in.MaxCiphertext,
			ExpiresAt: in.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")})
	}))
	mux.HandleFunc("PUT /v1/uploads/{intent}/ciphertext", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		id, err := cryptowire.ParseUUID(r.PathValue("intent"))
		sum, err2 := cryptowire.ParseDigest(r.Header.Get("Fga-Ciphertext-Sha256"))
		if err != nil || err2 != nil || r.ContentLength <= 0 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		rec, err := svc.PutCiphertext(r.Context(), c, id, r.ContentLength, sum, http.MaxBytesReader(w, r.Body, r.ContentLength))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, receiptBody{BlobID: rec.Blob.String(), CiphertextLength: rec.Length, CiphertextSHA256: rec.SHA256.String()})
	}))
	mux.HandleFunc("POST /v1/uploads/{intent}/finalize", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		id, err := cryptowire.ParseUUID(r.PathValue("intent"))
		var b finalizeBody
		if err != nil {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		req := content.FinalizeRequest{Descriptor: b.Descriptor, DescriptorSignature: b.DescriptorSignature}
		for _, e := range b.Envelopes {
			req.Envelopes = append(req.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		}
		p, err := svc.Finalize(r.Context(), c, id, req)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, p)
	}))
	object := func(r *http.Request) (bucket, key, version string, ok bool) {
		q := r.URL.Query()
		if len(q["key"]) != 1 || len(q["version"]) > 1 || !content.ValidKey(q.Get("key")) || r.Header.Get("Range") != "" {
			return "", "", "", false
		}
		return r.PathValue("bucket"), q.Get("key"), q.Get("version"), true
	}
	mux.HandleFunc("GET /v1/buckets/{bucket}/object", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		info, err := svc.Stat(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, info)
	}))
	mux.HandleFunc("DELETE /v1/buckets/{bucket}/object", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		var out content.DeleteOutcome
		var err error
		if v == "" {
			out, err = svc.DeleteKey(r.Context(), c, b, k)
		} else {
			out, err = svc.DeleteVersion(r.Context(), c, b, k, v)
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/package", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok || len(r.URL.Query()["recipient"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		p, err := svc.ReadPackage(r.Context(), c, b, k, v, r.URL.Query().Get("recipient"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, packageBody{Version: p.Version, Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
			EnvelopeID: p.Envelope.EnvelopeID, Envelope: httpapi.EnvelopeBody{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext,
				Signature: p.Envelope.Signature}, Receipt: p.Envelope.Receipt, ReceiptSignature: p.Envelope.ReceiptSignature})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/ciphertext", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		s, err := svc.ReadCiphertext(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer s.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(s.Version.CiphertextLength, 10))
		w.Header().Set("Fga-Version-Id", s.Version.Version)
		w.Header().Set("Fga-Ciphertext-Sha256", s.Version.CiphertextSHA256)
		w.WriteHeader(http.StatusOK)
		if n, err := io.Copy(w, s); err != nil || n != s.Version.CiphertextLength {
			// Abort rather than complete a shorter body (CNT-009).
			panic(http.ErrAbortHandler)
		}
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/objects", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		page, err := svc.List(r.Context(), c, r.PathValue("bucket"), q.Get("prefix"), limit, q.Get("continuation"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, page)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/versions", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, _, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		vs, err := svc.ListVersions(r.Context(), c, b, k)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"versions": vs})
	}))
	mux.HandleFunc("PUT /v1/buckets/{bucket}/object/label", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		var body labelBody
		if !ok || v != "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		out, err := svc.SetLabel(r.Context(), c, b, k, body.Label)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/object/label-proposals", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		var body proposalBody
		if !ok || v != "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		p, err := svc.ProposeLabel(r.Context(), c, b, k, body.Label, body.Classifier)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, p)
	}))
	mux.HandleFunc("GET /v1/approvals", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		q := r.URL.Query()
		limit := 100
		if l := q.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > 100 {
				httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
				return
			}
			limit = n
		}
		views, next, err := svc.PendingApprovals(r.Context(), c, q.Get("after"), limit)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, approvalsBody{Approvals: views, Next: next})
	}))
	mux.HandleFunc("POST /v1/approvals/{id}", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var body approvalDecisionBody
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		if body.Decision != "approve" && body.Decision != "reject" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		v, err := svc.DecideApproval(r.Context(), c, r.PathValue("id"), body.Decision == "approve")
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, v)
	}))
	return mux
}
