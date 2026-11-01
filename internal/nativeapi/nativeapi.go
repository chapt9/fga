// Package nativeapi is the storage role's native HTTP API (specification
// 2.5, CNT-009, ADP-001, TB1; docs/design/native-api.md). It authenticates
// the caller, validates the request and delegates to the content service;
// it never decides access itself (CNT-002). Errors are redacted to a code.
package nativeapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"fga/internal/admission"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/httpapi"
	"fga/internal/textunits"
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
	case errors.Is(err, content.ErrEncryptionMode):
		return http.StatusConflict, httpapi.CodeEncryptionMode, true
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
		Derived        bool   `json:"derived,omitempty"`
	}
	approvalRequiredBody struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
		// IntentID names a staged server-mode upload to finalize once the
		// approval is given.
		IntentID string `json:"intent_id,omitempty"`
	}
	encryptionBody struct {
		Encryption string `json:"encryption"`
	}
	labelBody struct {
		Label string `json:"label"`
	}
	proposalBody struct {
		Label      string `json:"label"`
		Classifier string `json:"classifier"`
		Signature  string `json:"signature"`
	}
	approvalDecisionBody struct {
		Decision string `json:"decision"`
	}
	documentBeginBody struct {
		Key            string                     `json:"key"`
		IdempotencyKey string                     `json:"idempotency_key"`
		Units          []content.DocumentUnitSpec `json:"units"`
		Original       bool                       `json:"original,omitempty"`
		Collection     bool                       `json:"collection,omitempty"`
		BaseVersion    string                     `json:"base_version,omitempty"`
	}
	unitFinalBody struct {
		Descriptor          []byte                 `json:"descriptor"`
		DescriptorSignature string                 `json:"descriptor_signature"`
		Envelopes           []httpapi.EnvelopeBody `json:"envelopes"`
	}
	documentFinalizeBody struct {
		Manifest          []byte          `json:"manifest"`
		ManifestSignature string          `json:"manifest_signature"`
		Units             []unitFinalBody `json:"units"`
		Original          *unitFinalBody  `json:"original,omitempty"`
	}
	selectBody struct {
		Units []string `json:"unit_ids"`
	}
	unitsBody struct {
		Units []content.UnitEntry `json:"units"`
	}
	manifestBody struct {
		Manifest          []byte `json:"manifest"`
		ManifestSignature string `json:"manifest_signature"`
	}
	unitPackageBody struct {
		Unit             content.UnitEntry    `json:"unit"`
		EnvelopeID       string               `json:"envelope_id"`
		Envelope         httpapi.EnvelopeBody `json:"envelope"`
		Receipt          []byte               `json:"receipt"`
		ReceiptSignature string               `json:"receipt_signature"`
	}
	exportBody struct {
		Units     []string `json:"unit_ids"`
		Recipient string   `json:"recipient"`
	}
	exportUnitBody struct {
		Unit             content.UnitEntry    `json:"unit"`
		Ciphertext       []byte               `json:"ciphertext"`
		EnvelopeID       string               `json:"envelope_id"`
		Envelope         httpapi.EnvelopeBody `json:"envelope"`
		Receipt          []byte               `json:"receipt"`
		ReceiptSignature string               `json:"receipt_signature"`
	}
	exportOutBody struct {
		DocumentVersion string           `json:"document_version_id"`
		Recipient       string           `json:"recipient"`
		Units           []exportUnitBody `json:"units"`
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
	finalizeBody struct {
		Descriptor          []byte                 `json:"descriptor"`
		DescriptorSignature string                 `json:"descriptor_signature"`
		Envelopes           []httpapi.EnvelopeBody `json:"envelopes"`
		// Lineage and LineageSignature finalize a derived output.
		Lineage          []byte `json:"lineage,omitempty"`
		LineageSignature string `json:"lineage_signature,omitempty"`
		// Sources finalize a staged server-mode derived output.
		Sources []cryptowire.LineageSource `json:"sources,omitempty"`
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
	return StorageWith(svc, tokens, ready, limiter, nil)
}

// StorageWith is Storage that also serves gw's gateway calls: the MCP
// role's requests for its users, each carrying the decision for the
// user's MCP tool call (TB3). Every route checks them as any other caller.
func StorageWith(svc *content.Service, tokens httpapi.TokenVerifier, ready func() bool, limiter *admission.Limiter, gw *httpapi.Gateway) http.Handler {
	mux := http.NewServeMux()
	httpapi.Health(mux, ready)
	auth := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return httpapi.AuthedVia(tokens, content.Audience, gw, httpapi.Admitted(limiter, false, h))
	}
	stream := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return httpapi.AuthedVia(tokens, content.Audience, gw, httpapi.Admitted(limiter, true, h))
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
			IdempotencyKey: b.IdempotencyKey, IfMatch: b.IfMatch, IfNoneMatch: b.IfNoneMatch == "*", Label: b.Label, Derived: b.Derived})
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
		var p content.Published
		switch {
		case b.Sources != nil && (b.Lineage != nil || b.Descriptor != nil || b.Envelopes != nil):
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		case b.Sources != nil:
			p, err = svc.FinalizeDerivedPlain(r.Context(), c, id, b.Sources)
		case b.Lineage != nil:
			p, err = svc.FinalizeDerived(r.Context(), c, id, req, b.Lineage, b.LineageSignature)
		default:
			p, err = svc.Finalize(r.Context(), c, id, req)
		}
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
	// Server mode (D-12, S3): plaintext in and out over TLS; the storage
	// role encrypts and decrypts (SSE-005).
	mux.HandleFunc("GET /v1/buckets/{bucket}/encryption", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		mode, err := svc.BucketEncryption(r.Context(), c, r.PathValue("bucket"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, encryptionBody{Encryption: mode})
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/documents/text", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		q := r.URL.Query()
		h := r.Header
		if !ok || v != "" || len(h.Get("Idempotency-Key")) > 128 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		req := content.TextRequest{Bucket: b, Key: k, IdempotencyKey: h.Get("Idempotency-Key"), Collection: q.Get("collection") == "1",
			Append: q.Get("append") == "1"}
		if req.IdempotencyKey == "" {
			req.IdempotencyKey = cryptowire.NewUUID().String()
		}
		text, ok := textBody(w, r, &req)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		p, err := svc.PutDocumentText(r.Context(), c, req, text)
		var staged *content.StagedApproval
		if errors.As(err, &staged) {
			httpapi.WriteJSON(w, http.StatusAccepted, approvalRequiredBody{Status: httpapi.CodeApprovalRequired, ApprovalID: staged.ID,
				IntentID: staged.Intent})
			return
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("PUT /v1/buckets/{bucket}/object", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		h := r.Header
		ifNoneMatch := h.Get("If-None-Match")
		if !ok || v != "" || r.ContentLength < 0 || ifNoneMatch != "" && ifNoneMatch != "*" || len(h.Get("Idempotency-Key")) > 128 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		idem := h.Get("Idempotency-Key")
		if idem == "" {
			idem = cryptowire.NewUUID().String()
		}
		p, err := svc.PutObject(r.Context(), c, content.BeginRequest{Bucket: b, Key: k, IdempotencyKey: idem, IfMatch: h.Get("If-Match"),
			IfNoneMatch: ifNoneMatch == "*", Label: h.Get("Fga-Label")}, r.ContentLength, http.MaxBytesReader(w, r.Body, r.ContentLength))
		var staged *content.StagedApproval
		if errors.As(err, &staged) {
			httpapi.WriteJSON(w, http.StatusAccepted, approvalRequiredBody{Status: httpapi.CodeApprovalRequired, ApprovalID: staged.ID,
				IntentID: staged.Intent})
			return
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		w.Header().Set("ETag", p.ETag)
		httpapi.WriteJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/content", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		s, err := svc.ReadObject(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer s.Close()
		plainBody(w, s)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/export", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		s, err := svc.ExportObjectPlain(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer s.Close()
		plainBody(w, s)
	}))
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
		httpapi.WriteJSON(w, http.StatusOK, info.Wire())
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
		streamBody(w, r, s)
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
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		page, err := svc.ListVersions(r.Context(), c, b, k, limit, q.Get("continuation"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, page)
	}))
	mux.HandleFunc("PUT /v1/buckets/{bucket}/encryption", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var body encryptionBody
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		out, err := svc.SetBucketEncryption(r.Context(), c, r.PathValue("bucket"), body.Encryption)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	// Share grants (SHR-001): the bucket itself without key; with key, the
	// object or derived output, or for a document its version (version)
	// or one of its units or entries (unit).
	grantTarget := func(r *http.Request) (content.GrantTarget, bool) {
		q := r.URL.Query()
		if len(q["key"]) > 1 || len(q["version"]) > 1 || len(q["unit"]) > 1 || q.Has("key") && !content.ValidKey(q.Get("key")) {
			return content.GrantTarget{}, false
		}
		return content.GrantTarget{Bucket: r.PathValue("bucket"), Key: q.Get("key"), Version: q.Get("version"), Unit: q.Get("unit")}, true
	}
	mux.HandleFunc("POST /v1/buckets/{bucket}/grants", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		t, ok := grantTarget(r)
		var body content.GrantRequest
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		out, err := svc.RecordGrant(r.Context(), c, t, body)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/grants", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		t, ok := grantTarget(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		grants, err := svc.ListGrants(r.Context(), c, t)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"grants": grants})
	}))
	mux.HandleFunc("DELETE /v1/buckets/{bucket}/grants", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		t, ok := grantTarget(r)
		if !ok || len(r.URL.Query()["grantee"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		out, err := svc.RemoveGrant(r.Context(), c, t, r.URL.Query().Get("grantee"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
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
		p, err := svc.ProposeLabel(r.Context(), c, b, k, body.Label, body.Classifier, body.Signature)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, p)
	}))
	// The caller's own record (principal.self read), for a console that
	// shows each person only what their rights allow.
	mux.HandleFunc("GET /v1/me", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		me, err := svc.Me(r.Context(), c)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, me)
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
	mux.HandleFunc("POST /v1/buckets/{bucket}/documents", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b documentBeginBody
		if !httpapi.DecodeJSON(w, r, &b) {
			return
		}
		in, err := svc.BeginDocument(r.Context(), c, content.DocumentBeginRequest{Bucket: r.PathValue("bucket"), Key: b.Key,
			IdempotencyKey: b.IdempotencyKey, Units: b.Units, Original: b.Original, Collection: b.Collection, BaseVersion: b.BaseVersion})
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, in)
	}))
	mux.HandleFunc("POST /v1/document-uploads/{intent}/finalize", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		if _, err := cryptowire.ParseUUID(r.PathValue("intent")); err != nil {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		var b documentFinalizeBody
		if !httpapi.DecodeJSONLimit(w, r, &b, httpapi.MaxDocumentJSONBody) {
			return
		}
		req := content.DocumentFinalizeRequest{Manifest: b.Manifest, ManifestSignature: b.ManifestSignature}
		for _, u := range b.Units {
			uf := content.UnitFinal{Descriptor: u.Descriptor, DescriptorSignature: u.DescriptorSignature}
			for _, e := range u.Envelopes {
				uf.Envelopes = append(uf.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
			}
			req.Units = append(req.Units, uf)
		}
		if o := b.Original; o != nil {
			of := content.UnitFinal{Descriptor: o.Descriptor, DescriptorSignature: o.DescriptorSignature}
			for _, e := range o.Envelopes {
				of.Envelopes = append(of.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
			}
			req.Original = &of
		}
		p, err := svc.FinalizeDocument(r.Context(), c, r.PathValue("intent"), req)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, p)
	}))
	document := func(r *http.Request) (bucket, key, version string, ok bool) {
		q := r.URL.Query()
		if len(q["key"]) != 1 || len(q["version"]) > 1 || !content.ValidKey(q.Get("key")) || r.Header.Get("Range") != "" {
			return "", "", "", false
		}
		return r.PathValue("bucket"), q.Get("key"), q.Get("version"), true
	}
	mux.HandleFunc("POST /v1/buckets/{bucket}/document/units/select", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		var body selectBody
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		units, err := svc.SelectUnits(r.Context(), c, b, k, v, body.Units)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, unitsBody{Units: units})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/units", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if r.URL.Query().Get("limit") == "" {
			limit, err = 0, nil
		}
		if !ok || err != nil {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		page, err := svc.ListUnits(r.Context(), c, b, k, v, limit, r.URL.Query().Get("continuation"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, page)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/manifest", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		m, sig, err := svc.Manifest(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, manifestBody{Manifest: m, ManifestSignature: sig})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/unit/package", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		q := r.URL.Query()
		if !ok || len(q["unit"]) != 1 || len(q["recipient"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		p, err := svc.UnitPackage(r.Context(), c, b, k, v, q.Get("unit"), q.Get("recipient"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, unitPackageBody{Unit: p.Unit, EnvelopeID: p.Envelope.EnvelopeID,
			Envelope: httpapi.EnvelopeBody{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature},
			Receipt:  p.Envelope.Receipt, ReceiptSignature: p.Envelope.ReceiptSignature})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/unit/ciphertext", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		q := r.URL.Query()
		if !ok || len(q["unit"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadUnitCiphertext(r.Context(), c, b, k, v, q.Get("unit"))
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		streamBody(w, r, st)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/original/content", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadOriginalPlain(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		plainBody(w, st)
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/document/export/content", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		var body struct {
			Units []string `json:"units"`
		}
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		x, err := svc.ExportUnitsPlain(r.Context(), c, b, k, v, body.Units)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, x)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/unit/content", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		q := r.URL.Query()
		if !ok || len(q["unit"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadUnitPlain(r.Context(), c, b, k, v, q.Get("unit"))
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		plainBody(w, st)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/original/package", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		q := r.URL.Query()
		if !ok || len(q["recipient"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		p, err := svc.OriginalPackage(r.Context(), c, b, k, v, q.Get("recipient"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, packageBody{Version: p.Version, Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
			EnvelopeID: p.Envelope.EnvelopeID, Envelope: httpapi.EnvelopeBody{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext,
				Signature: p.Envelope.Signature}, Receipt: p.Envelope.Receipt, ReceiptSignature: p.Envelope.ReceiptSignature})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/document/original/ciphertext", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadOriginal(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		streamBody(w, r, st)
	}))
	derived := func(r *http.Request) (bucket, key, version, recipient string, ok bool) {
		q := r.URL.Query()
		if len(q["key"]) != 1 || len(q["version"]) > 1 || !content.ValidKey(q.Get("key")) || len(q["recipient"]) > 1 || r.Header.Get("Range") != "" {
			return "", "", "", "", false
		}
		return r.PathValue("bucket"), q.Get("key"), q.Get("version"), q.Get("recipient"), true
	}
	mux.HandleFunc("GET /v1/buckets/{bucket}/derived/package", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, fp, ok := derived(r)
		if !ok || fp == "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		p, err := svc.DerivedPackage(r.Context(), c, b, k, v, fp)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, packageBody{Version: p.Version, Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
			EnvelopeID: p.Envelope.EnvelopeID, Envelope: httpapi.EnvelopeBody{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext,
				Signature: p.Envelope.Signature}, Receipt: p.Envelope.Receipt, ReceiptSignature: p.Envelope.ReceiptSignature})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/derived/ciphertext", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, fp, ok := derived(r)
		if !ok || fp == "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadDerivedCiphertext(r.Context(), c, b, k, v, fp)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		streamBody(w, r, st)
	}))
	// Server-mode derived outputs (D-12, S4b): the lineage is declared in
	// the request; a reader reads under deliver and her own reader path.
	mux.HandleFunc("POST /v1/buckets/{bucket}/derived/content", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, _, ok := derived(r)
		h := r.Header
		ifNoneMatch := h.Get("If-None-Match")
		if !ok || v != "" || ifNoneMatch != "" && ifNoneMatch != "*" || len(h.Get("Idempotency-Key")) > 128 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		sources, body, ok := derivedBody(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		idem := h.Get("Idempotency-Key")
		if idem == "" {
			idem = cryptowire.NewUUID().String()
		}
		p, err := svc.PutDerivedPlain(r.Context(), c, content.BeginRequest{Bucket: b, Key: k, IdempotencyKey: idem, IfMatch: h.Get("If-Match"),
			IfNoneMatch: ifNoneMatch == "*", Label: h.Get("Fga-Label")}, sources, -1, body)
		var staged *content.StagedApproval
		if errors.As(err, &staged) {
			httpapi.WriteJSON(w, http.StatusAccepted, approvalRequiredBody{Status: httpapi.CodeApprovalRequired, ApprovalID: staged.ID,
				IntentID: staged.Intent})
			return
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		w.Header().Set("ETag", p.ETag)
		httpapi.WriteJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/derived/content", stream(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, fp, ok := derived(r)
		if !ok || fp != "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		st, err := svc.ReadDerivedPlain(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		defer st.Close()
		plainBody(w, st)
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/derived/envelopes", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, _, ok := derived(r)
		var e httpapi.EnvelopeBody
		if !ok || v == "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &e) {
			return
		}
		ref, err := svc.ShareDerived(r.Context(), c, b, k, v, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, ref)
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/document/export", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		var body exportBody
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		x, err := svc.ExportUnits(r.Context(), c, b, k, v, body.Units, body.Recipient)
		if err != nil {
			fail(w, r, err)
			return
		}
		out := exportOutBody{DocumentVersion: x.DocumentVersion, Recipient: x.Recipient, Units: []exportUnitBody{}}
		for _, u := range x.Units {
			out.Units = append(out.Units, exportUnitBody{Unit: u.Unit, Ciphertext: u.Ciphertext, EnvelopeID: u.Envelope.EnvelopeID,
				Envelope: httpapi.EnvelopeBody{Context: u.Envelope.Context, Ciphertext: u.Envelope.Ciphertext, Signature: u.Envelope.Signature},
				Receipt:  u.Envelope.Receipt, ReceiptSignature: u.Envelope.ReceiptSignature})
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/documents/search", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		q := r.URL.Query()
		limit := 0
		if l := q.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil {
				httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
				return
			}
			limit = n
		}
		page, err := svc.SearchDocuments(r.Context(), c, r.PathValue("bucket"),
			content.SearchQuery{Prefix: q.Get("prefix"), Project: q.Get("project"), MaxLabel: q.Get("max_label")}, limit, q.Get("continuation"))
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, page)
	}))
	mux.HandleFunc("PUT /v1/buckets/{bucket}/document/unit/label", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		var body labelBody
		if !ok || len(r.URL.Query()["unit"]) != 1 {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		out, err := svc.SetUnitLabel(r.Context(), c, b, k, v, r.URL.Query().Get("unit"), body.Label)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("PUT /v1/buckets/{bucket}/derived/label", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, _, ok := derived(r)
		var body labelBody
		if !ok || v != "" {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		out, err := svc.SetDerivedLabel(r.Context(), c, b, k, body.Label)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("DELETE /v1/buckets/{bucket}/document", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := document(r)
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		var out content.DeleteOutcome
		var err error
		if v == "" {
			out, err = svc.DeleteDocument(r.Context(), c, b, k)
		} else {
			out, err = svc.WithdrawDocumentVersion(r.Context(), c, b, k, v)
		}
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("POST /v1/buckets/{bucket}/object/export", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		var body struct {
			Recipient string `json:"recipient"`
		}
		if !ok {
			httpapi.WriteError(w, http.StatusBadRequest, httpapi.CodeInvalid)
			return
		}
		if !httpapi.DecodeJSON(w, r, &body) {
			return
		}
		x, err := svc.ExportObject(r.Context(), c, b, k, v, body.Recipient)
		if err != nil {
			fail(w, r, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, struct {
			packageBody
			Ciphertext []byte `json:"ciphertext"`
		}{packageBody{Version: x.Version, Descriptor: x.Descriptor, DescriptorSignature: x.DescriptorSignature, EnvelopeID: x.Envelope.EnvelopeID,
			Envelope: httpapi.EnvelopeBody{Context: x.Envelope.Context, Ciphertext: x.Envelope.Ciphertext, Signature: x.Envelope.Signature},
			Receipt:  x.Envelope.Receipt, ReceiptSignature: x.Envelope.ReceiptSignature}, x.Ciphertext})
	}))
	return mux
}

// textBody reads a server-mode text upload: a text/plain body of known
// length, or multipart/form-data with a "text" part followed by an
// optional "original" part, which req.Original then streams from.
func textBody(w http.ResponseWriter, r *http.Request, req *content.TextRequest) ([]byte, bool) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if r.ContentLength < 0 || r.ContentLength > textunits.MaxText {
			return nil, false
		}
		text, err := io.ReadAll(http.MaxBytesReader(w, r.Body, r.ContentLength))
		return text, err == nil && int64(len(text)) == r.ContentLength
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, false
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "text" {
		return nil, false
	}
	text, err := io.ReadAll(io.LimitReader(part, textunits.MaxText+1))
	if err != nil || len(text) > textunits.MaxText {
		return nil, false
	}
	part, err = mr.NextPart()
	switch {
	case err == io.EOF:
	case err != nil || part.FormName() != "original":
		return nil, false
	default:
		req.Original = part
	}
	return text, true
}

// derivedBody reads a server-mode derived upload: multipart/form-data with
// a "lineage" part, {"sources": [...]}, followed by a "content" part the
// upload streams from.
func derivedBody(r *http.Request) ([]cryptowire.LineageSource, io.Reader, bool) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return nil, nil, false
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, false
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "lineage" {
		return nil, nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(part, cryptowire.MaxLineageBytes+1))
	if err != nil || len(raw) > cryptowire.MaxLineageBytes {
		return nil, nil, false
	}
	var l struct {
		Sources []cryptowire.LineageSource `json:"sources"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil || dec.More() {
		return nil, nil, false
	}
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "content" {
		return nil, nil, false
	}
	return l.Sources, part, true
}

// plainBody writes an admitted server-mode plaintext stream. A failed
// authentication, truncation or lease aborts the response rather than
// completing a shorter body (SSE-005).
func plainBody(w http.ResponseWriter, s *content.Stream) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(s.Version.Length, 10))
	w.Header().Set("Fga-Version-Id", s.Version.Version)
	w.Header().Set("ETag", s.Version.ETag)
	w.WriteHeader(http.StatusOK)
	if n, err := io.Copy(w, s); err != nil || n != s.Version.Length {
		panic(http.ErrAbortHandler)
	}
}

// streamBody writes an admitted ciphertext stream. A stream that ends
// early or fails aborts the response rather than completing a shorter
// body (CNT-009).
func streamBody(w http.ResponseWriter, _ *http.Request, s *content.Stream) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(s.Version.CiphertextLength, 10))
	w.Header().Set("Fga-Version-Id", s.Version.Version)
	w.Header().Set("Fga-Ciphertext-Sha256", s.Version.CiphertextSHA256)
	w.WriteHeader(http.StatusOK)
	if n, err := io.Copy(w, s); err != nil || n != s.Version.CiphertextLength {
		panic(http.ErrAbortHandler)
	}
}
