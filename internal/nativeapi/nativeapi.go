// Package nativeapi is the native HTTP API of the storage and keys roles
// (specification 2.5, CNT-009, ADP-001, TB1, TB3;
// docs/design/native-api.md). It authenticates the caller, validates the
// request and delegates to the shared services; it never decides access
// itself (CNT-002). Errors are redacted to a code.
package nativeapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"fga/internal/authn"
	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/envelope"
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
)

// TokenVerifier verifies access tokens; authn.Verifier implements it.
type TokenVerifier interface {
	Verify(token, audience string) (authn.Claims, error)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail maps a service error to a redacted response. The cause goes to the
// operational log with no object key, token or payload.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, content.ErrNotFound), errors.Is(err, envelope.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound)
	case errors.Is(err, content.ErrInvalid), errors.Is(err, envelope.ErrInvalid):
		writeError(w, http.StatusBadRequest, CodeInvalid)
	case errors.Is(err, content.ErrPrecondition):
		writeError(w, http.StatusPreconditionFailed, CodePrecondition)
	case errors.Is(err, content.ErrConflict), errors.Is(err, envelope.ErrConflict):
		writeError(w, http.StatusConflict, CodeConflict)
	case errors.Is(err, content.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, CodeTooLarge)
	case errors.Is(err, envelope.ErrDecision):
		writeError(w, http.StatusForbidden, CodeInvalid)
	default:
		slog.Warn("request failed", "method", r.Method, "route", r.Pattern, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable)
	}
}

// authenticate verifies the bearer token for audience and returns the
// caller (TB1, ADP-001).
func authenticate(tokens TokenVerifier, audience string, r *http.Request) (content.Caller, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return content.Caller{}, false
	}
	c, err := tokens.Verify(token, audience)
	if err != nil {
		return content.Caller{}, false
	}
	return content.Caller{Tenant: c.Tenant, Principal: c.Subject, Token: token}, true
}

func authed(tokens TokenVerifier, audience string, h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := authenticate(tokens, audience, r)
		if !ok {
			writeError(w, http.StatusUnauthorized, CodeUnauth)
			return
		}
		h(w, r, c)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxJSONBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, CodeTooLarge)
		return false
	}
	if err := strictjson.Decode(body, v); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalid)
		return false
	}
	return true
}

func health(mux *http.ServeMux, ready func() bool) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// wire types of the storage API.
type (
	beginBody struct {
		Key            string `json:"key"`
		IdempotencyKey string `json:"idempotency_key"`
		IfMatch        string `json:"if_match,omitempty"`
		IfNoneMatch    string `json:"if_none_match,omitempty"`
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
	// EnvelopeBody is an envelope on the wire.
	EnvelopeBody struct {
		Context    []byte `json:"context"`
		Ciphertext []byte `json:"ciphertext"`
		Signature  string `json:"signature"`
	}
	finalizeBody struct {
		Descriptor          []byte         `json:"descriptor"`
		DescriptorSignature string         `json:"descriptor_signature"`
		Envelopes           []EnvelopeBody `json:"envelopes"`
	}
	receiptBody struct {
		BlobID           string `json:"blob_id"`
		CiphertextLength int64  `json:"ciphertext_length"`
		CiphertextSHA256 string `json:"ciphertext_sha256"`
	}
	packageBody struct {
		Version             content.VersionInfo `json:"version"`
		Descriptor          []byte              `json:"descriptor"`
		DescriptorSignature string              `json:"descriptor_signature"`
		EnvelopeID          string              `json:"envelope_id"`
		Envelope            EnvelopeBody        `json:"envelope"`
		Receipt             []byte              `json:"receipt"`
		ReceiptSignature    string              `json:"receipt_signature"`
	}
)

// Storage returns the storage role's handler.
func Storage(svc *content.Service, tokens TokenVerifier, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	health(mux, ready)
	auth := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return authed(tokens, content.Audience, h)
	}
	mux.HandleFunc("POST /v1/buckets/{bucket}/uploads", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b beginBody
		if !decodeJSON(w, r, &b) {
			return
		}
		if b.IfNoneMatch != "" && b.IfNoneMatch != "*" {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		in, err := svc.Begin(r.Context(), c, content.BeginRequest{Bucket: r.PathValue("bucket"), Key: b.Key,
			IdempotencyKey: b.IdempotencyKey, IfMatch: b.IfMatch, IfNoneMatch: b.IfNoneMatch == "*"})
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, intentBody{IntentID: in.IntentID.String(), TenantID: in.Tenant.String(), ObjectID: in.Object.String(),
			LogicalVersionID: in.LogicalVersion.String(), CryptoVersionID: in.CryptoVersion.String(), BlobID: in.Blob.String(),
			AttemptID: in.Attempt.String(), Suite: in.Suite, Format: in.Format, MaxCiphertextLength: in.MaxCiphertext,
			ExpiresAt: in.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")})
	}))
	mux.HandleFunc("PUT /v1/uploads/{intent}/ciphertext", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		id, err := cryptowire.ParseUUID(r.PathValue("intent"))
		sum, err2 := cryptowire.ParseDigest(r.Header.Get("Fga-Ciphertext-Sha256"))
		if err != nil || err2 != nil || r.ContentLength <= 0 {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		rec, err := svc.PutCiphertext(r.Context(), c, id, r.ContentLength, sum, http.MaxBytesReader(w, r.Body, r.ContentLength))
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, receiptBody{BlobID: rec.Blob.String(), CiphertextLength: rec.Length, CiphertextSHA256: rec.SHA256.String()})
	}))
	mux.HandleFunc("POST /v1/uploads/{intent}/finalize", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		id, err := cryptowire.ParseUUID(r.PathValue("intent"))
		var b finalizeBody
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		if !decodeJSON(w, r, &b) {
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
		writeJSON(w, http.StatusOK, p)
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
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		info, err := svc.Stat(r.Context(), c, b, k, v)
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	}))
	mux.HandleFunc("DELETE /v1/buckets/{bucket}/object", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			writeError(w, http.StatusBadRequest, CodeInvalid)
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
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/package", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok || len(r.URL.Query()["recipient"]) != 1 {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		p, err := svc.ReadPackage(r.Context(), c, b, k, v, r.URL.Query().Get("recipient"))
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, packageBody{Version: p.Version, Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
			EnvelopeID: p.Envelope.EnvelopeID, Envelope: EnvelopeBody{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext,
				Signature: p.Envelope.Signature}, Receipt: p.Envelope.Receipt, ReceiptSignature: p.Envelope.ReceiptSignature})
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/ciphertext", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, v, ok := object(r)
		if !ok {
			writeError(w, http.StatusBadRequest, CodeInvalid)
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
		writeJSON(w, http.StatusOK, page)
	}))
	mux.HandleFunc("GET /v1/buckets/{bucket}/object/versions", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		b, k, _, ok := object(r)
		if !ok {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		vs, err := svc.ListVersions(r.Context(), c, b, k)
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": vs})
	}))
	return mux
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
		Bucket   string       `json:"bucket"`
		Key      string       `json:"key"`
		Version  string       `json:"version"`
		Envelope EnvelopeBody `json:"envelope"`
	}
	// DeliverBody is the storage role's internal delivery request (TB3).
	DeliverBody struct {
		Payload    []byte `json:"payload"`
		JWS        string `json:"jws"`
		EnvelopeID string `json:"envelope_id"`
	}
	// DeliveredBody is the internal delivery response.
	DeliveredBody struct {
		EnvelopeID       string       `json:"envelope_id"`
		Envelope         EnvelopeBody `json:"envelope"`
		Receipt          []byte       `json:"receipt"`
		ReceiptSignature string       `json:"receipt_signature"`
	}
)

// Keys returns the keys role's handler. adapterOf identifies the workload
// calling the internal delivery endpoint, which only storage may call
// (TB3); its decision is verified as well (TRU-005).
func Keys(svc *envelope.Service, tokens TokenVerifier, adapterOf func(*http.Request) (string, error), storageAdapter string, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	health(mux, ready)
	auth := func(h func(http.ResponseWriter, *http.Request, content.Caller)) http.HandlerFunc {
		return authed(tokens, content.KeysAudience, h)
	}
	mux.HandleFunc("POST /v1/recipients", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b enrollBody
		if !decodeJSON(w, r, &b) {
			return
		}
		ch, err := svc.EnrollRecipient(r.Context(), c, b.PublicKey)
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, ch)
	}))
	mux.HandleFunc("POST /v1/recipients/{fp}/activate", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b proofBody
		if !decodeJSON(w, r, &b) {
			return
		}
		proof, err := base64.StdEncoding.DecodeString(b.Proof)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalid)
			return
		}
		rec, err := svc.ActivateRecipient(r.Context(), c, r.PathValue("fp"), b.ChallengeID, proof)
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("GET /v1/recipients/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		rec, err := svc.Recipient(r.Context(), c, r.PathValue("fp"))
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("DELETE /v1/recipients/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		if err := svc.RevokeRecipient(r.Context(), c, r.PathValue("fp")); err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"fingerprint": r.PathValue("fp"), "status": "REVOKED"})
	}))
	mux.HandleFunc("GET /v1/signing-keys/{fp}", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		rec, err := svc.SigningKey(r.Context(), c, r.PathValue("fp"))
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
	}))
	mux.HandleFunc("POST /v1/envelopes", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		var b shareBody
		if !decodeJSON(w, r, &b) {
			return
		}
		ref, err := svc.Publish(r.Context(), c, b.Bucket, b.Key, b.Version,
			content.EnvelopeIn{Context: b.Envelope.Context, Ciphertext: b.Envelope.Ciphertext, Signature: b.Envelope.Signature})
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, ref)
	}))
	mux.HandleFunc("DELETE /v1/envelopes/{id}", auth(func(w http.ResponseWriter, r *http.Request, c content.Caller) {
		ref, err := svc.Retire(r.Context(), c, r.PathValue("id"))
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, ref)
	}))
	mux.HandleFunc("POST /internal/v1/deliver", func(w http.ResponseWriter, r *http.Request) {
		if a, err := adapterOf(r); err != nil || a != storageAdapter {
			writeError(w, http.StatusUnauthorized, CodeUnauth)
			return
		}
		var b DeliverBody
		if !decodeJSON(w, r, &b) {
			return
		}
		d, err := svc.Deliver(r.Context(), signingSigned(b), b.EnvelopeID)
		if err != nil {
			fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, DeliveredBody{EnvelopeID: d.EnvelopeID, Envelope: EnvelopeBody{Context: d.Context,
			Ciphertext: d.Ciphertext, Signature: d.Signature}, Receipt: d.Receipt, ReceiptSignature: d.ReceiptSignature})
	})
	return mux
}

func signingSigned(b DeliverBody) signing.Signed {
	return signing.Signed{Payload: b.Payload, JWS: b.JWS}
}
