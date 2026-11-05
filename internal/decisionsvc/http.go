package decisionsvc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"fga/internal/authn"
	"fga/internal/strictjson"
)

// MaxRequestBytes bounds a request body (DEC-009).
const MaxRequestBytes = 64 << 10

// AdapterOf returns the authenticated adapter behind a request, or an error.
type AdapterOf func(*http.Request) (string, error)

// AdapterFromClientCert identifies the adapter by its verified client
// certificate: the first URI SAN, otherwise the subject common name
// (DEC-007, TRU-002).
func AdapterFromClientCert(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("no verified client certificate")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String(), nil
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName, nil
	}
	return "", errors.New("client certificate names no adapter")
}

// Handler serves the adapter facade (DEC-001), the public facade and the
// health endpoints (REL-006): POST /v1/decide-batch, POST /v1/check,
// GET /healthz, GET /readyz.
func (s *Service) Handler(adapterOf AdapterOf) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/decide-batch", func(w http.ResponseWriter, r *http.Request) {
		adapter, err := adapterOf(r)
		if err != nil {
			http.Error(w, "unauthenticated adapter", http.StatusUnauthorized)
			return
		}
		release, ok := s.admit(w, adapter)
		if !ok {
			return
		}
		defer release()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			http.Error(w, "request too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		var req Request
		if err := strictjson.Decode(body, &req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Decide(r.Context(), adapter, req))
	})
	// The public facade authenticates the user by bearer token and answers
	// with the public projection only (DEC-001, DEC-010). The token is
	// verified before an admission slot is taken or anything is recorded,
	// so an unauthenticated caller holds neither (fga-audit F-12).
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		token, ok := authn.Bearer(r.Header.Get("Authorization"))
		if ok && s.d.Authn != nil {
			_, err := s.d.Authn.Verify(token, s.d.PublicAudience)
			ok = err == nil
		}
		if !ok || s.d.Authn == nil {
			w.Header().Set("Connection", "close")
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		release, ok := s.admit(w, PublicAdapter)
		if !ok {
			return
		}
		defer release()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			http.Error(w, "request too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		var req Request
		if err := strictjson.Decode(body, &req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.DecidePublic(r.Context(), token, req))
	})
	// A gateway (the MCP role), which keeps no catalog, looks up the
	// ACTIVE sign-in key that signed a user's token here, for its own
	// token check; the decisions it then asks for check the token again.
	mux.HandleFunc("GET /v1/sign-in-keys/{fingerprint}", func(w http.ResponseWriter, r *http.Request) {
		adapter, err := adapterOf(r)
		if err != nil || len(s.d.Gateways[adapter]) == 0 || s.d.SignInKeys == nil {
			http.Error(w, "not a gateway", http.StatusForbidden)
			return
		}
		k, found, err := s.d.SignInKeys(r.URL.Query().Get("tenant"), r.PathValue("fingerprint"))
		switch {
		case err != nil:
			http.Error(w, "catalog unavailable", http.StatusServiceUnavailable)
			return
		case !found:
			http.Error(w, "no active sign-in key", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SignInKeyAnswer{Principal: k.Principal, PublicKey: k.Public, Limits: k.Limits})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.Ready() {
			http.Error(w, "no active policy snapshot", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// admit takes one of caller's request slots (Deps.Admission). Over a
// bound it answers 429 at once and returns false; callers treat that as
// the role being unavailable, so nothing is allowed (fail closed). The
// connection is closed, so the server reads nothing more of a refused
// request's body.
func (s *Service) admit(w http.ResponseWriter, caller string) (func(), bool) {
	if s.d.Admission == nil {
		return func() {}, true
	}
	release, ok := s.d.Admission.Acquire(caller, false)
	if !ok {
		w.Header().Set("Connection", "close")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "overloaded", http.StatusTooManyRequests)
	}
	return release, ok
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// SignInKeyAnswer is the answer of GET /v1/sign-in-keys/{fingerprint}.
type SignInKeyAnswer struct {
	Principal string          `json:"principal"`
	PublicKey []byte          `json:"public_key"`
	Limits    authn.KeyLimits `json:"limits"`
}
