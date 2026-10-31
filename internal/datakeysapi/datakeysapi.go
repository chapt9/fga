// Package datakeysapi serves the keys role's internal server-mode data-key
// routes (SSE-003). Only the storage role may call them, identified by its
// workload certificate like the internal delivery route (TB3), and every
// request carries a decision the service verifies in full. Only the keys
// role links this package.
package datakeysapi

import (
	"errors"
	"net/http"

	"fga/internal/datakeys"
	"fga/internal/httpapi"
	"fga/internal/keysapi"
	"fga/internal/signing"
)

func classify(err error) (int, string, bool) {
	switch {
	case errors.Is(err, datakeys.ErrNotFound):
		return http.StatusNotFound, httpapi.CodeNotFound, true
	case errors.Is(err, datakeys.ErrConflict):
		return http.StatusConflict, httpapi.CodeConflict, true
	case errors.Is(err, datakeys.ErrDecision):
		return http.StatusForbidden, httpapi.CodeInvalid, true
	}
	return 0, "", false
}

// Register adds POST /internal/v1/data-keys/seal and
// POST /internal/v1/data-keys/release to mux.
func Register(svc *datakeys.Service, adapterOf func(*http.Request) (string, error), storageAdapter string) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		handle := func(path string, serve func(r *http.Request, b keysapi.DataKeyRequest) (keysapi.DataKeyBody, error)) {
			mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
				if a, err := adapterOf(r); err != nil || a != storageAdapter {
					httpapi.WriteError(w, http.StatusUnauthorized, httpapi.CodeUnauth)
					return
				}
				var b keysapi.DataKeyRequest
				if !httpapi.DecodeJSON(w, r, &b) {
					return
				}
				out, err := serve(r, b)
				if err != nil {
					httpapi.Fail(w, r, err, classify)
					return
				}
				httpapi.WriteJSON(w, http.StatusOK, out)
				clear(out.Key)
			})
		}
		handle("/internal/v1/data-keys/seal", func(r *http.Request, b keysapi.DataKeyRequest) (keysapi.DataKeyBody, error) {
			if b.IntentID == "" || b.VersionID != "" {
				return keysapi.DataKeyBody{}, datakeys.ErrNotFound
			}
			k, err := svc.Seal(r.Context(), signing.Signed{Payload: b.Payload, JWS: b.JWS}, b.IntentID)
			return keysapi.DataKeyBody{Key: k.Key, Sealed: k.Sealed, KEKVersion: k.KEKVersion}, err
		})
		handle("/internal/v1/data-keys/release", func(r *http.Request, b keysapi.DataKeyRequest) (keysapi.DataKeyBody, error) {
			if b.VersionID == "" || b.IntentID != "" {
				return keysapi.DataKeyBody{}, datakeys.ErrNotFound
			}
			k, err := svc.Release(r.Context(), signing.Signed{Payload: b.Payload, JWS: b.JWS}, b.VersionID)
			return keysapi.DataKeyBody{Key: k}, err
		})
	}
}
