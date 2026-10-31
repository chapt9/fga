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

// Register adds POST /internal/v1/data-keys/seal, seal-document, release,
// release-unit and release-original to mux.
func Register(svc *datakeys.Service, adapterOf func(*http.Request) (string, error), storageAdapter string) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		handle := func(path string, serve func(r *http.Request, b keysapi.DataKeyRequest) (any, error)) {
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
				switch o := out.(type) {
				case keysapi.DataKeyBody:
					clear(o.Key)
				case keysapi.DataKeysBody:
					for _, k := range o.Keys {
						clear(k.Key)
					}
				}
			})
		}
		decision := func(b keysapi.DataKeyRequest) signing.Signed { return signing.Signed{Payload: b.Payload, JWS: b.JWS} }
		handle("/internal/v1/data-keys/seal", func(r *http.Request, b keysapi.DataKeyRequest) (any, error) {
			if b.IntentID == "" || b.VersionID != "" || b.UnitID != "" {
				return nil, datakeys.ErrNotFound
			}
			k, err := svc.Seal(r.Context(), decision(b), b.IntentID)
			return keysapi.DataKeyBody{Key: k.Key, Sealed: k.Sealed, KEKVersion: k.KEKVersion}, err
		})
		handle("/internal/v1/data-keys/seal-document", func(r *http.Request, b keysapi.DataKeyRequest) (any, error) {
			if b.IntentID == "" || b.VersionID != "" || b.UnitID != "" {
				return nil, datakeys.ErrNotFound
			}
			ks, err := svc.SealDocument(r.Context(), decision(b), b.IntentID)
			out := keysapi.DataKeysBody{Keys: []keysapi.DataKeyBody{}}
			for _, k := range ks {
				out.Keys = append(out.Keys, keysapi.DataKeyBody{Key: k.Key, Sealed: k.Sealed, KEKVersion: k.KEKVersion, IntentID: k.Intent})
			}
			return out, err
		})
		handle("/internal/v1/data-keys/release", func(r *http.Request, b keysapi.DataKeyRequest) (any, error) {
			if b.VersionID == "" || b.IntentID != "" || b.UnitID != "" {
				return nil, datakeys.ErrNotFound
			}
			k, err := svc.Release(r.Context(), decision(b), b.VersionID)
			return keysapi.DataKeyBody{Key: k}, err
		})
		handle("/internal/v1/data-keys/release-original", func(r *http.Request, b keysapi.DataKeyRequest) (any, error) {
			if b.VersionID == "" || b.UnitID != "" || b.IntentID != "" {
				return nil, datakeys.ErrNotFound
			}
			var extra []signing.Signed
			for _, x := range b.Extra {
				extra = append(extra, signing.Signed{Payload: x.Payload, JWS: x.JWS})
			}
			k, err := svc.ReleaseOriginal(r.Context(), decision(b), extra, b.VersionID)
			return keysapi.DataKeyBody{Key: k}, err
		})
		handle("/internal/v1/data-keys/release-unit", func(r *http.Request, b keysapi.DataKeyRequest) (any, error) {
			if b.VersionID == "" || b.UnitID == "" || b.IntentID != "" {
				return nil, datakeys.ErrNotFound
			}
			k, err := svc.ReleaseUnit(r.Context(), decision(b), b.VersionID, b.UnitID)
			return keysapi.DataKeyBody{Key: k}, err
		})
	}
}
