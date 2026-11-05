package adminapi

import (
	"net/http"

	"fga/internal/authn"
)

// listSignInKeys answers an account's sign-in keys, active and removed
// (docs/design/sign-in-keys.md).
func (s *server) listSignInKeys(w http.ResponseWriter, r *http.Request, c caller) {
	items, err := s.Ops.SignInKeys(r.Context(), c.tenant, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// addSignInKey registers a sign-in key for an account, after the
// administrator checked its fingerprint with the owner.
func (s *server) addSignInKey(w http.ResponseWriter, r *http.Request, c caller) {
	var body struct {
		PublicKey []byte          `json:"public_key"`
		Label     string          `json:"label"`
		Limits    authn.KeyLimits `json:"limits"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	fp, err := s.Ops.AddSignInKey(r.Context(), c.who(), c.tenant, r.PathValue("id"), body.PublicKey, body.Label, body.Limits)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"fingerprint": fp})
}

// removeSignInKey removes one of an account's sign-in keys at once.
func (s *server) removeSignInKey(w http.ResponseWriter, r *http.Request, c caller) {
	removed, err := s.Ops.RemoveSignInKey(r.Context(), c.who(), c.tenant, r.PathValue("id"), r.PathValue("fp"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": removed})
}
