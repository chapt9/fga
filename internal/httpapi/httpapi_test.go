package httpapi_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"fga/internal/authn"
	"fga/internal/httpapi"
)

type verifier struct{}

func (verifier) Verify(token, audience string) (authn.Claims, error) {
	if token != "good" || audience != "fga-storage" {
		return authn.Claims{}, errors.New("does not verify")
	}
	return authn.Claims{Subject: "alice", Tenant: "t-acme"}, nil
}

// TestAuthenticateScheme covers audit F8 for the roles that authenticate
// through httpapi (storage, keys, tools): the bearer scheme is
// case-insensitive (RFC 9110, section 11.1), and nothing else is a token.
func TestAuthenticateScheme(t *testing.T) {
	for header, want := range map[string]bool{
		"Bearer good": true, "bearer good": true, "BEARER good": true,
		"Basic good": false, "Bearer": false, "Bearer ": false, "Bearer bad": false, "good": false, "Bearergood": false, "Bearer good extra": false,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", header)
		c, ok := httpapi.Authenticate(verifier{}, "fga-storage", r)
		if ok != want || ok && (c.Principal != "alice" || c.Token != "good") {
			t.Errorf("%q: %+v %t, want %t", header, c, ok, want)
		}
	}
}
