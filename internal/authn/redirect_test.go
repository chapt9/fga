package authn

import (
	"crypto"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestRemoteJWKSRefusesRedirects: a redirect from the key set's URL is not
// followed (security review of 4 November 2026, finding 9).
func TestRemoteJWKSRefusesRedirects(t *testing.T) {
	p := newProvider(t)
	served := jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			http.Redirect(w, r, "/keys", http.StatusFound)
			return
		}
		w.Write(served)
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := IssuerConfig{Issuer: "https://idp.example/realms/acme", JWKSURL: srv.URL + "/", JWKSCAFile: ca}
	v, err := cfg.Verifier(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(token(t, p.rsa, "rsa", jose.RS256, TokenType, time.Minute), "fga-storage"); err == nil {
		t.Fatal("a key set reached through a redirect was accepted")
	}
	cfg.JWKSURL = srv.URL + "/keys"
	if v, err = cfg.Verifier(time.Now); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(token(t, p.rsa, "rsa", jose.RS256, TokenType, time.Minute), "fga-storage"); err != nil {
		t.Fatalf("the key set at its own URL: %v", err)
	}
}
