package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type provider struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
}

func newProvider(t *testing.T) provider {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, d, _ := ed25519.GenerateKey(rand.Reader)
	return provider{rsa: r, ec: e, ed: d}
}

func jwks(t *testing.T, keys map[string]crypto.PublicKey) []byte {
	t.Helper()
	var set jose.JSONWebKeySet
	for kid, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k, KeyID: kid, Use: "sig"})
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// token signs claims for user-42 in t-acme with key under kid and alg.
func token(t *testing.T, key any, kid string, alg jose.SignatureAlgorithm, typ string, lifetime time.Duration) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	std := jwt.Claims{Issuer: "https://idp.example/realms/acme", Subject: "user-42", Audience: jwt.Audience{"fga-storage"}, ID: "j-1",
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(lifetime))}
	tok, err := jwt.Signed(s).Claims(std).Claims(private{Tenant: "t-acme"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestJWKSIssuer covers D-04: tokens of an OIDC provider verify against
// its key set with RS256, ES256 and EdDSA, each key with its own
// algorithm only; the token type and lifetime are the configured ones.
func TestJWKSIssuer(t *testing.T) {
	p := newProvider(t)
	file := filepath.Join(t.TempDir(), "jwks.json")
	set := jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey, "ec": &p.ec.PublicKey, "ed": p.ed.Public()})
	// A key the provider publishes for encryption signs nothing.
	enc, _ := rsa.GenerateKey(rand.Reader, 2048)
	var parsed jose.JSONWebKeySet
	_ = json.Unmarshal(set, &parsed)
	parsed.Keys = append(parsed.Keys, jose.JSONWebKey{Key: &enc.PublicKey, KeyID: "enc", Use: "enc"})
	set, _ = json.Marshal(parsed)
	if err := os.WriteFile(file, set, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := IssuerConfig{Issuer: "https://idp.example/realms/acme", JWKSFile: file}
	v, err := cfg.Verifier(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"RS256": token(t, p.rsa, "rsa", jose.RS256, TokenType, time.Minute),
		"ES256": token(t, p.ec, "ec", jose.ES256, TokenType, time.Minute),
		"EdDSA": token(t, p.ed, "ed", jose.EdDSA, TokenType, time.Minute),
	} {
		if c, err := v.Verify(tok, "fga-storage"); err != nil || c.Subject != "user-42" || c.Tenant != "t-acme" {
			t.Errorf("%s: %+v %v", name, c, err)
		}
	}
	for name, tok := range map[string]string{
		"another key's ID":         token(t, p.rsa, "ec", jose.RS256, TokenType, time.Minute),
		"an encryption key":        token(t, enc, "enc", jose.RS256, TokenType, time.Minute),
		"HS256":                    token(t, []byte("a shared secret of thirty-two bytes!"), "rsa", jose.HS256, TokenType, time.Minute),
		"typed JWT":                token(t, p.rsa, "rsa", jose.RS256, "JWT", time.Minute),
		"longer than the lifetime": token(t, p.rsa, "rsa", jose.RS256, TokenType, 2*time.Hour),
		"altered":                  func() string { return "x" + token(t, p.rsa, "rsa", jose.RS256, TokenType, time.Minute)[1:] }(),
	} {
		if _, err := v.Verify(tok, "fga-storage"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s verified: %v", name, err)
		}
	}
	cfg.TokenTypes, cfg.MaxLifetime = []string{TokenType, "JWT"}, "3h"
	v, _ = cfg.Verifier(time.Now)
	for name, tok := range map[string]string{
		"typed JWT":               token(t, p.rsa, "rsa", jose.RS256, "JWT", time.Minute),
		"longer than the default": token(t, p.rsa, "rsa", jose.RS256, TokenType, 2*time.Hour),
	} {
		if _, err := v.Verify(tok, "fga-storage"); err != nil {
			t.Errorf("%s with the issuer configured for it: %v", name, err)
		}
	}
}

// TestRemoteJWKS covers D-04 for a key set fetched over https: a key the
// provider adds is fetched when a token names it, at most once a minute.
func TestRemoteJWKS(t *testing.T) {
	p := newProvider(t)
	var mu sync.Mutex
	served := jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey})
	fetches := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		w.Write(served)
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	cfg := IssuerConfig{Issuer: "https://idp.example/realms/acme", JWKSURL: srv.URL, JWKSCAFile: ca}
	v, err := cfg.Verifier(func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(token(t, p.rsa, "rsa", jose.RS256, TokenType, time.Minute), "fga-storage"); err != nil {
		t.Fatal(err)
	}
	rotated := token(t, p.ec, "ec", jose.ES256, TokenType, time.Minute)
	mu.Lock()
	served = jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey, "ec": &p.ec.PublicKey})
	mu.Unlock()
	if _, err := v.Verify(rotated, "fga-storage"); err == nil {
		t.Fatal("a key fetched again within a minute of the last fetch")
	}
	clock = clock.Add(61 * time.Second)
	if _, err := v.Verify(rotated, "fga-storage"); err != nil {
		t.Fatalf("the provider's new key: %v", err)
	}
	if fetches != 2 {
		t.Fatalf("%d fetches, want 2", fetches)
	}
}

func TestIssuerConfigValidate(t *testing.T) {
	for name, c := range map[string]IssuerConfig{
		"no key source":          {Issuer: "https://idp.example"},
		"two key sources":        {Issuer: "https://idp.example", JWKSURL: "https://idp.example/certs", JWKSFile: "jwks.json"},
		"a key set over http":    {Issuer: "https://idp.example", JWKSURL: "http://idp.example/certs"},
		"a CA without a URL":     {Issuer: "https://idp.example", JWKSFile: "jwks.json", JWKSCAFile: "ca.pem"},
		"a lifetime above a day": {Issuer: "https://idp.example", JWKSFile: "jwks.json", MaxLifetime: "25h"},
		"the development issuer": {Issuer: DevIssuer, Keys: map[string]string{"tok-1": "k"}},
	} {
		if err := c.Validate(true); err == nil {
			t.Errorf("%s: accepted in production", name)
		}
	}
	if err := (IssuerConfig{Issuer: DevIssuer, Keys: map[string]string{"tok-1": "k"}}).Validate(false); err != nil {
		t.Errorf("the development issuer in development: %v", err)
	}
}
