package authn

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var now = time.Unix(1_800_000_000, 0)

func clock() time.Time { return now }

func setup(t *testing.T) (*Issuer, *Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	iss, err := NewIssuer("fga-dev", "k1", priv, clock)
	if err != nil {
		t.Fatal(err)
	}
	return iss, NewVerifier("fga-dev", map[string]ed25519.PublicKey{"k1": pub}, clock), priv
}

// sign builds a token with arbitrary headers and claims, for the negative
// cases the issuer would never produce.
func sign(t *testing.T, priv ed25519.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: "k1"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerify(t *testing.T) {
	iss, v, priv := setup(t)
	tok, err := iss.Issue("user-42", "t-acme", "fga-storage", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok, "fga-storage")
	if err != nil || c.Subject != "user-42" || c.Tenant != "t-acme" || c.ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("Verify = %+v, %v", c, err)
	}

	valid := map[string]any{"iss": "fga-dev", "sub": "user-42", "aud": "fga-storage", "jti": "j1", "fga_tenant": "t-acme",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	with := func(k string, val any) map[string]any {
		m := map[string]any{}
		for key, v := range valid {
			m[key] = v
		}
		if val == nil {
			delete(m, k)
		} else {
			m[k] = val
		}
		return m
	}
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_ = otherPub
	for name, token := range map[string]string{
		"ID token type (ID-007)": sign(t, priv, "JWT", valid),
		"no type":                sign(t, priv, "", valid),
		"other audience":         tok + "",
		"other issuer":           sign(t, priv, TokenType, with("iss", "evil")),
		"expired":                sign(t, priv, TokenType, with("exp", now.Add(-time.Minute).Unix())),
		"too long":               sign(t, priv, TokenType, with("exp", now.Add(2*time.Hour).Unix())),
		"no tenant":              sign(t, priv, TokenType, with("fga_tenant", nil)),
		"no subject":             sign(t, priv, TokenType, with("sub", nil)),
		"no token ID":            sign(t, priv, TokenType, with("jti", nil)),
		"wrong key":              sign(t, otherPriv, TokenType, valid),
		"garbage":                "not.a.token",
	} {
		audience := "fga-storage"
		if name == "other audience" {
			audience = "fga-keys"
		}
		if _, err := v.Verify(token, audience); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want %v", name, err, ErrInvalid)
		}
	}
	if _, err := iss.Issue("user-42", "t-acme", "fga-storage", 2*time.Hour); err == nil {
		t.Error("issuing a token above the maximum lifetime must fail")
	}
}

// TestBearer covers audit F8: the Bearer scheme in any case, then a token
// without spaces; nothing else is a bearer token.
func TestBearer(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer tok": "tok", "bearer tok": "tok", "BEARER tok": "tok", "Bearer  tok": "tok",
		"": "", "Bearer": "", "Bearer ": "", "Basic tok": "", "Bearertok": "", "Bearer tok more": "", "tok": "", "Bearer\ttok": "",
	} {
		got, ok := Bearer(header)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %t, want %q", header, got, ok, want)
		}
	}
}
