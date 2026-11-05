package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"fga/internal/cryptowire"
)

type signInFixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	fp     string
	limits KeyLimits
	ok     bool
	err    error
	now    time.Time
}

func newSignInFixture(t *testing.T) *signInFixture {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signInFixture{pub: pub, priv: priv, fp: cryptowire.SignInKeyFingerprint(pub).String(), ok: true,
		now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
}

func (f *signInFixture) verifier() *Verifier {
	return NewVerifier(DevIssuer, map[string]ed25519.PublicKey{}, func() time.Time { return f.now }).AcceptSignInKeys(
		func(tenant, fp string) (SignInKey, bool, error) {
			if f.err != nil {
				return SignInKey{}, false, f.err
			}
			if tenant != "t-acme" || fp != f.fp || !f.ok {
				return SignInKey{}, false, nil
			}
			return SignInKey{Tenant: "t-acme", Principal: "dana", Public: f.pub, Limits: f.limits}, true, nil
		})
}

// token signs claims as an account would, with the given header type and
// key, so a test can make the tokens SignInToken refuses to make.
func (f *signInFixture) token(t *testing.T, key ed25519.PrivateKey, typ string, edit func(*jwt.Claims, *private)) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: f.fp}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	std := jwt.Claims{Issuer: SignInIssuer, Subject: "dana", Audience: jwt.Audience{"fga-storage"}, ID: "p1",
		IssuedAt: jwt.NewNumericDate(f.now), Expiry: jwt.NewNumericDate(f.now.Add(SignInMaxLifetime))}
	pc := private{Tenant: "t-acme", ClientID: "fga"}
	if edit != nil {
		edit(&std, &pc)
	}
	tok, err := jwt.Signed(s).Claims(std).Claims(pc).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSignInTokens(t *testing.T) {
	f := newSignInFixture(t)
	good, err := SignInToken(f.priv, f.fp, "t-acme", "dana", "fga", "fga-storage", f.now, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.verifier().Verify(good, "fga-storage")
	if err != nil || c.Subject != "dana" || c.Tenant != "t-acme" || c.SignInKey != f.fp || c.Issuer != SignInIssuer || c.ClientID != "fga" {
		t.Fatalf("a key-signed token: %+v, %v", c, err)
	}
	if c.ExpiresAt.Sub(c.IssuedAt) != SignInMaxLifetime {
		t.Fatalf("lifetime %s", c.ExpiresAt.Sub(c.IssuedAt))
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	refused := map[string]string{
		"for another account":   f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Subject = "lena" }),
		"another tenant's key":  f.token(t, f.priv, TokenType, func(_ *jwt.Claims, p *private) { p.Tenant = "t-other" }),
		"signed by another key": f.token(t, other, TokenType, nil),
		"longer than 5 minutes": f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Expiry = jwt.NewNumericDate(f.now.Add(6 * time.Minute)) }),
		"two audiences":         f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Audience = jwt.Audience{"fga-storage", "fga-keys"} }),
		"another audience":      f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Audience = jwt.Audience{"fga-keys"} }),
		"typed JWT":             f.token(t, f.priv, "JWT", nil),
		"expired":               f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Expiry = jwt.NewNumericDate(f.now.Add(-time.Minute)) }),
		"without a token ID":    f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.ID = "" }),
		"without iat":           f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.IssuedAt = nil }),
		"of the development issuer, signed by the key": f.token(t, f.priv, TokenType, func(c *jwt.Claims, _ *private) { c.Issuer = DevIssuer }),
	}
	for name, tok := range refused {
		if _, err := f.verifier().Verify(tok, "fga-storage"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}

	if _, err := NewVerifier(DevIssuer, nil, func() time.Time { return f.now }).Verify(good, "fga-storage"); err == nil || !strings.Contains(err.Error(), "not accepted here") {
		t.Errorf("a role that does not accept sign-in keys: %v", err)
	}
	f.ok = false
	if _, err := f.verifier().Verify(good, "fga-storage"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a removed key: %v", err)
	}
	f.ok, f.err = true, errors.New("catalog down")
	if _, err := f.verifier().Verify(good, "fga-storage"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a failed lookup: %v", err)
	}
	f.err = nil

	// Limits: a key for the push API only is refused at the keys role, and
	// its limits travel with the claims for the decision role.
	f.limits = KeyLimits{Services: []string{"fga-storage"}, MaxLabel: "internal", Spaces: []string{"greenhouse"}}
	keys, _ := SignInToken(f.priv, f.fp, "t-acme", "dana", "fga", "fga-keys", f.now, 0)
	if _, err := f.verifier().Verify(keys, "fga-keys"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a service outside the key's limits: %v", err)
	}
	if c, err := f.verifier().Verify(good, "fga-storage"); err != nil || c.Limits.MaxLabel != "internal" || c.Limits.Spaces[0] != "greenhouse" {
		t.Errorf("limits with the claims: %+v, %v", c.Limits, err)
	}
}

func TestSignInIssuerIsReserved(t *testing.T) {
	c := IssuerConfig{Issuer: SignInIssuer, Keys: map[string]string{"k": "AAAA"}}
	if err := c.Validate(false); err == nil {
		t.Fatal("a configured issuer named fga-sign-in-key")
	}
}

func TestKeyLimitsValidate(t *testing.T) {
	if err := (KeyLimits{Services: []string{"fga-storage"}, MaxLabel: "internal", Spaces: []string{"greenhouse"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []KeyLimits{{Services: []string{"a b"}}, {MaxLabel: "x/y"}, {Spaces: []string{""}}} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
