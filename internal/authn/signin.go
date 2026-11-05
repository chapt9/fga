package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SignInIssuer is the issuer of the access tokens an account signs itself
// with a registered sign-in key (docs/design/sign-in-keys.md). A token of
// this issuer is accepted only for the key's owner.
const SignInIssuer = "fga-sign-in-key"

// SignInMaxLifetime bounds a key-signed token: it is short because the
// account makes it itself (S-1).
const SignInMaxLifetime = 5 * time.Minute

// KeyLimits narrow what a token signed with a sign-in key may do, below
// what its account may do. Empty fields limit nothing. Services are the
// audiences the key may sign in to; MaxLabel is the highest label of any
// resource a decision for it may cover; Spaces are the buckets, by name,
// whose resources it may cover.
type KeyLimits struct {
	Services []string `json:"services,omitempty"`
	MaxLabel string   `json:"max_label,omitempty"`
	Spaces   []string `json:"spaces,omitempty"`
}

// Empty reports whether l limits nothing.
func (l KeyLimits) Empty() bool {
	return len(l.Services) == 0 && l.MaxLabel == "" && len(l.Spaces) == 0
}

var limitName = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Validate checks that every named service, label and space is a plain
// name, at most 64 of each.
func (l KeyLimits) Validate() error {
	if len(l.Services) > 64 || len(l.Spaces) > 64 {
		return fmt.Errorf("at most 64 services and 64 spaces")
	}
	for _, n := range append(append([]string{}, l.Services...), l.Spaces...) {
		if !limitName.MatchString(n) {
			return fmt.Errorf("limit %q is not a plain name", n)
		}
	}
	if l.MaxLabel != "" && !limitName.MatchString(l.MaxLabel) {
		return fmt.Errorf("label %q is not a plain name", l.MaxLabel)
	}
	return nil
}

// SignInKey is an ACTIVE registered sign-in key: its owner, its public key
// and its limits.
type SignInKey struct {
	Tenant    string
	Principal string
	Public    ed25519.PublicKey
	Limits    KeyLimits
}

// SignInKeys looks up the ACTIVE sign-in key with fingerprint in tenant;
// ok is false when there is none. A role answers it from the catalog on
// every token, with no cache, so a removed key stops at once.
type SignInKeys func(tenant, fingerprint string) (key SignInKey, ok bool, err error)

// AcceptSignInKeys lets v accept key-signed tokens, with keys from keys.
func (v *Verifier) AcceptSignInKeys(keys SignInKeys) *Verifier {
	v.signIn = keys
	return v
}

var fingerprintText = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// verifySignIn checks a token of SignInIssuer: typed at+jwt, EdDSA, its
// key ID the fingerprint of an ACTIVE sign-in key of the token's tenant,
// signed by that key, for exactly one audience the key may sign in to,
// at most SignInMaxLifetime long, and for the key's owner only.
func (v *Verifier) verifySignIn(tok *jwt.JSONWebToken, h jose.Header, audience string) (Claims, error) {
	fail := func(format string, args ...any) (Claims, error) {
		return Claims{}, fmt.Errorf("%w: sign-in key: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	if v.signIn == nil {
		return fail("not accepted here")
	}
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TokenType || h.Algorithm != string(jose.EdDSA) {
		return fail("want typ %s and EdDSA", TokenType)
	}
	if !fingerprintText.MatchString(h.KeyID) {
		return fail("key ID %q is not a fingerprint", h.KeyID)
	}
	var claimed private
	if err := tok.UnsafeClaimsWithoutVerification(&claimed); err != nil || claimed.Tenant == "" {
		return fail("fga_tenant is required")
	}
	key, ok, err := v.signIn(claimed.Tenant, h.KeyID)
	switch {
	case err != nil:
		return fail("lookup: %v", err)
	case !ok:
		return fail("no active key %s", h.KeyID)
	}
	var std jwt.Claims
	var priv private
	if err := tok.Claims(key.Public, &std, &priv); err != nil {
		return fail("signature: %v", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{Issuer: SignInIssuer, AnyAudience: jwt.Audience{audience}, Time: v.now()}, ClockSkew); err != nil {
		return fail("claims: %v", err)
	}
	switch {
	case len(std.Audience) != 1:
		return fail("a key-signed token names exactly one audience")
	case std.Subject == "" || std.ID == "" || priv.Tenant == "":
		return fail("sub, jti and fga_tenant are required")
	case std.Expiry == nil || std.IssuedAt == nil:
		return fail("exp and iat are required")
	case std.Expiry.Time().Sub(std.IssuedAt.Time()) > SignInMaxLifetime:
		return fail("lifetime above %s", SignInMaxLifetime)
	case std.Subject != key.Principal || priv.Tenant != key.Tenant:
		return fail("the key signs only for %s", key.Principal)
	case len(key.Limits.Services) > 0 && !slices.Contains(key.Limits.Services, audience):
		return fail("the key may not sign in to %s", audience)
	}
	return Claims{Issuer: std.Issuer, Subject: std.Subject, Tenant: priv.Tenant, ClientID: priv.ClientID, TokenID: std.ID,
		Audience: std.Audience, IssuedAt: std.IssuedAt.Time(), ExpiresAt: std.Expiry.Time(),
		SignInKey: h.KeyID, Limits: key.Limits}, nil
}

// SignInToken signs a token for audience with a sign-in key: what the fga
// program and the add-on send instead of a login service's token.
func SignInToken(key ed25519.PrivateKey, fingerprint, tenant, subject, clientID, audience string, now time.Time, lifetime time.Duration) (string, error) {
	if lifetime <= 0 || lifetime > SignInMaxLifetime {
		lifetime = SignInMaxLifetime
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: fingerprint}},
		(&jose.SignerOptions{}).WithType(TokenType))
	if err != nil {
		return "", err
	}
	id, err := tokenID()
	if err != nil {
		return "", err
	}
	std := jwt.Claims{Issuer: SignInIssuer, Subject: subject, Audience: jwt.Audience{audience}, ID: id,
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(lifetime))}
	return jwt.Signed(s).Claims(std).Claims(private{Tenant: tenant, ClientID: clientID}).Serialize()
}

func tokenID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	return hex.EncodeToString(id), nil
}
