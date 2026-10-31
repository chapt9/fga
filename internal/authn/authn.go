// Package authn verifies first-hop user authentication evidence: bearer
// access tokens issued by a registered provider (specification 2.5,
// TRU-003, DEC-007, ID-001, ID-007).
//
// D-04 (identity providers) is open, so the only profile is the development
// one: JWT access tokens (typ at+jwt, RFC 9068) signed with EdDSA by a
// configured local issuer. An ID token or any other token type is rejected,
// keys are never taken from the token (no jku, x5u, x5c or embedded jwk),
// and the same JOSE implementation verifies tokens, decisions and content
// signatures.
package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenType is the JOSE type of an access token.
const TokenType = "at+jwt"

// Bounds of the development profile.
const (
	MaxLifetime = time.Hour
	ClockSkew   = 30 * time.Second
)

// ErrInvalid is returned for any token that does not verify. The cause is
// wrapped for logs and never returned to a caller.
var ErrInvalid = errors.New("invalid access token")

// Claims are the verified claims of an access token.
type Claims struct {
	Issuer    string
	Subject   string
	Tenant    string
	ClientID  string
	TokenID   string
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// private holds the claims beyond the registered ones.
type private struct {
	Tenant   string `json:"fga_tenant"`
	ClientID string `json:"client_id"`
}

// Verifier verifies access tokens from one issuer.
type Verifier struct {
	issuer string
	keys   map[string]ed25519.PublicKey
	now    func() time.Time
}

// NewVerifier returns a Verifier for issuer's keys, by key ID.
func NewVerifier(issuer string, keys map[string]ed25519.PublicKey, now func() time.Time) *Verifier {
	return &Verifier{issuer: issuer, keys: keys, now: now}
}

// Verify checks the token's type, algorithm, key, signature, issuer,
// audience, times and required claims, and returns its claims.
func (v *Verifier) Verify(token, audience string) (Claims, error) {
	fail := func(format string, args ...any) (Claims, error) {
		return Claims{}, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return fail("parse: %v", err)
	}
	if len(tok.Headers) != 1 {
		return fail("want exactly one signature")
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != TokenType {
		return fail("token type %q is not %q", typ, TokenType)
	}
	_, x5cErr := h.Certificates(x509.VerifyOptions{})
	if h.JSONWebKey != nil || !errors.Is(x5cErr, jose.ErrMissingX5cHeader) || h.ExtraHeaders["jku"] != nil || h.ExtraHeaders["x5u"] != nil {
		return fail("the token names its own key")
	}
	key, ok := v.keys[h.KeyID]
	if !ok {
		return fail("unknown key %q", h.KeyID)
	}
	var std jwt.Claims
	var priv private
	if err := tok.Claims(key, &std, &priv); err != nil {
		return fail("signature: %v", err)
	}
	now := v.now()
	if err := std.ValidateWithLeeway(jwt.Expected{Issuer: v.issuer, AnyAudience: jwt.Audience{audience}, Time: now}, ClockSkew); err != nil {
		return fail("claims: %v", err)
	}
	switch {
	case std.Subject == "" || std.ID == "" || priv.Tenant == "":
		return fail("sub, jti and fga_tenant are required")
	case std.Expiry == nil || std.IssuedAt == nil:
		return fail("exp and iat are required")
	case std.Expiry.Time().Sub(std.IssuedAt.Time()) > MaxLifetime:
		return fail("lifetime above %s", MaxLifetime)
	}
	return Claims{Issuer: std.Issuer, Subject: std.Subject, Tenant: priv.Tenant, ClientID: priv.ClientID, TokenID: std.ID,
		Audience: std.Audience, IssuedAt: std.IssuedAt.Time(), ExpiresAt: std.Expiry.Time()}, nil
}

// Issuer signs development access tokens. Only the development profile
// uses it; its private key never reaches a server role.
type Issuer struct {
	issuer string
	signer jose.Signer
	now    func() time.Time
}

// NewIssuer returns an issuer that signs with key under keyID.
func NewIssuer(issuer, keyID string, key ed25519.PrivateKey, now func() time.Time) (*Issuer, error) {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType(TokenType))
	if err != nil {
		return nil, fmt.Errorf("authn: %w", err)
	}
	return &Issuer{issuer: issuer, signer: s, now: now}, nil
}

// Issue returns a token for subject in tenant, for audience, valid for
// lifetime (at most MaxLifetime).
func (i *Issuer) Issue(subject, tenant, audience string, lifetime time.Duration) (string, error) {
	if lifetime <= 0 || lifetime > MaxLifetime {
		return "", fmt.Errorf("authn: lifetime must be in (0, %s]", MaxLifetime)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := i.now()
	std := jwt.Claims{Issuer: i.issuer, Subject: subject, Audience: jwt.Audience{audience}, ID: hex.EncodeToString(id),
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(lifetime))}
	return jwt.Signed(i.signer).Claims(std).Claims(private{Tenant: tenant, ClientID: "fga-dev"}).Serialize()
}
