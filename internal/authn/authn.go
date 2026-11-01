// Package authn verifies first-hop user authentication evidence: bearer
// access tokens issued by a registered provider (specification 2.5,
// TRU-003, DEC-007, ID-001, ID-007).
//
// Tokens are JWT access tokens (typ at+jwt, RFC 9068, unless an issuer is
// configured otherwise) from the development issuer, signed with EdDSA, or
// from an OIDC provider by its JSON Web Key Set, signed with RS256, ES256
// or EdDSA (D-04, issuer.go). An ID token or any other token type is
// rejected, keys are never taken from the token (no jku, x5u, x5c or
// embedded jwk), and the same JOSE implementation verifies tokens,
// decisions and content signatures.
package authn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenType is the JOSE type of an access token.
const TokenType = "at+jwt"

// Default bounds of a token.
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
	issuer      string
	keys        func(kid string) (any, bool)
	now         func() time.Time
	types       []string
	maxLifetime time.Duration
}

// NewVerifier returns a Verifier for issuer's Ed25519 keys, by key ID.
func NewVerifier(issuer string, keys map[string]ed25519.PublicKey, now func() time.Time) *Verifier {
	return &Verifier{issuer: issuer, keys: staticKeys(keys), now: now, types: []string{TokenType}, maxLifetime: MaxLifetime}
}

// Verify checks the token's type, algorithm, key, signature, issuer,
// audience, times and required claims, and returns its claims.
func (v *Verifier) Verify(token, audience string) (Claims, error) {
	fail := func(format string, args ...any) (Claims, error) {
		return Claims{}, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.RS256})
	if err != nil {
		return fail("parse: %v", err)
	}
	if len(tok.Headers) != 1 {
		return fail("want exactly one signature")
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !slices.Contains(v.types, typ) {
		return fail("token type %q is not one of %q", typ, v.types)
	}
	_, x5cErr := h.Certificates(x509.VerifyOptions{})
	if h.JSONWebKey != nil || !errors.Is(x5cErr, jose.ErrMissingX5cHeader) || h.ExtraHeaders["jku"] != nil || h.ExtraHeaders["x5u"] != nil {
		return fail("the token names its own key")
	}
	key, ok := v.keys(h.KeyID)
	if !ok {
		return fail("unknown key %q", h.KeyID)
	}
	// Each key signs with its own algorithm only.
	switch key.(type) {
	case ed25519.PublicKey:
		ok = h.Algorithm == string(jose.EdDSA)
	case *ecdsa.PublicKey:
		ok = h.Algorithm == string(jose.ES256)
	case *rsa.PublicKey:
		ok = h.Algorithm == string(jose.RS256)
	default:
		ok = false
	}
	if !ok {
		return fail("algorithm %q does not fit key %q", h.Algorithm, h.KeyID)
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
	case std.Expiry.Time().Sub(std.IssuedAt.Time()) > v.maxLifetime:
		return fail("lifetime above %s", v.maxLifetime)
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

// Bearer returns the token of an Authorization header value in the Bearer
// scheme: the scheme's name in any case (RFC 9110, section 11.1; audit
// F8), spaces, and a token without spaces. Every role that reads a bearer
// token itself reads it with Bearer.
func Bearer(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	token = strings.TrimLeft(token, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
