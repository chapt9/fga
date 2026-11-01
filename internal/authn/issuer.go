package authn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DevIssuer is the development token issuer, which production refuses.
const DevIssuer = "fga-dev"

// IssuerConfig is one access-token issuer (D-04): the development issuer
// or another with Ed25519 keys by key ID (Keys, base64), or an OIDC
// provider such as Keycloak, Entra ID, Okta or Auth0 by its JSON Web Key
// Set, fetched from JWKSURL (https) or read from JWKSFile.
type IssuerConfig struct {
	Issuer string            `json:"issuer"`
	Keys   map[string]string `json:"keys,omitempty"`
	// JWKSURL is refetched hourly, and at most once a minute for a key ID
	// it does not hold; JWKSCAFile, if set, is the CA its server
	// certificate must chain to.
	JWKSURL    string `json:"jwks_url,omitempty"`
	JWKSCAFile string `json:"jwks_ca_file,omitempty"`
	JWKSFile   string `json:"jwks_file,omitempty"`
	// TokenTypes are the accepted JOSE types (default at+jwt); a provider
	// that types its access tokens JWT needs "JWT" here and an audience
	// its ID tokens never carry.
	TokenTypes []string `json:"token_types,omitempty"`
	// MaxLifetime bounds a token's lifetime (Go duration, default 1h, at
	// most 24h).
	MaxLifetime string `json:"max_lifetime,omitempty"`
}

// Validate reports the configuration's problems; production refuses the
// development issuer and a key set fetched over plain http.
func (c IssuerConfig) Validate(production bool) error {
	sources := 0
	for _, set := range []bool{len(c.Keys) > 0, c.JWKSURL != "", c.JWKSFile != ""} {
		if set {
			sources++
		}
	}
	switch {
	case c.Issuer == "" || sources != 1:
		return errors.New("token_issuer needs issuer and exactly one of keys, jwks_url and jwks_file")
	case production && c.Issuer == DevIssuer:
		return errors.New("the development token issuer is not allowed in production")
	case c.JWKSURL != "" && !strings.HasPrefix(c.JWKSURL, "https://"):
		return errors.New("token_issuer.jwks_url must be https")
	case c.JWKSCAFile != "" && c.JWKSURL == "":
		return errors.New("token_issuer.jwks_ca_file needs jwks_url")
	}
	if _, err := c.lifetime(); err != nil {
		return err
	}
	return nil
}

func (c IssuerConfig) lifetime() (time.Duration, error) {
	if c.MaxLifetime == "" {
		return MaxLifetime, nil
	}
	d, err := time.ParseDuration(c.MaxLifetime)
	if err != nil || d <= 0 || d > 24*time.Hour {
		return 0, errors.New("token_issuer.max_lifetime must be a duration in (0, 24h]")
	}
	return d, nil
}

// Verifier returns the issuer's token verifier.
func (c IssuerConfig) Verifier(now func() time.Time) (*Verifier, error) {
	lifetime, err := c.lifetime()
	if err != nil {
		return nil, err
	}
	types := c.TokenTypes
	if len(types) == 0 {
		types = []string{TokenType}
	}
	v := &Verifier{issuer: c.Issuer, now: now, types: types, maxLifetime: lifetime}
	switch {
	case len(c.Keys) > 0:
		keys := map[string]ed25519.PublicKey{}
		for id, b64 := range c.Keys {
			k, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("token issuer key %q is not a base64 Ed25519 public key", id)
			}
			keys[id] = k
		}
		v.keys = staticKeys(keys)
	case c.JWKSFile != "":
		raw, err := os.ReadFile(c.JWKSFile)
		if err != nil {
			return nil, err
		}
		set, err := parseJWKS(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.JWKSFile, err)
		}
		v.keys = func(kid string) (any, bool) { k, ok := set[kid]; return k, ok }
	default:
		client := &http.Client{Timeout: 10 * time.Second}
		if c.JWKSCAFile != "" {
			pem, err := os.ReadFile(c.JWKSCAFile)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("token_issuer.jwks_ca_file holds no certificates")
			}
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
		}
		v.keys = NewRemoteJWKS(c.JWKSURL, client, now).Key
	}
	return v, nil
}

func staticKeys(keys map[string]ed25519.PublicKey) func(string) (any, bool) {
	return func(kid string) (any, bool) {
		k, ok := keys[kid]
		return k, ok
	}
}

// maxJWKS bounds a fetched key set.
const maxJWKS = 1 << 20

// parseJWKS returns a key set's signing keys by key ID: Ed25519, ECDSA
// P-256 and RSA of at least 2048 bits, public, each with a key ID. Other
// keys (encryption keys, symmetric keys) are left out.
func parseJWKS(raw []byte) (map[string]any, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a JSON Web Key Set: %w", err)
	}
	out := map[string]any{}
	for _, k := range set.Keys {
		if k.KeyID == "" || !k.IsPublic() || !k.Valid() || k.Use != "" && k.Use != "sig" {
			continue
		}
		switch pub := k.Key.(type) {
		case ed25519.PublicKey:
			out[k.KeyID] = pub
		case *ecdsa.PublicKey:
			if pub.Curve == elliptic.P256() {
				out[k.KeyID] = pub
			}
		case *rsa.PublicKey:
			if pub.N.BitLen() >= 2048 {
				out[k.KeyID] = pub
			}
		}
	}
	return out, nil
}

// RemoteJWKS is a provider's key set fetched over https. A failed fetch
// keeps the keys it had.
type RemoteJWKS struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	keys    map[string]any
	fetched time.Time
}

// JWKS refresh: hourly, and on an unknown key ID at most once a minute.
const (
	jwksRefresh  = time.Hour
	jwksMinFetch = time.Minute
)

// NewRemoteJWKS returns the key set at url, fetched on first use.
func NewRemoteJWKS(url string, client *http.Client, now func() time.Time) *RemoteJWKS {
	return &RemoteJWKS{url: url, client: client, now: now}
}

// Key returns the key for kid.
func (r *RemoteJWKS) Key(kid string) (any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[kid]
	since := r.now().Sub(r.fetched)
	if r.fetched.IsZero() || since >= jwksRefresh || !ok && since >= jwksMinFetch {
		r.fetched = r.now()
		if keys, err := r.fetch(); err == nil {
			r.keys = keys
			k, ok = keys[kid]
		}
	}
	return k, ok
}

func (r *RemoteJWKS) fetch() (map[string]any, error) {
	resp, err := r.client.Get(r.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil || len(raw) > maxJWKS {
		return nil, errors.New("jwks: unreadable or too large")
	}
	return parseJWKS(raw)
}
