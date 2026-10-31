# First-hop authentication (TRU-003, DEC-007, ID-001, ID-007)

Status: design record, 31 October 2026. D-04 (identity providers) is open, so this record defines the evidence interface and a development profile only. No provider is chosen.

## Evidence

A user's request reaches the native API (TB1) with a bearer access token. The storage or keys role verifies it, then passes the same token unchanged to the decision role as `evidence` (TB2). The decision role verifies it again, independently, and binds the verified claims to the actor (and, without a delegation, the principal) it evaluates. The adapter's workload identity (mTLS, or the single development adapter on loopback) identifies the adapter, never the user (DEC-007).

```go
// internal/authn
type Claims struct {
    Issuer, Subject, Tenant, ClientID, TokenID string
    Audience  []string
    IssuedAt, ExpiresAt time.Time
}
type Verifier interface {
    // Verify checks issuer, signature, audience, expiry and intended use.
    Verify(ctx context.Context, token string, audience string) (Claims, error)
}
```

## Token profile (development)

- JWT access token in compact JWS, header `typ` = `at+jwt` (RFC 9068). A token with any other `typ`, for example an ID token, is rejected (ID-007).
- Algorithm EdDSA only; key chosen by `kid` from the configured issuer keys. `jku`, `x5u` and embedded keys are never used (RCP-003).
- Claims: `iss` (configured issuer), `sub` (identity ID), `aud` (the role audience, for example `fga-storage`), `exp`, `iat`, `jti`, `client_id`, and `fga_tenant`.
- Lifetime at most 1 hour; clock skew 30 s.
- One JOSE implementation, go-jose, verifies tokens, decisions and content signatures (ID-007).

The development issuer is a local Ed25519 key pair. `fga dev-token` signs tokens with its private key; the roles hold only the public key. The issuer is named `fga-dev` and is accepted only by roles whose configuration profile is `development`; a production profile refuses to start with it.

## Binding at the decision role

1. The adapter is authenticated by its connection.
2. The decision role verifies the token with audience equal to the adapter's configured user-facing audience (the storage role's adapter ID maps to audience `fga-storage`, the keys role's to `fga-keys`).
3. `fga_tenant` must equal the request tenant and `sub` must equal the request actor. A delegated request additionally names its delegation, which the gate verifies against authoritative state (TRU-003: "or a delegation reference verified against authoritative state").
4. Missing, invalid or mismatched evidence denies the batch with `AUTHENTICATION_FAILED` before any policy runs. The public projection does not distinguish the cause.

Roles and attributes still come only from the catalog (ID-002, ID-003); a token never carries roles that the platform uses.

## Not done

- No OIDC discovery, JWKS refresh, introspection or production issuer (D-04).
- No sender-constrained tokens (RCP-009, R2).
- Identity expiry: the catalog's `identities.expires_at` bounds `valid_until` (DEC-005); token expiry bounds only the first hop.
