# D-04: identity providers

Status: decided by the owner, 31 October 2026; built 1 November 2026.

## Decision

Users authenticate to every role with JWT access tokens of an OIDC provider, such as Keycloak, Entra ID, Okta or Auth0, verified against the provider's JSON Web Key Set, from a URL or a local file. RS256, ES256 and EdDSA are accepted. The development issuer stays for the development profile only.

## Consequences

- One shared configuration, `authn.IssuerConfig` (`token_issuer` in every role), replaces the roles' separate issuer settings ([first-hop-authentication.md](../design/first-hop-authentication.md)).
- The provider must issue `fga_tenant`, `sub`, `jti`, `iat` and `exp`, and an audience per role. Roles and attributes still come only from the catalog (ID-002, ID-003).
- This supersedes ruling 5 of [rulings-2026-10-31.md](rulings-2026-10-31.md) for D-04. D-08 is recorded separately.
