# Admin API

`fga-admin serve -config admin.json` serves the directory changes of `fga-admin` over HTTPS, for an administration console that may run on another machine (the console is a separate repository). It runs on the fga host, because it writes the security journal.

## Who may call

Every request passes three checks, in this order:

1. **Console.** The client certificate, verified against `tls.client_ca_file`, names one of `consoles` (its URI SAN, else its common name). In the development profile without TLS, on a loopback address only, every caller is `dev_console_id`.
2. **Token.** The bearer token verifies with `token_issuer` (D-04: keys, a JWKS URL or a JWKS file) for `audience`, normally `fga-admin`.
3. **Administrator.** The token's subject is listed under its tenant in `admins`. Only the configuration file names administrators, so no request can make one (ADM-002). A request acts in the token's tenant only.

A refusal is logged with the console, tenant and subject; it changes nothing.

## What it does

| Method and path | Change or view |
|---|---|
| `GET /v1/admin/whoami` | the caller's tenant, subject and console |
| `GET /v1/admin/identities?after=&limit=` | identities with roles, attributes and capabilities, in ID order |
| `PUT /v1/admin/identities/{id}` | create an identity or replace its `roles` and `attributes` |
| `POST /v1/admin/identities/{id}/disable` | disable an identity (final) |
| `POST /v1/admin/identities/{id}/capabilities/grant` | grant a `preset` (`storage`, `approver`) or `capabilities` (type to actions) |
| `POST /v1/admin/identities/{id}/capabilities/revoke` | revoke them; answers whether the identity held any |
| `GET /v1/admin/delegations`, `POST /v1/admin/delegations` | list; add one (`id`, `actor`, `subject`, `audience`, `grants`, `expires_in`, optional `parent`) |
| `POST /v1/admin/delegations/{id}/revoke` | revoke a delegation |
| `GET /v1/admin/buckets`, `POST /v1/admin/buckets` | list; create one (`name`, `project`, `label`, `scope`, `encryption`, defaults `internal` and `server`) |
| `POST /v1/admin/mcp/enable` | register the MCP tools for the tenant |
| `GET /v1/admin/policy` | the signed bundle in `bundle_dir`, after its signature verifies with `publisher_keys` |
| `GET /v1/admin/events?limit=` | the tenant's latest audit events still in the outbox |

Lists answer `{"items": [...], "next": "..."}`; pass `next` as `after` for the following page (at most 500 per page). Errors answer `{"error": "..."}`: 400 for a request the directory does not take, 404 for an unknown identity or delegation, 409 for one that exists, 503 when the security journal or the bundle cannot be used.

The `fga-admin` commands `identity put`, `identity disable`, `grant`, `revoke`, `delegation add`, `delegation revoke`, `bucket create` and `mcp enable` make the same changes through the same code, `internal/adminops`.

## Audit and journal

Each change commits in one transaction with an `administration` audit event naming the administrator (`operator` at the command line), the console (`via console …` or `via cli`), the change (`identity.put`, `capabilities.revoke`, …) and its target, without attribute values (AUD-002, AUD-003).

A change that takes access away is journaled before it is made, and the journal's state is recorded in its transaction:

- disabling an identity and revoking a delegation, as before (`identity-disabled`, `delegation-revoked`). The target is locked before the journal's state, the order every journaled change takes, so concurrent changes cannot deadlock (audit F1). An unknown target is refused (404) and one already disabled or revoked is left as it is, neither journaled, so a restore cannot disable an identity or revoke a delegation created under that ID later (audit F2);
- replacing an identity's roles or attributes, or revoking capabilities, when something is taken away: an `access-removed` entry lists the roles, attribute values and capabilities removed.

After a restore, reconcile re-applies each `access-removed` entry: it removes what the entry names that is still there, and adds nothing. Access granted after the backup is therefore lost by the restore, and access removed after it stays removed (owner decision of 1 November 2026, closing review item AMB-1 for directory changes). A list attribute loses the removed values; a scalar that was changed or dropped is removed if it still holds the old value, so rules that read it no longer match. Without a journal, such a change is refused; a change that only adds is made.

## What it does not do

- It reads no content and releases no keys: an administrator is not a data reader (ADM-001).
- Bootstrap and recovery stay with `fga-admin`'s commands: `journal init`, key rings, backup keys, backup, restore, reconcile, reclaim and audit export (ADM-003).
- It does not sign or activate policy. Rule changes are signed offline with `fga policy sign` and activated by restarting `fga-decision` with the new bundle; the publisher's private key never reaches this server.
- It does not enable a disabled identity again, and it does not change tools, which `fga-tools` manages.

## Configuration

```json
{"version": 1, "profile": "production", "listen": "0.0.0.0:8450",
 "tls": {"cert_file": "admin.crt", "key_file": "admin.key", "client_ca_file": "consoles-ca.crt"},
 "consoles": ["spiffe://example.org/fga-console"],
 "database_url": "postgres://…", "journal_dir": "/var/lib/fga/journal",
 "token_issuer": {"issuer": "https://login.example.org/", "jwks_url": "https://login.example.org/.well-known/jwks.json"},
 "audience": "fga-admin", "admins": {"t-acme": ["00u1ab2C3D"]},
 "bundle_dir": "/etc/fga/bundle", "publisher_keys": {"publisher-1": "BASE64"}}
```

`scripts/smoke.sh` runs it in the development profile on loopback and drives it with curl.
