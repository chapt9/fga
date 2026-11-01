# Admin API

`fga-admin serve -config admin.json` serves the directory changes of `fga-admin` over HTTPS, for an administration console that may run on another machine (the console is a separate repository). It runs on the fga host, because it writes the security journal.

## Who may call

Every request passes three checks, in this order:

1. **Console.** The client certificate, verified against `tls.client_ca_file`, names one of `consoles` (its URI SAN, else its common name). In the development profile without TLS, on a loopback address only, every caller is `dev_console_id`.
2. **Token.** The bearer token (the `Bearer` scheme in any case, audit F8) verifies with `token_issuer` (D-04: keys, a JWKS URL or a JWKS file) for `audience`, normally `fga-admin`.
3. **Administrator.** The token's subject is listed under its tenant in `admins`. Only the configuration file names administrators, so no request can make one (ADM-002). A request acts in the token's tenant only.

A refusal is logged with the console, tenant and subject; it changes nothing.

## What it does

| Method and path | Change or view |
|---|---|
| `GET /v1/admin/whoami` | the caller's tenant, subject and console |
| `GET /v1/admin/identities?after=&limit=` | identities with roles, attributes and capabilities, in ID order |
| `PUT /v1/admin/identities/{id}` | create an identity or replace its `roles` and `attributes` |
| `POST /v1/admin/identities/{id}/disable` | disable an identity (final). Refused with 409 and `unreadable`, client-mode files per bucket, while it is the last reader of any; optional body `{"confirm_unreadable": true}` disables it anyway (see "Last readers") |
| `POST /v1/admin/identities/{id}/capabilities/grant` | grant a `preset` (`storage`, `approver`) or `capabilities` (type to actions) |
| `POST /v1/admin/identities/{id}/capabilities/revoke` | revoke them; answers whether the identity held any |
| `GET /v1/admin/delegations`, `POST /v1/admin/delegations` | list; add one (`id`, `actor`, `subject`, `audience`, `grants`, `expires_in`, optional `parent`) |
| `POST /v1/admin/delegations/{id}/revoke` | revoke a delegation |
| `GET /v1/admin/buckets`, `POST /v1/admin/buckets` | list; create one (`name`, `project`, `label`, `scope`, `encryption`, defaults `internal` and `server`) |
| `POST /v1/admin/mcp/enable` | register the MCP tools for the tenant |
| `GET /v1/admin/policy` | the signed bundle in `bundle_dir`, after its signature verifies with `publisher_keys` |
| `GET /v1/admin/events?limit=` | the tenant's latest audit events still in the outbox |

Lists answer `{"items": [...], "next": "..."}`; pass `next` as `after` for the following page (at most 500 per page). Errors answer `{"error": "..."}`:
- 400 for a request the directory does not take, with the reason. This includes a delegation the catalog refuses as given: its parent is missing, revoked, expired or narrower, or its ID is longer than 128 bytes (audit F3).
- 404 for an unknown identity or delegation, and 409 for one that exists.
- 503 when a change cannot be recorded as it must be: the security journal cannot record its entry, the catalog is bound to another journal, or the audit outbox is full. 503 also when the bundle cannot be used (audit F5).

The `fga-admin` commands `identity put`, `identity disable`, `grant`, `revoke`, `delegation add`, `delegation revoke`, `bucket create` and `mcp enable` make the same changes through the same code, `internal/adminops`.

## Audit and journal

Each change commits in one transaction with an `administration` audit event naming the administrator (`operator` at the command line), the console (`via console …` or `via cli`), the change (`identity.put`, `capabilities.revoke`, …) and its target, without attribute values (AUD-002, AUD-003).

A change that a restore must not undo is journaled before it is made, and the journal's state is recorded in its transaction:

- disabling an identity and revoking a delegation, as before (`identity-disabled`, `delegation-revoked`). The target is locked before the journal's state, the order every journaled change takes, so concurrent changes cannot deadlock (audit F1). An unknown target is refused (404) and one already disabled or revoked is left as it is, neither journaled, so a restore cannot disable an identity or revoke a delegation created under that ID later (audit F2);
- replacing an existing identity's roles or attributes, whenever they change: an `identity-set` entry holds the roles and attributes the change leaves;
- revoking capabilities an identity holds: an `access-removed` entry lists the capabilities removed.

After a restore, reconcile replays the entries in journal order. Each `identity-set` entry sets the identity's roles and attributes, so every identity ends with the state of its last recorded change, whether that change added or removed (owner decision of 1 November 2026, review v5 F01). Policies may deny by role or attribute, so adding a role such as `contractor` can take access away and removing it can give access; the effect of a change cannot be read from what it removed, which the earlier `access-removed` replay of roles and attributes assumed. An identity the restored catalog does not hold, created after the backup, stays unknown and has no access. Each `access-removed` entry takes away the capabilities it names that are still there and adds nothing, so capabilities granted after the backup are lost by the restore and those removed after it stay removed (AMB-1). Entries written before `identity-set` existed are replayed as before. Without a journal, a change to an existing identity is refused, and so is a revoke; creating an identity and granting capabilities are made.

## Last readers

A client-mode file opens only with a recipient key it has an envelope for; fga keeps no other copy of its key (no escrow, owner's decision of 1 November 2026). Disabling the last person who can open some files, or revoking the last key that opens them, loses them for good. So before such a change, fga counts the files that would be left without a reader (`catalog.LastReaders`):
- a file counts when one of its LIVE versions (for a document, a unit or the original of a LIVE document version) has ACTIVE envelopes for usable keys, all of them the person's keys, or the key being revoked;
- a usable key is ACTIVE and belongs to a person who is not disabled.

The change is refused, with the count per bucket and never a file name, until it is confirmed. Nothing is journaled or changed by the refusal. This holds on every path (safeguard 2):

| Path | Refused with | Confirmed with |
|---|---|---|
| `POST /v1/admin/identities/{id}/disable` | 409, `{"error", "unreadable": [{"bucket", "files"}]}` | body `{"confirm_unreadable": true}` |
| `fga-admin identity disable`, `fga-admin recipient revoke` | an error naming the counts | `-confirm-unreadable` |
| `DELETE /v1/recipients/{fp}` (the key's owner, through the keys role) | 409 `LAST_READER` with `unreadable`, once the revocation is authorized | `?confirm_unreadable=true` |

The count tells the key's owner, per bucket, how many of the files they can open nobody else can; it names no file and no other reader.

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

`outbox_capacity` (default 100,000) bounds the undelivered audit events, and `outbox_tenant_capacity`, if set, each tenant's share of them, as in the other roles (AUD-002, audit F6).

`scripts/smoke.sh` runs it in the development profile on loopback and drives it with curl.
