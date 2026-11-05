# Sign-in keys

Status: built on 5 November 2026 (branch `key-sign-in`) and checked against the running demo the same day. It follows the owner's decisions recorded in mosaic-key-store's `docs/sign-in.md`:
- every account signs in with public key signatures, with no login service;
- three kinds of account (a person, an MCP account, a push account), each with its own keys;
- an administrator registers each sign-in key;
- S-1 to S-6 as recommended;
- access is given both through the account and with optional limits per key.

## What it is

An account signs its own short access tokens with an Ed25519 **sign-in key** that an administrator registered for it. fga accepts such a token only for the key's owner. Sign-in keys are a key purpose of their own (RCP-001): they neither open nor sign content. Their fingerprint is SHA-256 of `fga.sign-in-key/v1`, a zero byte and the raw public key (`cryptowire.SignInKeyFingerprint`).

Everything after sign-in is unchanged: fga decides each request for that account under the signed rules, delegations included. Development tokens and an OIDC issuer keep working beside key-signed tokens.

## Tokens

A key-signed token is a JWT access token (`internal/authn`, `signin.go`):

| Field | Value |
|---|---|
| Header | `typ` `at+jwt`, `alg` `EdDSA`, `kid` the key's fingerprint (`sha256:…`) |
| `iss` | `fga-sign-in-key` (`authn.SignInIssuer`); no configured issuer may take this name |
| `sub`, `fga_tenant` | the key's owner and tenant, which must match the registered key |
| `aud` | exactly one audience |
| `iat`, `exp` | at most 5 minutes apart (`authn.SignInMaxLifetime`, S-1) |
| `jti`, `client_id` | required, and the program's name |

The check reads the issuer only to choose this path. It then verifies everything again with the registered key, looked up by tenant and fingerprint on every token with no cache, so a removed key stops at once. A token isn't recorded as used, so replay within its 5 minutes is accepted for now (S-2).

## Where it is checked

- **Turning it on.** A role accepts key-signed tokens when its `token_issuer` has `"sign_in_keys": true` (`IssuerConfig.VerifierWith`).
- **Storage, keys, tools, decision and `fga-admin serve`** look keys up in their catalog (`catalog.Store.ActiveSignInKey`): an ACTIVE key of an enabled identity.
- **The decision role** verifies the token again, independently, as for any first-hop evidence.
- **The MCP role** has no catalog. It looks keys up at the decision role: `GET /v1/sign-in-keys/{fingerprint}?tenant=T`, answered only to a configured gateway adapter, with the owner, public key and limits. Each lookup takes one of the gateway's request slots there, as its decisions do.
- **Lookups are bounded.** A lookup comes before the token's signature can be checked, so each role's verifier runs at most 16 at once (`authn.MaxSignInLookups`); a token over the bound is refused at once (security review of 5 November 2026, finding 3).

## Limits

A key may carry limits below its account's rights (`authn.KeyLimits`). Empty fields limit nothing. Limits are fixed when the key is registered: to change them, register another key and remove this one.

| Limit | Enforced by |
|---|---|
| `services`: the audiences the key may sign in to | the token check of every role |
| `max_label`: the highest label of any resource a decision covers | the decision role, by the release's label order; a label outside the order is outside the limit |
| `spaces`: buckets by name | the decision role: a bucket's `name`, or the `bucket` attribute of what it holds; resources with neither (a tool, a key) are not limited |

The decision role checks the limits after resolving the targets and before the rules (`keyUse.allows`), and denies with `KEY_LIMIT`. They only ever narrow what the rules allow.

**Forwarded MCP calls.** A decision made from a key-signed token records the key in the signed record (`actor_key`). When a gateway's decision comes back as the user's evidence (TB3), the decision role looks that key up again. The key must still be the actor's and ACTIVE, and its limits hold for the chained request. So an MCP account's limits also hold for the storage reads its tool calls make, and removing its key ends them.

## Registry and administration

- **Table `sign_in_keys`** (migration 0033): tenant, fingerprint, owner, public key, label, limits, status (`ACTIVE` or `REMOVED`), revision and times. It is backed up with the catalog.
- **A removal is journaled first** (`journal.SignInKeyRemoved`), and reconcile removes the key again after a restore. A removed key is never registered again.
- **Admin API**, for administrators only (ADM-002):
  - `GET /v1/admin/identities/{id}/sign-in-keys`;
  - `POST …/sign-in-keys` with `{"public_key", "label", "limits"}`, answering the fingerprint; the label is one line of plain text of at most 100 characters, without control or invisible characters (`internal/plaintext`);
  - `POST …/sign-in-keys/{fp}/remove`.
- **`fga-admin sign-in-key add|remove|list`**, for the first administrator and on the server. The administrator checks the key's fingerprint with its owner before registering it.

## The fga program

- **`fga sign-in-key new [-dir D] [-protect]`** writes `D/signin.key`, optionally passphrase-protected (D-08). It prints the fingerprint and public key for the administrator.
- **Signing its own tokens.** With `$FGA_TOKEN` and `$FGA_KEYS_TOKEN` unset, the client commands sign tokens with `D/signin.key` as `$FGA_PRINCIPAL` of `$FGA_TENANT`. So does `fga mcp-bridge` with `$FGA_MCP_TOKEN` unset. One token per audience is reused until a minute before it expires (`sdk/go/client` `TokenSource`).
- **`fga sign-in-key token -aud A`** prints a fresh token, for a tool such as `curl`.

### A person's key box (stop 3)

A person's fga program and browser add-on share one account and one set of keys: the sign-in, opening and content-signing keys and the trust list, in the person's key box. The layout is `fga.browser-keys/v1`, from mosaic-key-store `docs/key-box.md`.
- **`sdk/go/keybox`** is the Go implementation of that layout, beside mosaic-key-store's Rust one. Each opens the other's files byte for byte (`testdata`).
- **`sdk/go/crypto`** converts a Tink recipient key to and from the box's raw X25519 key (`RecipientKeyFromRawInsecure`, `RawPrivateInsecure`).

In **box mode**, a key directory holds only three files:
- `keybox`;
- `unlock.key`, the program's X25519 unlock key, optionally passphrase-protected;
- `unlock.id`, the ID of the box's unlocker for that key.

Every client command then works from the box and signs its tokens as the box's owner, with no `$FGA_TENANT` or `$FGA_PRINCIPAL` (`cmd/fga/box.go`):

| Command | Does |
|---|---|
| `fga box init -dir D [-id ID] [-protect]` | Puts an enrolled key directory's keys in a box opened by a new unlock key, checks that the box opens with the same keys, then removes the separate key files |
| `fga box unlock-key -dir D -id ID` | Makes this program's unlock key, for the program that has the box; prints its public key and fingerprint |
| `fga box add-unlock-key -dir D -id ID -public-key B64 -out FILE` | After the person compared the fingerprint, lets the other program's unlock key open the box, and writes the box for it to FILE |
| `fga box import -dir D -in FILE [-tenant T -principal P]` | Takes the box another program locked for this one's key, only when it is the box of P in T (by default `$FGA_TENANT` and `$FGA_PRINCIPAL`): another person's box is refused before it is opened or kept |
| `fga box show` | The owner, the three keys, the unlockers and the trust list |
| `fga box remove-unlocker -dir D -id ID` | Removes another program's unlocker, for a lost computer |
| `fga trust add` in box mode | Pins a key in the box's trust list; it needs `-principal`, whose key it is |

MCP accounts and push accounts keep keys of their own, in a key directory with `signin.key`, never in a person's box. `fga mcp-bridge` signs its MCP tokens only with such a `signin.key`.

## Tests

| Test | Covers |
|---|---|
| `internal/authn` `TestSignInTokens` | Valid tokens. Refused: another subject or tenant, another key, over 5 minutes, two audiences, `typ` JWT, expired, missing `jti` or `iat`, the development issuer's name, a removed key, a failed lookup, a role that doesn't accept them, a service outside the limits |
| `internal/decisionsvc` `TestKeyLimits` | Spaces by name and by attribute, labels by order, unknown labels, resources without a space or label |
| `internal/nativeapi` `TestSignInKeys` | End to end: a person's key through the decision role and the storage role's HTTP API; another account refused; a space or label outside the limits; removal at once, journaled, never registered again; an MCP account's limits on chained requests; an MCP-only key at storage; a removed agent key ending its chained decisions |
| `internal/adminapi` `TestSignInKeyRoutes` | Register, list and remove; duplicates, unknown accounts, short keys, another account's key; non-administrators refused |
| `internal/recovery` `TestBackupCoversEveryTable` | `sign_in_keys` is backed up |
| `cmd/fga` `TestSignInKeyTokens` | The program's key file, its account variables, and reusing tokens per audience |
| `sdk/go/keybox` `TestRustBox`, `TestGoBox`, `TestSealRefuses` | The box mosaic-key-store's Rust module made opens here byte for byte with both kinds of unlocker. The box made here opens too, and with `-update` it is written for the Rust module to open. Refusals: wrong secrets or keys, trailing bytes, a changed box, another name |
| `cmd/fga` `TestKeyBox`, `TestImportRustBox` | Converting an enrolled key directory, then working from the box; pairing a second program by file, refusing another person's box; trust in the box; removing an unlocker; importing the Rust module's box |

## Checked against the running demo (5 November 2026)

| Account | Checked |
|---|---|
| Alice, a person | Listed `shared` with the fga program and her own key, with no development token. Refused: her key claiming Bob; her `reports`-only key on `shared` (audit `KEY_LIMIT`). After removing that key, it got 401 at once while her other key kept working, and the removal was journaled |
| `agent-7`, an MCP account (delegation `dlg-agent7-lena-2`) | Listed tools and read `read_climate` with its own key through the MCP role (key lookup at the decision role), and through `fga mcp-bridge` signing its own tokens. Refused: its `shared`-only key (`KEY_LIMIT`; the bridge then lists only the four tools outside data sources); a call without the delegation; its MCP-only key at storage (401) |
| `greenhouse-sensor`, a push account | Posted a reading to `greenhouse-climate` with its key, which `agent-7` then read. Refused: `greenhouse-soil` outside its spaces (`KEY_LIMIT`); its push-only key at the keys role (401) |
| Rita, an administrator | Listed a key through the admin API with her own key; Alice was refused (403) |

Development tokens and the console kept working.

Stop 3, the same evening:
- **Alice's keys in a box.** Her test key directory enrolled its opening key (version 2) and signing key with her sign-in key, then `fga box init` put them in a box. From the box, with no account variables, the program listed `shared` and put a locked file in `reports` for her own key. Getting it back verified and decrypted it.
- **Pairing with the add-on.** The program locked the box for an unlock key the Rust module made (`examples/pair.rs`, standing in for the add-on). The module opened it, found the same keys, and signed passes with the shared sign-in key. The storage role (which listed the new file) and the keys role accepted them.

## Not done

- **Replay** within a token's 5 minutes (S-2): a pass ID could be accepted only once.
- **The console's "Sign-in keys" part** on each account's page (mosaic-key-store stop 5).
- **A copy of the box in fga**, for a new device (decision A-1 in mosaic-key-store `docs/design.md`): the programs exchange the box as a file until it is decided.
- **The specification:** the erratum below, which waits for the owner's approval of its text.

## Specification erratum (draft for the owner)

To specification 2.6.2, part "Custody", RCP-001, and part "Trust", first-hop authentication:
- **RCP-001** gains "account sign-in" beside request authentication as its own key purpose: an Ed25519 key registered by an administrator for one identity, which signs only that identity's access tokens.
- **First-hop authentication** gains key-signed access tokens of the issuer `fga-sign-in-key`:
  - accepted only by roles configured for them;
  - only for the key's owner, with exactly one audience and a lifetime of at most 5 minutes;
  - the key looked up on every token, and a removal journaled before it takes effect.
- **A sign-in key may carry limits** (services, highest label, spaces) that only narrow a decision. A gateway's decision records the key, so a chained request is held to the same limits.
