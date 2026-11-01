# Browser client for client-mode objects

Status: proposal, 1 November 2026, for the owner's web-only console plan (stop 4). Implemented in fga-console (stops 4b to 4d) and, for key custody, in the keys role (stop 4c). Not qualified.

## Purpose

A person who uses only the web console can make their keys, enroll them, upload and open files in client-mode (end-to-end encrypted) spaces, and share them, without the fga program. The browser holds the private keys. Neither the console nor fga can open them or the files.

Scope: ordinary objects under [wire profile 1](crypto-wire-profile.md): enrollment of a recipient key and a content-signing key, `Encrypt`, `Decrypt` and `Reshare` as `sdk/go/crypto` defines them. Documents and units (profile 2), collections, derived outputs and exports stay with the fga program.

## Same profile, second implementation

The browser implements suite 1 and format 1 exactly; there is no browser format. It is an independent implementation of profile 1, which is what RCP-007 asks for before production use ([crypto-wire-profile.md](crypto-wire-profile.md), status).

| Element | In the browser |
|---|---|
| Fingerprints, payload AAD, `RecipientEnvelopeContextV1`, HPKE `contextInfo`, signing inputs, envelope digest, descriptor JSON | Byte formats written in the console's own JavaScript, with the same strictness as `internal/cryptowire` (canonical protobuf re-encoding, strict JSON, size limits) |
| HPKE base mode, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`, Tink variant NO_PREFIX (`enc` ‖ ciphertext, `info` = `contextInfo`, empty AAD) | Composed from WebCrypto `X25519`, `HKDF`, `HMAC` and `AES-GCM` following RFC 9180; no library |
| Key package and its Tink binary keyset | A minimal protobuf reader and writer for exactly one enabled primary `AesGcmHkdfStreamingKey` (32-byte key, HKDF-SHA256, 1 MiB segments); anything else rejects, as in the SDK |
| Tink streaming AEAD AES-GCM-HKDF | Header (length byte, 32-byte salt, 7-byte nonce prefix), segment key HKDF-SHA256(key, salt, info = AAD), each 1 MiB segment AES-256-GCM with nonce prefix ‖ segment number ‖ last-segment flag. One segment at a time, so a file is never held twice in memory |
| Content signatures | WebCrypto `Ed25519`, compact detached JWS with the types of the profile |
| Recipient enrollment proof | X25519 with the challenge's ephemeral key, HKDF-SHA256 (salt = nonce, info `fga.recipient-proof/v1`), HMAC-SHA256, as the profile defines |

`Decrypt` keeps the SDK's order: descriptor signature, complete ciphertext digest and length, envelope signature, bindings (context against descriptor, recipient fingerprint), key package, then plaintext. Nothing is shown or saved before those checks. An AEAD failure later in the stream discards everything written. Uploads refuse any recipient not pinned in the person's trust list, as the SDK does.

## Keys and custody

- **Two keys per person**, made in the browser: an X25519 recipient key and an Ed25519 content-signing key. Both are enrolled with possession proofs through the keys role, as `fga keys enroll` and `enroll-signer` do.
- **The key bundle**: `fga.browser-keys/v1`, holding both private keys, their key versions and the person's **trust list** (the recipients and signers they approved after seeing their fingerprints). It is encrypted with AES-256-GCM under a random bundle key. The tenant, principal and both fingerprints are its associated data. Keeping the trust list inside the bundle protects it like the keys: the server can neither read nor change it.
- **A key file unlocks it, for now** (owner, 1 November 2026: keys are used by hand for the time being). When the keys are made, the browser offers the bundle key as a file to save, `fga-console-key.json`: the tenant, the principal, the recipient fingerprint and the 32-byte bundle key. The person keeps that file and picks it each time they unlock, so the browser stores nothing. It is a plain key file, protected only by where it is kept, like the fga program's plain `recipient.key` (D-08 open). There is never a passphrase.
- **Passkeys later**: the same bundle key wrapped once per passkey under HKDF-SHA256 of that passkey's WebAuthn PRF output, registered at the console's address for this purpose only (sign-in passkeys belong to the login service's address). A second passkey, such as a hardware key, would be the recovery path. Not built until the owner asks.
- **fga keeps the locked bundle** (owner's decision D4), next to the recipient key it belongs to: the encrypted bundle (and later the passkey-wrapped bundle keys and their credential IDs), as one opaque record of at most 64 KiB. fga backs it up with the catalog and cannot open it. Opening needs both: the record, which only its owner may read, and the person's key file. Losing the key file (or later every passkey) loses the keys and the files they alone open, because fga holds no escrow copy ([admin-api.md](admin-api.md), "Last readers").
- **In use**: unlocked keys are imported as non-extractable WebCrypto keys for the page's lifetime, never sent anywhere, and gone at sign-out or reload. JavaScript cannot promise to erase memory (as KEY-007 notes for Go).

New fga surface for custody (stop 4c): `GET` and `PUT /v1/recipients/{fp}/custody` on the keys role. A write carries `If-Match` with the record's revision, so two browsers do not overwrite each other. They are decided as `crypto.recipient` actions `custody-read` and `custody-write`, with a rule limiting both to the key's own principal. These two actions would be our additions to the spec's table, like `principal.self` (decision C1 below).

## Path through the console

Browser → console (same origin, session cookie) → fga's file API and keys role, with the person's own pass. The console relays bytes it cannot read and logs no bodies. New console routes relay client-mode upload (begin, stage, finalize), package and ciphertext reads, recipient and signing-key enrollment, key and signer lookup, envelope sharing and the custody record. The console decides nothing; fga decides each request as for the fga program.

## Threats and limits

- **The browser runs the code the console serves.** Whoever controls the console server can serve code that copies the keys at the next unlock. The fga program has no such weakness. The strict content security policy (scripts only from the console, no inline code) narrows script injection but not a compromised server. People who need protection against their own console server use the fga program.
- **Directory lookups are not trust.** The console shows fingerprints for the person to approve. Encrypting needs the recipient pinned in the trust list, and opening needs the signer pinned (RCP-002, RCP-008).
- **The key file is in the clear** on the person's disk, so anyone who copies it and can read the person's custody record (which fga gives only to its owner) can open their files. Passkeys, later, remove the file.
- **Size**: uploads and downloads stream through the console. A first limit of 2 GiB per file is a configuration value.

## Test data (stop 4a)

- **fga to browser**: `sdk/go/crypto` gains `TestBrowserVectors`, which writes `testdata/browser-v1.json` with `-update` and otherwise checks it against the Go implementation. The vectors are:
  - exact bytes for fingerprints, AAD, profile-1 contexts, `contextInfo`, signing inputs, the envelope digest, Ed25519 JWS (deterministic), both enrollment proofs (fixed keys, nonce and ephemeral key), and a key package with its keyset;
  - envelopes and ciphertexts sealed by the Go SDK for a test recipient and signer, to be opened by the browser code: empty, 1 byte, 1,000 bytes and two segments, the last kept as a separate binary file of about 1 MiB (`browser-v1-two-segments.bin`); plaintext byte i is i mod 251;
  - negative samples the browser must reject with the named error: another recipient's key and an envelope of another object (binding), an untrusted signer, a truncated, extended or corrupted ciphertext (integrity), a tampered envelope (signature), a non-canonical context signed by a trusted signer (format), and, sealed again by a malicious trusted signer so that only the payload's authentication can catch them, a corrupted segment and a dropped last segment (aead).
- **Browser to fga** (stop 4b): ciphertexts, envelopes and descriptors made by the console's code, committed as `testdata/browser-produced-v1.json`, which a Go test opens and verifies with the SDK. Together the two directions are the cross-implementation check RCP-007 requires.
- The console runs its side with Node's built-in test runner, on a copy of the vectors that names the fga commit it came from.

## Decisions for the owner

| | Question | Proposal |
|---|---|---|
| C1 | Custody record in fga: new `crypto.recipient` actions `custody-read` and `custody-write`, limited to the key's own principal | Yes; another addition to the spec's table, and bundles re-signed |
| C2 | Scope of the browser client | Profile-1 objects only; documents later |
| C3 | Test data size | One two-segment sample of about 1 MiB as a binary file in `sdk/go/crypto/testdata` |
| C4 | Unlocking the keys | For now a key file the person saves once and picks by hand; passkeys with PRF later; never a passphrase |
