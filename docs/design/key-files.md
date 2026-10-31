# Passphrase-protected key files

Status: design record, 31 October 2026. Our own design; no upstream mapping. D-08 (client key custody) stays open: this protects a key file at rest, not a running process or the machine it runs on.

## Scope

Optional protection of the files that hold the fga client's private keys (`recipient.key`, `signing.key`) and fga-admin's backup key. Plain files keep working. Server roles' keys (decision signing, receipt, token issuer, publisher, listing tokens) are not covered.

## Format `fga.keyfile/v1`

A JSON object, parsed strictly:

| Field | Value |
|---|---|
| `format` | `fga.keyfile/v1` |
| `kdf` | `argon2id` |
| `time`, `memory_kib`, `threads` | 3, 65536, 4 for new files; a file may ask for at most 10, 1 GiB and 16, so a crafted file cannot make opening it arbitrarily expensive |
| `salt` | 16 random bytes, fresh for every file |
| `ciphertext` | the file's plain contents encrypted with Tink AES-256-GCM under the 32-byte Argon2id key, with every other field as associated data |

A wrong passphrase and an altered file give the same error.

## Use

- The passphrase comes from a passphrase file (`-passphrase-file`) or an environment variable: `FGA_KEY_PASSPHRASE` for the client, `FGA_BACKUP_KEY_PASSPHRASE` for fga-admin. There is no interactive prompt; one would need `golang.org/x/term`, which is not admitted.
- A protected file is recognized by its format and decrypted in memory only when its key is used; the decrypted bytes are cleared after parsing where Go allows (KEY-007 does not promise perfect zeroization).
- `fga keys init -encrypt`, `fga keys protect`, `fga keys unprotect`; `fga-admin backup-key generate -encrypt`, `fga-admin key protect|unprotect -file F`. Files are replaced atomically (temporary file, flush, rename) with mode 0600.

## Not done

No passphrase prompt, no change of KDF parameters for existing files short of unprotect and protect, no hardware or OS key store (D-08).
