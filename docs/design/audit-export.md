# Audit export (AUD-002, AUD-003)

Status: design record, 31 October 2026; the signed chain, collector and capacity alarm 1 November 2026. Our own design; no upstream mapping.

## Problem

Every role appends its mandatory audit events to the catalog's outbox inside the transaction of the outcome they record, and refuses the operation when the outbox is full (AUD-002). Nothing drained the outbox in R1. So a busy deployment would eventually refuse everything, and a restore replaced the outbox with the backup's, losing every event recorded after the backup.

## Contract

- **Exporter.** `internal/auditexport` moves undelivered events, oldest first by outbox sequence, into an export directory outside the catalog. One batch becomes one file of JSON lines (one event per line). The file is created exclusively with mode 0600 in a 0700 directory, written, flushed, and its directory flushed. Only then are the batch's events marked delivered in the same session.
- **One exporter at a time.** A PostgreSQL session advisory lock is held for the batch. A second exporter finds it taken and does nothing.
- **Idempotent delivery.** Event IDs are unique. A crash after the file is flushed but before the events are marked delivered exports them again in a later file; readers deduplicate by event ID (AUD-003). An event is never marked delivered before it is durable in the export directory.
- **Process.** `fga-admin audit export -dir D -key FILE` exports until the outbox is empty; with `-follow` it keeps exporting at an interval. It runs as the local administrator, beside the roles. The roles stay unchanged and keep refusing operations when the outbox is full.
- **Restore.** The export directory is not part of the catalog and survives a restore. Events exported before the restore stay exported. The restored outbox may hold events that were pending at backup time and exported afterwards; exporting them again yields duplicates by ID, which readers drop. Events recorded after the backup and not yet exported are still lost, so operators should export before taking a backup and before restoring.
- **Access and retention.** Export files hold IDs, outcomes, digests and resource identities only (AUD-001, AUD-003); no keys, tokens or object keys. Retention of export files is the operator's; R1 deletes none.

## Signed hash chain

Export files are evidence, so changing, deleting, reordering or truncating them must show.

- **Link.** Each export file `F` gets a link `F.link` (JSON, format `fga.audit-chain/v1`) and its signature `F.link.jws`. The link holds:
  - the file name, the event count and the first and last outbox sequence;
  - the file's SHA-256;
  - `previous`: the previous link's digest (empty for the first link);
  - `reset`: set on a link an operator started after a lost head (see below);
  - `digest`: SHA-256 over the format and every field above.

  The signature is a detached compact JWS (EdDSA, type `fga-audit-link+jws`). Its key ID is the export key's fingerprint.
- **Export key.** A separate Ed25519 key, used for nothing else. `fga-admin audit-key generate -out FILE [-encrypt]` creates it and prints the public key. A protected file is opened with `-passphrase-file` or `$FGA_AUDIT_KEY_PASSPHRASE`. After a key change, `-trusted` lists the earlier keys' public keys, whose links the directory still holds.
- **Write order.** The file, its link, then the signature, each created exclusively and flushed with its directory. Only after that does one transaction mark the batch's events delivered and record the new head in the catalog (`audit_export_state`: digest, file, time).
- **Crash leftovers.** An export file without a signature is the leftover of an interrupted export. Its events were never marked delivered. The next exporter renames the file and its link to `*.incomplete`, which keeps them for inspection outside the chain, and exports those events again.
- **Head check.** Before writing, the exporter checks that the directory holds one unbroken chain through the catalog's head. Every link must be signed by a trusted key and match its file, with no file outside the chain and no fork. The next link continues the end of the head's segment.
  - A running exporter rechecks only its last link while the catalog still records it.
  - If the directory does not hold the catalog's head (it was truncated, or replaced by an empty directory), the exporter stops with a chain error. With `-reset` it continues: the next link is a reset link whose `previous` is the lost head, which records the operator's decision.
  - Any other break (a changed, missing or extra file in the middle) always stops the exporter. The operator keeps that directory as evidence and exports into a new directory with `-reset`.
- **Restore.** The chain head is part of a backup. A restored catalog records an older head that the directory still holds, and the exporter continues from the end of the chain past it, so links exported after the backup stay in the chain.
- **Verification.** `fga-admin audit verify -dir D -public-key KEY[,KEY...]` checks:
  - every file's link and signature;
  - one chain from its first link, plus one from each reset link;
  - no file outside the chain.

  Without `-db` it runs offline with the public keys alone, which is the auditor's check. With `-db` it also requires the catalog's head to be in the directory, which shows a truncated directory. Reset links are reported, not failed.

## Collector

`audit export -collector URL` also sends each export file to a collector:
- **Request.** A `POST` of the file's JSON lines, in chain order, with headers `Fga-Audit-Link` (the link, base64) and `Fga-Audit-Link-Signature`. The bearer token comes from `$FGA_AUDIT_COLLECTOR_TOKEN`. The URL must be https, or http to a loopback address.
- **Acknowledgment.** A 2xx acknowledges the file, which is then marked `F.shipped`. The collector deduplicates by link digest or event ID.
- **Outage.** A failure ends the pass, and the next pass sends the rest. Exporting never waits for the collector, so an outage does not hold up the outbox.
- **Exit status.** Without `-follow` the command fails after a complete export if shipping stopped. With `-follow` it reports the failure and continues.

## Capacity alarm

`fga-admin audit status [-capacity N [-warn 0.8]]` prints the outbox backlog and the chain head. When the backlog reaches the alarm level of the roles' `outbox_capacity`, it fails with a nonzero exit, for a monitor to act on before the roles start refusing operations (AUD-002).

## Not done

- No retention or deletion of export files.
- No collector protocol beyond the POST above.
- No alarm pushed by the roles themselves; `audit status` is polled.
- Events recorded after the last export and before a restore are still lost by the restore.
