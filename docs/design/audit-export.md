# Audit export (AUD-002, AUD-003)

Status: design record, 31 October 2026. Our own design; no upstream mapping.

## Problem

Every role appends its mandatory audit events to the catalog's outbox inside the transaction of the outcome they record, and refuses the operation when the outbox is full (AUD-002). Nothing drained the outbox in R1. So a busy deployment would eventually refuse everything, and a restore replaced the outbox with the backup's, losing every event recorded after the backup.

## Contract

- **Exporter.** `internal/auditexport` moves undelivered events, oldest first by outbox sequence, into an export directory outside the catalog. One batch becomes one file of JSON lines (one event per line). The file is created exclusively with mode 0600 in a 0700 directory, written, flushed, and its directory flushed. Only then are the batch's events marked delivered in the same session.
- **One exporter at a time.** A PostgreSQL session advisory lock is held for the batch. A second exporter finds it taken and does nothing.
- **Idempotent delivery.** Event IDs are unique. A crash after the file is flushed but before the events are marked delivered exports them again in a later file; readers deduplicate by event ID (AUD-003). An event is never marked delivered before it is durable in the export directory.
- **Process.** `fga-admin audit export -dir D` exports until the outbox is empty; with `-follow` it keeps exporting at an interval. It runs as the local administrator, beside the roles. The roles stay unchanged and keep refusing operations when the outbox is full.
- **Restore.** The export directory is not part of the catalog and survives a restore. Events exported before the restore stay exported. The restored outbox may hold events that were pending at backup time and exported afterwards; exporting them again yields duplicates by ID, which readers drop. Events recorded after the backup and not yet exported are still lost, so operators should export before taking a backup and before restoring.
- **Access and retention.** Export files hold IDs, outcomes, digests and resource identities only (AUD-001, AUD-003); no keys, tokens or object keys. Retention of export files is the operator's; R1 deletes none.

## Not done

No shipping to an external collector, no signing or hash-chaining of export files, no capacity alarm beyond the outbox refusal.
