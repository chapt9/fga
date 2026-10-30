# D-02: Object storage and deployment

- **Status:** decided 30 October 2026.
- **Decision:** our own object storage.
  - **R1:** a single-node blob store on local disk, written by us, with the catalog in PostgreSQL.
  - **Later:** replication across three failure domains, repair and evacuation.
  - **R3:** the S3-compatible API, our own implementation of a strict S3 subset.
- **No external object store.** Specification 2.1's default, an external durable store under R1, is withdrawn.
- **MinIO:** studied for ideas only; no MinIO code is used (D-03).
- **Deployment:** everything runs locally for now. There is no cloud deployment and no AWS S3. The multi-domain production topology of the specification (AVL-001, Part 5) remains a later target.

## Consequences for specification 2.1

- **BKD-002:** rewritten for the local single-node store.
- **New non-guarantee:** in R1, losing the node loses blobs written since the last backup. R1 makes no zero-loss claim for blob content.
- **AVL-001 to AVL-005:** describe the later target topology, not the local setup.
