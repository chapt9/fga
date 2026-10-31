# D-06: Label order and label sources

- **Status:** decided by the owner, 31 October 2026.
- **Order.** One total order per deployment, carried in the signed policy release (`label_order` with `label_generation`, REL-001, FLW-004). The initial order is `public` < `internal` < `confidential` < `restricted`. The order is immutable within a generation; a new order is a new release with a new generation. A unit or output with no label, or with a label outside the order, counts as the highest level.
- **Sources, in order of precedence (LAB-002):**
  1. explicit labeling by a principal whose policy allows `label` (raising, or setting at publication) or `relabel` (lowering) on the resource; never below the collection's floor;
  2. the collection's default, where a collection is a bucket; the default is also the collection's floor (LAB-003);
  3. a signed proposal from a client classifier, which is advisory and never applied until a principal applies it under (1).
- **Lineage.** Any client signing with its own active content-signing key may declare lineage (DRV-001). The server validates signer authority, references, bounds and cycles; it cannot prove that the declaration is complete.
- **Not decided here:** per-tenant orders (a later release can add them), and a registry of trusted classifier workloads (proposals stay advisory either way).
