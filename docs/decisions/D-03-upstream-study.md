# D-03: Upstream study and licensing

- **Status:** decided in principle 30 October 2026. The license record below must be completed before the first distribution.
- **Rule:** MinIO and Cerbos are studied for ideas, behavior and design. Their code is not copied, translated, paraphrased or reproduced from memory. All code is written from this project's specification (SRC-001).
- **Why:** to keep the freedom to choose the license of the project's own code.

## License record (to verify at the studied revisions)

| Upstream | Expected license | Consequence if code were copied |
|---|---|---|
| MinIO | AGPL-3.0 | Copyleft, including the network-use clause, would apply to the derived work |
| Cerbos | Apache-2.0 | Allowed with notices; not used anyway, by choice |

## Practice

- Copyright protects expression, not ideas, algorithms or interfaces. Close paraphrase or a structural translation can still count as copying, so code is written from requirements, not from upstream files.
- Each studied mechanism is recorded in the evaluation matrix (SRC-002) with its source revision and what was adopted.
- Independent implementation does not protect against patents, and names are trademarks: neither "MinIO" nor "Cerbos" is used in product names.
- General-purpose libraries are separate dependencies. Each gets the license and maintenance record of LIB-002.
- Before distribution, a qualified person reviews the license record (SRC-004, GATE-001).
