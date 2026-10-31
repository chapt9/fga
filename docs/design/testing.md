# Tests: conventions

Status: design record, 31 October 2026.

## What a test is for

Every test names what it covers in its doc comment: a requirement (`covers DOC-007`), a validation vector (`V-169`), or a review finding (`the regression test of review v3 F05`). A test that would name nothing new is not added. Where the same requirement is checked at two layers, for example the content service and the HTTP route, each test covers what only its layer can get wrong: the service's checks, or the route's encoding, status codes and SDK.

## Shape

- **One flow, several variants:** a table of cases or subtests, not copies. Examples: `TestGrantApprovals` (a document version and a collection entry), and `TestServerApprovals` (objects and derived outputs in one flow).
- **Fixtures are shared, not copied:**
  - `internal/r1test`: the whole stack in process, plus `Stack.Count` and `Stack.UnitIDs`;
  - `internal/mcptest`: the MCP role deployed over HTTP, plus the client-mode fixture;
  - `internal/pgtest`: a database schema of its own per test.
- **Regression tests** stay separate tests named after their finding, so a finding can be traced to its test.

## Checking a cleanup

A change that merges or removes tests is checked by whole-suite coverage, before and after:

```bash
FGA_TEST_DATABASE_URL=… go test -count=1 -coverpkg=fga/... -coverprofile=cover.out ./...
```

A function whose coverage drops gets a look:
- A conflict branch reached only by a race moves from run to run; that is not a loss.
- A branch that only one test covered by accident gets a deterministic test.

The 31 October 2026 cleanup:
- **Coverage:** 70.3% before and after.
- **Merges:** two same-flow pairs, and the copied `unitIDs` and row-count helpers.
- **Added:** a deterministic test of a derived stream ending when its own authority changes. Before, only timing in another test reached that branch.
