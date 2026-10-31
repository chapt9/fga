# Dependency record: MCP Go SDK (LIB-002, MCP-001)

| Field | Record |
|---|---|
| Module | `github.com/modelcontextprotocol/go-sdk` v1.8.0 (`h1:KIvahhYqwtbeniWVPs3TcXEA7b8jEtwfBpOTAI+Urx4=`), published 4 September 2026, the latest stable release (no v2 module). Module zip 691 KB, from `proxy.golang.org`. It goes into `go.mod` and `go.sum` with the MCP role (R2 stretch M2) |
| Owner | The MCP role only (`cmd/fga-mcp`), and the local bridge in `cmd/fga`. No other role may link it: an import guard rejects it elsewhere (V-137) |
| License | From the module's `LICENSE` (31 October 2026): the project is moving from MIT to Apache-2.0. New code is Apache-2.0, code whose authors have not consented to relicensing stays MIT, and documentation is CC-BY-4.0. The file carries the full Apache-2.0 and MIT texts (copyright Model Context Protocol a Series of LF Projects, LLC). Notices are to be carried in `LICENSES/` before distribution |
| Why | MCP-001 requires the official MCP Go SDK for protocol transport and JSON-RPC: the `mcp` package's server and client, the streamable HTTP and stdio transports. Project code supplies only the mapping to the storage API |
| Alternatives | A hand-written MCP transport, which MCP-001 rules out as the default |
| Maintainers | The Model Context Protocol project, with Google. Active: last push 30 October 2026 |
| Advisories | None checked yet. `govulncheck` must run before release (LIB-003) |
| Our evidence | To come with stretch M2: the MCP role's tests and smoke steps |
| Transitive footprint | A program importing only the `mcp` package links 29 non-standard packages from these modules: `github.com/google/jsonschema-go` v0.4.3 (MIT), `github.com/segmentio/encoding` v0.5.4 (MIT), `github.com/segmentio/asm` v1.1.3 (MIT), `github.com/yosida95/uritemplate/v3` v3.0.2 (BSD-3-Clause), `golang.org/x/oauth2` v0.35.0 and `golang.org/x/time` v0.15.0 (BSD-3-Clause), plus `x/sync` and `x/sys`, already used here at newer versions. The SDK's `go.mod` also names `golang-jwt/jwt/v5` (only its `auth` package), `golang.org/x/tools` and `google/go-cmp`; the `mcp` package links none of them. The MCP role's allowlist will list the linked packages |
| API stability | v1, semantic versioning. Upgrades are reviewed, and the MCP role's tests must pass before any upgrade |
| Replacement path | The MCP role keeps the SDK behind its own handler mapping, so a replacement changes the transport layer only |
