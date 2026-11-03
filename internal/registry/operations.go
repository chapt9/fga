package registry

import "slices"

// R1 operation names. Each maps to the exact checks it needs (RES-001,
// RES-006, Table "Compound operations for encrypted content"); an adapter
// names the operation and binds resources to its roles, and cannot choose
// other actions (DEC-001).
const (
	OpBeginCreate       = "storage.object.begin-create"
	OpBeginVersion      = "storage.object.begin-version"
	OpStageCreate       = "storage.object.stage-create"
	OpStageVersion      = "storage.object.stage-version"
	OpPublishCreate     = "storage.object.publish-create"
	OpPublishVersion    = "storage.object.publish-version"
	OpStat              = "storage.object.stat"
	OpStatHistory       = "storage.object.stat-history"
	OpRead              = "storage.object.read"
	OpReadHistory       = "storage.object.read-history"
	OpListBucket        = "storage.bucket.list"
	OpListVersions      = "storage.object.list-versions"
	OpDiscover          = "storage.object.discover"
	OpDiscoverHistory   = "storage.object.discover-history"
	OpDelete            = "storage.object.delete"
	OpDeleteVersion     = "storage.object.delete-version"
	OpGetEnvelope       = "storage.envelope.get"
	OpGetEnvelopeOld    = "storage.envelope.get-history"
	OpPublishEnvelope   = "crypto.envelope.publish"
	OpRetireEnvelope    = "crypto.envelope.retire"
	OpEnrollRecipient   = "crypto.recipient.enroll"
	OpActivateRecipient = "crypto.recipient.activate"
	OpRevokeRecipient   = "crypto.recipient.revoke"
	OpLookupRecipient   = "crypto.recipient.discover"
	OpLookupSigner      = "crypto.signing-key.discover"
	// OpReadSelf reads the caller's own record (principal.self).
	OpReadSelf = "principal.self.read"
	// Self-service content-signing keys (RCP-002, RCP-011): enrollment
	// of the caller's planned key, activation by possession proof, and
	// retirement for rotation. Compromise stays an administrator's,
	// journaled operation.
	OpEnrollSigner   = "crypto.signing-key.enroll"
	OpActivateSigner = "crypto.signing-key.activate"
	OpRetireSigner   = "crypto.signing-key.retire"
	OpApproveSigner  = "crypto.signing-key.approve"
	// Labels (LAB-002, LAB-004): a raise or an explicit label at
	// publication is label, a lowering relabel; a classifier proposal is
	// advisory.
	OpLabel                = "storage.object.label"
	OpRelabel              = "storage.object.relabel"
	OpProposeLabel         = "storage.object.propose-label"
	OpPublishCreateLabeled = "storage.object.publish-create-labeled"
	// Approvals (ruling 6): an approver decides with approve on the
	// approval's target.
	OpApproveObject = "storage.object.approve"
	OpApproveBucket = "storage.bucket.approve"
	// OpBucketSetEncryption changes a bucket's encryption mode for uploads
	// begun afterwards (ENC-001).
	OpBucketSetEncryption = "storage.bucket.set-encryption"
	// Server-mode data keys (SSE-003), decided for the keys role and
	// single-use. Sealing gives an upload intent its data key under the
	// write's checks: create-object for a new key, new-version for an
	// existing one. Releasing opens a version's data key under the read's
	// checks; an older version also needs read-history.
	OpKeySealCreate     = "storage.key.seal-create"
	OpKeySealVersion    = "storage.key.seal-version"
	OpKeyRelease        = "storage.key.release"
	OpKeyReleaseHistory = "storage.key.release-history"
	// Server-mode publication (SSE-005): the write's checks without
	// envelopes, since no recipient key is involved.
	OpPublishServerCreate        = "storage.object.publish-server-create"
	OpPublishServerCreateLabeled = "storage.object.publish-server-create-labeled"
	OpPublishServerVersion       = "storage.object.publish-server-version"
	// Server-mode documents (S4a). One decision seals the data keys of
	// every new unit of a document intent, under the document's write
	// check; a unit's or entry's data key is released under the unit read's
	// checks (read-units on the version, read on the unit).
	OpKeySealDocCreate  = "storage.key.seal-document-create"
	OpKeySealDocVersion = "storage.key.seal-document-version"
	OpKeyReleaseUnit    = "storage.key.release-unit"
	OpKeyReleaseEntry   = "storage.key.release-entry"
	// OpKeyReleaseOriginal releases an original file's data key under
	// raw-read on its document version; the release also needs the
	// complete-content decisions (CNT-003, internal/keycheck).
	OpKeyReleaseOriginal = "storage.key.release-original"
	// Server-mode derived outputs (S4b). A new version's data key is sealed
	// under new-version on the output; a version's key is released under
	// deliver on it, with the reader path: the caller's own read (deliver
	// for derived sources) on every source of the transitive lineage
	// (derived.sources), or a declassification for the caller
	// (derived.declassify-reader). A server-mode reader has no recipient key.
	OpKeySealDerivedVersion   = "storage.key.seal-derived-version"
	OpKeyReleaseDerived       = "storage.key.release-derived"
	OpDerivedDeclassifyReader = "derived.declassify-reader"
	// Server-mode derived publication: the write's checks and an explicit
	// label, without envelopes.
	OpDerivedPublishServer        = "derived.publish-server"
	OpDerivedPublishServerVersion = "derived.publish-server-version"
	// Documents (DOC-001 to DOC-004). A publication's checks are split
	// into batches of at most 50 (DEC-009): the document itself, explicit
	// unit labels, reused units, the document version per recipient, and
	// each unit per recipient. The fence admits all of them together.
	OpDocBeginCreate    = "document.begin-create"
	OpDocBeginVersion   = "document.begin-version"
	OpDocPublishCreate  = "document.publish-create"
	OpDocPublishVersion = "document.publish-version"
	OpDocLabelUnits     = "document.label-units"
	OpDocReuseUnits     = "document.reuse-units"
	OpDocShareVersion   = "document.share-version"
	OpDocShareUnits     = "document.share-units"
	OpDocDiscover       = "document.version.discover"

	// Readings of sources (docs/design/mcp-data-tools.md, ING-012): the
	// reading twins of a server-mode document's begin, key seal, unit
	// staging and publication. They have the same checks with post-reading
	// in place of create-object and new-version, so no rule for uploads or
	// owners reaches a post (ReadingOp).
	OpReadingBeginCreate    = "reading.begin-create"
	OpReadingBeginVersion   = "reading.begin-version"
	OpReadingStageCreate    = "reading.stage-create"
	OpReadingStageVersion   = "reading.stage-version"
	OpReadingPublishCreate  = "reading.publish-create"
	OpReadingPublishVersion = "reading.publish-version"
	OpKeySealReadingCreate  = "storage.key.seal-reading-create"
	OpKeySealReadingVersion = "storage.key.seal-reading-version"

	// Disclosure (DOC-006, DOC-007, DSC-001): selecting units, reading a
	// unit's ciphertext, the full manifest, and a unit's envelope from the
	// keys role.
	OpDocSelectUnits     = "document.select-units"
	OpDocReadUnit        = "document.unit.read"
	OpDocManifest        = "document.manifest"
	OpDocGetUnitEnvelope = "document.unit.get-envelope"
	// The encrypted original file (CNT-003): publishing its envelopes, and
	// reading it, which needs raw-read on the version and read on every
	// unit (complete content).
	OpDocShareOriginal       = "document.share-original"
	OpDocRawRead             = "document.raw-read"
	OpDocGetOriginalEnvelope = "document.original.get-envelope"
	// Derived outputs (DRV-001 to DRV-003, DRV-007 to DRV-009). Lineage
	// sources are of three types, so the source roles are optional.
	OpDerivedBegin            = "derived.begin"
	OpDerivedPublish          = "derived.publish"
	OpDerivedSources          = "derived.sources"
	OpDerivedRecipientSources = "derived.recipient-sources"
	OpDerivedDeliver          = "derived.deliver"
	OpDerivedDeclassify       = "derived.declassify"
	OpDerivedShare            = "derived.share"
	OpDerivedGetEnvelope      = "derived.get-envelope"
	OpDerivedBeginVersion     = "derived.begin-version"
	OpDerivedStageVersion     = "derived.stage-version"
	OpDerivedPublishVersion   = "derived.publish-version"
	// Export of document units to a target recipient (Table "Compound
	// operations", V-132 to V-136) and metadata search (SRH-001 to
	// SRH-004).
	OpDocExport         = "document.export"
	OpDocExportEnvelope = "document.export-envelope"
	OpDocSearch         = "document.search"
	// Text entries (DOC-005): a collection's units are text.entry
	// resources. These operations are the unit operations with the entry
	// type, and update in place of the writer's share.
	OpDocReuseEntries     = "collection.reuse-entries"
	OpDocShareEntries     = "collection.share-entries"
	OpDocSelectEntries    = "collection.select-entries"
	OpDocReadEntry        = "collection.entry.read"
	OpDocManifestEntries  = "collection.manifest"
	OpDocGetEntryEnvelope = "collection.entry.get-envelope"
	// Labels of document units and derived outputs (LAB-002, LAB-004), and
	// approvals on them (ruling 6).
	OpUnitLabel      = "document.unit.label"
	OpUnitRelabel    = "document.unit.relabel"
	OpDerivedLabel   = "derived.label"
	OpDerivedRelabel = "derived.relabel"
	OpApproveUnit    = "document.unit.approve"
	// OpApproveVersion decides an approval whose target is a document
	// version, such as a share grant on it (review v3 F03).
	OpApproveVersion = "document.version.approve"
	// OpApproveEntry decides an approval whose target is a collection
	// entry (specification 2.6.2).
	OpApproveEntry = "collection.entry.approve"
	// OpApproveEnvelope and OpApproveRecipient decide approvals whose
	// target is an envelope (its retirement) or a recipient key (its
	// activation or revocation).
	OpApproveEnvelope  = "crypto.envelope.approve"
	OpApproveRecipient = "crypto.recipient.approve"
	OpApproveDerived   = "derived.approve"
	// Withdrawal of documents (PUB-005, DOC-002): deleting the key clears
	// its head; withdrawing a version also withdraws units no live version
	// references any more.
	OpDocDelete        = "document.delete"
	OpDocDeleteVersion = "document.delete-version"
	// Export of a whole object version to a target recipient; the history
	// role is filled for a version that is not current.
	OpObjectExport         = "storage.object.export"
	OpObjectExportEnvelope = "storage.object.export-envelope"
)

// Check roles shared by several operations.
const (
	RoleBucket        = "bucket"
	RoleObject        = "object"
	RoleHistory       = "history"
	RoleEnvelope      = "envelope"
	RoleRecipient     = "recipient"
	RoleSigner        = "signer"
	RoleSelf          = "self"
	RoleShare         = "share"
	RoleRecipientRead = "recipient-read"
	RoleRecipientKey  = "recipient-key"
	RoleLabel         = "label"
	RoleDocument      = "document"
	RoleVersion       = "version"
	RoleUnit          = "unit"
	// RoleRecipientVersion is the recipient's read-units on a document
	// version.
	RoleRecipientVersion = "recipient-version"
	// Derived-output roles.
	RoleOutput           = "output"
	RoleSourceObject     = "source-object"
	RoleSourceUnit       = "source-unit"
	RoleSourceDerived    = "source-derived"
	RoleRecipientDeclass = "recipient-declassify"
	RoleDeclassify       = "declassify"
	// Export roles.
	RoleVersionRead = "version-read"
	RoleUnitExport  = "unit-export"
	RoleObjectRead  = "object-read"
	// RoleGrantTarget is the resource a share grant names.
	RoleGrantTarget = "target"
	// RoleTool is an MCP operation, an agent.tool resource.
	RoleTool = "tool"
)

// MCP operations (MCP-003, specification 2.6.2): calling an MCP tool is
// invoke on its agent.tool resource, and tools/list shows the tools the
// caller may discover. Neither authorizes the content the call reaches,
// which the storage role checks as for any client. A decision for
// OpMCPInvoke, addressed to the storage role, is also what the MCP role
// presents there for the user (TB3).
const (
	OpMCPInvoke   = "mcp.tool.invoke"
	OpMCPDiscover = "mcp.tool.discover"
	// MCPToolNamespace is the alias namespace of the MCP tools.
	MCPToolNamespace = "mcp.tool"
)

// Executor operations (R2, AGT-001, INV-006, INV-009). A registered tool is
// an agent.tool resource "tool:<id>" (alias ToolNamespace) sending to a
// network.destination "destination:<id>" (alias DestinationNamespace); its
// invocation is the operation ToolOperationPrefix+id, whose checks the
// tool's registration records in the catalog (catalog.RegisterTool), since
// the decision role links no tool code. Resolving an UNKNOWN invocation and
// writing off an abandoned one are actions on the tool.
const (
	ToolOperationPrefix  = "tool:"
	ToolNamespace        = "tool"
	DestinationNamespace = "destination"
	OpToolResolve        = "agent.tool.resolve"
	OpToolWriteOff       = "agent.tool.write-off"
	// OpToolApprove decides an approval whose target is a tool: a call
	// that policy lets through only with an approval (APR-001).
	OpToolApprove = "agent.tool.approve"
	// OpToolDiscover lists registered tools: discover on each.
	OpToolDiscover = "agent.tool.discover"
)

// MCPTools are the operations the MCP service offers, each an agent.tool
// resource of every tenant that enables MCP.
var MCPTools = []string{"resources.list", "resources.read", "documents.search", "documents.read", "text.read", "documents.export", "tools.list", "tools.call"}

// mcpReadRoutes are the native API routes an MCP read uses: plaintext of
// server-mode content, and packages and ciphertext of client-mode content.
var mcpReadRoutes = []string{
	"GET /v1/buckets/{bucket}/object/content", "GET /v1/buckets/{bucket}/object/package", "GET /v1/buckets/{bucket}/object/ciphertext",
	"GET /v1/buckets/{bucket}/document/units", "POST /v1/buckets/{bucket}/document/units/select",
	"GET /v1/buckets/{bucket}/document/unit/content", "GET /v1/buckets/{bucket}/document/unit/package",
	"GET /v1/buckets/{bucket}/document/unit/ciphertext",
}

// MCPToolRoutes are the routes of the storage and tools roles on which a
// gateway's decision for each MCP tool stands for the user: the routes
// that tool's calls use, and no other (fga-audit F-06).
var MCPToolRoutes = map[string][]string{
	"resources.list":   {"GET /v1/buckets/{bucket}/objects", "GET /v1/buckets/{bucket}/documents/search"},
	"resources.read":   mcpReadRoutes,
	"documents.search": {"GET /v1/buckets/{bucket}/documents/search"},
	"documents.read":   mcpReadRoutes,
	"text.read":        mcpReadRoutes,
	"documents.export": {"GET /v1/buckets/{bucket}/object/export", "POST /v1/buckets/{bucket}/object/export",
		"GET /v1/buckets/{bucket}/document/units", "POST /v1/buckets/{bucket}/document/units/select",
		"POST /v1/buckets/{bucket}/document/export", "POST /v1/buckets/{bucket}/document/export/content"},
	"tools.list": {"GET /v1/tools"},
	"tools.call": {"POST /v1/invocations"},
}

// CoreOperations returns the registered operations of the core types: R1's
// and the MCP service's.
func CoreOperations(types *Types) *Operations {
	o, err := NewOperations(types, append(r1Operations(), Operation{Name: OpMCPInvoke,
		Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "invoke"}}},
		Operation{Name: OpMCPDiscover, Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "discover", Repeated: true}}},
		Operation{Name: OpToolResolve, Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "resolve"}}},
		Operation{Name: OpToolWriteOff, Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "write-off"}}},
		Operation{Name: OpToolApprove, Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "approve"}}},
		Operation{Name: OpToolDiscover, Checks: []CheckSpec{{Role: RoleTool, ResourceType: "agent.tool", Action: "discover", Repeated: true}}}))
	if err != nil {
		panic(err) // the table is static; a failure is a programming error
	}
	return o
}

// Share grants (SHR-001): recording, removing and listing the grants of a
// resource need share on it. Each grantable type has its own operations,
// named "<type>.record-grant", "<type>.remove-grant" and
// "<type>.list-grants".
const (
	GrantRecord = "record-grant"
	GrantRemove = "remove-grant"
	GrantList   = "list-grants"
)

// GrantOperation names the grant operation verb on resource type typ.
func GrantOperation(typ, verb string) string { return typ + "." + verb }

// envelopeChecks are the publisher and target-recipient checks every
// envelope publication needs, once per envelope (KEY-012, RES-009).
func envelopeChecks(repeated bool) []CheckSpec {
	return []CheckSpec{
		{Role: RoleShare, ResourceType: "storage.object", Action: "share", Repeated: repeated},
		{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create", Repeated: repeated},
		{Role: RoleRecipientRead, ResourceType: "storage.object", Action: "read", Kind: KindRecipientEligibility, Repeated: repeated},
		{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility, Repeated: repeated},
	}
}

func r1Operations() []Operation {
	ops := baseOperations()
	ops = append(ops, entryTwins(ops)...)
	ops = append(ops, readingTwins(ops)...)
	ops = append(ops, grantOperations()...)
	for i := range ops {
		ops[i].Preparatory = preparatory[ops[i].Name]
	}
	return ops
}

// preparatory are the operations that reserve or stage an upload; their
// commits (publish and finalize operations) decide the same rights again.
var preparatory = map[string]bool{
	OpBeginCreate: true, OpBeginVersion: true, OpStageCreate: true, OpStageVersion: true,
	OpDocBeginCreate: true, OpDocBeginVersion: true,
	OpDerivedBegin: true, OpDerivedBeginVersion: true, OpDerivedStageVersion: true,
	OpKeySealCreate: true, OpKeySealVersion: true, OpKeySealDocCreate: true, OpKeySealDocVersion: true, OpKeySealDerivedVersion: true,
	OpReadingBeginCreate: true, OpReadingBeginVersion: true, OpReadingStageCreate: true, OpReadingStageVersion: true,
	OpKeySealReadingCreate: true, OpKeySealReadingVersion: true,
}

// readingOps maps each operation of a server-mode document's write to its
// reading twin (ING-012).
var readingOps = map[string]string{
	OpDocBeginCreate: OpReadingBeginCreate, OpDocBeginVersion: OpReadingBeginVersion,
	OpKeySealDocCreate: OpKeySealReadingCreate, OpKeySealDocVersion: OpKeySealReadingVersion,
	OpStageCreate: OpReadingStageCreate, OpStageVersion: OpReadingStageVersion,
	OpDocPublishCreate: OpReadingPublishCreate, OpDocPublishVersion: OpReadingPublishVersion,
}

// ReadingOp returns the reading twin of a document write operation, and ""
// for any other operation, which no decision is made for.
func ReadingOp(op string) string { return readingOps[op] }

// readingTwins are the reading twins of the document write operations: the
// same roles and resource types, deciding post-reading.
func readingTwins(ops []Operation) []Operation {
	var out []Operation
	for _, op := range ops {
		name, ok := readingOps[op.Name]
		if !ok {
			continue
		}
		twin := Operation{Name: name}
		for _, c := range op.Checks {
			c.Action = "post-reading"
			twin.Checks = append(twin.Checks, c)
		}
		out = append(out, twin)
	}
	return out
}

// entryTwins are the text-entry forms of the unit operations (DOC-005):
// the same checks with text.entry in place of document.text_unit, and
// update, the entry's write action, in place of the writer's share.
func entryTwins(ops []Operation) []Operation {
	twins := map[string]string{OpDocReuseUnits: OpDocReuseEntries, OpDocShareUnits: OpDocShareEntries, OpDocSelectUnits: OpDocSelectEntries,
		OpDocReadUnit: OpDocReadEntry, OpDocManifest: OpDocManifestEntries, OpDocGetUnitEnvelope: OpDocGetEntryEnvelope,
		OpKeyReleaseUnit: OpKeyReleaseEntry}
	var out []Operation
	for _, op := range ops {
		name, ok := twins[op.Name]
		if !ok {
			continue
		}
		twin := Operation{Name: name}
		for _, c := range op.Checks {
			if c.ResourceType == "document.text_unit" {
				c.ResourceType = "text.entry"
				if c.Action == "share" {
					c.Action = "update"
				}
			}
			twin.Checks = append(twin.Checks, c)
		}
		out = append(out, twin)
	}
	return out
}

// grantOperations are the share-grant operations of every grantable type.
func grantOperations() []Operation {
	types := make([]string, 0, len(GrantableActions))
	for typ := range GrantableActions {
		types = append(types, typ)
	}
	slices.Sort(types)
	var out []Operation
	for _, typ := range types {
		for _, verb := range []string{GrantRecord, GrantRemove, GrantList} {
			out = append(out, Operation{Name: GrantOperation(typ, verb),
				Checks: []CheckSpec{{Role: RoleGrantTarget, ResourceType: typ, Action: "share"}}})
		}
	}
	return out
}

func baseOperations() []Operation {
	one := func(name, role, typ, action string) Operation {
		return Operation{Name: name, Checks: []CheckSpec{{Role: role, ResourceType: typ, Action: action}}}
	}
	withHistory := func(name, action, history string) Operation {
		return Operation{Name: name, Checks: []CheckSpec{
			{Role: RoleObject, ResourceType: "storage.object", Action: action},
			{Role: RoleHistory, ResourceType: "storage.object", Action: history},
		}}
	}
	getEnvelope := []CheckSpec{
		{Role: RoleObject, ResourceType: "storage.object", Action: "read"},
		{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
		{Role: RoleRecipientRead, ResourceType: "storage.object", Action: "read", Kind: KindRecipientEligibility},
		{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
	}
	return []Operation{
		one(OpBeginCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpBeginVersion, RoleObject, "storage.object", "new-version"),
		one(OpStageCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpStageVersion, RoleObject, "storage.object", "new-version"),
		{Name: OpPublishCreate, Checks: append([]CheckSpec{{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"}}, envelopeChecks(true)...)},
		{Name: OpPublishVersion, Checks: append([]CheckSpec{{Role: RoleObject, ResourceType: "storage.object", Action: "new-version"}}, envelopeChecks(true)...)},
		one(OpStat, RoleObject, "storage.object", "stat"),
		withHistory(OpStatHistory, "stat", "discover-history"),
		one(OpRead, RoleObject, "storage.object", "read"),
		withHistory(OpReadHistory, "read", "read-history"),
		one(OpListBucket, RoleBucket, "storage.bucket", "list"),
		{Name: OpListVersions, Checks: []CheckSpec{
			{Role: RoleBucket, ResourceType: "storage.bucket", Action: "list"},
			{Role: RoleObject, ResourceType: "storage.object", Action: "discover"},
		}},
		{Name: OpDiscover, Checks: []CheckSpec{{Role: RoleObject, ResourceType: "storage.object", Action: "discover", Repeated: true}}},
		withHistory(OpDiscoverHistory, "discover", "discover-history"),
		one(OpDelete, RoleObject, "storage.object", "delete"),
		one(OpDeleteVersion, RoleObject, "storage.object", "delete-version"),
		{Name: OpGetEnvelope, Checks: getEnvelope},
		{Name: OpGetEnvelopeOld, Checks: append(getEnvelope[:1:1], append([]CheckSpec{{Role: RoleHistory, ResourceType: "storage.object", Action: "read-history"}}, getEnvelope[1:]...)...)},
		{Name: OpPublishEnvelope, Checks: envelopeChecks(false)},
		one(OpRetireEnvelope, RoleEnvelope, "crypto.envelope", "retire"),
		one(OpEnrollRecipient, RoleRecipient, "crypto.recipient", "enroll"),
		one(OpActivateRecipient, RoleRecipient, "crypto.recipient", "activate"),
		one(OpRevokeRecipient, RoleRecipient, "crypto.recipient", "revoke"),
		one(OpLookupRecipient, RoleRecipient, "crypto.recipient", "discover"),
		one(OpLookupSigner, RoleSigner, "crypto.signing-key", "discover"),
		one(OpReadSelf, RoleSelf, "principal.self", "read"),
		one(OpLabel, RoleObject, "storage.object", "label"),
		one(OpRelabel, RoleObject, "storage.object", "relabel"),
		one(OpProposeLabel, RoleObject, "storage.object", "propose-label"),
		{Name: OpPublishCreateLabeled, Checks: append([]CheckSpec{
			{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"},
			{Role: RoleLabel, ResourceType: "storage.object", Action: "label"},
		}, envelopeChecks(true)...)},
		one(OpApproveObject, RoleObject, "storage.object", "approve"),
		one(OpApproveBucket, RoleBucket, "storage.bucket", "approve"),
		one(OpBucketSetEncryption, RoleBucket, "storage.bucket", "manage"),
		one(OpKeySealCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpKeySealVersion, RoleObject, "storage.object", "new-version"),
		one(OpKeyRelease, RoleObject, "storage.object", "read"),
		{Name: OpKeyReleaseHistory, Checks: []CheckSpec{{Role: RoleObject, ResourceType: "storage.object", Action: "read"},
			{Role: RoleHistory, ResourceType: "storage.object", Action: "read-history"}}},
		one(OpPublishServerCreate, RoleBucket, "storage.bucket", "create-object"),
		{Name: OpPublishServerCreateLabeled, Checks: []CheckSpec{{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"},
			{Role: RoleLabel, ResourceType: "storage.object", Action: "label"}}},
		one(OpPublishServerVersion, RoleObject, "storage.object", "new-version"),
		one(OpKeySealDocCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpKeySealDocVersion, RoleDocument, "storage.object", "new-version"),
		one(OpKeyReleaseOriginal, RoleVersion, "document.version", "raw-read"),
		one(OpKeySealDerivedVersion, RoleOutput, "document.derived", "new-version"),
		one(OpKeyReleaseDerived, RoleOutput, "document.derived", "deliver"),
		{Name: OpDerivedPublishServer, Checks: []CheckSpec{{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"},
			{Role: RoleLabel, ResourceType: "document.derived", Action: "label", Optional: true}}},
		{Name: OpDerivedPublishServerVersion, Checks: []CheckSpec{{Role: RoleOutput, ResourceType: "document.derived", Action: "new-version"},
			{Role: RoleLabel, ResourceType: "document.derived", Action: "label", Optional: true}}},
		{Name: OpDerivedDeclassifyReader, Checks: []CheckSpec{{Role: RoleOutput, ResourceType: "document.derived", Action: "deliver"},
			{Role: RoleDeclassify, ResourceType: "document.derived", Action: "declassify"}}, BindsLineage: RoleOutput},
		{Name: OpKeyReleaseUnit, Checks: []CheckSpec{{Role: RoleVersion, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read"}}},
		one(OpDocBeginCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpDocBeginVersion, RoleDocument, "storage.object", "new-version"),
		one(OpDocPublishCreate, RoleBucket, "storage.bucket", "create-object"),
		one(OpDocPublishVersion, RoleDocument, "storage.object", "new-version"),
		{Name: OpDocLabelUnits, Checks: []CheckSpec{{Role: RoleLabel, ResourceType: "document.text_unit", Action: "label", Repeated: true}}},
		{Name: OpDocReuseUnits, Checks: []CheckSpec{{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read", Repeated: true}}},
		{Name: OpDocShareVersion, Checks: []CheckSpec{
			{Role: RoleShare, ResourceType: "document.version", Action: "share", Repeated: true},
			{Role: RoleRecipientRead, ResourceType: "document.version", Action: "read-units", Kind: KindRecipientEligibility, Repeated: true},
		}},
		{Name: OpDocShareUnits, Checks: []CheckSpec{
			{Role: RoleShare, ResourceType: "document.text_unit", Action: "share", Repeated: true},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create", Repeated: true},
			{Role: RoleRecipientRead, ResourceType: "document.text_unit", Action: "read", Kind: KindRecipientEligibility, Repeated: true},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility, Repeated: true},
		}},
		one(OpDocDiscover, RoleVersion, "document.version", "discover"),
		{Name: OpDocSelectUnits, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read", Repeated: true},
		}},
		{Name: OpDocReadUnit, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read"},
		}},
		{Name: OpDocManifest, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read", Repeated: true},
		}},
		{Name: OpDocShareOriginal, Checks: []CheckSpec{
			{Role: RoleShare, ResourceType: "document.version", Action: "share", Repeated: true},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create", Repeated: true},
			{Role: RoleRecipientVersion, ResourceType: "document.version", Action: "raw-read", Kind: KindRecipientEligibility, Repeated: true},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility, Repeated: true},
		}},
		{Name: OpDocRawRead, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "raw-read"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read", Repeated: true},
		}},
		{Name: OpDocGetOriginalEnvelope, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "raw-read"},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
			{Role: RoleRecipientVersion, ResourceType: "document.version", Action: "raw-read", Kind: KindRecipientEligibility},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
		one(OpDerivedBegin, RoleBucket, "storage.bucket", "create-object"),
		{Name: OpDerivedPublish, Checks: []CheckSpec{
			{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"},
			{Role: RoleLabel, ResourceType: "document.derived", Action: "label", Optional: true},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create", Repeated: true},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility, Repeated: true},
		}},
		one(OpDerivedBeginVersion, RoleOutput, "document.derived", "new-version"),
		one(OpDerivedStageVersion, RoleOutput, "document.derived", "new-version"),
		{Name: OpDerivedPublishVersion, Checks: []CheckSpec{
			{Role: RoleOutput, ResourceType: "document.derived", Action: "new-version"},
			{Role: RoleLabel, ResourceType: "document.derived", Action: "label", Optional: true},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create", Repeated: true},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility, Repeated: true},
		}},
		{Name: OpDerivedSources, Checks: sourceChecks(KindOperation)},
		{Name: OpDerivedRecipientSources, Checks: sourceChecks(KindRecipientEligibility)},
		one(OpDerivedDeliver, RoleOutput, "document.derived", "deliver"),
		one(OpUnitLabel, RoleUnit, "document.text_unit", "label"),
		one(OpUnitRelabel, RoleUnit, "document.text_unit", "relabel"),
		one(OpDerivedLabel, RoleOutput, "document.derived", "label"),
		one(OpDerivedRelabel, RoleOutput, "document.derived", "relabel"),
		one(OpApproveUnit, RoleUnit, "document.text_unit", "approve"),
		one(OpApproveVersion, RoleVersion, "document.version", "approve"),
		one(OpApproveEntry, RoleUnit, "text.entry", "approve"),
		one(OpApproveEnvelope, RoleEnvelope, "crypto.envelope", "approve"),
		one(OpApproveRecipient, RoleRecipient, "crypto.recipient", "approve"),
		one(OpEnrollSigner, RoleSigner, "crypto.signing-key", "enroll"),
		one(OpActivateSigner, RoleSigner, "crypto.signing-key", "activate"),
		one(OpRetireSigner, RoleSigner, "crypto.signing-key", "retire"),
		one(OpApproveSigner, RoleSigner, "crypto.signing-key", "approve"),
		one(OpApproveDerived, RoleOutput, "document.derived", "approve"),
		{Name: OpObjectExport, Checks: []CheckSpec{
			{Role: RoleObject, ResourceType: "storage.object", Action: "export"},
			{Role: RoleObjectRead, ResourceType: "storage.object", Action: "read"},
			{Role: RoleHistory, ResourceType: "storage.object", Action: "read-history", Optional: true},
		}},
		{Name: OpObjectExportEnvelope, Checks: []CheckSpec{
			{Role: RoleObject, ResourceType: "storage.object", Action: "export"},
			{Role: RoleObjectRead, ResourceType: "storage.object", Action: "read"},
			{Role: RoleHistory, ResourceType: "storage.object", Action: "read-history", Optional: true},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
			{Role: RoleRecipientRead, ResourceType: "storage.object", Action: "read", Kind: KindRecipientEligibility},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
		one(OpDocDelete, RoleDocument, "storage.object", "delete"),
		one(OpDocDeleteVersion, RoleDocument, "storage.object", "delete-version"),
		{Name: OpDerivedDeclassify, Checks: []CheckSpec{
			{Role: RoleOutput, ResourceType: "document.derived", Action: "deliver"},
			{Role: RoleRecipientDeclass, ResourceType: "document.derived", Action: "declassify", Kind: KindRecipientEligibility},
		}, BindsLineage: RoleOutput},
		{Name: OpDerivedShare, Checks: []CheckSpec{
			{Role: RoleOutput, ResourceType: "document.derived", Action: "deliver"},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "create"},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
		{Name: OpDerivedGetEnvelope, Checks: []CheckSpec{
			{Role: RoleOutput, ResourceType: "document.derived", Action: "deliver"},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
		{Name: OpDocExport, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "export"},
			{Role: RoleVersionRead, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read", Repeated: true},
			{Role: RoleUnitExport, ResourceType: "document.text_unit", Action: "export-key", Repeated: true},
		}},
		{Name: OpDocExportEnvelope, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "export"},
			{Role: RoleVersionRead, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read"},
			{Role: RoleUnitExport, ResourceType: "document.text_unit", Action: "export-key"},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
			{Role: RoleRecipientVersion, ResourceType: "document.version", Action: "read-units", Kind: KindRecipientEligibility},
			{Role: RoleRecipientRead, ResourceType: "document.text_unit", Action: "read", Kind: KindRecipientEligibility},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
		{Name: OpDocSearch, Checks: []CheckSpec{{Role: RoleVersion, ResourceType: "document.version", Action: "discover", Repeated: true}}},
		{Name: OpDocGetUnitEnvelope, Checks: []CheckSpec{
			{Role: RoleVersion, ResourceType: "document.version", Action: "read-units"},
			{Role: RoleUnit, ResourceType: "document.text_unit", Action: "read"},
			{Role: RoleEnvelope, ResourceType: "crypto.envelope", Action: "release"},
			{Role: RoleRecipientVersion, ResourceType: "document.version", Action: "read-units", Kind: KindRecipientEligibility},
			{Role: RoleRecipientRead, ResourceType: "document.text_unit", Action: "read", Kind: KindRecipientEligibility},
			{Role: RoleRecipientKey, ResourceType: "crypto.recipient", Action: "receive-key", Kind: KindRecipientEligibility},
		}},
	}
}

// R1Operations returns the registered operations of release R1.
func R1Operations(types *Types) *Operations {
	o, err := NewOperations(types, r1Operations())
	if err != nil {
		panic(err) // the table is static; a failure is a programming error
	}
	return o
}

// sourceChecks are the checks on a derived output's lineage sources:
// read on objects and units, deliver on other derived outputs, for the
// caller (OPERATION) or a recipient (RECIPIENT_ELIGIBILITY). Each role is
// optional because a lineage need not name every type.
func sourceChecks(kind CheckKind) []CheckSpec {
	return []CheckSpec{
		{Role: RoleSourceObject, ResourceType: "storage.object", Action: "read", Kind: kind, Repeated: true, Optional: true},
		{Role: RoleSourceUnit, ResourceType: "document.text_unit", Action: "read", Kind: kind, Repeated: true, Optional: true},
		{Role: RoleSourceDerived, ResourceType: "document.derived", Action: "deliver", Kind: kind, Repeated: true, Optional: true},
	}
}
