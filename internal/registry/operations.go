package registry

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
	OpApproveDerived = "derived.approve"
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
	// Export roles.
	RoleVersionRead = "version-read"
	RoleUnitExport  = "unit-export"
	RoleObjectRead  = "object-read"
)

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
}

// entryTwins are the text-entry forms of the unit operations (DOC-005):
// the same checks with text.entry in place of document.text_unit, and
// update, the entry's write action, in place of the writer's share.
func entryTwins(ops []Operation) []Operation {
	twins := map[string]string{OpDocReuseUnits: OpDocReuseEntries, OpDocShareUnits: OpDocShareEntries, OpDocSelectUnits: OpDocSelectEntries,
		OpDocReadUnit: OpDocReadEntry, OpDocManifest: OpDocManifestEntries, OpDocGetUnitEnvelope: OpDocGetEntryEnvelope}
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
		one(OpLabel, RoleObject, "storage.object", "label"),
		one(OpRelabel, RoleObject, "storage.object", "relabel"),
		one(OpProposeLabel, RoleObject, "storage.object", "propose-label"),
		{Name: OpPublishCreateLabeled, Checks: append([]CheckSpec{
			{Role: RoleBucket, ResourceType: "storage.bucket", Action: "create-object"},
			{Role: RoleLabel, ResourceType: "storage.object", Action: "label"},
		}, envelopeChecks(true)...)},
		one(OpApproveObject, RoleObject, "storage.object", "approve"),
		one(OpApproveBucket, RoleBucket, "storage.bucket", "approve"),
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
		}},
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
