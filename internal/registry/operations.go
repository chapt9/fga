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
