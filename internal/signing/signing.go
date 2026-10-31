// Package signing signs allowed decisions so that another role can verify
// that the sole policy authority made them, and consumes single-use
// decisions exactly once (specification 2.5, DEC-008, DEC-011, DEC-012,
// TRU-003, TRU-004).
//
// The record is JSON, signed exactly as transmitted, with a detached JWS
// (EdDSA). Verifiers parse it strictly. A valid signature does not replace
// the fresh revision checks of the gate.
package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"fga/internal/strictjson"
)

// RecordVersion identifies the record format.
const RecordVersion = "fga.decision/v2"

// NoObligations is the obligation mapping of release R1: no policy output is
// mapped to an obligation (POL-011), so a signed allow carries an empty
// obligation set. A record with any obligation, or another mapping version,
// is rejected, because an enforcement point must not act on obligations it
// does not understand (DEC-002).
const NoObligations = "fga.obligations/none-v1"

// ObligationsV1 is the obligation mapping a release may configure
// (POL-011): its obligations carry their parameters, which their digest
// binds. An enforcement point accepts a decision under it only if it can
// apply every obligation the decision carries (DEC-002, APR-007).
const ObligationsV1 = "fga.obligations/v1"

// Obligation types of ObligationsV1.
const (
	// MetadataProjection limits the metadata a response returns to the
	// fields named by its parameters: {"fields": [...]}.
	MetadataProjection = "metadata_projection"
	// Reservation requires the enforcing role to reserve the operation's
	// budget and commit the reservation with the operation (APR-004);
	// parameters: {}.
	Reservation = "reservation"
)

// MaxClockSkew is tolerated between the signer's and verifier's clocks.
const MaxClockSkew = 5 * time.Second

// Errors returned by verification and consumption.
var (
	ErrSignature   = errors.New("decision signature does not verify")
	ErrUnknownKey  = errors.New("decision signed with an unknown key")
	ErrRevokedKey  = errors.New("decision signed with a revoked key")
	ErrKeyValidity = errors.New("decision issued outside its key's validity")
	ErrRecord      = errors.New("malformed decision record")
	ErrAudience    = errors.New("decision is for another audience")
	ErrExpired     = errors.New("decision expired")
	ErrNotYetValid = errors.New("decision issued in the future")
	ErrReplayed    = errors.New("single-use decision already consumed")
	ErrObligation  = errors.New("decision carries obligations this enforcement point cannot apply")
	ErrBinding     = errors.New("decision's binding digests do not match its content")
)

// Ref names an identity at a revision.
type Ref struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// Check is one allowed check, the principal it was evaluated for, its
// effects and the resource state it was bound to.
type Check struct {
	ID string `json:"id"`
	// Kind is OPERATION or RECIPIENT_ELIGIBILITY. A recipient check names
	// the key fingerprint it was bound to and the key's revision.
	Kind             string `json:"kind"`
	PrincipalBinding string `json:"principal_binding"`
	Principal        Ref    `json:"principal"`
	KeyRevision      uint64 `json:"key_revision"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	// Version is the exact immutable version the check is bound to, when
	// the operation names one.
	Version          string   `json:"version"`
	Generation       uint64   `json:"generation"`
	MetadataRevision uint64   `json:"metadata_revision"`
	Action           string   `json:"action"`
	BusinessEffect   string   `json:"business_effect"`
	CeilingEffect    string   `json:"ceiling_effect"`
	Requires         []string `json:"requires"`
}

// Context holds the revisions of the decision's context facts beyond
// identities, delegation and resources (DEC-008).
type Context struct {
	LabelOrderGeneration uint64 `json:"label_order_generation"`
	// Approval names a satisfied approval the decision relied on, if any
	// (DEC-002).
	Approval Ref `json:"approval"`
}

// Obligation is one platform obligation of a decision (APR-007).
type Obligation struct {
	Type    string `json:"type"`
	Version uint64 `json:"version"`
	// Parameters are the obligation's parameters, canonical JSON, which
	// ParametersDigest names.
	Parameters          json.RawMessage `json:"parameters,omitempty"`
	ParametersDigest    string          `json:"parameters_digest"`
	ReferencedRevisions []Ref           `json:"referenced_revisions"`
}

// ParametersDigest is the digest of an obligation's parameters.
func ParametersDigest(parameters []byte) string {
	sum := sha256.Sum256(append([]byte("fga.obligation-parameters/v1\n"), parameters...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Has reports whether rec carries an obligation of type t.
func (rec Record) Has(t string) bool {
	return slices.ContainsFunc(rec.Obligations, func(o Obligation) bool { return o.Type == t })
}

// Obligation returns rec's obligation of type t, if any.
func (rec Record) Obligation(t string) (Obligation, bool) {
	i := slices.IndexFunc(rec.Obligations, func(o Obligation) bool { return o.Type == t })
	if i < 0 {
		return Obligation{}, false
	}
	return rec.Obligations[i], true
}

// Record is the signed content of an allowed decision (DEC-008): audience,
// tenant and recovery incarnation; actor, subject, delegation chain and
// context with revisions; the registered operation and its digest; every
// check with its principal, effects and bound resource state; the policy
// snapshot; the complete obligation set; and the validity window.
type Record struct {
	Version             string `json:"version"`
	DecisionID          string `json:"decision_id"`
	Audience            string `json:"audience"`
	Tenant              string `json:"tenant"`
	RecoveryIncarnation uint64 `json:"recovery_incarnation"`
	// Adapter is the authenticated workload that requested the decision.
	Adapter         string  `json:"adapter"`
	Actor           Ref     `json:"actor"`
	Subject         Ref     `json:"subject"`
	Delegation      string  `json:"delegation"`
	DelegationChain []Ref   `json:"delegation_chain"`
	Context         Context `json:"context_revisions"`
	Operation       string  `json:"operation"`
	OperationID     string  `json:"operation_id"`
	OperationDigest string  `json:"operation_digest"`
	Checks          []Check `json:"checks"`
	// ResourceBindingsDigest covers every check's resource binding; it
	// lets an enforcement point compare one value with its own plan.
	ResourceBindingsDigest   string       `json:"resource_bindings_digest"`
	BundleDigest             string       `json:"bundle_digest"`
	PolicyEpoch              uint64       `json:"policy_epoch"`
	EvaluatorVersion         string       `json:"evaluator_version"`
	ObligationMappingVersion string       `json:"obligation_mapping_version"`
	ObligationsDigest        string       `json:"obligations_digest"`
	Obligations              []Obligation `json:"obligations"`
	SingleUse                bool         `json:"single_use"`
	IssuedAt                 time.Time    `json:"issued_at"`
	ValidUntil               time.Time    `json:"valid_until"`
}

// ResourceBindingsDigest is the digest of the checks' resource bindings, in
// check order.
func ResourceBindingsDigest(checks []Check) string {
	h := sha256.New()
	h.Write([]byte("fga.resource-bindings/v1\n"))
	for _, c := range checks {
		fmt.Fprintf(h, "%q %q %q %q %d %d\n", c.ID, c.ResourceType, c.ResourceID, c.Version, c.Generation, c.MetadataRevision)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ObligationsDigest is the digest of an obligation set under a mapping
// version.
func ObligationsDigest(mapping string, obligations []Obligation) string {
	h := sha256.New()
	fmt.Fprintf(h, "fga.obligations/v1\n%q\n", mapping)
	for _, o := range obligations {
		fmt.Fprintf(h, "%q %d %q %d\n", o.Type, o.Version, o.ParametersDigest, len(o.ReferencedRevisions))
		for _, r := range o.ReferencedRevisions {
			fmt.Fprintf(h, "%q %d\n", r.ID, r.Revision)
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Signed is a record's exact bytes and its detached compact JWS.
type Signed struct {
	Payload []byte
	JWS     string
}

// EvidencePrefix marks a signed decision presented on a later hop as the
// proof of who the user is (TRU-003, TB3): the MCP role's decision for a
// tool call, which the storage role accepts from it and passes to the
// decision role as evidence.
const EvidencePrefix = "fga-decision:"

// Evidence encodes s for a header or an evidence field.
func (s Signed) Evidence() string {
	return EvidencePrefix + base64.RawURLEncoding.EncodeToString(s.Payload) + ":" + s.JWS
}

// ParseEvidence decodes Evidence. It verifies nothing.
func ParseEvidence(e string) (Signed, bool) {
	rest, ok := strings.CutPrefix(e, EvidencePrefix)
	if !ok {
		return Signed{}, false
	}
	payload, jws, ok := strings.Cut(rest, ":")
	if !ok || jws == "" {
		return Signed{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(b) == 0 {
		return Signed{}, false
	}
	return Signed{Payload: b, JWS: jws}, true
}

// Signer signs records with one decision-signing key.
type Signer struct {
	signer jose.Signer
	public ed25519.PublicKey
}

// Public is the signing key's public half.
func (s *Signer) Public() ed25519.PublicKey { return s.public }

// NewSigner returns a signer for the key with the given ID. The key is used
// for nothing but decision signing (DEC-012).
func NewSigner(keyID string, key ed25519.PrivateKey) (*Signer, error) {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("fga-decision+jws"))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return &Signer{signer: s, public: key.Public().(ed25519.PublicKey)}, nil
}

// Sign fills in the record's version and digests, serializes it once and
// signs those bytes. A record without an obligation mapping gets the R1
// mapping and an empty obligation set.
func (s *Signer) Sign(rec Record) (Signed, error) {
	rec.Version = RecordVersion
	if rec.ObligationMappingVersion == "" {
		rec.ObligationMappingVersion = NoObligations
	}
	if rec.Obligations == nil {
		rec.Obligations = []Obligation{}
	}
	rec.ObligationsDigest = ObligationsDigest(rec.ObligationMappingVersion, rec.Obligations)
	rec.ResourceBindingsDigest = ResourceBindingsDigest(rec.Checks)
	payload, err := json.Marshal(rec)
	if err != nil {
		return Signed{}, fmt.Errorf("signing: encode record: %w", err)
	}
	return s.signBytes(payload)
}

func (s *Signer) signBytes(payload []byte) (Signed, error) {
	obj, err := s.signer.Sign(payload)
	if err != nil {
		return Signed{}, fmt.Errorf("signing: %w", err)
	}
	compact, err := obj.DetachedCompactSerialize()
	if err != nil {
		return Signed{}, fmt.Errorf("signing: %w", err)
	}
	return Signed{Payload: payload, JWS: compact}, nil
}

// Key is a verification key and the period in which it may sign. Rotation
// adds a new key before the old one's NotAfter; revocation is immediate
// (DEC-012).
type Key struct {
	Public    ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
}

// Consumption records single-use decisions. Consume must be atomic and
// durable, and shared by every replica of the verifying role (DEC-011).
type Consumption interface {
	// Consume returns true the first time a decision ID is consumed and false
	// afterwards. An error means it could not record the consumption.
	Consume(ctx context.Context, decisionID string, until time.Time) (bool, error)
}

// Verifier verifies decisions for one audience (one role).
type Verifier struct {
	audience    string
	keys        func() map[string]Key
	consumption Consumption
	now         func() time.Time
	applies     func(operation, obligation string) bool
}

// Applying makes v accept decisions under ObligationsV1 whose every
// obligation applies reports it can apply to the decision's operation.
// Without it, v accepts no obligation at all.
func (v *Verifier) Applying(applies func(operation, obligation string) bool) *Verifier {
	v.applies = applies
	return v
}

// NewVerifier returns a verifier for audience. keys returns the current key
// set, so rotation and revocation take effect without a restart.
func NewVerifier(audience string, keys func() map[string]Key, consumption Consumption, now func() time.Time) *Verifier {
	return &Verifier{audience: audience, keys: keys, consumption: consumption, now: now}
}

// Verify checks the signature, key, record, audience and validity, and
// consumes a single-use decision. It returns the record only if all hold.
func (v *Verifier) Verify(ctx context.Context, s Signed) (Record, error) {
	rec, err := v.check(s, true)
	if err != nil {
		return Record{}, err
	}
	if rec.SingleUse {
		first, err := v.consumption.Consume(ctx, rec.DecisionID, rec.ValidUntil)
		if err != nil {
			return Record{}, fmt.Errorf("signing: record consumption: %w", err)
		}
		if !first {
			return Record{}, ErrReplayed
		}
	}
	return rec, nil
}

// Audience returns the audience the verifier accepts.
func (v *Verifier) Audience() string { return v.audience }

// Check verifies like Verify but consumes nothing. The caller must consume
// a single-use decision itself, atomically with the protected transition
// it authorizes (DEC-011): the authority fence does.
func (v *Verifier) Check(s Signed) (Record, error) {
	return v.check(s, true)
}

// Inspect checks a decision's signature, key, record and validity for any
// audience and consumes nothing. The decision role uses it to recheck its
// own decisions for the roles that will act on them.
func (v *Verifier) Inspect(s Signed) (Record, error) {
	return v.check(s, false)
}

func (v *Verifier) check(s Signed, matchAudience bool) (Record, error) {
	obj, err := jose.ParseDetached(s.JWS, s.Payload, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(obj.Signatures) != 1 {
		return Record{}, ErrSignature
	}
	key, ok := v.keys()[obj.Signatures[0].Header.KeyID]
	switch {
	case !ok:
		return Record{}, ErrUnknownKey
	case key.Revoked:
		return Record{}, ErrRevokedKey
	}
	if err := obj.DetachedVerify(s.Payload, key.Public); err != nil {
		return Record{}, ErrSignature
	}

	var rec Record
	if err := strictjson.Decode(s.Payload, &rec); err != nil || rec.Version != RecordVersion || rec.DecisionID == "" || len(rec.Checks) == 0 {
		return Record{}, fmt.Errorf("%w: %v", ErrRecord, err)
	}
	if err := v.obligations(rec); err != nil {
		return Record{}, err
	}
	if rec.ObligationsDigest != ObligationsDigest(rec.ObligationMappingVersion, rec.Obligations) ||
		rec.ResourceBindingsDigest != ResourceBindingsDigest(rec.Checks) {
		return Record{}, ErrBinding
	}
	for _, c := range rec.Checks {
		if c.BusinessEffect != "ALLOW" || c.CeilingEffect != "PASS" || !satisfied(c.Requires, rec) {
			return Record{}, fmt.Errorf("%w: check %q is not an unconditional allow", ErrRecord, c.ID)
		}
		if (c.Kind == "RECIPIENT_ELIGIBILITY") != (c.PrincipalBinding != "") || (c.Kind != "OPERATION" && c.Kind != "RECIPIENT_ELIGIBILITY") {
			return Record{}, fmt.Errorf("%w: check %q has an inconsistent kind", ErrRecord, c.ID)
		}
	}
	if slices.ContainsFunc(rec.Checks, func(c Check) bool { return c.ID == "" }) {
		return Record{}, fmt.Errorf("%w: a check has no ID", ErrRecord)
	}
	now := v.now()
	switch {
	case rec.IssuedAt.Before(key.NotBefore) || !rec.IssuedAt.Before(key.NotAfter):
		return Record{}, ErrKeyValidity
	case matchAudience && rec.Audience != v.audience:
		return Record{}, ErrAudience
	case rec.IssuedAt.After(now.Add(MaxClockSkew)):
		return Record{}, ErrNotYetValid
	case !now.Before(rec.ValidUntil):
		return Record{}, ErrExpired
	}
	return rec, nil
}

// satisfied reports whether a check's prerequisites are met by the record
// itself: the only prerequisite a record can satisfy is an approval, and
// only by binding one, which the fence consumes (APR-002). A reservation
// (R2) is never satisfied here.
func satisfied(requires []string, rec Record) bool {
	for _, r := range requires {
		switch {
		case r == "approval" && rec.Context.Approval.ID != "":
		case r == "reservation" && rec.Has(Reservation):
		default:
			return false
		}
	}
	return true
}

// obligations admits rec's obligation set: none under NoObligations;
// under ObligationsV1, only obligations whose parameters match their
// digest and that this enforcement point applies to the operation.
func (v *Verifier) obligations(rec Record) error {
	switch rec.ObligationMappingVersion {
	case NoObligations:
		if len(rec.Obligations) != 0 {
			return ErrObligation
		}
	case ObligationsV1:
		for _, o := range rec.Obligations {
			switch {
			case o.Version != 1 || o.ParametersDigest != ParametersDigest(o.Parameters):
				return ErrBinding
			case v.applies == nil || !v.applies(rec.Operation, o.Type):
				return ErrObligation
			}
		}
	default:
		return ErrObligation
	}
	return nil
}
