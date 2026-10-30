// Package signing signs allowed decisions so that another role can verify
// that the sole policy authority made them, and consumes single-use
// decisions exactly once (specification 2.2, DEC-008, DEC-011, DEC-012,
// TRU-003, TRU-004).
//
// The record is JSON, signed exactly as transmitted, with a detached JWS
// (EdDSA). Verifiers parse it strictly. A valid signature does not replace
// the fresh revision checks of the gate.
package signing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"

	"fga/internal/strictjson"
)

// RecordVersion identifies the record format.
const RecordVersion = "fga.decision/v1"

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
)

// Ref names an identity at a revision.
type Ref struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// Check is one allowed check and the resource state it was bound to.
type Check struct {
	ID               string `json:"id"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	Generation       uint64 `json:"generation"`
	MetadataRevision uint64 `json:"metadata_revision"`
	Action           string `json:"action"`
}

// Record is the signed content of an allowed decision.
type Record struct {
	Version             string    `json:"version"`
	DecisionID          string    `json:"decision_id"`
	Audience            string    `json:"audience"`
	Tenant              string    `json:"tenant"`
	Actor               Ref       `json:"actor"`
	Subject             Ref       `json:"subject"`
	Delegation          string    `json:"delegation"`
	DelegationRevisions []uint64  `json:"delegation_revisions"`
	OperationDigest     string    `json:"operation_digest"`
	Checks              []Check   `json:"checks"`
	BundleDigest        string    `json:"bundle_digest"`
	PolicyEpoch         uint64    `json:"policy_epoch"`
	SingleUse           bool      `json:"single_use"`
	IssuedAt            time.Time `json:"issued_at"`
	ValidUntil          time.Time `json:"valid_until"`
}

// Signed is a record's exact bytes and its detached compact JWS.
type Signed struct {
	Payload []byte
	JWS     string
}

// Signer signs records with one decision-signing key.
type Signer struct {
	signer jose.Signer
}

// NewSigner returns a signer for the key with the given ID. The key is used
// for nothing but decision signing (DEC-012).
func NewSigner(keyID string, key ed25519.PrivateKey) (*Signer, error) {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("fga-decision+jws"))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return &Signer{signer: s}, nil
}

// Sign serializes rec once and signs those bytes.
func (s *Signer) Sign(rec Record) (Signed, error) {
	rec.Version = RecordVersion
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
}

// NewVerifier returns a verifier for audience. keys returns the current key
// set, so rotation and revocation take effect without a restart.
func NewVerifier(audience string, keys func() map[string]Key, consumption Consumption, now func() time.Time) *Verifier {
	return &Verifier{audience: audience, keys: keys, consumption: consumption, now: now}
}

// Verify checks the signature, key, record, audience and validity, and
// consumes a single-use decision. It returns the record only if all hold.
func (v *Verifier) Verify(ctx context.Context, s Signed) (Record, error) {
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
	if err := strictjson.Decode(s.Payload, &rec); err != nil || rec.Version != RecordVersion || rec.DecisionID == "" {
		return Record{}, fmt.Errorf("%w: %v", ErrRecord, err)
	}
	now := v.now()
	switch {
	case rec.IssuedAt.Before(key.NotBefore) || !rec.IssuedAt.Before(key.NotAfter):
		return Record{}, ErrKeyValidity
	case rec.Audience != v.audience:
		return Record{}, ErrAudience
	case rec.IssuedAt.After(now.Add(MaxClockSkew)):
		return Record{}, ErrNotYetValid
	case !now.Before(rec.ValidUntil):
		return Record{}, ErrExpired
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
