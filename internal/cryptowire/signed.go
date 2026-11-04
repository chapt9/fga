package cryptowire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-jose/go-jose/v4"

	"fga/internal/strictjson"
)

// JWS types of the signed objects of profile 1. A signature verifies only
// as the type it was made for.
const (
	TypeDescriptor   = "fga-descriptor+jws"
	TypeEnvelope     = "fga-envelope+jws"
	TypeReceipt      = "fga-receipt+jws"
	TypeSigningProof = "fga-signing-proof+jws"
	// TypeLabelProposal signs a classifier's label proposal (LAB-002).
	TypeLabelProposal = "fga-label-proposal+jws"
)

// ErrSignature is returned for a signature that does not verify, has the
// wrong type, or comes from an untrusted key.
var ErrSignature = errors.New("cryptowire: signature does not verify")

// Sign returns a detached compact JWS (EdDSA) of payload with the given
// type and key ID.
func Sign(typ, keyID string, key ed25519.PrivateKey, payload []byte) (string, error) {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", err
	}
	obj, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.DetachedCompactSerialize()
}

// Verify checks a detached JWS of payload: one EdDSA signature of type typ
// by the key that keyFor returns for its key ID. It returns the key ID.
func Verify(typ, jws string, payload []byte, keyFor func(keyID string) (ed25519.PublicKey, error)) (string, error) {
	if len(jws) > MaxSignatureBytes {
		return "", ErrSignature
	}
	obj, err := jose.ParseDetached(jws, payload, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(obj.Signatures) != 1 {
		return "", ErrSignature
	}
	h := obj.Signatures[0].Header
	if t, _ := h.ExtraHeaders[jose.HeaderType].(string); t != typ || h.JSONWebKey != nil {
		return "", ErrSignature
	}
	key, err := keyFor(h.KeyID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if err := obj.DetachedVerify(payload, key); err != nil {
		return "", ErrSignature
	}
	return h.KeyID, nil
}

// Descriptor is the signed ciphertext descriptor of one immutable version
// (CRY-004, RCP-008). Its JSON bytes are signed exactly as transmitted.
type Descriptor struct {
	Version          string    `json:"version"`
	TenantID         string    `json:"tenant_id"`
	ObjectID         string    `json:"object_id"`
	LogicalVersionID string    `json:"logical_version_id"`
	CryptoVersionID  string    `json:"crypto_version_id"`
	BlobID           string    `json:"blob_id"`
	AttemptID        string    `json:"attempt_id"`
	Suite            uint16    `json:"suite"`
	Format           uint16    `json:"format"`
	CiphertextSHA256 string    `json:"ciphertext_sha256"`
	CiphertextLength uint64    `json:"ciphertext_length"`
	Signer           string    `json:"signer"`
	CreatedAt        time.Time `json:"created_at"`
	// KeyCommitment is KeyCommitment of the key package every envelope of
	// the version wraps, so one signed version decrypts to one plaintext
	// for every recipient (security review of 4 November 2026, finding 5).
	// Descriptors from before it carry none.
	KeyCommitment string `json:"key_commitment,omitempty"`
}

// DescriptorVersion is the only supported Descriptor.Version.
const DescriptorVersion = "fga.descriptor/v1"

// Marshal encodes d once for signing.
func (d Descriptor) Marshal() ([]byte, error) {
	d.Version = DescriptorVersion
	d.CreatedAt = d.CreatedAt.UTC().Truncate(time.Second)
	b, err := json.Marshal(d)
	if err != nil || len(b) > MaxDescriptorBytes {
		return nil, formatErr("descriptor")
	}
	if _, err := ParseDescriptor(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseDescriptor parses strictly and checks every identifier, digest,
// profile and length.
func ParseDescriptor(b []byte) (Descriptor, error) {
	var d Descriptor
	if len(b) > MaxDescriptorBytes {
		return d, formatErr("descriptor size")
	}
	if err := strictjson.Decode(b, &d); err != nil {
		return d, formatErr("descriptor: %v", err)
	}
	for _, id := range []string{d.TenantID, d.ObjectID, d.LogicalVersionID, d.CryptoVersionID, d.BlobID, d.AttemptID} {
		if _, err := ParseUUID(id); err != nil {
			return d, err
		}
	}
	if _, err := ParseDigest(d.CiphertextSHA256); err != nil {
		return d, err
	}
	if _, err := ParseDigest(d.Signer); err != nil {
		return d, err
	}
	if d.KeyCommitment != "" {
		if _, err := ParseDigest(d.KeyCommitment); err != nil {
			return d, err
		}
	}
	if d.Version != DescriptorVersion || !SupportedProfile(d.Suite, d.Format) || d.CiphertextLength == 0 || d.CreatedAt.IsZero() {
		return d, formatErr("descriptor version, profile or length")
	}
	return d, nil
}

// Receipt is a signed record of one envelope delivery (RCP-006). Its
// expiry is not a self-destructing key (KEY-010).
type Receipt struct {
	Version             string    `json:"version"`
	EnvelopeID          string    `json:"envelope_id"`
	EnvelopeDigest      string    `json:"envelope_digest"`
	TenantID            string    `json:"tenant_id"`
	ObjectID            string    `json:"object_id"`
	LogicalVersionID    string    `json:"logical_version_id"`
	Recipient           string    `json:"recipient"`
	Audience            string    `json:"audience"`
	DecisionID          string    `json:"decision_id"`
	OperationID         string    `json:"operation_id"`
	RecoveryIncarnation uint64    `json:"recovery_incarnation"`
	IssuedAt            time.Time `json:"issued_at"`
	ValidUntil          time.Time `json:"valid_until"`
}

// ReceiptVersion is the only supported Receipt.Version.
const ReceiptVersion = "fga.delivery-receipt/v1"

// ParseReceipt parses a receipt strictly.
func ParseReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if err := strictjson.Decode(b, &r); err != nil || r.Version != ReceiptVersion {
		return r, formatErr("receipt")
	}
	return r, nil
}

// SigningProofInput is what a content-signing key signs to prove
// possession during enrollment (RCP-002).
func SigningProofInput(challengeID, tenant, principal string, fingerprint Digest, nonce []byte) []byte {
	b := []byte("fga.signing-key-proof/v1\x00")
	for _, s := range []string{challengeID, tenant, principal, fingerprint.String()} {
		b = append(b, s...)
		b = append(b, 0)
	}
	return append(b, nonce...)
}

// LabelProposalInput is what a registered classifier signs to propose a
// label for one exact version of a resource, which the version's ID names
// (LAB-002 source 3).
func LabelProposalInput(resourceType, version, label, classifier string) []byte {
	var b []byte
	for i, f := range []string{"fga.label-proposal/v1", resourceType, version, label, classifier} {
		if i > 0 {
			b = append(b, 0)
		}
		b = append(b, f...)
	}
	return b
}

// RecipientProof is the possession proof for an X25519 recipient key
// (RCP-002): HMAC-SHA256 under HKDF-SHA256(shared secret, salt nonce) over
// the challenge's bindings. The client computes the shared secret with its
// private key, the server with its ephemeral one.
func RecipientProof(shared, nonce []byte, challengeID, tenant, principal string, fingerprint Digest) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, shared, nonce, "fga.recipient-proof/v1", 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	for _, s := range []string{challengeID, tenant, principal} {
		m.Write([]byte(s))
		m.Write([]byte{0})
	}
	m.Write([]byte(fingerprint.String()))
	return m.Sum(nil), nil
}

// ValidEd25519PublicKey reports whether b is a canonical Ed25519 public
// key of large order (RCP-002). A small-order key would let anyone forge a
// share of signatures, its possession proof included. The check maps the
// point to its Montgomery form, u = (1+y)/(1-y) (RFC 7748, 4.1), which has
// the same order, and lets ValidX25519PublicKey reject low order there.
func ValidEd25519PublicKey(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	le := make([]byte, 32)
	for i := range b {
		le[31-i] = b[i]
	}
	le[0] &= 0x7f
	y := new(big.Int).SetBytes(le)
	one := big.NewInt(1)
	if y.Cmp(p) >= 0 || y.Cmp(one) == 0 {
		return false // a non-canonical encoding, or the identity
	}
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)
	u := new(big.Int).Add(one, y)
	u.Mul(u, new(big.Int).ModInverse(den, p))
	u.Mod(u, p)
	ub := u.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		ub[i], ub[j] = ub[j], ub[i]
	}
	return ValidX25519PublicKey(ub)
}

// ValidX25519PublicKey reports whether b is a usable X25519 public key.
func ValidX25519PublicKey(b []byte) bool {
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return false
	}
	// Reject low-order points: they yield an all-zero shared secret.
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	_, err = probe.ECDH(pub)
	return err == nil
}
