package cryptowire

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"fga/internal/strictjson"
)

// Document formats of client encryption wire profile 2 (DOC-001,
// docs/design/crypto-wire-profile.md): the uploader-signed manifest of a
// document version and the per-unit descriptors a subset client verifies
// without the manifest.

// JWS types of the document formats.
const (
	TypeManifest       = "fga-manifest+jws"
	TypeUnitDescriptor = "fga-unit-descriptor+jws"
)

// Versions and limits of the document formats.
const (
	ManifestVersion       = "fga.manifest/v1"
	UnitDescriptorVersion = "fga.unit-descriptor/v1"
	MaxManifestBytes      = 512 << 10
	MaxUnits              = 1000
)

// ManifestUnit is one unit entry of a manifest, in document order.
type ManifestUnit struct {
	UnitID           string `json:"unit_id"`
	UnitVersionID    string `json:"unit_version_id"`
	CryptoVersionID  string `json:"crypto_version_id"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	CiphertextLength uint64 `json:"ciphertext_length"`
	Suite            uint16 `json:"suite"`
	Format           uint16 `json:"format"`
}

// ManifestOriginal names the encrypted original file of a document
// version, if it has one (CNT-003).
type ManifestOriginal struct {
	ObjectID         string `json:"object_id"`
	VersionID        string `json:"version_id"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	CiphertextLength uint64 `json:"ciphertext_length"`
}

// Manifest is the canonical core of a document version's manifest. Its
// digest is computed over these bytes, which hold no descriptor or
// signature, so nothing refers to itself (DOC-001).
type Manifest struct {
	Version              string            `json:"version"`
	TenantID             string            `json:"tenant_id"`
	DocumentID           string            `json:"document_id"`
	DocumentVersionID    string            `json:"document_version_id"`
	ExtractionVersion    string            `json:"extraction_version"`
	NormalizationVersion string            `json:"normalization_version"`
	Original             *ManifestOriginal `json:"original,omitempty"`
	Units                []ManifestUnit    `json:"units"`
}

// Marshal encodes m once; the uploader signs these bytes and the digest
// covers them.
func (m Manifest) Marshal() ([]byte, error) {
	m.Version = ManifestVersion
	b, err := json.Marshal(m)
	if err != nil {
		return nil, formatErr("manifest")
	}
	if _, err := ParseManifest(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ServerFormat is the payload format of server-mode versions (D-12,
// internal/payload): the client suite's streaming AEAD under the server
// payload binding.
const ServerFormat uint16 = 2

// MarshalServer encodes a server-mode manifest (D-12, S4a): the storage
// role's record of a document version's units, in the client manifest's
// shape, with every unit in suite 1 and the server format. Nobody signs
// it, and ParseManifest, which clients use, refuses it.
func (m Manifest) MarshalServer() ([]byte, error) {
	m.Version = ManifestVersion
	if len(m.Units) == 0 || len(m.Units) > MaxUnits || m.NormalizationVersion == "" {
		return nil, formatErr("server manifest")
	}
	if err := uuids(m.TenantID, m.DocumentID, m.DocumentVersionID); err != nil {
		return nil, err
	}
	if o := m.Original; o != nil {
		if err := uuids(o.ObjectID, o.VersionID); err != nil {
			return nil, err
		}
		if _, err := ParseDigest(o.CiphertextSHA256); err != nil || o.CiphertextLength == 0 {
			return nil, formatErr("server manifest original")
		}
	}
	seen := map[string]bool{}
	for _, u := range m.Units {
		if err := uuids(u.UnitID, u.UnitVersionID, u.CryptoVersionID); err != nil {
			return nil, err
		}
		if _, err := ParseDigest(u.CiphertextSHA256); err != nil || u.CiphertextLength == 0 || u.Suite != Suite1 || u.Format != ServerFormat ||
			seen[u.UnitID] {
			return nil, formatErr("server manifest unit")
		}
		seen[u.UnitID] = true
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, formatErr("server manifest")
	}
	return b, nil
}

// ManifestDigest is SHA-256 over "fga.manifest/v1", a zero byte and the
// manifest bytes.
func ManifestDigest(core []byte) Digest {
	h := sha256.New()
	h.Write([]byte(ManifestVersion + "\x00"))
	h.Write(core)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}

// ParseManifest parses strictly and checks every identifier, digest,
// profile and bound; unit IDs are distinct.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > MaxManifestBytes {
		return m, formatErr("manifest size")
	}
	if err := strictjson.Decode(b, &m); err != nil {
		return m, formatErr("manifest: %v", err)
	}
	if m.Version != ManifestVersion || len(m.Units) == 0 || len(m.Units) > MaxUnits || len(m.ExtractionVersion) > 64 ||
		m.NormalizationVersion == "" || len(m.NormalizationVersion) > 64 {
		return m, formatErr("manifest version, units or versions")
	}
	if err := uuids(m.TenantID, m.DocumentID, m.DocumentVersionID); err != nil {
		return m, err
	}
	if o := m.Original; o != nil {
		if err := uuids(o.ObjectID, o.VersionID); err != nil {
			return m, err
		}
		if _, err := ParseDigest(o.CiphertextSHA256); err != nil || o.CiphertextLength == 0 {
			return m, formatErr("manifest original")
		}
	}
	seen := map[string]bool{}
	for _, u := range m.Units {
		if err := uuids(u.UnitID, u.UnitVersionID, u.CryptoVersionID); err != nil {
			return m, err
		}
		if _, err := ParseDigest(u.CiphertextSHA256); err != nil || u.CiphertextLength == 0 || !SupportedProfile(u.Suite, u.Format) || seen[u.UnitID] {
			return m, formatErr("manifest unit")
		}
		seen[u.UnitID] = true
	}
	return m, nil
}

// UnitDescriptor is the signed descriptor of one unit within one document
// version (DOC-001): a client given a subset verifies each unit with it.
type UnitDescriptor struct {
	Version           string    `json:"version"`
	TenantID          string    `json:"tenant_id"`
	DocumentID        string    `json:"document_id"`
	DocumentVersionID string    `json:"document_version_id"`
	ManifestDigest    string    `json:"manifest_digest"`
	UnitID            string    `json:"unit_id"`
	UnitVersionID     string    `json:"unit_version_id"`
	CryptoVersionID   string    `json:"crypto_version_id"`
	BlobID            string    `json:"blob_id"`
	CiphertextSHA256  string    `json:"ciphertext_sha256"`
	CiphertextLength  uint64    `json:"ciphertext_length"`
	Suite             uint16    `json:"suite"`
	Format            uint16    `json:"format"`
	Signer            string    `json:"signer"`
	CreatedAt         time.Time `json:"created_at"`
	// KeyCommitment is KeyCommitment of the unit's key package, as in
	// Descriptor.
	KeyCommitment string `json:"key_commitment,omitempty"`
}

// Marshal encodes d once for signing.
func (d UnitDescriptor) Marshal() ([]byte, error) {
	d.Version = UnitDescriptorVersion
	d.CreatedAt = d.CreatedAt.UTC().Truncate(time.Second)
	b, err := json.Marshal(d)
	if err != nil || len(b) > MaxDescriptorBytes {
		return nil, formatErr("unit descriptor")
	}
	if _, err := ParseUnitDescriptor(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseUnitDescriptor parses strictly.
func ParseUnitDescriptor(b []byte) (UnitDescriptor, error) {
	var d UnitDescriptor
	if len(b) > MaxDescriptorBytes {
		return d, formatErr("unit descriptor size")
	}
	if err := strictjson.Decode(b, &d); err != nil {
		return d, formatErr("unit descriptor: %v", err)
	}
	if err := uuids(d.TenantID, d.DocumentID, d.DocumentVersionID, d.UnitID, d.UnitVersionID, d.CryptoVersionID, d.BlobID); err != nil {
		return d, err
	}
	for _, s := range []string{d.ManifestDigest, d.CiphertextSHA256, d.Signer} {
		if _, err := ParseDigest(s); err != nil {
			return d, err
		}
	}
	if d.KeyCommitment != "" {
		if _, err := ParseDigest(d.KeyCommitment); err != nil {
			return d, err
		}
	}
	if d.Version != UnitDescriptorVersion || !SupportedProfile(d.Suite, d.Format) || d.CiphertextLength == 0 || d.CreatedAt.IsZero() {
		return d, formatErr("unit descriptor version, profile or length")
	}
	return d, nil
}

func uuids(ids ...string) error {
	for _, id := range ids {
		if _, err := ParseUUID(id); err != nil {
			return err
		}
	}
	return nil
}
