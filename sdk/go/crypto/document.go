package crypto

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"fga/internal/cryptowire"
)

// Client-side document ingestion (DOC-003, DOC-004): the client splits
// bounded UTF-8 text into units, encrypts each unit with its own keyset,
// and signs the manifest, the unit descriptors and the profile-2 envelopes.
// The server never parses or splits content.

// NormalizationVersion names the splitting scheme of SplitText; it is
// recorded in the manifest.
const NormalizationVersion = "fga.text/nfc-paragraphs-v1"

// MaxText bounds the text SplitText accepts.
const MaxText = 64 << 20

// SplitText normalizes text to NFC and splits it into paragraphs at blank
// lines. Empty paragraphs are dropped; paragraphs keep their inner line
// breaks. Text that is not valid UTF-8, too large, empty, or that yields
// more than cryptowire.MaxUnits paragraphs is refused.
func SplitText(text []byte) ([]string, error) {
	if len(text) > MaxText || !utf8.Valid(text) {
		return nil, errors.New("crypto: text must be valid UTF-8 of at most 64 MiB")
	}
	normalized := strings.ReplaceAll(norm.NFC.String(string(text)), "\r\n", "\n")
	var units []string
	for _, p := range strings.Split(normalized, "\n\n") {
		if p = strings.Trim(p, "\n"); strings.TrimSpace(p) != "" {
			units = append(units, p)
		}
	}
	if len(units) == 0 || len(units) > cryptowire.MaxUnits {
		return nil, fmt.Errorf("crypto: text yields %d units; between 1 and %d are allowed", len(units), cryptowire.MaxUnits)
	}
	return units, nil
}

// UnitParams are a new unit's identifiers from a document intent.
type UnitParams struct {
	Unit, UnitVersion, CryptoVersion, Blob cryptowire.UUID
}

// SealedUnit is an encrypted unit: its ciphertext digest and length, and
// its key package, kept in memory to wrap envelopes once the manifest
// digest is known. Close clears the key package.
type SealedUnit struct {
	Params           UnitParams
	CiphertextSHA256 cryptowire.Digest
	CiphertextLength uint64
	tenant           cryptowire.UUID
	pkg              []byte
}

// Close clears the unit's key package.
func (u *SealedUnit) Close() { clear(u.pkg) }

// EncryptUnit encrypts one unit under a fresh single-key keyset bound to
// its tenant, unit and crypto version, and writes the ciphertext to dst.
func EncryptUnit(dst io.Writer, src io.Reader, tenant cryptowire.UUID, p UnitParams) (*SealedUnit, error) {
	u := &SealedUnit{Params: p, tenant: tenant}
	aad := cryptowire.PayloadAAD(tenant, p.Unit, p.CryptoVersion, cryptowire.Suite1, cryptowire.Format1)
	pkg, err := seal(dst, src, aad, &u.CiphertextSHA256, &u.CiphertextLength)
	if err != nil {
		return nil, err
	}
	u.pkg = pkg
	return u, nil
}

// DocumentParams identify the document version being sealed.
type DocumentParams struct {
	Tenant, Document, DocumentVersion cryptowire.UUID
	ExtractionVersion                 string
	NormalizationVersion              string
}

// SealedUnitFinal is one unit's signed descriptor and envelopes.
type SealedUnitFinal struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelopes           []Envelope
}

// SealedDocument is what FinalizeDocument needs: the signed manifest and,
// in manifest order, each unit's descriptor and envelopes.
type SealedDocument struct {
	Manifest          []byte
	ManifestSignature string
	ManifestDigest    cryptowire.Digest
	Units             []SealedUnitFinal
}

// SealDocument builds and signs the manifest over units in order, then
// signs each unit's descriptor and wraps its key to every recipient in a
// profile-2 envelope bound to this document version and manifest
// (DOC-001, DOC-007). Every recipient must be pinned in trust. A reused
// unit is passed as the SealedUnit its client kept or recovered.
func SealDocument(p DocumentParams, units []*SealedUnit, recipients []Recipient, signer SigningKey, trust TrustStore, now time.Time) (SealedDocument, error) {
	if len(units) == 0 || len(units) > cryptowire.MaxUnits || len(recipients) == 0 {
		return SealedDocument{}, errors.New("crypto: a document needs units and recipients")
	}
	pubs := make([][]byte, len(recipients))
	for i, r := range recipients {
		pub, ok := trust.Recipient(r.Fingerprint)
		if !ok || cryptowire.RecipientFingerprint(cryptowire.Suite1, pub) != r.Fingerprint {
			return SealedDocument{}, fmt.Errorf("%w: recipient %s", ErrUntrusted, r.Fingerprint)
		}
		pubs[i] = pub
	}
	m := cryptowire.Manifest{TenantID: p.Tenant.String(), DocumentID: p.Document.String(), DocumentVersionID: p.DocumentVersion.String(),
		ExtractionVersion: p.ExtractionVersion, NormalizationVersion: p.NormalizationVersion}
	for _, u := range units {
		if u.tenant != p.Tenant || len(u.pkg) == 0 {
			return SealedDocument{}, errors.New("crypto: a unit is of another tenant or closed")
		}
		m.Units = append(m.Units, cryptowire.ManifestUnit{UnitID: u.Params.Unit.String(), UnitVersionID: u.Params.UnitVersion.String(),
			CryptoVersionID: u.Params.CryptoVersion.String(), CiphertextSHA256: u.CiphertextSHA256.String(), CiphertextLength: u.CiphertextLength,
			Suite: cryptowire.Suite1, Format: cryptowire.Format1})
	}
	var out SealedDocument
	var err error
	if out.Manifest, err = m.Marshal(); err != nil {
		return SealedDocument{}, err
	}
	if out.ManifestSignature, err = signer.Sign(cryptowire.TypeManifest, out.Manifest); err != nil {
		return SealedDocument{}, err
	}
	out.ManifestDigest = cryptowire.ManifestDigest(out.Manifest)
	for _, u := range units {
		d := cryptowire.UnitDescriptor{TenantID: p.Tenant.String(), DocumentID: p.Document.String(), DocumentVersionID: p.DocumentVersion.String(),
			ManifestDigest: out.ManifestDigest.String(), UnitID: u.Params.Unit.String(), UnitVersionID: u.Params.UnitVersion.String(),
			CryptoVersionID: u.Params.CryptoVersion.String(), BlobID: u.Params.Blob.String(), CiphertextSHA256: u.CiphertextSHA256.String(),
			CiphertextLength: u.CiphertextLength, Suite: cryptowire.Suite1, Format: cryptowire.Format1, Signer: signer.Fingerprint.String(), CreatedAt: now}
		var f SealedUnitFinal
		if f.Descriptor, err = d.Marshal(); err != nil {
			return SealedDocument{}, err
		}
		if f.DescriptorSignature, err = signer.Sign(cryptowire.TypeUnitDescriptor, f.Descriptor); err != nil {
			return SealedDocument{}, err
		}
		for i, r := range recipients {
			ctx := cryptowire.EnvelopeContext{Tenant: p.Tenant, Object: u.Params.Unit, LogicalVersion: u.Params.UnitVersion,
				CryptoVersion: u.Params.CryptoVersion, Suite: cryptowire.Suite1, Format: cryptowire.Format1,
				CiphertextSHA256: u.CiphertextSHA256, CiphertextLength: u.CiphertextLength, Recipient: r.Fingerprint,
				RecipientKeyVersion: r.KeyVersion, Generation: 1, Sharer: signer.Fingerprint, CreatedAt: now,
				Document: p.Document, DocumentVersion: p.DocumentVersion, ManifestDigest: out.ManifestDigest}
			env, err := wrap(ctx, pubs[i], u.pkg, signer)
			if err != nil {
				return SealedDocument{}, err
			}
			f.Envelopes = append(f.Envelopes, env)
		}
		out.Units = append(out.Units, f)
	}
	return out, nil
}

// UnitPackage is what a recipient receives for one unit: its signed
// descriptor and the recipient's envelope.
type UnitPackage struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelope            Envelope
}

// DecryptUnit verifies a unit package and writes the unit's plaintext to
// dst, with the checks of Decrypt: the descriptor's signature by a
// trusted signer, the complete ciphertext's digest and length, and the
// envelope's signature and profile-2 bindings to the same document
// version and manifest. It returns the verified descriptor. A subset
// client verifies each unit this way without the manifest (DOC-001).
func DecryptUnit(dst io.Writer, ciphertext io.ReadSeeker, pkg UnitPackage, key *RecipientKey, trust TrustStore) (cryptowire.UnitDescriptor, error) {
	keyFor := trustedSigner(trust)
	if _, err := cryptowire.Verify(cryptowire.TypeUnitDescriptor, pkg.DescriptorSignature, pkg.Descriptor, keyFor); err != nil {
		return cryptowire.UnitDescriptor{}, err
	}
	d, err := cryptowire.ParseUnitDescriptor(pkg.Descriptor)
	if err != nil {
		return cryptowire.UnitDescriptor{}, err
	}
	if err := checkCiphertext(ciphertext, d.CiphertextSHA256, d.CiphertextLength); err != nil {
		return cryptowire.UnitDescriptor{}, err
	}
	if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, pkg.Envelope.Signature,
		cryptowire.EnvelopeSigningInput(pkg.Envelope.Context, pkg.Envelope.Ciphertext), keyFor); err != nil {
		return cryptowire.UnitDescriptor{}, err
	}
	ctx, err := cryptowire.ParseEnvelopeContext(pkg.Envelope.Context)
	if err != nil {
		return cryptowire.UnitDescriptor{}, err
	}
	if !unitContextMatches(ctx, d) || ctx.Recipient != key.fingerprint {
		return cryptowire.UnitDescriptor{}, ErrBinding
	}
	return d, open(dst, ciphertext, pkg.Envelope, ctx, key)
}

func unitContextMatches(c cryptowire.EnvelopeContext, d cryptowire.UnitDescriptor) bool {
	return c.Profile() == 2 && c.Tenant.String() == d.TenantID && c.Object.String() == d.UnitID && c.LogicalVersion.String() == d.UnitVersionID &&
		c.CryptoVersion.String() == d.CryptoVersionID && c.Suite == d.Suite && c.Format == d.Format &&
		c.CiphertextSHA256.String() == d.CiphertextSHA256 && c.CiphertextLength == d.CiphertextLength &&
		c.Document.String() == d.DocumentID && c.DocumentVersion.String() == d.DocumentVersionID && c.ManifestDigest.String() == d.ManifestDigest
}
