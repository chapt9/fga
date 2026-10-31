package cryptowire

import (
	"bytes"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// EnvelopeContext is RecipientEnvelopeContextV1 (RCP-005, RCP-006): exactly
// one object or unit version and one recipient, with the ciphertext it
// unlocks. Profile 1 is an ordinary object; profile 2 is a document unit
// and also names the document version and its manifest (DOC-007, V-152).
type EnvelopeContext struct {
	Tenant              UUID
	Object              UUID
	LogicalVersion      UUID
	CryptoVersion       UUID
	Suite               uint16
	Format              uint16
	CiphertextSHA256    Digest
	CiphertextLength    uint64
	Recipient           Digest
	RecipientKeyVersion uint64
	Generation          uint64
	// Sharer is the fingerprint of the content-signing key that signs the
	// envelope.
	Sharer Digest
	// CreatedAt is informational and never evidence (RCP-011).
	CreatedAt time.Time
	// Document, DocumentVersion and ManifestDigest are set together, and
	// only for a unit (profile 2).
	Document        UUID
	DocumentVersion UUID
	ManifestDigest  Digest
}

// Profile is 2 for a document unit's context and 1 otherwise.
func (c EnvelopeContext) Profile() uint64 {
	if c.Document.IsZero() && c.DocumentVersion.IsZero() && c.ManifestDigest == (Digest{}) {
		return 1
	}
	return 2
}

// Field numbers of RecipientEnvelopeContextV1. Fields 15 to 17 exist only
// in profile 2 (document units) and reject in profile 1.
const (
	fieldProfileVersion protowire.Number = iota + 1
	fieldTenant
	fieldObject
	fieldLogicalVersion
	fieldCryptoVersion
	fieldSuite
	fieldFormat
	fieldCiphertextSHA256
	fieldCiphertextLength
	fieldRecipient
	fieldRecipientKeyVersion
	fieldGeneration
	fieldSharer
	fieldCreatedAt
	fieldDocument
	fieldDocumentVersion
	fieldManifestDigest
)

// sizes gives the exact length of each bytes field.
var sizes = map[protowire.Number]int{
	fieldTenant: 16, fieldObject: 16, fieldLogicalVersion: 16, fieldCryptoVersion: 16,
	fieldCiphertextSHA256: 32, fieldRecipient: 32, fieldSharer: 32,
	fieldDocument: 16, fieldDocumentVersion: 16, fieldManifestDigest: 32,
}

func (c EnvelopeContext) valid() bool {
	return !c.Tenant.IsZero() && !c.Object.IsZero() && !c.LogicalVersion.IsZero() && !c.CryptoVersion.IsZero() &&
		SupportedProfile(c.Suite, c.Format) && c.CiphertextLength > 0 && c.RecipientKeyVersion > 0 && c.Generation > 0 &&
		c.CreatedAt.UnixMilli() > 0 && c.CiphertextSHA256 != Digest{} && c.Recipient != Digest{} && c.Sharer != Digest{} &&
		(c.Profile() == 1 || !c.Document.IsZero() && !c.DocumentVersion.IsZero() && c.ManifestDigest != Digest{})
}

// Marshal encodes the context once, every field present, in field order.
// Signers sign these exact bytes; receivers verify the bytes they received.
func (c EnvelopeContext) Marshal() ([]byte, error) {
	if !c.valid() {
		return nil, formatErr("envelope context has a missing or unsupported value")
	}
	return c.encode(), nil
}

func (c EnvelopeContext) encode() []byte {
	var b []byte
	varint := func(n protowire.Number, v uint64) {
		b = protowire.AppendTag(b, n, protowire.VarintType)
		b = protowire.AppendVarint(b, v)
	}
	raw := func(n protowire.Number, v []byte) {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		b = protowire.AppendBytes(b, v)
	}
	varint(fieldProfileVersion, c.Profile())
	raw(fieldTenant, c.Tenant[:])
	raw(fieldObject, c.Object[:])
	raw(fieldLogicalVersion, c.LogicalVersion[:])
	raw(fieldCryptoVersion, c.CryptoVersion[:])
	varint(fieldSuite, uint64(c.Suite))
	varint(fieldFormat, uint64(c.Format))
	raw(fieldCiphertextSHA256, c.CiphertextSHA256[:])
	varint(fieldCiphertextLength, c.CiphertextLength)
	raw(fieldRecipient, c.Recipient[:])
	varint(fieldRecipientKeyVersion, c.RecipientKeyVersion)
	varint(fieldGeneration, c.Generation)
	raw(fieldSharer, c.Sharer[:])
	varint(fieldCreatedAt, uint64(c.CreatedAt.UnixMilli()))
	if c.Profile() == 2 {
		raw(fieldDocument, c.Document[:])
		raw(fieldDocumentVersion, c.DocumentVersion[:])
		raw(fieldManifestDigest, c.ManifestDigest[:])
	}
	return b
}

// ParseEnvelopeContext parses strictly (RCP-006): every field exactly once,
// in field order, with its wire type and exact length; no unknown,
// reserved, duplicate or aggregate field; at most MaxContextBytes; and the
// input must be the canonical encoding of the values it holds.
func ParseEnvelopeContext(in []byte) (EnvelopeContext, error) {
	var c EnvelopeContext
	if len(in) == 0 || len(in) > MaxContextBytes {
		return c, formatErr("envelope context size %d", len(in))
	}
	b := in
	last := fieldCreatedAt // profile 2 extends it to fieldManifestDigest
	for want := protowire.Number(1); want <= last; want++ {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 || num != want {
			return c, formatErr("envelope context field %d missing, out of order, duplicated or unknown", want)
		}
		b = b[n:]
		if size, isBytes := sizes[num]; isBytes {
			v, n := protowire.ConsumeBytes(b)
			if typ != protowire.BytesType || n < 0 || len(v) != size {
				return c, formatErr("envelope context field %d", num)
			}
			b = b[n:]
			switch num {
			case fieldTenant:
				copy(c.Tenant[:], v)
			case fieldObject:
				copy(c.Object[:], v)
			case fieldLogicalVersion:
				copy(c.LogicalVersion[:], v)
			case fieldCryptoVersion:
				copy(c.CryptoVersion[:], v)
			case fieldCiphertextSHA256:
				copy(c.CiphertextSHA256[:], v)
			case fieldRecipient:
				copy(c.Recipient[:], v)
			case fieldSharer:
				copy(c.Sharer[:], v)
			case fieldDocument:
				copy(c.Document[:], v)
			case fieldDocumentVersion:
				copy(c.DocumentVersion[:], v)
			case fieldManifestDigest:
				copy(c.ManifestDigest[:], v)
			}
			continue
		}
		v, n := protowire.ConsumeVarint(b)
		if typ != protowire.VarintType || n < 0 {
			return c, formatErr("envelope context field %d", num)
		}
		b = b[n:]
		switch num {
		case fieldProfileVersion:
			switch v {
			case 1:
			case 2:
				last = fieldManifestDigest
			default:
				return c, formatErr("profile version %d", v)
			}
		case fieldSuite, fieldFormat:
			if v > 0xffff {
				return c, formatErr("envelope context field %d", num)
			}
			if num == fieldSuite {
				c.Suite = uint16(v)
			} else {
				c.Format = uint16(v)
			}
		case fieldCiphertextLength:
			c.CiphertextLength = v
		case fieldRecipientKeyVersion:
			c.RecipientKeyVersion = v
		case fieldGeneration:
			c.Generation = v
		case fieldCreatedAt:
			if int64(v) <= 0 {
				return c, formatErr("created time")
			}
			c.CreatedAt = time.UnixMilli(int64(v)).UTC()
		}
	}
	if len(b) != 0 {
		return c, formatErr("envelope context has trailing or extra fields")
	}
	if !c.valid() || !bytes.Equal(c.encode(), in) {
		return c, formatErr("envelope context is not the canonical encoding of supported values")
	}
	return c, nil
}
