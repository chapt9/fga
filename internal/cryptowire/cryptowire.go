// Package cryptowire holds the byte-level formats of client encryption wire
// profile 1 (docs/design/crypto-wire-profile.md; specification 2.5, CRY-003,
// CRY-004, KEY-006, RCP-005 to RCP-008). Clients and servers share it.
//
// It contains no key handling and no decryption: servers use it to check
// identifiers, digests, fingerprints and signatures of opaque material, and
// the client SDK uses it to build that material. Tink is not linked here
// (MOD-004).
package cryptowire

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Registered suite and format values (CRY-001). Any other value rejects.
const (
	Suite1  uint16 = 1
	Format1 uint16 = 1
)

// Limits of profile 1.
const (
	MaxContextBytes       = 512
	MaxHPKECiphertext     = 66_000
	MaxDescriptorBytes    = 4 << 10
	MaxKeysetBytes        = 64 << 10
	MaxSignatureBytes     = 1 << 10
	BindingSize           = 60
	keyPackageHeaderBytes = 2 + 2 + BindingSize + 4
	// MaxExportBytes bounds the content one export carries: the
	// ciphertext of an export package, or the plaintext of a server-mode
	// export. The storage role enforces it and the SDK reads exports of
	// that size (review v4 F12).
	MaxExportBytes = 32 << 20
)

// ErrFormat is returned for any malformed or unsupported wire value.
var ErrFormat = errors.New("cryptowire: malformed or unsupported value")

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}

// SupportedProfile reports whether suite and format are registered.
func SupportedProfile(suite, format uint16) bool { return suite == Suite1 && format == Format1 }

// UUID is a random identifier in its 16-byte RFC 9562 form.
type UUID [16]byte

// NewUUID returns a fresh version-4 UUID.
func NewUUID() UUID {
	var u UUID
	if _, err := rand.Read(u[:]); err != nil {
		panic(fmt.Sprintf("cryptowire: random UUID: %v", err)) // crypto/rand does not fail on supported platforms
	}
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return u
}

// String returns the lowercase 8-4-4-4-12 form.
func (u UUID) String() string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// IsZero reports whether u is all zero bytes.
func (u UUID) IsZero() bool { return u == UUID{} }

// ParseUUID accepts only the lowercase 8-4-4-4-12 form of a non-zero UUID.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
		return u, formatErr("UUID %q", s)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return u, formatErr("UUID %q", s)
	}
	copy(u[:], b)
	if u.IsZero() {
		return u, formatErr("zero UUID")
	}
	return u, nil
}

// Digest is a SHA-256 digest.
type Digest [32]byte

// String returns "sha256:" and 64 lowercase hex digits.
func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }

// ParseDigest accepts only the String form.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 || strings.ToLower(h) != h {
		return d, formatErr("digest %q", s)
	}
	if _, err := hex.Decode(d[:], []byte(h)); err != nil {
		return d, formatErr("digest %q", s)
	}
	return d, nil
}

// domainHash returns SHA-256 of domain, a zero byte and each part in turn.
func domainHash(domain string, parts ...[]byte) Digest {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	var d Digest
	h.Sum(d[:0])
	return d
}

// RecipientFingerprint identifies an X25519 recipient public key of a suite.
func RecipientFingerprint(suite uint16, publicKey []byte) Digest {
	return domainHash("fga.recipient-key/v1", binary.BigEndian.AppendUint16(nil, suite), publicKey)
}

// SigningKeyFingerprint identifies an Ed25519 content-signing public key.
func SigningKeyFingerprint(publicKey []byte) Digest {
	return domainHash("fga.signing-key/v1", publicKey)
}

// SignInKeyFingerprint identifies an Ed25519 sign-in public key, a key
// purpose of its own (RCP-001, sign-in-keys.md).
func SignInKeyFingerprint(publicKey []byte) Digest {
	return domainHash("fga.sign-in-key/v1", publicKey)
}

// PayloadAAD is the 60-byte payload binding of crypto-format-profile.tex
// (CRY-003): "FGAAD001", tenant, object and crypto-version UUIDs, suite and
// format.
func PayloadAAD(tenant, object, cryptoVersion UUID, suite, format uint16) []byte {
	b := make([]byte, 0, BindingSize)
	b = append(b, "FGAAD001"...)
	b = append(b, tenant[:]...)
	b = append(b, object[:]...)
	b = append(b, cryptoVersion[:]...)
	b = binary.BigEndian.AppendUint16(b, suite)
	return binary.BigEndian.AppendUint16(b, format)
}

// KeyCommitment is the commitment a signed descriptor makes to a key
// package: a recipient checks the package its envelope holds against it
// before decrypting, so one signed version decrypts to one plaintext for
// every recipient although the payload cipher is not key-committing
// (security review of 4 November 2026, finding 5).
func KeyCommitment(keyPackage []byte) Digest {
	return domainHash("fga.key-commitment/v1", keyPackage)
}

// EncodeKeyPackage frames one serialized keyset with its payload binding
// (KEY-006): format 1, binding length 60, binding, keyset length, keyset.
func EncodeKeyPackage(binding, keyset []byte) ([]byte, error) {
	if len(binding) != BindingSize || len(keyset) == 0 || len(keyset) > MaxKeysetBytes {
		return nil, formatErr("key package sizes")
	}
	b := make([]byte, 0, keyPackageHeaderBytes+len(keyset))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, BindingSize)
	b = append(b, binding...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(keyset)))
	return append(b, keyset...), nil
}

// DecodeKeyPackage reverses EncodeKeyPackage. Inconsistent lengths, trailing
// bytes, unknown versions and keysets above 64 KiB reject.
func DecodeKeyPackage(pkg []byte) (binding, keyset []byte, err error) {
	if len(pkg) < keyPackageHeaderBytes {
		return nil, nil, formatErr("key package too short")
	}
	if binary.BigEndian.Uint16(pkg[0:2]) != 1 || binary.BigEndian.Uint16(pkg[2:4]) != BindingSize {
		return nil, nil, formatErr("key package version or binding length")
	}
	n := binary.BigEndian.Uint32(pkg[4+BindingSize : keyPackageHeaderBytes])
	if n == 0 || n > MaxKeysetBytes || uint64(len(pkg)) != uint64(keyPackageHeaderBytes)+uint64(n) {
		return nil, nil, formatErr("key package keyset length")
	}
	return pkg[4 : 4+BindingSize], pkg[keyPackageHeaderBytes:], nil
}

// HPKEInfo is the HPKE context information for an envelope context
// (RCP-006).
func HPKEInfo(context []byte) []byte {
	d := domainHash("fga.envelope-hpke-info/v1", context)
	return d[:]
}

// EnvelopeSigningInput is what the sharer's content-signing key signs for
// one envelope: the exact context bytes and the HPKE ciphertext's digest.
func EnvelopeSigningInput(context, hpkeCiphertext []byte) []byte {
	ct := sha256.Sum256(hpkeCiphertext)
	b := []byte("fga.envelope-signature/v1\x00")
	b = binary.BigEndian.AppendUint32(b, uint32(len(context)))
	b = append(b, context...)
	return append(b, ct[:]...)
}

// EnvelopeDigest identifies an envelope's exact bytes in receipts and audit.
func EnvelopeDigest(context, hpkeCiphertext []byte) Digest {
	return domainHash("fga.envelope-digest/v1",
		binary.BigEndian.AppendUint32(nil, uint32(len(context))), context,
		binary.BigEndian.AppendUint32(nil, uint32(len(hpkeCiphertext))), hpkeCiphertext)
}
