// Package payload encrypts and decrypts server-mode payloads in the
// storage role (specification 2.6, D-12, SSE-001, SSE-005;
// docs/design/server-objects.md). A version's data key comes from the keys
// role for one upload or read and is cleared afterwards; this package never
// sees a key-encryption key and holds no key beyond one stream.
//
// The cipher is Tink's streaming AEAD AES-256-GCM-HKDF with 1 MiB
// segments, the primitive of client payloads, keyed directly with the
// 32-byte data key. Its associated data binds the version's identity under
// a domain of its own, so ciphertext copied to another version, object or
// tenant, or read as a client payload, fails authentication. Only the
// storage role links this package (MOD-004).
package payload

import (
	"errors"
	"io"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
	"github.com/tink-crypto/tink-go/v2/tink"

	"fga/internal/cryptowire"
)

// Suite and Format are recorded with every server-mode version (CRY-001,
// KEY-016): the client suite's streaming AEAD in the server payload
// format.
const (
	Suite  uint16 = 1
	Format uint16 = 2
)

// domain separates server payloads from every other use of a data key.
const domain = "fga-server-payload/v1"

// Segment and stream sizes of the cipher (Tink AES-GCM-HKDF streaming:
// a header of one length byte, a 32-byte salt and a 7-byte nonce prefix;
// each segment carries a 16-byte tag; the first segment also holds the
// header).
const (
	segmentSize = 1 << 20
	headerSize  = 1 + 32 + 7
	tagSize     = 16
)

// ErrKey is returned for a data key of the wrong size.
var ErrKey = errors.New("payload: a data key is 32 bytes")

// Binding is the identity a payload is bound to: the version's tenant,
// object, logical version, crypto version and blob.
type Binding struct {
	Tenant, Object, Version, CryptoVersion, Blob cryptowire.UUID
}

func (b Binding) aad() []byte {
	out := make([]byte, 0, len(domain)+1+5*16)
	out = append(out, domain...)
	out = append(out, 0)
	for _, u := range []cryptowire.UUID{b.Tenant, b.Object, b.Version, b.CryptoVersion, b.Blob} {
		out = append(out, u[:]...)
	}
	return out
}

// cipher builds the streaming AEAD from a data key. Tink copies the key,
// so the caller may clear its slice once this returns.
func cipher(dataKey []byte) (tink.StreamingAEAD, error) {
	if len(dataKey) != 32 {
		return nil, ErrKey
	}
	params, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 32,
		HKDFHashType: aesgcmhkdf.SHA256, SegmentSizeInBytes: segmentSize})
	if err != nil {
		return nil, err
	}
	k, err := aesgcmhkdf.NewKey(params, secretdata.NewBytesFromData(dataKey, insecuresecretdataaccess.Token{}))
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	id, err := km.AddKey(k)
	if err != nil {
		return nil, err
	}
	if err := km.SetPrimary(id); err != nil {
		return nil, err
	}
	h, err := km.Handle()
	if err != nil {
		return nil, err
	}
	return streamingaead.New(h)
}

// Encrypt returns a writer that encrypts into dst for b. Closing it writes
// the final segment; an unclosed stream does not decrypt.
func Encrypt(dataKey []byte, b Binding, dst io.Writer) (io.WriteCloser, error) {
	c, err := cipher(dataKey)
	if err != nil {
		return nil, err
	}
	return c.NewEncryptingWriter(dst, b.aad())
}

// Decrypt returns a reader of the plaintext of src for b. A wrong key or
// binding, corruption, reordering, truncation or a missing final segment
// makes a read fail; a failed read never ends as a shorter plaintext
// (SSE-005).
func Decrypt(dataKey []byte, b Binding, src io.Reader) (io.Reader, error) {
	c, err := cipher(dataKey)
	if err != nil {
		return nil, err
	}
	return c.NewDecryptingReader(src, b.aad())
}

// CiphertextSize is the size of the ciphertext of n plaintext bytes.
func CiphertextSize(n int64) int64 {
	first := int64(segmentSize - headerSize - tagSize)
	segments := int64(1)
	if n > first {
		rest := n - first
		segments += (rest + segmentSize - tagSize - 1) / (segmentSize - tagSize)
	}
	return headerSize + n + segments*tagSize
}
