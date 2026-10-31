// Package backupcrypt encrypts backup files (specification 2.5, AVL-005:
// encrypted, access-separated backups) with Tink's streaming AEAD
// AES-256-GCM-HKDF with 1 MiB segments. Only the administrator's tool links
// it; it holds no HPKE code and cannot open recipient envelopes, and server
// roles do not link it (MOD-004).
//
// The backup key is a Tink keyset that the operator keeps apart from the
// catalog and from the backups. Losing it makes the backups unreadable.
package backupcrypt

import (
	"bytes"
	"errors"
	"io"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// Scheme names the encryption in a backup's marker file.
const Scheme = "fga.backup-encryption/v1 tink AES256_GCM_HKDF_1MB"

// Key is a loaded backup key.
type Key struct {
	aead tink.StreamingAEAD
}

func parameters() (*aesgcmhkdf.Parameters, error) {
	return aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 32,
		HKDFHashType: aesgcmhkdf.SHA256, SegmentSizeInBytes: 1 << 20})
}

// Generate returns a new backup key in Tink's binary keyset format, to be
// stored by the operator with mode 0600.
func Generate() ([]byte, error) {
	params, err := parameters()
	if err != nil {
		return nil, err
	}
	km := keyset.NewManager()
	id, err := km.AddNewKeyFromParameters(params)
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
	var buf bytes.Buffer
	if err := insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&buf)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ErrKey is returned for a key file that is not exactly one enabled
// backup key of this scheme.
var ErrKey = errors.New("backupcrypt: not a backup key of this scheme")

// Load reads a key written by Generate.
func Load(b []byte) (*Key, error) {
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(b)))
	if err != nil || h.Len() != 1 {
		return nil, ErrKey
	}
	e, err := h.Primary()
	if err != nil || e.KeyStatus() != keyset.Enabled {
		return nil, ErrKey
	}
	want, err := parameters()
	if err != nil {
		return nil, err
	}
	if k, ok := e.Key().(*aesgcmhkdf.Key); !ok || !k.Parameters().Equal(want) {
		return nil, ErrKey
	}
	aead, err := streamingaead.New(h)
	if err != nil {
		return nil, err
	}
	return &Key{aead: aead}, nil
}

// Seal returns a writer that encrypts into w, bound to aad.
func (k *Key) Seal(w io.Writer, aad []byte) (io.WriteCloser, error) {
	return k.aead.NewEncryptingWriter(w, aad)
}

// Open returns a reader that decrypts r, bound to aad. Truncation,
// reordering, corruption or another aad fail.
func (k *Key) Open(r io.Reader, aad []byte) (io.Reader, error) {
	return k.aead.NewDecryptingReader(r, aad)
}
