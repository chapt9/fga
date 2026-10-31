// Package keyfile optionally protects key files with a passphrase: the
// fga client's recipient and signing keys and fga-admin's backup key
// (docs/design/key-files.md). A protected file is decrypted in memory only
// when the key is used and is never written back decrypted unless the
// operator asks for it. Plain key files keep working. D-08 (client key
// custody) stays open: this guards a file at rest, not a running process.
//
// The key is derived from the passphrase with Argon2id
// (golang.org/x/crypto/argon2) and the file is encrypted with Tink's
// AES-256-GCM; the header is bound as associated data.
package keyfile

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"

	"fga/internal/strictjson"
)

// Format identifies a protected key file.
const Format = "fga.keyfile/v1"

// KDF parameters of new files, and the bounds a file may ask for, so that
// a crafted file cannot make opening it arbitrarily expensive.
const (
	Time       = 3
	MemoryKiB  = 64 << 10
	Threads    = 4
	maxTime    = 10
	maxMemory  = 1 << 20 // 1 GiB in KiB
	maxThreads = 16
	saltBytes  = 16
	maxPayload = 1 << 20
)

// Errors of the package. A wrong passphrase and a changed file are the same
// ErrDecrypt.
var (
	ErrDecrypt    = errors.New("keyfile: wrong passphrase or altered file")
	ErrFormat     = errors.New("keyfile: not a valid protected key file")
	ErrPassphrase = errors.New("keyfile: a passphrase is required")
)

type file struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

// header is the associated data: every field except the ciphertext.
func (f file) header() []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d\x00%x", f.Format, f.KDF, f.Time, f.MemoryKiB, f.Threads, f.Salt))
}

func cipherFor(passphrase []byte, f file) (interface {
	Encrypt(plaintext, associatedData []byte) ([]byte, error)
	Decrypt(ciphertext, associatedData []byte) ([]byte, error)
}, error) {
	if len(passphrase) == 0 {
		return nil, ErrPassphrase
	}
	key := argon2.IDKey(passphrase, f.Salt, f.Time, f.MemoryKiB, f.Threads, 32)
	defer clear(key)
	params, err := aesgcm.NewParameters(aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix})
	if err != nil {
		return nil, err
	}
	k, err := aesgcm.NewKey(secretdata.NewBytesFromData(key, insecuresecretdataaccess.Token{}), 0, params)
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
	return aead.New(h)
}

// Seal protects payload with passphrase.
func Seal(payload, passphrase []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxPayload {
		return nil, ErrFormat
	}
	f := file{Format: Format, KDF: "argon2id", Time: Time, MemoryKiB: MemoryKiB, Threads: Threads, Salt: make([]byte, saltBytes)}
	if _, err := rand.Read(f.Salt); err != nil {
		return nil, err
	}
	c, err := cipherFor(passphrase, f)
	if err != nil {
		return nil, err
	}
	if f.Ciphertext, err = c.Encrypt(payload, f.header()); err != nil {
		return nil, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Protected reports whether data is a protected key file.
func Protected(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte(`{"format":"`+Format+`"`))
}

// Open returns the payload of a protected file.
func Open(data, passphrase []byte) ([]byte, error) {
	var f file
	if err := strictjson.Decode(bytes.TrimSpace(data), &f); err != nil || f.Format != Format || f.KDF != "argon2id" ||
		len(f.Salt) != saltBytes || f.Time == 0 || f.Time > maxTime || f.MemoryKiB < 8*uint32(f.Threads) || f.MemoryKiB > maxMemory ||
		f.Threads == 0 || f.Threads > maxThreads || len(f.Ciphertext) == 0 {
		return nil, ErrFormat
	}
	c, err := cipherFor(passphrase, f)
	if err != nil {
		return nil, err
	}
	payload, err := c.Decrypt(f.Ciphertext, f.header())
	if err != nil {
		return nil, ErrDecrypt
	}
	return payload, nil
}

// Passphrase returns the passphrase from a file when path is set,
// otherwise from the environment variable env. A trailing newline of the
// file is dropped.
func Passphrase(env, path string) ([]byte, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		b = []byte(strings.TrimRight(string(b), "\r\n"))
		if len(b) == 0 {
			return nil, ErrPassphrase
		}
		return b, nil
	}
	if v := os.Getenv(env); v != "" {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("%w: set $%s or give a passphrase file", ErrPassphrase, env)
}

// Read returns the contents of a key file, opening it with the
// passphrase from passphrase() when it is protected. passphrase is called
// only for a protected file; the slice it returns belongs to the caller,
// who clears it when done.
func Read(path string, passphrase func() ([]byte, error)) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !Protected(data) {
		return data, nil
	}
	p, err := passphrase()
	if err != nil {
		return nil, err
	}
	return Open(data, p)
}

// Write writes a key file with mode 0600, replacing path atomically and
// durably: a temporary file in the same directory is flushed and renamed,
// and the directory is flushed, so the new file survives a crash before a
// change that depends on it commits (review v3 F14).
func Write(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
