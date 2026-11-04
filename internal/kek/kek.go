// Package kek holds the key-encryption keys of server mode (specification
// 2.6, D-12, SSE-001 to SSE-004). Each tenant has numbered KEK versions;
// a server-mode data key is stored only sealed under one of them. The
// keys role uses them to seal new data keys and to open them for a
// release it has authorized; the local administrator's tool uses them to
// rotate. No other role links this package (MOD-004).
//
// The keys are kept in a ring file, optionally protected with a passphrase
// like other local key files (internal/keyfile). That is the development
// custody; production custody is decision D-13. The catalog, not the ring,
// says which version is active (table kek_versions).
//
// A data key is 32 random bytes. The keys role does not know which payload
// cipher uses it; the storage role derives its payload key from it. A data
// key is sealed with AES-256-GCM (Tink) under the KEK, with the identity
// of the version it protects as associated data, so a sealed key moved to
// another version does not open.
package kek

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/tink"

	"fga/internal/cryptowire"
	"fga/internal/keyfile"
	"fga/internal/strictjson"
)

// Format identifies a ring file.
const Format = "fga.kek-ring/v1"

// DataKeySize is the size of a data key.
const DataKeySize = 32

// sealDomain separates sealed data keys from every other use of the KEKs.
const sealDomain = "fga-kek-seal/v1"

// Errors of the package.
var (
	// ErrNoKey: the ring has no such tenant or version.
	ErrNoKey = errors.New("kek: no such key-encryption key")
	// ErrOpen: a sealed data key does not open under its KEK and binding.
	ErrOpen = errors.New("kek: the sealed data key does not open")
	// ErrFormat: not a valid ring file.
	ErrFormat = errors.New("kek: not a valid ring file")
)

// Binding is the identity a data key protects: the version's tenant,
// object, logical version, crypto version and blob (SSE-001).
type Binding struct {
	Tenant, Object, Version, CryptoVersion, Blob cryptowire.UUID
}

// aad is the associated data of a sealed data key: the domain, the KEK
// version and the binding, in fixed-length fields.
func (b Binding) aad(version uint32) []byte {
	out := make([]byte, 0, len(sealDomain)+1+4+5*16)
	out = append(out, sealDomain...)
	out = append(out, 0, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	for _, u := range []cryptowire.UUID{b.Tenant, b.Object, b.Version, b.CryptoVersion, b.Blob} {
		out = append(out, u[:]...)
	}
	return out
}

// NewDataKey returns a fresh random data key. The caller owns it and
// clears it after use (SSE-004).
func NewDataKey() ([]byte, error) {
	k := make([]byte, DataKeySize)
	_, err := rand.Read(k)
	return k, err
}

type entry struct {
	Version   uint32    `json:"version"`
	Key       []byte    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type ringFile struct {
	Format  string             `json:"format"`
	Tenants map[string][]entry `json:"tenants"`
}

// Ring is the set of KEK versions of every tenant.
type Ring struct {
	tenants map[string][]entry
}

// NewRing returns an empty ring.
func NewRing() *Ring { return &Ring{tenants: map[string][]entry{}} }

// Parse reads a ring file's payload.
func Parse(data []byte) (*Ring, error) {
	var f ringFile
	if err := strictjson.Decode(data, &f); err != nil || f.Format != Format || f.Tenants == nil {
		return nil, ErrFormat
	}
	for tenant, versions := range f.Tenants {
		if tenant == "" {
			return nil, ErrFormat
		}
		for i, e := range versions {
			if e.Version != uint32(i+1) || len(e.Key) != 32 {
				return nil, ErrFormat
			}
		}
	}
	return &Ring{tenants: f.Tenants}, nil
}

// Marshal returns the ring file's payload.
func (r *Ring) Marshal() ([]byte, error) {
	return json.Marshal(ringFile{Format: Format, Tenants: r.tenants})
}

// Add adds the next KEK version of tenant, 1 for its first, and returns it.
func (r *Ring) Add(tenant string, now time.Time) (uint32, error) {
	if tenant == "" {
		return 0, ErrNoKey
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 0, err
	}
	v := uint32(len(r.tenants[tenant]) + 1)
	r.tenants[tenant] = append(r.tenants[tenant], entry{Version: v, Key: key, CreatedAt: now.UTC()})
	return v, nil
}

// Versions returns the KEK versions of tenant in order.
func (r *Ring) Versions(tenant string) []uint32 {
	var out []uint32
	for _, e := range r.tenants[tenant] {
		out = append(out, e.Version)
	}
	return out
}

func (r *Ring) cipher(tenant string, version uint32) (tink.AEAD, error) {
	versions := r.tenants[tenant]
	if version == 0 || int(version) > len(versions) {
		return nil, ErrNoKey
	}
	params, err := aesgcm.NewParameters(aesgcm.ParametersOpts{KeySizeInBytes: 32, IVSizeInBytes: 12, TagSizeInBytes: 16, Variant: aesgcm.VariantNoPrefix})
	if err != nil {
		return nil, err
	}
	k, err := aesgcm.NewKey(secretdata.NewBytesFromData(versions[version-1].Key, insecuresecretdataaccess.Token{}), 0, params)
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

// Seal seals a data key under tenant's KEK version for b.
func (r *Ring) Seal(tenant string, version uint32, dataKey []byte, b Binding) ([]byte, error) {
	if len(dataKey) != DataKeySize {
		return nil, fmt.Errorf("kek: data key of %d bytes", len(dataKey))
	}
	c, err := r.cipher(tenant, version)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(dataKey, b.aad(version))
}

// Open opens a data key sealed under tenant's KEK version for b. The
// caller owns the key and clears it after use (SSE-004).
func (r *Ring) Open(tenant string, version uint32, sealed []byte, b Binding) ([]byte, error) {
	c, err := r.cipher(tenant, version)
	if err != nil {
		return nil, err
	}
	k, err := c.Decrypt(sealed, b.aad(version))
	if err != nil || len(k) != DataKeySize {
		clear(k)
		return nil, ErrOpen
	}
	return k, nil
}

// Reseal opens a data key under one version and seals it under another,
// for rotation (SSE-002); the data key never leaves this call.
func (r *Ring) Reseal(tenant string, from, to uint32, sealed []byte, b Binding) ([]byte, error) {
	k, err := r.Open(tenant, from, sealed, b)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return r.Seal(tenant, to, k, b)
}

// File is a ring read from a ring file. When asked for a version it does
// not hold, it reads the file again once, so a rotation made by the
// administrator's tool is picked up without a restart.
type File struct {
	path       string
	passphrase func() ([]byte, error)
	mu         sync.Mutex
	ring       *Ring
}

// ReadRing reads a ring file, protected or not.
func ReadRing(path string, passphrase func() ([]byte, error)) (*Ring, error) {
	data, err := keyfile.Read(path, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return Parse(data)
}

// WriteRing writes r to path, protected with passphrase unless it is
// empty, replacing the file atomically.
func WriteRing(path string, r *Ring, passphrase []byte) error {
	data, err := r.Marshal()
	if err != nil {
		return err
	}
	defer clear(data)
	if len(passphrase) > 0 {
		sealed, err := keyfile.Seal(data, passphrase)
		if err != nil {
			return err
		}
		return keyfile.Write(path, sealed)
	}
	return keyfile.Write(path, data)
}

// Load opens a ring file.
func Load(path string, passphrase func() ([]byte, error)) (*File, error) {
	r, err := ReadRing(path, passphrase)
	if err != nil {
		return nil, err
	}
	return &File{path: path, passphrase: passphrase, ring: r}, nil
}

// current returns the ring, reading the file again when it lacks version.
func (f *File) current(tenant string, version uint32) (*Ring, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if version != 0 && int(version) <= len(f.ring.tenants[tenant]) {
		return f.ring, nil
	}
	r, err := ReadRing(f.path, f.passphrase)
	if err != nil {
		return nil, err
	}
	f.ring = r
	return r, nil
}

// Seal seals a data key under tenant's KEK version for b.
func (f *File) Seal(tenant string, version uint32, dataKey []byte, b Binding) ([]byte, error) {
	r, err := f.current(tenant, version)
	if err != nil {
		return nil, err
	}
	return r.Seal(tenant, version, dataKey, b)
}

// Open opens a data key sealed under tenant's KEK version for b.
func (f *File) Open(tenant string, version uint32, sealed []byte, b Binding) ([]byte, error) {
	r, err := f.current(tenant, version)
	if err != nil {
		return nil, err
	}
	return r.Open(tenant, version, sealed, b)
}
