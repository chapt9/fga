// Package keybox reads and writes the key box, fga.browser-keys/v1: all of
// a person's private keys (sign-in, opening and content-signing) and their
// trust list, locked with AES-256-GCM under a random box key that each
// unlocker wraps: a secret, or another program's X25519 unlock key. The
// person's programs (the fga program and the mosaic-key-store add-on)
// share the box, so they share one account and one set of keys. It is
// the second implementation of mosaic-key-store's crypto/src/keybox.rs;
// the layout is mosaic-key-store docs/key-box.md, and the two are checked
// against each other's files (testdata).
package keybox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"fga/internal/cryptowire"
)

// Magic starts every box.
const Magic = "fga.browser-keys/v1\x00"

// Bounds of a box.
const (
	MaxBox        = 64 << 10
	MaxUnlockers  = 16
	MaxTrust      = 1000
	maxName       = 255
	maxUnlockerID = 1023
	wrappedLen    = 32 + 16
	sealedLen     = 32 + 32 + 16 // HPKE: enc, the box key, its tag
)

// Errors, by kind: as the Rust implementation's error kinds.
var (
	ErrFormat  = errors.New("keybox: not in the key box format")
	ErrUnlock  = errors.New("keybox: the key box does not open")
	ErrBinding = errors.New("keybox: the key box holds other keys than it names, or is someone else's")
)

// TrustKind says what a trusted key is for.
type TrustKind uint8

// Kinds of trusted keys.
const (
	TrustRecipient TrustKind = 1
	TrustSigner    TrustKind = 2
)

// TrustEntry is a key the person approved after seeing its fingerprint.
type TrustEntry struct {
	Kind       TrustKind
	Public     [32]byte
	KeyVersion uint32 // the recipient key's version in fga; 0 for a signer
	Owner      string
}

// Fingerprint is the entry's fingerprint, as fga computes it.
func (t TrustEntry) Fingerprint() cryptowire.Digest {
	if t.Kind == TrustRecipient {
		return cryptowire.RecipientFingerprint(cryptowire.Suite1, t.Public[:])
	}
	return cryptowire.SigningKeyFingerprint(t.Public[:])
}

// Contents is what an open box holds. Clear wipes its keys.
type Contents struct {
	RecipientPrivate    [32]byte
	RecipientKeyVersion uint32
	SigningSeed         [32]byte
	SignInSeed          [32]byte
	Trust               []TrustEntry
}

// Clear wipes the private keys.
func (c *Contents) Clear() {
	clear(c.RecipientPrivate[:])
	clear(c.SigningSeed[:])
	clear(c.SignInSeed[:])
}

// Owner names whose the box is, in clear and bound into every encryption.
type Owner struct {
	Tenant               string
	Principal            string
	RecipientFingerprint cryptowire.Digest
	SigningFingerprint   cryptowire.Digest
	SignInFingerprint    cryptowire.Digest
}

// OwnerOf names the owner of c's keys.
func OwnerOf(tenant, principal string, c *Contents) (Owner, error) {
	rpub, err := x25519Public(c.RecipientPrivate[:])
	if err != nil {
		return Owner{}, err
	}
	return Owner{Tenant: tenant, Principal: principal, RecipientFingerprint: cryptowire.RecipientFingerprint(cryptowire.Suite1, rpub),
		SigningFingerprint: cryptowire.SigningKeyFingerprint(ed25519.NewKeyFromSeed(c.SigningSeed[:]).Public().(ed25519.PublicKey)),
		SignInFingerprint:  cryptowire.SignInKeyFingerprint(ed25519.NewKeyFromSeed(c.SignInSeed[:]).Public().(ed25519.PublicKey))}, nil
}

func x25519Public(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// Unlocker holds the box key for one secret or one unlock key.
type Unlocker struct {
	ID        []byte
	publicKey bool
	salt      [32]byte
	nonce     [12]byte
	wrapped   [wrappedLen]byte
	sealed    [sealedLen]byte
}

// ForPublicKey reports whether the unlocker opens with an unlock key
// rather than a secret.
func (u Unlocker) ForPublicKey() bool { return u.publicKey }

// Box is a key box.
type Box struct {
	Owner     Owner
	Unlockers []Unlocker
	nonce     [12]byte
	sealed    []byte
}

// UnlockKeyFingerprint is what a program shows for its unlock key, for
// the person to compare before adding it.
func UnlockKeyFingerprint(public []byte) cryptowire.Digest {
	return domainHash("fga.browser-keys/v1 unlock-key", public)
}

func domainHash(domain string, b []byte) cryptowire.Digest {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(b)
	var d cryptowire.Digest
	copy(d[:], h.Sum(nil))
	return d
}

func short(out []byte, b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(out, uint16(len(b))), b...)
}

func checkName(s string) error {
	if s == "" || len(s) > maxName || !utf8.ValidString(s) {
		return fmt.Errorf("%w: a name is 1 to 255 bytes of UTF-8", ErrFormat)
	}
	return nil
}

func checkID(id []byte) error {
	if len(id) == 0 || len(id) > maxUnlockerID {
		return fmt.Errorf("%w: an unlocker ID is 1 to 1,023 bytes", ErrFormat)
	}
	return nil
}

func (o Owner) header() ([]byte, error) {
	if err := checkName(o.Tenant); err != nil {
		return nil, err
	}
	if err := checkName(o.Principal); err != nil {
		return nil, err
	}
	h := []byte(Magic)
	h = short(h, []byte(o.Tenant))
	h = short(h, []byte(o.Principal))
	h = append(h, o.RecipientFingerprint[:]...)
	h = append(h, o.SigningFingerprint[:]...)
	return append(h, o.SignInFingerprint[:]...), nil
}

func unlockerAAD(header, id []byte) []byte {
	return short(bytes.Clone(header), id)
}

func wrapKey(secret, salt []byte) ([]byte, error) {
	if len(secret) < 32 || len(secret) > 64 {
		return nil, fmt.Errorf("%w: an unlocker secret is 32 to 64 bytes", ErrFormat)
	}
	return hkdf.Key(sha256.New, secret, salt, "fga.browser-keys/v1 unlocker", 32)
}

func gcm(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // the keys here are 32 bytes
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

// WrapSecret wraps the box key for an unlocker opened with secret.
func WrapSecret(owner Owner, boxKey *[32]byte, id, secret []byte) (Unlocker, error) {
	if err := checkID(id); err != nil {
		return Unlocker{}, err
	}
	header, err := owner.header()
	if err != nil {
		return Unlocker{}, err
	}
	u := Unlocker{ID: bytes.Clone(id)}
	if _, err := rand.Read(u.salt[:]); err != nil {
		return Unlocker{}, err
	}
	if _, err := rand.Read(u.nonce[:]); err != nil {
		return Unlocker{}, err
	}
	key, err := wrapKey(secret, u.salt[:])
	if err != nil {
		return Unlocker{}, err
	}
	defer clear(key)
	copy(u.wrapped[:], gcm(key).Seal(nil, u.nonce[:], boxKey[:], unlockerAAD(header, id)))
	return u, nil
}

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// WrapForKey wraps the box key for another program's unlock key, an X25519
// public key, with HPKE; the info is the header and the unlocker's ID.
func WrapForKey(owner Owner, boxKey *[32]byte, id, public []byte) (Unlocker, error) {
	if err := checkID(id); err != nil {
		return Unlocker{}, err
	}
	header, err := owner.header()
	if err != nil {
		return Unlocker{}, err
	}
	pk, err := kem.NewPublicKey(public)
	if err != nil {
		return Unlocker{}, fmt.Errorf("%w: not an X25519 public key", ErrFormat)
	}
	ct, err := hpke.Seal(pk, kdf, aead, unlockerAAD(header, id), boxKey[:])
	if err != nil || len(ct) != sealedLen {
		return Unlocker{}, fmt.Errorf("keybox: HPKE: %v", err)
	}
	u := Unlocker{ID: bytes.Clone(id), publicKey: true}
	copy(u.sealed[:], ct)
	return u, nil
}

func encodeContents(c *Contents) ([]byte, error) {
	if len(c.Trust) > MaxTrust || c.RecipientKeyVersion == 0 {
		return nil, fmt.Errorf("%w: contents", ErrFormat)
	}
	out := append([]byte{}, c.RecipientPrivate[:]...)
	out = binary.BigEndian.AppendUint32(out, c.RecipientKeyVersion)
	out = append(out, c.SigningSeed[:]...)
	out = append(out, c.SignInSeed[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.Trust)))
	for _, t := range c.Trust {
		if err := checkName(t.Owner); err != nil || (t.Kind != TrustRecipient && t.Kind != TrustSigner) {
			return nil, fmt.Errorf("%w: trust entry", ErrFormat)
		}
		out = append(out, byte(t.Kind))
		out = append(out, t.Public[:]...)
		out = binary.BigEndian.AppendUint32(out, t.KeyVersion)
		out = short(out, []byte(t.Owner))
	}
	return out, nil
}

// Seal locks c under boxKey for owner, with the given unlockers.
func Seal(owner Owner, boxKey *[32]byte, c *Contents, unlockers []Unlocker) (*Box, error) {
	if len(unlockers) == 0 || len(unlockers) > MaxUnlockers {
		return nil, fmt.Errorf("%w: a key box has 1 to 16 unlockers", ErrFormat)
	}
	header, err := owner.header()
	if err != nil {
		return nil, err
	}
	plain, err := encodeContents(c)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	b := &Box{Owner: owner, Unlockers: unlockers}
	if _, err := rand.Read(b.nonce[:]); err != nil {
		return nil, err
	}
	b.sealed = gcm(boxKey[:]).Seal(nil, b.nonce[:], plain, header)
	enc, err := b.Encode()
	if err != nil {
		return nil, err
	}
	if len(enc) > MaxBox {
		return nil, fmt.Errorf("%w: size", ErrFormat)
	}
	return b, nil
}

func (b *Box) unlocker(id []byte) (Unlocker, error) {
	for _, u := range b.Unlockers {
		if bytes.Equal(u.ID, id) {
			return u, nil
		}
	}
	return Unlocker{}, fmt.Errorf("%w: no such unlocker", ErrUnlock)
}

// BoxKey opens the box key with an unlocker's secret.
func (b *Box) BoxKey(id, secret []byte) ([32]byte, error) {
	var out [32]byte
	u, err := b.unlocker(id)
	if err != nil {
		return out, err
	}
	if u.publicKey {
		return out, fmt.Errorf("%w: this unlocker opens with a key, not a secret", ErrUnlock)
	}
	header, err := b.Owner.header()
	if err != nil {
		return out, err
	}
	key, err := wrapKey(secret, u.salt[:])
	if err != nil {
		return out, err
	}
	defer clear(key)
	k, err := gcm(key).Open(nil, u.nonce[:], u.wrapped[:], unlockerAAD(header, id))
	if err != nil {
		return out, ErrUnlock
	}
	copy(out[:], k)
	clear(k)
	return out, nil
}

// BoxKeyWithKey opens the box key with the unlock key an unlocker was
// wrapped for (its raw X25519 private key).
func (b *Box) BoxKeyWithKey(id, unlockPrivate []byte) ([32]byte, error) {
	var out [32]byte
	u, err := b.unlocker(id)
	if err != nil {
		return out, err
	}
	if !u.publicKey {
		return out, fmt.Errorf("%w: this unlocker opens with a secret, not a key", ErrUnlock)
	}
	header, err := b.Owner.header()
	if err != nil {
		return out, err
	}
	sk, err := kem.NewPrivateKey(unlockPrivate)
	if err != nil {
		return out, fmt.Errorf("%w: not an X25519 private key", ErrFormat)
	}
	k, err := hpke.Open(sk, kdf, aead, unlockerAAD(header, id), u.sealed[:])
	if err != nil || len(k) != 32 {
		return out, ErrUnlock
	}
	copy(out[:], k)
	clear(k)
	return out, nil
}

// Contents opens what the box holds, and checks that the keys inside are
// the ones its owner names.
func (b *Box) Contents(boxKey *[32]byte) (*Contents, error) {
	header, err := b.Owner.header()
	if err != nil {
		return nil, err
	}
	plain, err := gcm(boxKey[:]).Open(nil, b.nonce[:], b.sealed, header)
	if err != nil {
		return nil, ErrUnlock
	}
	defer clear(plain)
	c, ok := decodeContents(plain)
	if !ok {
		return nil, fmt.Errorf("%w: contents", ErrFormat)
	}
	owner, err := OwnerOf(b.Owner.Tenant, b.Owner.Principal, c)
	if err != nil || owner != b.Owner {
		c.Clear()
		return nil, ErrBinding
	}
	return c, nil
}

// Encode writes the box in its layout.
func (b *Box) Encode() ([]byte, error) {
	out, err := b.Owner.header()
	if err != nil {
		return nil, err
	}
	out = append(out, byte(len(b.Unlockers)))
	for _, u := range b.Unlockers {
		if u.publicKey {
			out = short(append(out, 2), u.ID)
			out = append(out, u.sealed[:]...)
			continue
		}
		out = short(append(out, 1), u.ID)
		out = append(out, u.salt[:]...)
		out = append(out, u.nonce[:]...)
		out = append(out, u.wrapped[:]...)
	}
	out = append(out, b.nonce[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.sealed)))
	return append(out, b.sealed...), nil
}

// reader reads the layout's parts; ok turns false at the first misfit.
type reader struct {
	b  []byte
	ok bool
}

func (r *reader) take(n int) []byte {
	if !r.ok || n < 0 || len(r.b) < n {
		r.ok = false
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) byte() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() int {
	if b := r.take(2); b != nil {
		return int(binary.BigEndian.Uint16(b))
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) short(max int) []byte {
	n := r.u16()
	if n == 0 || n > max {
		r.ok = false
		return nil
	}
	return r.take(n)
}

func (r *reader) text() string {
	b := r.short(maxName)
	if r.ok && !utf8.Valid(b) {
		r.ok = false
	}
	return string(b)
}

func (r *reader) into(dst []byte) { copy(dst, r.take(len(dst))) }

func decodeContents(b []byte) (*Contents, bool) {
	r := &reader{b: b, ok: true}
	c := &Contents{}
	r.into(c.RecipientPrivate[:])
	if c.RecipientKeyVersion = r.u32(); c.RecipientKeyVersion == 0 {
		return nil, false
	}
	r.into(c.SigningSeed[:])
	r.into(c.SignInSeed[:])
	n := r.u16()
	if n > MaxTrust {
		return nil, false
	}
	for i := 0; i < n && r.ok; i++ {
		var t TrustEntry
		t.Kind = TrustKind(r.byte())
		r.into(t.Public[:])
		t.KeyVersion = r.u32()
		t.Owner = r.text()
		if t.Kind != TrustRecipient && t.Kind != TrustSigner {
			return nil, false
		}
		c.Trust = append(c.Trust, t)
	}
	if !r.ok || len(r.b) != 0 {
		c.Clear()
		return nil, false
	}
	return c, true
}

// Parse reads a box strictly: the exact layout, distinct unlocker IDs and
// no trailing bytes.
func Parse(b []byte) (*Box, error) {
	if len(b) > MaxBox || !bytes.HasPrefix(b, []byte(Magic)) {
		return nil, ErrFormat
	}
	r := &reader{b: b[len(Magic):], ok: true}
	box := &Box{}
	box.Owner.Tenant, box.Owner.Principal = r.text(), r.text()
	r.into(box.Owner.RecipientFingerprint[:])
	r.into(box.Owner.SigningFingerprint[:])
	r.into(box.Owner.SignInFingerprint[:])
	n := int(r.byte())
	if n == 0 || n > MaxUnlockers {
		return nil, ErrFormat
	}
	for i := 0; i < n && r.ok; i++ {
		kind := r.byte()
		u := Unlocker{ID: bytes.Clone(r.short(maxUnlockerID))}
		for _, other := range box.Unlockers {
			if bytes.Equal(other.ID, u.ID) {
				return nil, ErrFormat
			}
		}
		switch kind {
		case 1:
			r.into(u.salt[:])
			r.into(u.nonce[:])
			r.into(u.wrapped[:])
		case 2:
			u.publicKey = true
			r.into(u.sealed[:])
		default:
			return nil, ErrFormat
		}
		box.Unlockers = append(box.Unlockers, u)
	}
	r.into(box.nonce[:])
	box.sealed = bytes.Clone(r.take(int(r.u32())))
	if !r.ok || len(r.b) != 0 {
		return nil, ErrFormat
	}
	return box, nil
}
