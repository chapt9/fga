// Package crypto is the client side of client encryption wire profile 1
// (docs/design/crypto-wire-profile.md; specification 2.5, CRY-002 to
// CRY-008, KEY-001, KEY-005 to KEY-007, RCP-002, RCP-004, RCP-006 to
// RCP-008). It runs only in clients: server roles must not link it
// (MOD-004).
//
// Tink does all cryptography: streaming AEAD for payloads and HPKE for
// recipient envelopes. This package frames, binds and signs what Tink
// produces; it implements no cipher of its own.
//
// Key custody (D-08) is open. Private keys are held by the caller; the
// helpers that serialize them in the clear exist for the development
// profile only.
package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"

	"fga/internal/cryptowire"
)

// Errors of the client. ErrUntrusted means a key was not pinned or trusted
// (RCP-002, RCP-008); ErrBinding that material does not belong to the
// object, version or recipient it claims to (CRY-004, RCP-005).
var (
	ErrUntrusted = errors.New("crypto: recipient or signer is not trusted")
	ErrBinding   = errors.New("crypto: material is bound to another object, version or recipient")
	ErrIntegrity = errors.New("crypto: ciphertext digest or length does not match its descriptor")
	ErrKeyset    = errors.New("crypto: envelope does not hold exactly one profile-1 payload key")
)

// hpkeParameters is the HPKE suite of profile 1 (RCP-004).
func hpkeParameters() (*hpke.Parameters, error) {
	return hpke.NewParameters(hpke.ParametersOpts{KEMID: hpke.DHKEM_X25519_HKDF_SHA256, KDFID: hpke.HKDFSHA256,
		AEADID: hpke.AES256GCM, Variant: hpke.VariantNoPrefix})
}

// payloadParameters is the streaming AEAD of profile 1 (CRY-002).
func payloadParameters() (*aesgcmhkdf.Parameters, error) {
	return aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 32,
		HKDFHashType: aesgcmhkdf.SHA256, SegmentSizeInBytes: 1 << 20})
}

// RecipientKey is a recipient's X25519 HPKE key pair.
type RecipientKey struct {
	handle      *keyset.Handle
	public      []byte
	fingerprint cryptowire.Digest
}

// NewRecipientKey generates a recipient key pair.
func NewRecipientKey() (*RecipientKey, error) {
	params, err := hpkeParameters()
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
	return recipientFromHandle(h)
}

func recipientFromHandle(h *keyset.Handle) (*RecipientKey, error) {
	priv, err := hpkePrivateKey(h)
	if err != nil {
		return nil, err
	}
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	pub := pubKey.(*hpke.PublicKey).PublicKeyBytes()
	return &RecipientKey{handle: h, public: pub, fingerprint: cryptowire.RecipientFingerprint(cryptowire.Suite1, pub)}, nil
}

func hpkePrivateKey(h *keyset.Handle) (*hpke.PrivateKey, error) {
	if h.Len() != 1 {
		return nil, errors.New("crypto: a recipient keyset holds exactly one key")
	}
	e, err := h.Primary()
	if err != nil {
		return nil, err
	}
	priv, ok := e.Key().(*hpke.PrivateKey)
	if !ok {
		return nil, errors.New("crypto: not an HPKE private key")
	}
	params, err := hpkeParameters()
	if err != nil {
		return nil, err
	}
	if !priv.Parameters().Equal(params) {
		return nil, errors.New("crypto: the recipient key is not of profile 1")
	}
	return priv, nil
}

// PublicKey returns the raw X25519 public key, which is what enrollment
// publishes.
func (k *RecipientKey) PublicKey() []byte { return bytes.Clone(k.public) }

// Fingerprint identifies the key (RCP-001).
func (k *RecipientKey) Fingerprint() cryptowire.Digest { return k.fingerprint }

// MarshalPrivateInsecure serializes the private keyset in the clear. It is
// for the development profile's local key file only (D-08 open).
func (k *RecipientKey) MarshalPrivateInsecure() ([]byte, error) {
	var buf bytes.Buffer
	if err := insecurecleartextkeyset.Write(k.handle, keyset.NewBinaryWriter(&buf)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseRecipientKeyInsecure reads a key written by MarshalPrivateInsecure.
func ParseRecipientKeyInsecure(b []byte) (*RecipientKey, error) {
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(b)))
	if err != nil {
		return nil, err
	}
	return recipientFromHandle(h)
}

// Prove answers an enrollment challenge (RCP-002): X25519 with the
// server's ephemeral public key, then the proof of cryptowire.
func (k *RecipientKey) Prove(ephemeralPublic, nonce []byte, challengeID, tenant, principal string) ([]byte, error) {
	priv, err := hpkePrivateKey(k.handle)
	if err != nil {
		return nil, err
	}
	raw := priv.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})
	defer clear(raw)
	sk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(ephemeralPublic)
	if err != nil {
		return nil, err
	}
	shared, err := sk.ECDH(pk)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	return cryptowire.RecipientProof(shared, nonce, challengeID, tenant, principal, k.fingerprint)
}

// SigningKey is a content-signing key (RCP-008), separate from every
// other key purpose (RCP-001).
type SigningKey struct {
	Private     ed25519.PrivateKey
	Fingerprint cryptowire.Digest
}

// NewSigningKey generates a content-signing key.
func NewSigningKey() (SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{Private: priv, Fingerprint: cryptowire.SigningKeyFingerprint(pub)}, nil
}

// SigningKeyFromPrivate wraps an existing Ed25519 private key.
func SigningKeyFromPrivate(priv ed25519.PrivateKey) SigningKey {
	return SigningKey{Private: priv, Fingerprint: cryptowire.SigningKeyFingerprint(priv.Public().(ed25519.PublicKey))}
}

// Sign signs payload as type typ with this key.
func (s SigningKey) Sign(typ string, payload []byte) (string, error) {
	return cryptowire.Sign(typ, s.Fingerprint.String(), s.Private, payload)
}

// ProveSigningKey answers a content-signing-key enrollment challenge.
func (s SigningKey) ProveSigningKey(challengeID, tenant, principal string, nonce []byte) (string, error) {
	return s.Sign(cryptowire.TypeSigningProof, cryptowire.SigningProofInput(challengeID, tenant, principal, s.Fingerprint, nonce))
}

// TrustStore holds the recipient keys and content signers a client has
// pinned from an owner-approved source (RCP-002, RCP-008, RCP-011). A
// directory lookup on the server is never a substitute.
type TrustStore interface {
	// Recipient returns the pinned public key of a fingerprint.
	Recipient(fingerprint cryptowire.Digest) (publicKey []byte, ok bool)
	// Signer returns the public key of a signer trusted for content.
	Signer(fingerprint cryptowire.Digest) (ed25519.PublicKey, bool)
}

// Recipient is one intended recipient of a new version.
type Recipient struct {
	Fingerprint cryptowire.Digest
	KeyVersion  uint64
}

// Params are the identities BeginEncryptedUpload allocated (KEY-003).
type Params struct {
	Tenant, Object, LogicalVersion, CryptoVersion, Blob, Attempt cryptowire.UUID
}

// Envelope is one recipient envelope: its context bytes, HPKE ciphertext
// and origin signature.
type Envelope struct {
	Context    []byte
	Ciphertext []byte
	Signature  string
}

// Sealed is everything a finalize request carries besides the ciphertext.
type Sealed struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelopes           []Envelope
	CiphertextSHA256    cryptowire.Digest
	CiphertextLength    uint64
}

// Encrypt reads plaintext from src, writes the profile-1 ciphertext to dst
// and returns the signed descriptor and one signed envelope per recipient
// (EncryptObjectVersion). Every recipient must be pinned in trust. The
// payload keyset is fresh and never leaves this call except inside HPKE.
func Encrypt(dst io.Writer, src io.Reader, p Params, recipients []Recipient, signer SigningKey, trust TrustStore, now time.Time) (Sealed, error) {
	if len(recipients) == 0 {
		return Sealed{}, errors.New("crypto: at least one recipient is required")
	}
	pubs := make([][]byte, len(recipients))
	for i, r := range recipients {
		pub, ok := trust.Recipient(r.Fingerprint)
		if !ok || cryptowire.RecipientFingerprint(cryptowire.Suite1, pub) != r.Fingerprint {
			return Sealed{}, fmt.Errorf("%w: recipient %s", ErrUntrusted, r.Fingerprint)
		}
		pubs[i] = pub
	}

	params, err := payloadParameters()
	if err != nil {
		return Sealed{}, err
	}
	km := keyset.NewManager()
	id, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		return Sealed{}, err
	}
	if err := km.SetPrimary(id); err != nil {
		return Sealed{}, err
	}
	handle, err := km.Handle()
	if err != nil {
		return Sealed{}, err
	}
	aead, err := streamingaead.New(handle)
	if err != nil {
		return Sealed{}, err
	}
	aad := cryptowire.PayloadAAD(p.Tenant, p.Object, p.CryptoVersion, cryptowire.Suite1, cryptowire.Format1)
	counted := &digestWriter{w: dst, h: sha256.New()}
	enc, err := aead.NewEncryptingWriter(counted, aad)
	if err != nil {
		return Sealed{}, err
	}
	if _, err := io.Copy(enc, src); err != nil {
		return Sealed{}, err
	}
	if err := enc.Close(); err != nil {
		return Sealed{}, err
	}
	var sealed Sealed
	copy(sealed.CiphertextSHA256[:], counted.h.Sum(nil))
	sealed.CiphertextLength = counted.n

	var ks bytes.Buffer
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(&ks)); err != nil {
		return Sealed{}, err
	}
	defer clear(ks.Bytes())
	pkg, err := cryptowire.EncodeKeyPackage(aad, ks.Bytes())
	if err != nil {
		return Sealed{}, err
	}
	defer clear(pkg)

	for i, r := range recipients {
		ctx := cryptowire.EnvelopeContext{Tenant: p.Tenant, Object: p.Object, LogicalVersion: p.LogicalVersion,
			CryptoVersion: p.CryptoVersion, Suite: cryptowire.Suite1, Format: cryptowire.Format1,
			CiphertextSHA256: sealed.CiphertextSHA256, CiphertextLength: sealed.CiphertextLength, Recipient: r.Fingerprint,
			RecipientKeyVersion: r.KeyVersion, Generation: 1, Sharer: signer.Fingerprint, CreatedAt: now}
		env, err := wrap(ctx, pubs[i], pkg, signer)
		if err != nil {
			return Sealed{}, err
		}
		sealed.Envelopes = append(sealed.Envelopes, env)
	}

	desc := cryptowire.Descriptor{TenantID: p.Tenant.String(), ObjectID: p.Object.String(), LogicalVersionID: p.LogicalVersion.String(),
		CryptoVersionID: p.CryptoVersion.String(), BlobID: p.Blob.String(), AttemptID: p.Attempt.String(),
		Suite: cryptowire.Suite1, Format: cryptowire.Format1, CiphertextSHA256: sealed.CiphertextSHA256.String(),
		CiphertextLength: sealed.CiphertextLength, Signer: signer.Fingerprint.String(), CreatedAt: now}
	if sealed.Descriptor, err = desc.Marshal(); err != nil {
		return Sealed{}, err
	}
	if sealed.DescriptorSignature, err = signer.Sign(cryptowire.TypeDescriptor, sealed.Descriptor); err != nil {
		return Sealed{}, err
	}
	return sealed, nil
}

// wrap encrypts pkg to one recipient under ctx and signs the result.
func wrap(ctx cryptowire.EnvelopeContext, recipientPublic, pkg []byte, signer SigningKey) (Envelope, error) {
	ctxBytes, err := ctx.Marshal()
	if err != nil {
		return Envelope{}, err
	}
	params, err := hpkeParameters()
	if err != nil {
		return Envelope{}, err
	}
	pub, err := hpke.NewPublicKey(recipientPublic, 0, params)
	if err != nil {
		return Envelope{}, err
	}
	km := keyset.NewManager()
	id, err := km.AddKey(pub)
	if err != nil {
		return Envelope{}, err
	}
	if err := km.SetPrimary(id); err != nil {
		return Envelope{}, err
	}
	h, err := km.Handle()
	if err != nil {
		return Envelope{}, err
	}
	enc, err := hybrid.NewHybridEncrypt(h)
	if err != nil {
		return Envelope{}, err
	}
	ct, err := enc.Encrypt(pkg, cryptowire.HPKEInfo(ctxBytes))
	if err != nil {
		return Envelope{}, err
	}
	sig, err := signer.Sign(cryptowire.TypeEnvelope, cryptowire.EnvelopeSigningInput(ctxBytes, ct))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Context: ctxBytes, Ciphertext: ct, Signature: sig}, nil
}

// Package is what a recipient needs besides the ciphertext: the signed
// descriptor and its own envelope.
type Package struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelope            Envelope
}

// trustedSigner returns the keyFor function of a trust store.
func trustedSigner(trust TrustStore) func(string) (ed25519.PublicKey, error) {
	return func(kid string) (ed25519.PublicKey, error) {
		fp, err := cryptowire.ParseDigest(kid)
		if err != nil {
			return nil, err
		}
		pub, ok := trust.Signer(fp)
		if !ok {
			return nil, ErrUntrusted
		}
		return pub, nil
	}
}

// Decrypt verifies a package and writes the plaintext of ciphertext to dst
// (CRY-006). Before any plaintext is released it checks the descriptor's
// signature, the complete ciphertext's digest and length, the envelope's
// signature and bindings and the key package. Wrong keys, wrong bindings,
// corruption, truncation and forged segments fail. ciphertext must be the
// complete stored ciphertext; dst receives plaintext only after those
// checks, and a later AEAD failure is returned as an error, so the caller
// must discard what it wrote.
func Decrypt(dst io.Writer, ciphertext io.ReadSeeker, pkg Package, key *RecipientKey, trust TrustStore) error {
	keyFor := trustedSigner(trust)
	if _, err := cryptowire.Verify(cryptowire.TypeDescriptor, pkg.DescriptorSignature, pkg.Descriptor, keyFor); err != nil {
		return err
	}
	desc, err := cryptowire.ParseDescriptor(pkg.Descriptor)
	if err != nil {
		return err
	}
	if err := checkCiphertext(ciphertext, desc); err != nil {
		return err
	}
	if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, pkg.Envelope.Signature,
		cryptowire.EnvelopeSigningInput(pkg.Envelope.Context, pkg.Envelope.Ciphertext), keyFor); err != nil {
		return err
	}
	ctx, err := cryptowire.ParseEnvelopeContext(pkg.Envelope.Context)
	if err != nil {
		return err
	}
	if !contextMatches(ctx, desc) || ctx.Recipient != key.fingerprint {
		return ErrBinding
	}
	dec, err := hybrid.NewHybridDecrypt(key.handle)
	if err != nil {
		return err
	}
	keyPackage, err := dec.Decrypt(pkg.Envelope.Ciphertext, cryptowire.HPKEInfo(pkg.Envelope.Context))
	if err != nil {
		return ErrBinding
	}
	defer clear(keyPackage)
	binding, ks, err := cryptowire.DecodeKeyPackage(keyPackage)
	if err != nil {
		return ErrKeyset
	}
	aad := cryptowire.PayloadAAD(ctx.Tenant, ctx.Object, ctx.CryptoVersion, ctx.Suite, ctx.Format)
	if !bytes.Equal(binding, aad) {
		return ErrBinding
	}
	aead, err := payloadAEAD(ks)
	if err != nil {
		return err
	}
	if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r, err := aead.NewDecryptingReader(ciphertext, aad)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}

// checkCiphertext reads the complete ciphertext once and compares it with
// the signed descriptor.
func checkCiphertext(ciphertext io.ReadSeeker, desc cryptowire.Descriptor) error {
	if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(ciphertext, int64(desc.CiphertextLength)+1))
	if err != nil {
		return err
	}
	var got cryptowire.Digest
	copy(got[:], h.Sum(nil))
	if uint64(n) != desc.CiphertextLength || got.String() != desc.CiphertextSHA256 {
		return ErrIntegrity
	}
	return nil
}

func contextMatches(c cryptowire.EnvelopeContext, d cryptowire.Descriptor) bool {
	return c.Tenant.String() == d.TenantID && c.Object.String() == d.ObjectID && c.LogicalVersion.String() == d.LogicalVersionID &&
		c.CryptoVersion.String() == d.CryptoVersionID && c.Suite == d.Suite && c.Format == d.Format &&
		c.CiphertextSHA256.String() == d.CiphertextSHA256 && c.CiphertextLength == d.CiphertextLength
}

// payloadAEAD opens a received keyset only if it holds exactly one enabled
// primary key with the profile-1 streaming parameters (KEY-006).
func payloadAEAD(ks []byte) (interface {
	NewDecryptingReader(io.Reader, []byte) (io.Reader, error)
}, error) {
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ks)))
	if err != nil || h.Len() != 1 {
		return nil, ErrKeyset
	}
	e, err := h.Primary()
	if err != nil || e.KeyStatus() != keyset.Enabled {
		return nil, ErrKeyset
	}
	want, err := payloadParameters()
	if err != nil {
		return nil, err
	}
	k, ok := e.Key().(*aesgcmhkdf.Key)
	if !ok || !k.Parameters().Equal(want) {
		return nil, ErrKeyset
	}
	return streamingaead.New(h)
}

// digestWriter hashes and counts what passes through it.
type digestWriter struct {
	w io.Writer
	h hash.Hash
	n uint64
}

func (d *digestWriter) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	d.h.Write(p[:n])
	d.n += uint64(n)
	return n, err
}

// Reshare is CreateRecipientEnvelope (KEY-004, KEY-011, RCP-002): from a
// package the caller can open, it verifies the origin and bindings, opens
// the key package locally and wraps the same package for a pinned target
// recipient with the given generation, signed by signer. The data key and
// ciphertext stay the same; the server receives only the new envelope.
func Reshare(pkg Package, key *RecipientKey, trust TrustStore, target Recipient, generation uint64, signer SigningKey, now time.Time) (Envelope, error) {
	targetPub, ok := trust.Recipient(target.Fingerprint)
	if !ok || cryptowire.RecipientFingerprint(cryptowire.Suite1, targetPub) != target.Fingerprint {
		return Envelope{}, fmt.Errorf("%w: recipient %s", ErrUntrusted, target.Fingerprint)
	}
	keyFor := trustedSigner(trust)
	if _, err := cryptowire.Verify(cryptowire.TypeDescriptor, pkg.DescriptorSignature, pkg.Descriptor, keyFor); err != nil {
		return Envelope{}, err
	}
	desc, err := cryptowire.ParseDescriptor(pkg.Descriptor)
	if err != nil {
		return Envelope{}, err
	}
	if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, pkg.Envelope.Signature,
		cryptowire.EnvelopeSigningInput(pkg.Envelope.Context, pkg.Envelope.Ciphertext), keyFor); err != nil {
		return Envelope{}, err
	}
	ctx, err := cryptowire.ParseEnvelopeContext(pkg.Envelope.Context)
	if err != nil {
		return Envelope{}, err
	}
	if !contextMatches(ctx, desc) || ctx.Recipient != key.fingerprint {
		return Envelope{}, ErrBinding
	}
	dec, err := hybrid.NewHybridDecrypt(key.handle)
	if err != nil {
		return Envelope{}, err
	}
	keyPackage, err := dec.Decrypt(pkg.Envelope.Ciphertext, cryptowire.HPKEInfo(pkg.Envelope.Context))
	if err != nil {
		return Envelope{}, ErrBinding
	}
	defer clear(keyPackage)
	binding, ks, err := cryptowire.DecodeKeyPackage(keyPackage)
	if err != nil {
		return Envelope{}, ErrKeyset
	}
	if !bytes.Equal(binding, cryptowire.PayloadAAD(ctx.Tenant, ctx.Object, ctx.CryptoVersion, ctx.Suite, ctx.Format)) {
		return Envelope{}, ErrBinding
	}
	if _, err := payloadAEAD(ks); err != nil {
		return Envelope{}, err
	}
	next := ctx
	next.Recipient, next.RecipientKeyVersion, next.Generation = target.Fingerprint, target.KeyVersion, generation
	next.Sharer, next.CreatedAt = signer.Fingerprint, now
	return wrap(next, targetPub, keyPackage, signer)
}

// StatusTrust narrows a TrustStore by each signer's current status
// (RCP-011): a COMPROMISED signer, or one whose status cannot be obtained,
// is not trusted, so its historical signatures fail closed; a RETIRED
// signer keeps verifying historical content. Status must come from an
// authenticated trust update; a status answer can only remove trust.
type StatusTrust struct {
	TrustStore
	Status func(fingerprint cryptowire.Digest) (string, error)
}

// Signer implements TrustStore.
func (t StatusTrust) Signer(fp cryptowire.Digest) (ed25519.PublicKey, bool) {
	status, err := t.Status(fp)
	if err != nil || (status != "ACTIVE" && status != "RETIRED") {
		return nil, false
	}
	return t.TrustStore.Signer(fp)
}
