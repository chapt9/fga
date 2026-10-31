package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	"fga/internal/cryptowire"
)

var now = time.Unix(1_800_000_000, 0).UTC()

type trust struct {
	recipients map[cryptowire.Digest][]byte
	signers    map[cryptowire.Digest]ed25519.PublicKey
}

func (t trust) Recipient(fp cryptowire.Digest) ([]byte, bool) {
	k, ok := t.recipients[fp]
	return k, ok
}
func (t trust) Signer(fp cryptowire.Digest) (ed25519.PublicKey, bool) {
	k, ok := t.signers[fp]
	return k, ok
}

type fixture struct {
	alice, bob *RecipientKey
	signer     SigningKey
	trust      trust
	params     Params
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	alice, err := NewRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := NewRecipientKey()
	signer, _ := NewSigningKey()
	return &fixture{alice: alice, bob: bob, signer: signer,
		trust: trust{recipients: map[cryptowire.Digest][]byte{alice.Fingerprint(): alice.PublicKey(), bob.Fingerprint(): bob.PublicKey()},
			signers: map[cryptowire.Digest]ed25519.PublicKey{signer.Fingerprint: signer.Private.Public().(ed25519.PublicKey)}},
		params: Params{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), LogicalVersion: cryptowire.NewUUID(),
			CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID(), Attempt: cryptowire.NewUUID()}}
}

func (f *fixture) encrypt(t *testing.T, plaintext []byte, to ...*RecipientKey) ([]byte, Sealed) {
	t.Helper()
	var recipients []Recipient
	for _, k := range to {
		recipients = append(recipients, Recipient{Fingerprint: k.Fingerprint(), KeyVersion: 1})
	}
	var ct bytes.Buffer
	sealed, err := Encrypt(&ct, bytes.NewReader(plaintext), f.params, recipients, f.signer, f.trust, now)
	if err != nil {
		t.Fatal(err)
	}
	return ct.Bytes(), sealed
}

func pkgFor(s Sealed, i int) Package {
	return Package{Descriptor: s.Descriptor, DescriptorSignature: s.DescriptorSignature, Envelope: s.Envelopes[i]}
}

func decrypt(ct []byte, pkg Package, key *RecipientKey, tr TrustStore) ([]byte, error) {
	var out bytes.Buffer
	err := Decrypt(&out, bytes.NewReader(ct), pkg, key, tr)
	return out.Bytes(), err
}

// TestRoundTrip covers CRY-002, KEY-001 and RCP-005: one fresh keyset per
// version, wrapped separately for each recipient; each decrypts with its
// own key, across several 1 MiB segments and for an empty payload.
func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	big := make([]byte, 5<<19+123) // two and a half segments
	_, _ = rand.Read(big)
	for name, plaintext := range map[string][]byte{"empty": {}, "small": []byte("quarterly figures"), "multi-segment": big} {
		ct, sealed := f.encrypt(t, plaintext, f.alice, f.bob)
		if len(sealed.Envelopes) != 2 || sealed.CiphertextLength != uint64(len(ct)) {
			t.Fatalf("%s: sealed = %d envelopes, length %d", name, len(sealed.Envelopes), sealed.CiphertextLength)
		}
		for i, key := range []*RecipientKey{f.alice, f.bob} {
			got, err := decrypt(ct, pkgFor(sealed, i), key, f.trust)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("%s: recipient %d: %v", name, i, err)
			}
		}
	}
}

func TestEncryptRequiresPinnedRecipients(t *testing.T) {
	f := newFixture(t)
	stranger, _ := NewRecipientKey()
	_, err := Encrypt(io.Discard, bytes.NewReader([]byte("x")), f.params, []Recipient{{Fingerprint: stranger.Fingerprint(), KeyVersion: 1}},
		f.signer, f.trust, now)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unpinned recipient: %v", err)
	}
	// A pinned fingerprint whose stored key is another key (a substituted
	// directory answer) is refused too (RCP-002).
	f.trust.recipients[stranger.Fingerprint()] = f.alice.PublicKey()
	_, err = Encrypt(io.Discard, bytes.NewReader([]byte("x")), f.params, []Recipient{{Fingerprint: stranger.Fingerprint(), KeyVersion: 1}},
		f.signer, f.trust, now)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("mismatched pin: %v", err)
	}
}

// TestDecryptFailures covers CRY-006, CRY-008, KEY-006, KEY-015 and
// RCP-008: nothing decrypts without trusted origin, exact ciphertext and
// exact bindings.
func TestDecryptFailures(t *testing.T) {
	f := newFixture(t)
	ct, sealed := f.encrypt(t, []byte("payroll"), f.alice)
	other := newFixture(t)
	otherCT, otherSealed := other.encrypt(t, []byte("other object"), other.alice)
	f.trust.signers[other.signer.Fingerprint] = other.signer.Private.Public().(ed25519.PublicKey)

	flipped := bytes.Clone(ct)
	flipped[len(flipped)/2] ^= 1
	// An authorized but malicious signer can sign a descriptor for corrupted
	// bytes; the AEAD still fails.
	resigned := func(ct []byte) Package {
		d, _ := cryptowire.ParseDescriptor(sealed.Descriptor)
		var sum cryptowire.Digest
		h := cryptowireDigest(ct)
		copy(sum[:], h[:])
		d.CiphertextSHA256 = sum.String()
		b, _ := d.Marshal()
		sig, _ := f.signer.Sign(cryptowire.TypeDescriptor, b)
		return Package{Descriptor: b, DescriptorSignature: sig, Envelope: sealed.Envelopes[0]}
	}

	for name, tc := range map[string]struct {
		ct   []byte
		pkg  Package
		key  *RecipientKey
		tr   TrustStore
		want error
	}{
		"other recipient's key":    {ct, pkgFor(sealed, 0), f.bob, f.trust, ErrBinding},
		"untrusted signer":         {ct, pkgFor(sealed, 0), f.alice, trust{signers: map[cryptowire.Digest]ed25519.PublicKey{}}, ErrUntrusted},
		"truncated ciphertext":     {ct[:len(ct)-1], pkgFor(sealed, 0), f.alice, f.trust, ErrIntegrity},
		"corrupted ciphertext":     {flipped, pkgFor(sealed, 0), f.alice, f.trust, ErrIntegrity},
		"envelope of other object": {ct, Package{Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature, Envelope: otherSealed.Envelopes[0]}, f.alice, f.trust, ErrBinding},
		"other object's bytes":     {otherCT, pkgFor(sealed, 0), f.alice, f.trust, ErrIntegrity},
		"tampered envelope":        {ct, Package{Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature, Envelope: Envelope{Context: sealed.Envelopes[0].Context, Ciphertext: append(bytes.Clone(sealed.Envelopes[0].Ciphertext[:10]), 0), Signature: sealed.Envelopes[0].Signature}}, f.alice, f.trust, cryptowire.ErrSignature},
	} {
		if _, err := decrypt(tc.ct, tc.pkg, tc.key, tc.tr); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := decrypt(flipped, resigned(flipped), f.alice, f.trust); err == nil {
		t.Error("corrupted ciphertext under a re-signed descriptor decrypted")
	}
}

// TestKeyPackageChecks covers KEY-006: a correctly signed envelope whose
// HPKE plaintext binds another object, or holds more than one key, is
// refused by the recipient.
func TestKeyPackageChecks(t *testing.T) {
	f := newFixture(t)
	ct, sealed := f.encrypt(t, []byte("payroll"), f.alice)
	ctx, _ := cryptowire.ParseEnvelopeContext(sealed.Envelopes[0].Context)
	twoKeys := func() []byte {
		params, _ := payloadParameters()
		km := keyset.NewManager()
		id, _ := km.AddNewKeyFromParameters(params)
		_ = km.SetPrimary(id)
		_, _ = km.AddNewKeyFromParameters(params)
		h, _ := km.Handle()
		var buf bytes.Buffer
		_ = insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&buf))
		return buf.Bytes()
	}
	rightAAD := cryptowire.PayloadAAD(ctx.Tenant, ctx.Object, ctx.CryptoVersion, ctx.Suite, ctx.Format)
	wrongAAD := cryptowire.PayloadAAD(ctx.Tenant, cryptowire.NewUUID(), ctx.CryptoVersion, ctx.Suite, ctx.Format)
	for name, tc := range map[string]struct {
		binding, keyset []byte
		want            error
	}{
		"other object binding": {wrongAAD, twoKeys(), ErrBinding},
		"two keys":             {rightAAD, twoKeys(), ErrKeyset},
	} {
		pkg, err := cryptowire.EncodeKeyPackage(tc.binding, tc.keyset)
		if err != nil {
			t.Fatal(err)
		}
		env, err := wrap(ctx, f.alice.PublicKey(), pkg, f.signer)
		if err != nil {
			t.Fatal(err)
		}
		p := Package{Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature, Envelope: env}
		if _, err := decrypt(ct, p, f.alice, f.trust); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestRecipientKeyStorageAndProof(t *testing.T) {
	k, _ := NewRecipientKey()
	raw, err := k.MarshalPrivateInsecure()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseRecipientKeyInsecure(raw)
	if err != nil || back.Fingerprint() != k.Fingerprint() {
		t.Fatalf("round trip: %v", err)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	nonce := []byte("0123456789abcdef0123456789abcdef")
	proof, err := back.Prove(eph.PublicKey().Bytes(), nonce, "c-1", "t-acme", "user-42")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ecdh.X25519().NewPublicKey(k.PublicKey())
	shared, _ := eph.ECDH(pub)
	want, _ := cryptowire.RecipientProof(shared, nonce, "c-1", "t-acme", "user-42", k.Fingerprint())
	if !bytes.Equal(proof, want) {
		t.Fatal("the client's proof does not match the server's computation")
	}
}

func cryptowireDigest(b []byte) [32]byte { return sha256.Sum256(b) }
