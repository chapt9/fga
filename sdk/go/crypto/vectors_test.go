package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"

	"fga/internal/cryptowire"
)

// Browser vectors (docs/design/browser-client.md, "Test data"): what the
// console's browser code, a second implementation of profile 1, must
// reproduce byte for byte or open, and what it must refuse. With -update
// the test makes new keys and samples and rewrites testdata/browser-v1.json
// and the two-segment ciphertext beside it; otherwise it checks every
// recorded value against this implementation.

var updateVectors = flag.Bool("update", false, "rewrite the browser vectors in testdata")

const vectorFile = "testdata/browser-v1.json"

type recipientVector struct {
	Private     []byte `json:"private"` // raw X25519
	Public      []byte `json:"public"`
	Fingerprint string `json:"fingerprint"`
	Keyset      []byte `json:"keyset"` // the fga program's key file form
}

type envelopeVector struct {
	Context    []byte `json:"context"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  string `json:"signature"`
}

type contextVector struct {
	ProfileVersion      uint64 `json:"profile_version"`
	Tenant              string `json:"tenant_id"`
	Object              string `json:"object_id"`
	LogicalVersion      string `json:"logical_version_id"`
	CryptoVersion       string `json:"crypto_version_id"`
	Suite               uint16 `json:"suite"`
	Format              uint16 `json:"format"`
	CiphertextSHA256    string `json:"ciphertext_sha256"`
	CiphertextLength    uint64 `json:"ciphertext_length"`
	Recipient           string `json:"recipient_fingerprint"`
	RecipientKeyVersion uint64 `json:"recipient_key_version"`
	Generation          uint64 `json:"envelope_generation"`
	Sharer              string `json:"sharer_signing_key"`
	CreatedAtUnixMs     int64  `json:"created_at_unix_ms"`
	Bytes               []byte `json:"bytes"`
}

type exactVectors struct {
	PayloadAAD struct {
		Tenant        string `json:"tenant_id"`
		Object        string `json:"object_id"`
		CryptoVersion string `json:"crypto_version_id"`
		Bytes         []byte `json:"bytes"`
	} `json:"payload_aad"`
	Context contextVector `json:"context"`
	// HPKEInfo, EnvelopeSigningInput, EnvelopeDigest and EnvelopeJWS are
	// over Context.Bytes and the fixed HPKECiphertext.
	HPKEInfo             []byte `json:"hpke_info"`
	HPKECiphertext       []byte `json:"hpke_ciphertext"`
	EnvelopeSigningInput []byte `json:"envelope_signing_input"`
	EnvelopeDigest       string `json:"envelope_digest"`
	EnvelopeJWS          string `json:"envelope_jws"`
	SigningProof         struct {
		ChallengeID string `json:"challenge_id"`
		Tenant      string `json:"tenant"`
		Principal   string `json:"principal"`
		Nonce       []byte `json:"nonce"`
		Input       []byte `json:"input"`
		JWS         string `json:"jws"`
	} `json:"signing_proof"`
	RecipientProof struct {
		ChallengeID      string `json:"challenge_id"`
		Tenant           string `json:"tenant"`
		Principal        string `json:"principal"`
		Nonce            []byte `json:"nonce"`
		EphemeralPrivate []byte `json:"ephemeral_private"`
		EphemeralPublic  []byte `json:"ephemeral_public"`
		Proof            []byte `json:"proof"`
	} `json:"recipient_proof"`
	KeyPackage struct {
		Binding  []byte `json:"binding"`
		Keyset   []byte `json:"keyset"`
		KeyValue []byte `json:"key_value"`
		Bytes    []byte `json:"bytes"`
	} `json:"key_package"`
}

type sampleVector struct {
	Name                string         `json:"name"`
	PlaintextLength     int            `json:"plaintext_length"`
	PlaintextSHA256     string         `json:"plaintext_sha256"`
	Ciphertext          []byte         `json:"ciphertext,omitempty"`
	CiphertextFile      string         `json:"ciphertext_file,omitempty"`
	CiphertextSHA256    string         `json:"ciphertext_sha256"`
	Descriptor          []byte         `json:"descriptor"`
	DescriptorSignature string         `json:"descriptor_signature"`
	Envelope            envelopeVector `json:"envelope"`
}

// negativeVector is a sample changed so that it must not open. Key is
// "recipient" or "other"; Mutation changes the ciphertext ("truncate",
// "append-zero", "flip-middle" or "drop-last-segment", the last keeping
// only the first 1 MiB); Descriptor and Envelope, when set, replace the
// sample's. Want names the error: untrusted, binding, integrity,
// signature, format or aead (the payload's authentication fails).
type negativeVector struct {
	Name                string          `json:"name"`
	Sample              string          `json:"sample"`
	Key                 string          `json:"key"`
	TrustSigner         bool            `json:"trust_signer"`
	Mutation            string          `json:"mutation,omitempty"`
	Descriptor          []byte          `json:"descriptor,omitempty"`
	DescriptorSignature string          `json:"descriptor_signature,omitempty"`
	Envelope            *envelopeVector `json:"envelope,omitempty"`
	Want                string          `json:"want"`
}

type browserVectors struct {
	Format           string          `json:"format"`
	About            string          `json:"about"`
	PlaintextPattern string          `json:"plaintext_pattern"`
	CreatedAtUnixMs  int64           `json:"created_at_unix_ms"`
	Recipient        recipientVector `json:"recipient"`
	Other            recipientVector `json:"other_recipient"`
	Signer           struct {
		Seed        []byte `json:"seed"`
		Public      []byte `json:"public"`
		Fingerprint string `json:"fingerprint"`
	} `json:"signer"`
	Exact    exactVectors     `json:"exact"`
	Samples  []sampleVector   `json:"samples"`
	Negative []negativeVector `json:"negative"`
}

// vectorUUID is a fixed version-4 UUID for label.
func vectorUUID(label string) cryptowire.UUID {
	h := sha256.Sum256([]byte("fga browser vectors/" + label))
	var u cryptowire.UUID
	copy(u[:], h[:16])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return u
}

// pattern is a sample's plaintext: byte i is i mod 251.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func digestOf(b []byte) string {
	var d cryptowire.Digest
	h := sha256.Sum256(b)
	copy(d[:], h[:])
	return d.String()
}

func recipientVectorOf(t *testing.T, k *RecipientKey) recipientVector {
	t.Helper()
	priv, err := hpkePrivateKey(k.handle)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := k.MarshalPrivateInsecure()
	if err != nil {
		t.Fatal(err)
	}
	return recipientVector{Private: bytes.Clone(priv.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})), Public: k.PublicKey(),
		Fingerprint: k.Fingerprint().String(), Keyset: ks}
}

// recipientFromVector reads a recorded key and checks its raw form.
func recipientFromVector(t *testing.T, v recipientVector) *RecipientKey {
	t.Helper()
	k, err := ParseRecipientKeyInsecure(v.Keyset)
	if err != nil {
		t.Fatal(err)
	}
	got := recipientVectorOf(t, k)
	sk, err := ecdh.X25519().NewPrivateKey(v.Private)
	if err != nil || !bytes.Equal(got.Private, v.Private) || !bytes.Equal(sk.PublicKey().Bytes(), v.Public) ||
		!bytes.Equal(got.Public, v.Public) || got.Fingerprint != v.Fingerprint {
		t.Fatalf("recorded recipient key %s does not hold together", v.Fingerprint)
	}
	return k
}

// computeExact derives every exact value from the keys, the ephemeral
// enrollment key and a payload keyset.
func computeExact(t *testing.T, rec *RecipientKey, signer SigningKey, eph *ecdh.PrivateKey, ks []byte) exactVectors {
	t.Helper()
	var x exactVectors
	tenant, object, logical, cv := vectorUUID("tenant"), vectorUUID("exact/object"), vectorUUID("exact/logical-version"), vectorUUID("exact/crypto-version")
	aad := cryptowire.PayloadAAD(tenant, object, cv, cryptowire.Suite1, cryptowire.Format1)
	x.PayloadAAD.Tenant, x.PayloadAAD.Object, x.PayloadAAD.CryptoVersion, x.PayloadAAD.Bytes = tenant.String(), object.String(), cv.String(), aad

	var sum cryptowire.Digest
	copy(sum[:], pattern(32))
	ctx := cryptowire.EnvelopeContext{Tenant: tenant, Object: object, LogicalVersion: logical, CryptoVersion: cv,
		Suite: cryptowire.Suite1, Format: cryptowire.Format1, CiphertextSHA256: sum, CiphertextLength: 1049592,
		Recipient: rec.Fingerprint(), RecipientKeyVersion: 3, Generation: 2, Sharer: signer.Fingerprint, CreatedAt: now}
	cb, err := ctx.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	x.Context = contextVector{ProfileVersion: 1, Tenant: tenant.String(), Object: object.String(), LogicalVersion: logical.String(),
		CryptoVersion: cv.String(), Suite: cryptowire.Suite1, Format: cryptowire.Format1, CiphertextSHA256: sum.String(),
		CiphertextLength: 1049592, Recipient: rec.Fingerprint().String(), RecipientKeyVersion: 3, Generation: 2,
		Sharer: signer.Fingerprint.String(), CreatedAtUnixMs: now.UnixMilli(), Bytes: cb}

	x.HPKEInfo = cryptowire.HPKEInfo(cb)
	x.HPKECiphertext = pattern(80)
	x.EnvelopeSigningInput = cryptowire.EnvelopeSigningInput(cb, x.HPKECiphertext)
	x.EnvelopeDigest = cryptowire.EnvelopeDigest(cb, x.HPKECiphertext).String()
	if x.EnvelopeJWS, err = signer.Sign(cryptowire.TypeEnvelope, x.EnvelopeSigningInput); err != nil {
		t.Fatal(err)
	}

	sp := &x.SigningProof
	sp.ChallengeID, sp.Tenant, sp.Principal, sp.Nonce = "challenge-signing-1", "t-acme", "dana", pattern(32)
	sp.Input = cryptowire.SigningProofInput(sp.ChallengeID, sp.Tenant, sp.Principal, signer.Fingerprint, sp.Nonce)
	if sp.JWS, err = signer.ProveSigningKey(sp.ChallengeID, sp.Tenant, sp.Principal, sp.Nonce); err != nil {
		t.Fatal(err)
	}

	rp := &x.RecipientProof
	rp.ChallengeID, rp.Tenant, rp.Principal, rp.Nonce = "challenge-recipient-1", "t-acme", "dana", pattern(32)[1:]
	rp.Nonce = append(rp.Nonce, 0xff)
	rp.EphemeralPrivate, rp.EphemeralPublic = eph.Bytes(), eph.PublicKey().Bytes()
	if rp.Proof, err = rec.Prove(rp.EphemeralPublic, rp.Nonce, rp.ChallengeID, rp.Tenant, rp.Principal); err != nil {
		t.Fatal(err)
	}
	// The server's side of the proof, from the ephemeral private key.
	pub, _ := ecdh.X25519().NewPublicKey(rec.PublicKey())
	shared, err := eph.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	if server, err := cryptowire.RecipientProof(shared, rp.Nonce, rp.ChallengeID, rp.Tenant, rp.Principal, rec.Fingerprint()); err != nil || !bytes.Equal(server, rp.Proof) {
		t.Fatalf("the server's recipient proof differs: %v", err)
	}

	kp := &x.KeyPackage
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ks)))
	if err != nil {
		t.Fatal(err)
	}
	e, err := h.Primary()
	if err != nil {
		t.Fatal(err)
	}
	kp.Binding, kp.Keyset, kp.KeyValue = aad, ks, bytes.Clone(e.Key().(*aesgcmhkdf.Key).KeyBytes().Data(insecuresecretdataaccess.Token{}))
	if kp.Bytes, err = cryptowire.EncodeKeyPackage(aad, ks); err != nil {
		t.Fatal(err)
	}
	return x
}

// newPayloadKeyset is a fresh single-key profile-1 payload keyset.
func newPayloadKeyset(t *testing.T) []byte {
	t.Helper()
	params, err := payloadParameters()
	if err != nil {
		t.Fatal(err)
	}
	km := keyset.NewManager()
	id, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := km.SetPrimary(id); err != nil {
		t.Fatal(err)
	}
	h, err := km.Handle()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&buf)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var vectorSamples = []struct {
	name string
	size int
}{{"empty", 0}, {"one byte", 1}, {"text", 1000}, {"two segments", 1<<20 - 56 + 1000}}

func makeVectors(t *testing.T) (browserVectors, map[string][]byte) {
	rec, _ := NewRecipientKey()
	other, _ := NewRecipientKey()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	signer := SigningKeyFromPrivate(ed25519.NewKeyFromSeed(seed))
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := browserVectors{Format: "fga.browser-vectors/v1", PlaintextPattern: "byte i is i mod 251", CreatedAtUnixMs: now.UnixMilli(),
		About:     "Wire profile 1 vectors for the browser client (docs/design/browser-client.md), written by sdk/go/crypto TestBrowserVectors -update. Binary values are standard base64. Test keys only.",
		Recipient: recipientVectorOf(t, rec), Other: recipientVectorOf(t, other), Exact: computeExact(t, rec, signer, eph, newPayloadKeyset(t))}
	v.Signer.Seed, v.Signer.Public, v.Signer.Fingerprint = seed, signer.Private.Public().(ed25519.PublicKey), signer.Fingerprint.String()

	tr := trust{recipients: map[cryptowire.Digest][]byte{rec.Fingerprint(): rec.PublicKey()},
		signers: map[cryptowire.Digest]ed25519.PublicKey{signer.Fingerprint: signer.Private.Public().(ed25519.PublicKey)}}
	files := map[string][]byte{}
	cts := map[string][]byte{}
	for _, s := range vectorSamples {
		p := Params{Tenant: vectorUUID("tenant"), Object: vectorUUID(s.name + "/object"), LogicalVersion: vectorUUID(s.name + "/logical-version"),
			CryptoVersion: vectorUUID(s.name + "/crypto-version"), Blob: vectorUUID(s.name + "/blob"), Attempt: vectorUUID(s.name + "/attempt")}
		var ct bytes.Buffer
		sealed, err := Encrypt(&ct, bytes.NewReader(pattern(s.size)), p, []Recipient{{Fingerprint: rec.Fingerprint(), KeyVersion: 1}}, signer, tr, now)
		if err != nil {
			t.Fatal(err)
		}
		e := sealed.Envelopes[0]
		sv := sampleVector{Name: s.name, PlaintextLength: s.size, PlaintextSHA256: digestOf(pattern(s.size)), CiphertextSHA256: digestOf(ct.Bytes()),
			Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature,
			Envelope: envelopeVector{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature}}
		if ct.Len() > 64<<10 {
			sv.CiphertextFile = "browser-v1-two-segments.bin"
			files[sv.CiphertextFile] = ct.Bytes()
		} else {
			sv.Ciphertext = ct.Bytes()
		}
		cts[s.name] = ct.Bytes()
		v.Samples = append(v.Samples, sv)
	}

	sample := func(name string) sampleVector {
		for _, s := range v.Samples {
			if s.Name == name {
				return s
			}
		}
		t.Fatalf("no sample %q", name)
		return sampleVector{}
	}
	// resealed is what a malicious authorized signer who can open the
	// sample makes for changed ciphertext: the descriptor signed again, and
	// the same key package sealed again under a context naming the changed
	// ciphertext. Only the payload's own authentication then catches it.
	resealed := func(name, mutation string) ([]byte, string, *envelopeVector) {
		s := sample(name)
		ct := mutate(cts[name], mutation)
		d, err := cryptowire.ParseDescriptor(s.Descriptor)
		if err != nil {
			t.Fatal(err)
		}
		d.CiphertextSHA256, d.CiphertextLength = digestOf(ct), uint64(len(ct))
		b, err := d.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signer.Sign(cryptowire.TypeDescriptor, b)
		if err != nil {
			t.Fatal(err)
		}
		ctx, err := cryptowire.ParseEnvelopeContext(s.Envelope.Context)
		if err != nil {
			t.Fatal(err)
		}
		ctx.CiphertextSHA256, ctx.CiphertextLength = sha256.Sum256(ct), uint64(len(ct))
		dec, err := hybrid.NewHybridDecrypt(rec.handle)
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := dec.Decrypt(s.Envelope.Ciphertext, cryptowire.HPKEInfo(s.Envelope.Context))
		if err != nil {
			t.Fatal(err)
		}
		e, err := wrap(ctx, rec.PublicKey(), pkg, signer)
		if err != nil {
			t.Fatal(err)
		}
		return b, sig, &envelopeVector{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature}
	}
	one := sample("one byte")
	tampered := one.Envelope
	tampered.Ciphertext = append(bytes.Clone(tampered.Ciphertext[:10]), 0)
	// A context whose first varint is written in two bytes: valid values,
	// not the canonical encoding, signed by the trusted signer.
	noncanonical := one.Envelope
	if noncanonical.Context[0] != 0x08 || noncanonical.Context[1] != 0x01 {
		t.Fatal("unexpected context start")
	}
	noncanonical.Context = append([]byte{0x08, 0x81, 0x00}, noncanonical.Context[2:]...)
	if noncanonical.Signature, err = signer.Sign(cryptowire.TypeEnvelope, cryptowire.EnvelopeSigningInput(noncanonical.Context, noncanonical.Ciphertext)); err != nil {
		t.Fatal(err)
	}
	otherEnvelope := sample("text").Envelope
	flippedDesc, flippedSig, flippedEnv := resealed("text", "flip-middle")
	droppedDesc, droppedSig, droppedEnv := resealed("two segments", "drop-last-segment")
	v.Negative = []negativeVector{
		{Name: "other recipient's key", Sample: "one byte", Key: "other", TrustSigner: true, Want: "binding"},
		{Name: "signer not trusted", Sample: "one byte", Key: "recipient", Want: "untrusted"},
		{Name: "truncated ciphertext", Sample: "text", Key: "recipient", TrustSigner: true, Mutation: "truncate", Want: "integrity"},
		{Name: "trailing byte", Sample: "text", Key: "recipient", TrustSigner: true, Mutation: "append-zero", Want: "integrity"},
		{Name: "corrupted ciphertext", Sample: "text", Key: "recipient", TrustSigner: true, Mutation: "flip-middle", Want: "integrity"},
		{Name: "corrupted ciphertext, descriptor and envelope signed again", Sample: "text", Key: "recipient", TrustSigner: true, Mutation: "flip-middle",
			Descriptor: flippedDesc, DescriptorSignature: flippedSig, Envelope: flippedEnv, Want: "aead"},
		{Name: "last segment dropped, descriptor and envelope signed again", Sample: "two segments", Key: "recipient", TrustSigner: true,
			Mutation: "drop-last-segment", Descriptor: droppedDesc, DescriptorSignature: droppedSig, Envelope: droppedEnv, Want: "aead"},
		{Name: "envelope of another object", Sample: "one byte", Key: "recipient", TrustSigner: true, Envelope: &otherEnvelope, Want: "binding"},
		{Name: "tampered envelope", Sample: "one byte", Key: "recipient", TrustSigner: true, Envelope: &tampered, Want: "signature"},
		{Name: "non-canonical context, signed", Sample: "one byte", Key: "recipient", TrustSigner: true, Envelope: &noncanonical, Want: "format"},
	}
	return v, files
}

func mutate(ct []byte, mutation string) []byte {
	c := bytes.Clone(ct)
	switch mutation {
	case "truncate":
		return c[:len(c)-1]
	case "append-zero":
		return append(c, 0)
	case "flip-middle":
		c[len(c)/2] ^= 1
		return c
	case "drop-last-segment":
		return c[:1<<20]
	}
	return c
}

func errorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrUntrusted):
		return "untrusted"
	case errors.Is(err, ErrBinding):
		return "binding"
	case errors.Is(err, ErrIntegrity):
		return "integrity"
	case errors.Is(err, cryptowire.ErrSignature):
		return "signature"
	case errors.Is(err, cryptowire.ErrFormat):
		return "format"
	case errors.Is(err, ErrKeyset):
		return "keyset"
	}
	return "aead"
}

func checkVectors(t *testing.T, v browserVectors) {
	rec, other := recipientFromVector(t, v.Recipient), recipientFromVector(t, v.Other)
	signer := SigningKeyFromPrivate(ed25519.NewKeyFromSeed(v.Signer.Seed))
	if signer.Fingerprint.String() != v.Signer.Fingerprint || !bytes.Equal(signer.Private.Public().(ed25519.PublicKey), v.Signer.Public) {
		t.Fatal("recorded signer does not hold together")
	}
	eph, err := ecdh.X25519().NewPrivateKey(v.Exact.RecipientProof.EphemeralPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if got := computeExact(t, rec, signer, eph, v.Exact.KeyPackage.Keyset); !reflect.DeepEqual(got, v.Exact) {
		a, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("exact values differ from the recorded ones; now:\n%s", a)
	}
	full := trust{recipients: map[cryptowire.Digest][]byte{}, signers: map[cryptowire.Digest]ed25519.PublicKey{signer.Fingerprint: signer.Private.Public().(ed25519.PublicKey)}}
	cts := map[string][]byte{}
	samples := map[string]sampleVector{}
	for _, s := range v.Samples {
		ct := s.Ciphertext
		if s.CiphertextFile != "" {
			if ct, err = os.ReadFile(filepath.Join("testdata", s.CiphertextFile)); err != nil {
				t.Fatal(err)
			}
		}
		if digestOf(ct) != s.CiphertextSHA256 || digestOf(pattern(s.PlaintextLength)) != s.PlaintextSHA256 {
			t.Fatalf("%s: recorded digests differ", s.Name)
		}
		var out bytes.Buffer
		pkg := Package{Descriptor: s.Descriptor, DescriptorSignature: s.DescriptorSignature,
			Envelope: Envelope{Context: s.Envelope.Context, Ciphertext: s.Envelope.Ciphertext, Signature: s.Envelope.Signature}}
		if err := Decrypt(&out, bytes.NewReader(ct), pkg, rec, full); err != nil || !bytes.Equal(out.Bytes(), pattern(s.PlaintextLength)) {
			t.Fatalf("%s: does not open: %v", s.Name, err)
		}
		cts[s.Name], samples[s.Name] = ct, s
	}
	for _, n := range v.Negative {
		s, ok := samples[n.Sample]
		if !ok {
			t.Fatalf("%s: no sample %q", n.Name, n.Sample)
		}
		pkg := Package{Descriptor: s.Descriptor, DescriptorSignature: s.DescriptorSignature,
			Envelope: Envelope{Context: s.Envelope.Context, Ciphertext: s.Envelope.Ciphertext, Signature: s.Envelope.Signature}}
		if n.Descriptor != nil {
			pkg.Descriptor, pkg.DescriptorSignature = n.Descriptor, n.DescriptorSignature
		}
		if n.Envelope != nil {
			pkg.Envelope = Envelope{Context: n.Envelope.Context, Ciphertext: n.Envelope.Ciphertext, Signature: n.Envelope.Signature}
		}
		key, tr := rec, full
		if n.Key == "other" {
			key = other
		}
		if !n.TrustSigner {
			tr = trust{}
		}
		var out bytes.Buffer
		if got := errorClass(Decrypt(&out, bytes.NewReader(mutate(cts[n.Sample], n.Mutation)), pkg, key, tr)); got != n.Want {
			t.Errorf("%s: %s, want %s", n.Name, got, n.Want)
		}
	}
}

// TestBrowserVectors checks (or with -update writes) the browser vectors.
func TestBrowserVectors(t *testing.T) {
	if *updateVectors {
		v, files := makeVectors(t)
		b, err := json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join("testdata", name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("%v (write them with go test ./sdk/go/crypto -run TestBrowserVectors -update)", err)
	}
	var v browserVectors
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	checkVectors(t, v)
}

// browserProduced is what the console's browser code made with the keys
// of browser-v1.json (fga-console test/produce-fga-samples.mjs).
type browserProduced struct {
	Format  string `json:"format"`
	About   string `json:"about"`
	Samples []struct {
		Name                string         `json:"name"`
		PlaintextLength     int            `json:"plaintext_length"`
		Ciphertext          []byte         `json:"ciphertext"`
		Descriptor          []byte         `json:"descriptor"`
		DescriptorSignature string         `json:"descriptor_signature"`
		Envelope            envelopeVector `json:"envelope"`
	} `json:"samples"`
	Reshare struct {
		Of         string         `json:"of"`
		Recipient  string         `json:"recipient"`
		KeyVersion uint64         `json:"key_version"`
		Generation uint64         `json:"generation"`
		Envelope   envelopeVector `json:"envelope"`
	} `json:"reshare"`
	RecipientProof struct {
		ChallengeID      string `json:"challenge_id"`
		Tenant           string `json:"tenant"`
		Principal        string `json:"principal"`
		Nonce            []byte `json:"nonce"`
		EphemeralPrivate []byte `json:"ephemeral_private"`
		EphemeralPublic  []byte `json:"ephemeral_public"`
		Proof            []byte `json:"proof"`
	} `json:"recipient_proof"`
	SigningProof struct {
		ChallengeID string `json:"challenge_id"`
		Tenant      string `json:"tenant"`
		Principal   string `json:"principal"`
		Nonce       []byte `json:"nonce"`
		JWS         string `json:"jws"`
	} `json:"signing_proof"`
}

// TestBrowserProduced opens and verifies, with this SDK, what the second
// implementation of profile 1 made: the other half of the
// cross-implementation check RCP-007 asks for.
func TestBrowserProduced(t *testing.T) {
	read := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	var v browserVectors
	var got browserProduced
	read("browser-v1.json", &v)
	read("browser-produced-v1.json", &got)
	if got.Format != "fga.browser-produced/v1" || len(got.Samples) == 0 {
		t.Fatalf("format %q, %d samples", got.Format, len(got.Samples))
	}
	rec, other := recipientFromVector(t, v.Recipient), recipientFromVector(t, v.Other)
	signer := SigningKeyFromPrivate(ed25519.NewKeyFromSeed(v.Signer.Seed))
	tr := trust{signers: map[cryptowire.Digest]ed25519.PublicKey{signer.Fingerprint: signer.Private.Public().(ed25519.PublicKey)}}
	pkgOf := func(desc []byte, sig string, e envelopeVector) Package {
		return Package{Descriptor: desc, DescriptorSignature: sig, Envelope: Envelope{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature}}
	}
	for _, s := range got.Samples {
		var out bytes.Buffer
		if err := Decrypt(&out, bytes.NewReader(s.Ciphertext), pkgOf(s.Descriptor, s.DescriptorSignature, s.Envelope), rec, tr); err != nil ||
			!bytes.Equal(out.Bytes(), pattern(s.PlaintextLength)) {
			t.Errorf("%s: %v", s.Name, err)
		}
	}

	var text sampleVector
	for _, s := range v.Samples {
		if s.Name == got.Reshare.Of {
			text = s
		}
	}
	ctx, err := cryptowire.ParseEnvelopeContext(got.Reshare.Envelope.Context)
	if err != nil || ctx.Recipient != other.Fingerprint() || ctx.RecipientKeyVersion != got.Reshare.KeyVersion || ctx.Generation != got.Reshare.Generation {
		t.Fatalf("reshared context %+v: %v", ctx, err)
	}
	var out bytes.Buffer
	if err := Decrypt(&out, bytes.NewReader(text.Ciphertext), pkgOf(text.Descriptor, text.DescriptorSignature, got.Reshare.Envelope), other, tr); err != nil ||
		!bytes.Equal(out.Bytes(), pattern(text.PlaintextLength)) {
		t.Errorf("reshared envelope: %v", err)
	}

	rp := got.RecipientProof
	eph, err := ecdh.X25519().NewPrivateKey(rp.EphemeralPrivate)
	if err != nil || !bytes.Equal(eph.PublicKey().Bytes(), rp.EphemeralPublic) {
		t.Fatalf("ephemeral key: %v", err)
	}
	pub, _ := ecdh.X25519().NewPublicKey(rec.PublicKey())
	shared, err := eph.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	if want, err := cryptowire.RecipientProof(shared, rp.Nonce, rp.ChallengeID, rp.Tenant, rp.Principal, rec.Fingerprint()); err != nil || !bytes.Equal(want, rp.Proof) {
		t.Errorf("the browser's recipient proof does not verify: %v", err)
	}
	sp := got.SigningProof
	if _, err := cryptowire.Verify(cryptowire.TypeSigningProof, sp.JWS, cryptowire.SigningProofInput(sp.ChallengeID, sp.Tenant, sp.Principal, signer.Fingerprint, sp.Nonce),
		func(string) (ed25519.PublicKey, error) { return signer.Private.Public().(ed25519.PublicKey), nil }); err != nil {
		t.Errorf("the browser's signing proof does not verify: %v", err)
	}
}
