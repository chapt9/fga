package cryptowire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func uuid(start byte) UUID     { var u UUID; copy(u[:], seq(start, 16)); return u }
func digest(start byte) Digest { var d Digest; copy(d[:], seq(start, 32)); return d }

// goldenContext is the frozen positive example of RCP-007.
func goldenContext() EnvelopeContext {
	return EnvelopeContext{Tenant: uuid(0x01), Object: uuid(0x11), LogicalVersion: uuid(0x21), CryptoVersion: uuid(0x31),
		Suite: Suite1, Format: Format1, CiphertextSHA256: digest(0x41), CiphertextLength: 1_048_604,
		Recipient: digest(0x61), RecipientKeyVersion: 1, Generation: 1, Sharer: digest(0x81),
		CreatedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
}

// goldenHex is the exact encoding of goldenContext. Changing it changes
// the wire profile and needs a new reviewed profile (RCP-007).
const goldenHex = "080112100102030405060708090a0b0c0d0e0f101a101112131415161718191a1b1c1d1e1f2022102122232425262728292a2b2c2d2e2f30" +
	"2a103132333435363738393a3b3c3d3e3f403001380142204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6048" +
	"9c804052206162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80580160016a208182838485868788898a8b8c8d8e" +
	"8f909192939495969798999a9b9c9d9e9fa07080f4d28e9934"

func golden(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContextGolden(t *testing.T) {
	b, err := goldenContext().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, golden(t)) {
		t.Fatalf("encoding changed:\n got %x\nwant %s", b, goldenHex)
	}
	c, err := ParseEnvelopeContext(b)
	if err != nil || c != goldenContext() {
		t.Fatalf("parse = %+v, %v", c, err)
	}
}

// TestContextNegative holds the negative wire examples of RCP-006 and
// RCP-007; each must be rejected before any field is used.
func TestContextNegative(t *testing.T) {
	g := golden(t)
	field := func(n protowire.Number, typ protowire.Type, v []byte) []byte {
		b := protowire.AppendTag(nil, n, typ)
		if typ == protowire.BytesType {
			return protowire.AppendBytes(b, v)
		}
		return append(b, v...)
	}
	// The suite field (6) starts at byte 72: tag 0x30 then varint 0x01.
	suiteAt := bytes.Index(g, []byte{0x30, 0x01, 0x38, 0x01})
	for name, b := range map[string][]byte{
		"empty":             nil,
		"trailing byte":     append(slices.Clone(g), 0),
		"unknown field 99":  append(slices.Clone(g), field(99, protowire.VarintType, []byte{1})...),
		"reserved field":    append(slices.Clone(g), field(15, protowire.BytesType, seq(1, 16))...),
		"duplicate field":   append(slices.Clone(g), field(fieldCreatedAt, protowire.VarintType, []byte{1})...),
		"missing field":     g[:len(g)-7], // created_at: tag 0x70 and a 6-byte varint
		"out of order":      append(append(slices.Clone(g[:2]), g[20:38]...), append(slices.Clone(g[2:20]), g[38:]...)...),
		"wrong wire type":   append(append(slices.Clone(g[:suiteAt]), field(6, protowire.BytesType, []byte{1})...), g[suiteAt+2:]...),
		"overlong varint":   append(append(slices.Clone(g[:suiteAt]), 0x30, 0x81, 0x00), g[suiteAt+2:]...),
		"unknown suite":     append(append(slices.Clone(g[:suiteAt]), 0x30, 0x02), g[suiteAt+2:]...),
		"short UUID":        append(append([]byte{0x08, 0x01, 0x12, 0x0f}, seq(1, 15)...), g[18:]...),
		"oversized":         append(slices.Clone(g), make([]byte, MaxContextBytes)...),
		"profile version 2": append([]byte{0x08, 0x02}, g[2:]...),
	} {
		if _, err := ParseEnvelopeContext(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	bad := goldenContext()
	bad.Generation = 0
	if _, err := bad.Marshal(); err == nil {
		t.Error("a context with generation 0 was encoded")
	}
}

func TestAADAndKeyPackage(t *testing.T) {
	aad := PayloadAAD(uuid(1), uuid(0x11), uuid(0x31), Suite1, Format1)
	if len(aad) != BindingSize || string(aad[:8]) != "FGAAD001" || aad[56] != 0 || aad[57] != 1 || aad[59] != 1 {
		t.Fatalf("aad = %x", aad)
	}
	pkg, err := EncodeKeyPackage(aad, []byte("keyset"))
	if err != nil {
		t.Fatal(err)
	}
	binding, keyset, err := DecodeKeyPackage(pkg)
	if err != nil || !bytes.Equal(binding, aad) || string(keyset) != "keyset" {
		t.Fatalf("decode = %x %q %v", binding, keyset, err)
	}
	for name, b := range map[string][]byte{
		"trailing":       append(slices.Clone(pkg), 0),
		"short":          pkg[:len(pkg)-1],
		"version 2":      append([]byte{0, 2}, pkg[2:]...),
		"binding len 59": append([]byte{0, 1, 0, 59}, pkg[4:]...),
		"empty keyset":   pkg[:4+BindingSize+4],
		"header only":    pkg[:10],
	} {
		if _, _, err := DecodeKeyPackage(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := EncodeKeyPackage(aad, make([]byte, MaxKeysetBytes+1)); err == nil {
		t.Error("a keyset above 64 KiB was framed")
	}
}

func TestIdentifiers(t *testing.T) {
	u := NewUUID()
	if p, err := ParseUUID(u.String()); err != nil || p != u || u[6]>>4 != 4 {
		t.Fatalf("UUID round trip %v %v", p, err)
	}
	for _, s := range []string{"", "00000000-0000-0000-0000-000000000000", strings.ToUpper(u.String()), u.String()[1:] + "0", "{" + u.String()[1:]} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	d := digest(1)
	if p, err := ParseDigest(d.String()); err != nil || p != d {
		t.Fatalf("digest round trip")
	}
	for _, s := range []string{"", "sha256:", "sha512:" + d.String()[7:], strings.ToUpper(d.String())} {
		if _, err := ParseDigest(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if RecipientFingerprint(Suite1, seq(1, 32)) == RecipientFingerprint(2, seq(1, 32)) || SigningKeyFingerprint(seq(1, 32)) == RecipientFingerprint(Suite1, seq(1, 32)) {
		t.Error("fingerprints of different purposes or suites must differ")
	}
}

func TestSignatures(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	fp := SigningKeyFingerprint(pub)
	keyFor := func(id string) (ed25519.PublicKey, error) {
		if id != fp.String() {
			return nil, errors.New("untrusted")
		}
		return pub, nil
	}
	desc := Descriptor{TenantID: uuid(1).String(), ObjectID: uuid(0x11).String(), LogicalVersionID: uuid(0x21).String(),
		CryptoVersionID: uuid(0x31).String(), BlobID: uuid(0x41).String(), AttemptID: uuid(0x51).String(), Suite: Suite1, Format: Format1,
		CiphertextSHA256: digest(1).String(), CiphertextLength: 9, Signer: fp.String(), CreatedAt: time.Unix(1_800_000_000, 0)}
	payload, err := desc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(TypeDescriptor, fp.String(), priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := Verify(TypeDescriptor, sig, payload, keyFor); err != nil || kid != fp.String() {
		t.Fatalf("verify = %q, %v", kid, err)
	}
	if _, err := Verify(TypeEnvelope, sig, payload, keyFor); !errors.Is(err, ErrSignature) {
		t.Error("a descriptor signature verified as an envelope signature")
	}
	if _, err := Verify(TypeDescriptor, sig, append(slices.Clone(payload), ' '), keyFor); !errors.Is(err, ErrSignature) {
		t.Error("a changed payload verified")
	}
	other, otherPriv, _ := ed25519.GenerateKey(nil)
	forged, _ := Sign(TypeDescriptor, SigningKeyFingerprint(other).String(), otherPriv, payload)
	if _, err := Verify(TypeDescriptor, forged, payload, keyFor); !errors.Is(err, ErrSignature) {
		t.Error("an untrusted signer verified")
	}
	for name, edit := range map[string]func(*Descriptor){
		"bad UUID":    func(d *Descriptor) { d.BlobID = "x" },
		"other suite": func(d *Descriptor) { d.Suite = 2 },
		"no length":   func(d *Descriptor) { d.CiphertextLength = 0 },
		"bad digest":  func(d *Descriptor) { d.CiphertextSHA256 = "md5:00" },
	} {
		d := desc
		edit(&d)
		if _, err := d.Marshal(); err == nil {
			t.Errorf("%s: marshaled", name)
		}
	}
	if _, err := ParseDescriptor(append(payload[:len(payload)-1], []byte(`,"extra":1}`)...)); err == nil {
		t.Error("a descriptor with an unknown field parsed")
	}
}

func TestRecipientProofAndKeys(t *testing.T) {
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	fp := RecipientFingerprint(Suite1, client.PublicKey().Bytes())
	s1, _ := client.ECDH(server.PublicKey())
	s2, _ := server.ECDH(client.PublicKey())
	p1, _ := RecipientProof(s1, seq(1, 32), "c-1", "t-acme", "user-42", fp)
	p2, _ := RecipientProof(s2, seq(1, 32), "c-1", "t-acme", "user-42", fp)
	p3, _ := RecipientProof(s2, seq(1, 32), "c-1", "t-acme", "user-77", fp)
	if !bytes.Equal(p1, p2) || bytes.Equal(p1, p3) {
		t.Fatal("proofs must agree for the same binding and differ for another principal")
	}
	if !ValidX25519PublicKey(client.PublicKey().Bytes()) || ValidX25519PublicKey(make([]byte, 32)) || ValidX25519PublicKey(seq(1, 31)) {
		t.Error("X25519 public key validation")
	}
}

// goldenUnitContext is the frozen profile-2 example (a document unit).
func goldenUnitContext() EnvelopeContext {
	c := goldenContext()
	c.Document, c.DocumentVersion, c.ManifestDigest = uuid(0xa1), uuid(0xb1), digest(0xc1)
	return c
}

// goldenUnitHex is profile 1's golden encoding with profile version 2 and
// fields 15 to 17 appended. Changing it changes the wire profile.
const goldenUnitHex = "080212100102030405060708090a0b0c0d0e0f101a101112131415161718191a1b1c1d1e1f2022102122232425262728292a2b2c2d2e2f30" +
	"2a103132333435363738393a3b3c3d3e3f403001380142204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6048" +
	"9c804052206162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80580160016a208182838485868788898a8b8c8d8e" +
	"8f909192939495969798999a9b9c9d9e9fa07080f4d28e99347a10a1a2a3a4a5a6a7a8a9aaabacadaeafb0820110b1b2b3b4b5b6b7b8b9babb" +
	"bcbdbebfc08a0120c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"

// TestUnitContext covers profile 2 (DOC-007, V-152): the frozen encoding,
// and the rejection of partial, misplaced and profile-mismatched document
// fields.
func TestUnitContext(t *testing.T) {
	g, _ := hex.DecodeString(goldenUnitHex)
	b, err := goldenUnitContext().Marshal()
	if err != nil || !bytes.Equal(b, g) {
		t.Fatalf("encoding changed:\n got %x\nwant %s (%v)", b, goldenUnitHex, err)
	}
	c, err := ParseEnvelopeContext(g)
	if err != nil || c != goldenUnitContext() || c.Profile() != 2 {
		t.Fatalf("parse = %+v, %v", c, err)
	}
	p1 := golden(t)
	tail := g[len(p1):] // fields 15 to 17
	for name, b := range map[string][]byte{
		"profile 1 with document fields": append(slices.Clone(p1), tail...),
		"profile 2 without them":         append([]byte{0x08, 0x02}, p1[2:]...),
		"profile 2 missing field 17":     g[:len(g)-35],
		"profile 2 fields reordered":     append(append(slices.Clone(g[:len(p1)]), tail[18:37]...), append(slices.Clone(tail[:18]), tail[37:]...)...),
		"profile 3":                      append([]byte{0x08, 0x03}, g[2:]...),
	} {
		if _, err := ParseEnvelopeContext(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	partial := goldenUnitContext()
	partial.ManifestDigest = Digest{}
	if _, err := partial.Marshal(); err == nil {
		t.Error("a context with a partial document binding was encoded")
	}
	// Two document versions reusing one unit have distinct contexts
	// (V-152).
	other := goldenUnitContext()
	other.DocumentVersion = uuid(0xd1)
	ob, _ := other.Marshal()
	if bytes.Equal(ob, g) {
		t.Error("contexts of two document versions are equal")
	}
}

// TestManifestAndUnitDescriptor covers the strict document formats of
// DOC-001.
func TestManifestAndUnitDescriptor(t *testing.T) {
	unit := ManifestUnit{UnitID: uuid(0x11).String(), UnitVersionID: uuid(0x21).String(), CryptoVersionID: uuid(0x31).String(),
		CiphertextSHA256: digest(0x41).String(), CiphertextLength: 100, Suite: Suite1, Format: Format1}
	m := Manifest{TenantID: uuid(1).String(), DocumentID: uuid(2).String(), DocumentVersionID: uuid(3).String(),
		NormalizationVersion: "fga.text/nfc-paragraphs-v1", Units: []ManifestUnit{unit}}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(b); err != nil {
		t.Fatal(err)
	}
	d1 := ManifestDigest(b)
	if d1 == ManifestDigest(append(slices.Clone(b), ' ')) {
		t.Error("the digest ignores the bytes")
	}
	for name, edit := range map[string]func(*Manifest){
		"no units":       func(m *Manifest) { m.Units = nil },
		"duplicate unit": func(m *Manifest) { m.Units = []ManifestUnit{unit, unit} },
		"bad unit digest": func(m *Manifest) {
			m.Units = []ManifestUnit{{UnitID: unit.UnitID, UnitVersionID: unit.UnitVersionID, CryptoVersionID: unit.CryptoVersionID, CiphertextSHA256: "sha256:00", CiphertextLength: 1, Suite: 1, Format: 1}}
		},
		"no normalization": func(m *Manifest) { m.NormalizationVersion = "" },
		"bad document":     func(m *Manifest) { m.DocumentID = "doc" },
	} {
		bad := m
		edit(&bad)
		if _, err := bad.Marshal(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := ParseManifest(append(b[:len(b)-1], []byte(`,"extra":1}`)...)); err == nil {
		t.Error("a manifest with an unknown field parsed")
	}
	ud := UnitDescriptor{TenantID: uuid(1).String(), DocumentID: uuid(2).String(), DocumentVersionID: uuid(3).String(),
		ManifestDigest: d1.String(), UnitID: unit.UnitID, UnitVersionID: unit.UnitVersionID, CryptoVersionID: unit.CryptoVersionID,
		BlobID: uuid(0x51).String(), CiphertextSHA256: unit.CiphertextSHA256, CiphertextLength: 100, Suite: Suite1, Format: Format1,
		Signer: digest(0x81).String(), CreatedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	db, err := ud.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ud.Version = UnitDescriptorVersion
	if got, err := ParseUnitDescriptor(db); err != nil || got != ud {
		t.Fatalf("unit descriptor = %+v, %v", got, err)
	}
	ud.ManifestDigest = "manifest"
	if _, err := ud.Marshal(); err == nil {
		t.Error("a unit descriptor without a manifest digest was encoded")
	}
}
