package keybox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

var update = flag.Bool("update", false, "write testdata/go-v1.json, for mosaic-key-store's crypto module to open")

// vector is a box with the keys and unlockers that open it, as
// mosaic-key-store's crypto/examples/box_vector.rs writes it.
type vector struct {
	Format              string `json:"format"`
	About               string `json:"about"`
	Box                 []byte `json:"box"`
	BoxKey              []byte `json:"box_key"`
	Tenant              string `json:"tenant"`
	Principal           string `json:"principal"`
	RecipientPrivate    []byte `json:"recipient_private"`
	RecipientKeyVersion uint32 `json:"recipient_key_version"`
	SigningSeed         []byte `json:"signing_seed"`
	SignInSeed          []byte `json:"sign_in_seed"`
	SecretUnlocker      struct {
		ID     string `json:"id"`
		Secret []byte `json:"secret"`
	} `json:"secret_unlocker"`
	KeyUnlocker struct {
		ID            string `json:"id"`
		UnlockPrivate []byte `json:"unlock_private"`
		UnlockPublic  []byte `json:"unlock_public"`
	} `json:"key_unlocker"`
	Trust []struct {
		Kind       TrustKind `json:"kind"`
		Public     []byte    `json:"public"`
		KeyVersion uint32    `json:"key_version"`
		Owner      string    `json:"owner"`
	} `json:"trust"`
}

func readVector(t *testing.T, name string) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// checkVector opens a box both ways and checks everything it holds.
func checkVector(t *testing.T, v vector) {
	t.Helper()
	b, err := Parse(v.Box)
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := b.Encode(); !bytes.Equal(enc, v.Box) {
		t.Fatal("the box does not encode back to its bytes")
	}
	if b.Owner.Tenant != v.Tenant || b.Owner.Principal != v.Principal {
		t.Fatalf("owner %+v", b.Owner)
	}
	k1, err := b.BoxKey([]byte(v.SecretUnlocker.ID), v.SecretUnlocker.Secret)
	if err != nil || !bytes.Equal(k1[:], v.BoxKey) {
		t.Fatalf("the secret's unlocker: %v", err)
	}
	k2, err := b.BoxKeyWithKey([]byte(v.KeyUnlocker.ID), v.KeyUnlocker.UnlockPrivate)
	if err != nil || k2 != k1 {
		t.Fatalf("the unlock key's unlocker: %v", err)
	}
	c, err := b.Contents(&k1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.RecipientPrivate[:], v.RecipientPrivate) || !bytes.Equal(c.SigningSeed[:], v.SigningSeed) ||
		!bytes.Equal(c.SignInSeed[:], v.SignInSeed) || c.RecipientKeyVersion != v.RecipientKeyVersion || len(c.Trust) != len(v.Trust) {
		t.Fatal("the contents differ")
	}
	for i, e := range v.Trust {
		got := c.Trust[i]
		if got.Kind != e.Kind || !bytes.Equal(got.Public[:], e.Public) || got.KeyVersion != e.KeyVersion || got.Owner != e.Owner {
			t.Fatalf("trust entry %d: %+v", i, got)
		}
	}
	// The fga program's view of the same keys: its Tink key from the raw
	// one has the fingerprint the box names.
	rk, err := crypto.RecipientKeyFromRawInsecure(c.RecipientPrivate[:])
	if err != nil || rk.Fingerprint() != b.Owner.RecipientFingerprint {
		t.Fatalf("the recipient key from its raw form: %v", err)
	}
	if raw, _ := rk.RawPrivateInsecure(); !bytes.Equal(raw, v.RecipientPrivate) {
		t.Fatal("the raw recipient key does not come back")
	}
	if cryptowire.SignInKeyFingerprint(ed25519.NewKeyFromSeed(v.SignInSeed).Public().(ed25519.PublicKey)) != b.Owner.SignInFingerprint {
		t.Fatal("the sign-in fingerprint")
	}

	// Refusals.
	if _, err := b.BoxKey([]byte(v.SecretUnlocker.ID), make([]byte, 32)); !errors.Is(err, ErrUnlock) {
		t.Errorf("the wrong secret: %v", err)
	}
	if _, err := b.BoxKey([]byte(v.KeyUnlocker.ID), v.SecretUnlocker.Secret); !errors.Is(err, ErrUnlock) {
		t.Errorf("a key's unlocker opened with a secret: %v", err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := b.BoxKeyWithKey([]byte(v.KeyUnlocker.ID), other.Bytes()); !errors.Is(err, ErrUnlock) {
		t.Errorf("another unlock key: %v", err)
	}
	if _, err := Parse(append(bytes.Clone(v.Box), 0)); !errors.Is(err, ErrFormat) {
		t.Errorf("trailing bytes: %v", err)
	}
	changed := bytes.Clone(v.Box)
	changed[len(changed)-1] ^= 1
	if cb, err := Parse(changed); err != nil {
		t.Fatal(err)
	} else if _, err := cb.Contents(&k1); !errors.Is(err, ErrUnlock) {
		t.Errorf("a changed box: %v", err)
	}
	renamed := bytes.Replace(bytes.Clone(v.Box), []byte(v.Principal), []byte("rana"), 1)
	if rb, err := Parse(renamed); err == nil {
		if _, err := rb.BoxKey([]byte(v.SecretUnlocker.ID), v.SecretUnlocker.Secret); !errors.Is(err, ErrUnlock) {
			t.Errorf("a box given to another name: %v", err)
		}
	}
}

// TestRustBox opens the box mosaic-key-store's Rust module wrote
// (testdata/rust-v1.json, a copy of its tests/vectors/key-box-rust-v1.json):
// byte for byte the same layout, and both kinds of unlocker.
func TestRustBox(t *testing.T) {
	v := readVector(t, "rust-v1.json")
	if v.Format != "mosaic.key-box-vector/v1" {
		t.Fatalf("format %q", v.Format)
	}
	checkVector(t, v)
}

// TestGoBox seals a box here and opens it again; with -update it writes
// testdata/go-v1.json for the Rust module to open.
func TestGoBox(t *testing.T) {
	v := vector{Format: "mosaic.key-box-vector/v1", Tenant: "t-acme", Principal: "dana", RecipientKeyVersion: 4,
		About: "A key box made by fga's Go implementation (sdk/go/keybox TestGoBox -update). Test keys only."}
	c := &Contents{RecipientKeyVersion: 4}
	for _, k := range [][]byte{c.RecipientPrivate[:], c.SigningSeed[:], c.SignInSeed[:]} {
		_, _ = rand.Read(k)
	}
	lena, _ := crypto.NewRecipientKey()
	var lenaPub [32]byte
	copy(lenaPub[:], lena.PublicKey())
	c.Trust = []TrustEntry{{Kind: TrustRecipient, Public: lenaPub, KeyVersion: 2, Owner: "lena"}}
	owner, err := OwnerOf(v.Tenant, v.Principal, c)
	if err != nil {
		t.Fatal(err)
	}
	var boxKey [32]byte
	_, _ = rand.Read(boxKey[:])
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	unlock, _ := ecdh.X25519().GenerateKey(rand.Reader)
	u1, err := WrapSecret(owner, &boxKey, []byte("passkey-1"), secret)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := WrapForKey(owner, &boxKey, []byte("fga program"), unlock.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(owner, &boxKey, c, []Unlocker{u1, u2})
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := b.Encode()
	v.Box, v.BoxKey = enc, boxKey[:]
	v.RecipientPrivate, v.SigningSeed, v.SignInSeed = c.RecipientPrivate[:], c.SigningSeed[:], c.SignInSeed[:]
	v.SecretUnlocker.ID, v.SecretUnlocker.Secret = "passkey-1", secret
	v.KeyUnlocker.ID, v.KeyUnlocker.UnlockPrivate, v.KeyUnlocker.UnlockPublic = "fga program", unlock.Bytes(), unlock.PublicKey().Bytes()
	v.Trust = append(v.Trust, struct {
		Kind       TrustKind `json:"kind"`
		Public     []byte    `json:"public"`
		KeyVersion uint32    `json:"key_version"`
		Owner      string    `json:"owner"`
	}{TrustRecipient, lenaPub[:], 2, "lena"})
	checkVector(t, v)
	if *update {
		out, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(filepath.Join("testdata", "go-v1.json"), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The committed Go vector still opens.
	checkVector(t, readVector(t, "go-v1.json"))
}

func TestSealRefuses(t *testing.T) {
	c := &Contents{RecipientKeyVersion: 1}
	owner, _ := OwnerOf("t", "p", c)
	var key [32]byte
	if _, err := Seal(owner, &key, c, nil); !errors.Is(err, ErrFormat) {
		t.Errorf("no unlocker: %v", err)
	}
	if _, err := WrapSecret(owner, &key, []byte("u"), make([]byte, 16)); !errors.Is(err, ErrFormat) {
		t.Errorf("a short secret: %v", err)
	}
	u, _ := WrapSecret(owner, &key, []byte("u"), make([]byte, 32))
	if _, err := Seal(owner, &key, &Contents{}, []Unlocker{u}); !errors.Is(err, ErrFormat) {
		t.Errorf("no recipient key version: %v", err)
	}
	if _, err := OwnerOf("", "p", c); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(Owner{Principal: "p"}, &key, c, []Unlocker{u}); !errors.Is(err, ErrFormat) {
		t.Errorf("no tenant: %v", err)
	}
}
