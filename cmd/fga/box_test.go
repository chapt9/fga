package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fga/sdk/go/crypto"
	"fga/sdk/go/keybox"
)

// TestKeyBox covers the fga program's box mode (box.go): an enrolled key
// directory's keys go into a box; the program then works from the box and
// signs its tokens as the box's owner; a second program gets the box as a
// file locked for its own unlock key; an unlocker is removed.
func TestKeyBox(t *testing.T) {
	none := func() ([]byte, error) { return nil, nil }
	dir := t.TempDir()
	if err := keysInit(dir, nil); err != nil {
		t.Fatal(err)
	}
	if err := signInKeyNew([]string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
	lena, _ := crypto.NewRecipientKey()
	tf, _ := readTrust(dir)
	tf.Recipients[lena.Fingerprint().String()] = base64.StdEncoding.EncodeToString(lena.PublicKey())
	if err := writeTrust(dir, tf); err != nil {
		t.Fatal(err)
	}
	before, err := keyFilesClient(dir, none)
	if err != nil {
		t.Fatal(err)
	}
	if err := boxInit(dir, "fga program", "t-acme", "dana", false, none); err == nil {
		t.Fatal("a box before the keys were enrolled")
	}
	if err := os.WriteFile(filepath.Join(dir, "key_version"), []byte("3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boxInit(dir, "fga program", "t-acme", "dana", false, none); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"recipient.key", "signing.key", signInFile, "trust.json", "key_version"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still there", name)
		}
	}

	// The program works from the box.
	t.Setenv("FGA_TOKEN", "")
	t.Setenv("FGA_KEYS_TOKEN", "")
	t.Setenv("FGA_PRINCIPAL", "")
	c, err := loadClient(dir, none)
	if err != nil {
		t.Fatal(err)
	}
	if c.Recipient.Fingerprint() != before.Recipient.Fingerprint() || c.Signer.Fingerprint != before.Signer.Fingerprint || c.KeyVersion != 3 {
		t.Fatal("the box holds other keys")
	}
	if pub, ok := c.Trust.Recipient(lena.Fingerprint()); !ok || string(pub) != string(lena.PublicKey()) {
		t.Fatal("the trust list did not come along")
	}
	signer, ok := c.Tokens.(*keySigner)
	if !ok || signer.subject != "dana" || signer.tenant != "t-acme" {
		t.Fatalf("tokens: %#v", c.Tokens)
	}
	if err := signInKeyToken([]string{"-dir", dir, "-aud", "fga-admin"}); err != nil {
		t.Fatalf("a token from the box: %v", err)
	}

	// A second program: its unlock key, the box locked for it, imported.
	second := t.TempDir()
	pub, err := newUnlockKey(second, "fga program, laptop 2", false, none)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "box")
	if err := boxCommand("add-unlock-key", []string{"-dir", dir, "-id", "fga program, laptop 2", "-public-key", base64.StdEncoding.EncodeToString(pub), "-out", file}); err != nil {
		t.Fatal(err)
	}
	// Only the person's own box is taken, and nothing is kept of another's
	// (security review of 5 November 2026, finding 2).
	for name, who := range map[string][]string{"someone else's": {"-tenant", "t-acme", "-principal", "mallory"},
		"another tenant's": {"-tenant", "t-other", "-principal", "dana"}, "anyone's": {}} {
		if err := boxCommand("import", append([]string{"-dir", second, "-in", file}, who...)); err == nil {
			t.Fatalf("imported the box as %s", name)
		}
		if boxMode(second) {
			t.Fatalf("kept the box after refusing it as %s", name)
		}
	}
	if err := boxCommand("import", []string{"-dir", second, "-in", file, "-tenant", "t-acme", "-principal", "dana"}); err != nil {
		t.Fatal(err)
	}
	c2, err := loadClient(second, none)
	if err != nil || c2.Recipient.Fingerprint() != c.Recipient.Fingerprint() {
		t.Fatalf("the second program's keys: %v", err)
	}
	if err := boxCommand("import", []string{"-dir", second, "-in", file, "-tenant", "t-acme", "-principal", "dana"}); err == nil {
		t.Fatal("a second import over the box")
	}

	// Trust added in one program's box.
	rita, _ := crypto.NewRecipientKey()
	if err := boxTrustAdd(dir, base64.StdEncoding.EncodeToString(rita.PublicKey()), "", "rita", 1, none); err != nil {
		t.Fatal(err)
	}
	if c, _ := loadClient(dir, none); c != nil {
		if _, ok := c.Trust.Recipient(rita.Fingerprint()); !ok {
			t.Fatal("rita is not trusted after trust add")
		}
	}
	if err := boxTrustAdd(dir, base64.StdEncoding.EncodeToString(rita.PublicKey()), "", "", 1, none); err == nil {
		t.Fatal("trust add without an owner")
	}

	// A lost laptop: its unlocker leaves the box; this program's stays.
	if err := boxCommand("remove-unlocker", []string{"-dir", dir, "-id", "fga program"}); err == nil {
		t.Fatal("removed this program's own unlocker")
	}
	if err := boxCommand("remove-unlocker", []string{"-dir", dir, "-id", "fga program, laptop 2"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, boxFile))
	b, err := keybox.Parse(raw)
	if err != nil || len(b.Unlockers) != 1 {
		t.Fatalf("unlockers after the removal: %v", err)
	}
	if err := boxCommand("show", []string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
}

// TestImportRustBox imports the box mosaic-key-store's Rust module made
// (sdk/go/keybox/testdata/rust-v1.json), as from the add-on.
func TestImportRustBox(t *testing.T) {
	raw, err := os.ReadFile("../../sdk/go/keybox/testdata/rust-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Box         []byte `json:"box"`
		KeyUnlocker struct {
			ID            string `json:"id"`
			UnlockPrivate []byte `json:"unlock_private"`
		} `json:"key_unlocker"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, unlockFile), []byte(base64.StdEncoding.EncodeToString(v.KeyUnlocker.UnlockPrivate)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, unlockIDFile), []byte(v.KeyUnlocker.ID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "box")
	if err := os.WriteFile(file, v.Box, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boxCommand("import", []string{"-dir", dir, "-in", file, "-tenant", "t-acme", "-principal", "lena"}); err == nil || boxMode(dir) {
		t.Fatalf("dana's box imported for lena: %v", err)
	}
	t.Setenv("FGA_TENANT", "t-acme")
	t.Setenv("FGA_PRINCIPAL", "dana")
	if err := boxCommand("import", []string{"-dir", dir, "-in", file}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FGA_TOKEN", "")
	t.Setenv("FGA_KEYS_TOKEN", "")
	c, err := loadClient(dir, func() ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyVersion != 3 || c.Tokens.(*keySigner).subject != "dana" {
		t.Fatalf("the Rust box's keys: version %d", c.KeyVersion)
	}
}
