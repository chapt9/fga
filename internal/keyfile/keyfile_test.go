package keyfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpen(t *testing.T) {
	payload := []byte("base64-ed25519-private-key\n")
	sealed, err := Seal(payload, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if !Protected(sealed) || Protected(payload) || bytes.Contains(sealed, payload[:10]) {
		t.Fatal("protection detection or plaintext in the file")
	}
	if got, err := Open(sealed, []byte("correct horse")); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("open = %q, %v", got, err)
	}
	if _, err := Open(sealed, []byte("wrong")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := Open(sealed, nil); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	again, _ := Seal(payload, []byte("correct horse"))
	if bytes.Equal(again, sealed) {
		t.Error("two seals of the same payload are equal; the salt must be fresh")
	}
}

// TestHeaderIsBound: changing the KDF parameters or salt breaks the file,
// and parameters outside the bounds are refused before any work.
func TestHeaderIsBound(t *testing.T) {
	sealed, _ := Seal([]byte("key"), []byte("pw"))
	edit := func(change func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(sealed, &m)
		change(m)
		b, _ := json.Marshal(m)
		return b
	}
	for name, tc := range map[string]struct {
		data []byte
		want error
	}{
		"weaker time":   {edit(func(m map[string]any) { m["time"] = 1 }), ErrDecrypt},
		"other salt":    {edit(func(m map[string]any) { m["salt"] = "AAAAAAAAAAAAAAAAAAAAAA==" }), ErrDecrypt},
		"huge memory":   {edit(func(m map[string]any) { m["memory_kib"] = 1 << 30 }), ErrFormat},
		"many threads":  {edit(func(m map[string]any) { m["threads"] = 200 }), ErrFormat},
		"other kdf":     {edit(func(m map[string]any) { m["kdf"] = "scrypt" }), ErrFormat},
		"unknown field": {edit(func(m map[string]any) { m["note"] = "x" }), ErrFormat},
	} {
		if _, err := Open(tc.data, []byte("pw")); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestReadWriteAndPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := Write(path, []byte("plain")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	asked := false
	if got, err := Read(path, func() ([]byte, error) { asked = true; return nil, nil }); err != nil || string(got) != "plain" || asked {
		t.Fatalf("plain read = %q, %v, asked %v", got, err, asked)
	}
	sealed, _ := Seal([]byte("secret"), []byte("pw"))
	if err := Write(path, sealed); err != nil {
		t.Fatal(err)
	}
	pw := []byte("pw")
	for i := 0; i < 2; i++ { // one passphrase opens several files
		if got, err := Read(path, func() ([]byte, error) { return pw, nil }); err != nil || string(got) != "secret" {
			t.Fatalf("protected read %d = %q, %v", i, got, err)
		}
	}
	if string(pw) != "pw" {
		t.Fatal("Read changed the caller's passphrase")
	}
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte("pw\n"), 0o600)
	if p, err := Passphrase("FGA_TEST_UNSET_PASSPHRASE", pwFile); err != nil || string(p) != "pw" {
		t.Fatalf("passphrase file = %q, %v", p, err)
	}
	t.Setenv("FGA_TEST_PASSPHRASE", "from-env")
	if p, err := Passphrase("FGA_TEST_PASSPHRASE", ""); err != nil || string(p) != "from-env" {
		t.Fatalf("passphrase env = %q, %v", p, err)
	}
	if _, err := Passphrase("FGA_TEST_UNSET_PASSPHRASE", ""); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
}
