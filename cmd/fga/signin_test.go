package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fga/internal/authn"
)

// TestSignInKeyTokens covers the fga program's sign-in key: it is made
// once, signs tokens only for $FGA_PRINCIPAL of $FGA_TENANT, and reuses a
// token per audience until a minute before it expires.
func TestSignInKeyTokens(t *testing.T) {
	dir := t.TempDir()
	if err := signInKeyNew([]string{"-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := signInKeyNew([]string{"-dir", dir}); err == nil {
		t.Fatal("a second key over the first")
	}
	none := func() ([]byte, error) { return nil, nil }
	t.Setenv("FGA_TENANT", "")
	t.Setenv("FGA_PRINCIPAL", "")
	if _, err := loadSigner(dir, "fga", none); err == nil {
		t.Fatal("a signer without an account")
	}
	if s, err := loadSigner(t.TempDir(), "fga", none); s != nil || err != nil {
		t.Fatalf("a directory without a key: %v %v", s, err)
	}
	t.Setenv("FGA_TENANT", "t-acme")
	t.Setenv("FGA_PRINCIPAL", "dana")
	s, err := loadSigner(dir, "fga", none)
	if err != nil || s == nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	first, _ := s.Token("fga-storage")
	again, _ := s.Token("fga-storage")
	keys, _ := s.Token("fga-keys")
	if first != again || first == keys {
		t.Fatal("tokens are reused per audience")
	}
	clock = clock.Add(authn.SignInMaxLifetime - time.Minute)
	if later, _ := s.Token("fga-storage"); later == first {
		t.Fatal("a token a minute from expiry was reused")
	}
	pub := s.priv.Public().(ed25519.PublicKey)
	v := authn.NewVerifier(authn.DevIssuer, nil, func() time.Time { return clock }).AcceptSignInKeys(
		func(tenant, fp string) (authn.SignInKey, bool, error) {
			return authn.SignInKey{Tenant: "t-acme", Principal: "dana", Public: pub}, fp == s.fingerprint, nil
		})
	tok, _ := s.Token("fga-keys")
	if c, err := v.Verify(tok, "fga-keys"); err != nil || c.Subject != "dana" || c.ClientID != "fga" {
		t.Fatalf("the program's token: %+v %v", c, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, signInFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("signin.key mode: %v %v", fi, err)
	}
}
