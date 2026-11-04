package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateKeysNeverOverwrites: a second run with the same prefix
// refuses, and the key pair stays (security review of 4 November 2026,
// finding 8).
func TestGenerateKeysNeverOverwrites(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "publisher")
	if err := generateKeys([]string{"-out", prefix}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if err := generateKeys([]string{"-out", prefix}); err == nil {
		t.Fatal("an existing key pair was overwritten")
	}
	after, err := os.ReadFile(prefix + ".key")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the key changed: %v", err)
	}
}
