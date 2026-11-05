package adminops

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"fga/internal/authn"
)

// TestSignInKeyLabels is the regression test of the security review of 5
// November 2026, finding 4: a key's label took bidirectional overrides,
// zero-width characters and C1 controls, so an administrator could read
// one key's label as another's before removing it. A label is now one
// line of plain text (package plaintext), refused before anything is
// stored; no catalog is needed to refuse it.
func TestSignInKeyLabels(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	who := Who{Actor: "rita", Via: "test"}
	for name, label := range map[string]string{
		"empty":                    "",
		"too long":                 strings.Repeat("x", MaxKeyLabel+1),
		"not UTF-8":                "laptop\xff",
		"a C0 control":             "laptop\x1b[2J",
		"a C1 control":             "laptop\u0085",
		"a right-to-left override": "Dana's laptop\u202epot-pal s'yrollam",
		"a zero-width space":       "Dana's laptop\u200b",
		"two lines":                "Dana's\nlaptop",
	} {
		if _, err := (Ops{}).AddSignInKey(context.Background(), who, "t-acme", "dana", pub, label, authn.KeyLimits{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
