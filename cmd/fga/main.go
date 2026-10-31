// Command fga holds the administrative tools of the platform:
//
//	fga keys generate -out PREFIX            write PREFIX.key and PREFIX.pub (Ed25519)
//	fga policy validate DIR                  parse, compile and run a bundle's sentinels
//	fga policy sign -key FILE -key-id ID -epoch N DIR
//	                                         sign a bundle directory in place
//	fga dev-token -key FILE -key-id ID -sub ID -tenant T -aud A [-ttl D]
//	                                         print a development access token
//
// and the client commands of client.go (keys init, keys enroll, trust add,
// put, get, ls, rm, share).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"fga/internal/authn"
	"fga/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fga:", err)
		os.Exit(1)
	}
}

const usage = "usage: fga keys generate -out PREFIX | fga policy validate DIR | fga policy sign -key FILE -key-id ID -epoch N DIR" +
	" | fga dev-token -key FILE -key-id ID -sub ID -tenant T -aud A [-ttl D]" +
	" | fga keys init|keys enroll|keys protect|keys unprotect|trust add|put|put-document|get|get-document|ls|rm|share|finalize|label|propose-label|approvals [flags]" +
	" | fga approve|reject [flags] ID (see cmd/fga/client.go)"

func run(args []string) error {
	if len(args) >= 1 && args[0] == "dev-token" {
		return devToken(args[1:])
	}
	if len(args) < 1 {
		return errors.New(usage)
	}
	switch args[0] {
	case "put", "put-document", "get", "get-document", "ls", "rm", "share", "finalize", "label", "propose-label", "approvals", "approve", "reject":
		return clientCommand(args[0], args[1:])
	}
	if len(args) < 2 {
		return errors.New(usage)
	}
	switch args[0] + " " + args[1] {
	case "keys init", "keys enroll", "keys protect", "keys unprotect", "trust add":
		return clientCommand(args[0]+" "+args[1], args[2:])
	case "keys generate":
		return generateKeys(args[2:])
	case "policy validate":
		return validate(args[2:])
	case "policy sign":
		return sign(args[2:])
	}
	return errors.New(usage)
}

func generateKeys(args []string) error {
	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	out := fs.String("out", "", "path prefix for PREFIX.key and PREFIX.pub")
	if err := fs.Parse(args); err != nil || *out == "" {
		return errors.New("keys generate needs -out PREFIX")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out+".key", []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(*out+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

// validate prepares the bundle as an instance would, without a signature
// check, so authors find errors before signing.
func validate(args []string) error {
	if len(args) != 1 {
		return errors.New("policy validate needs one bundle directory")
	}
	b, _, err := release.LoadBundle(args[0])
	if err != nil {
		return err
	}
	env := release.R1Environment()
	env.Stamp(&b.Info)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := signBundle(&b, "validate", priv); err != nil {
		return err
	}
	m := release.NewManager(map[string]ed25519.PublicKey{"validate": pub}, env, noEpochs{}, time.Now)
	if err := m.Activate(context.Background(), b); err != nil {
		return err
	}
	fmt.Printf("bundle valid: %d documents, %d sentinels\n", len(b.Documents), len(b.Sentinels))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "Ed25519 private key file (base64)")
	keyID := fs.String("key-id", "", "publisher key ID")
	epoch := fs.Uint64("epoch", 0, "release epoch; must exceed the active epoch")
	if err := fs.Parse(args); err != nil || *keyFile == "" || *keyID == "" || *epoch == 0 || fs.NArg() != 1 {
		return errors.New("policy sign needs -key, -key-id, -epoch and one bundle directory")
	}
	dir := fs.Arg(0)
	priv, err := readPrivateKey(*keyFile)
	if err != nil {
		return err
	}
	b, m, err := release.LoadBundle(dir)
	if err != nil {
		return err
	}
	// The signer attests the environment it validated against (REL-001).
	release.R1Environment().Stamp(&m.Info)
	b.Epoch, b.Info = *epoch, m.Info
	if err := signBundle(&b, *keyID, priv); err != nil {
		return err
	}
	m.Epoch, m.KeyID, m.Signature = b.Epoch, b.KeyID, base64.StdEncoding.EncodeToString(b.Signature)
	if err := release.WriteManifest(dir, m); err != nil {
		return err
	}
	digest, _ := b.Digest()
	fmt.Printf("signed %s epoch %d with %s\n", digest, b.Epoch, b.KeyID)
	return nil
}

// devToken prints an access token of the development profile
// (first-hop-authentication.md). The key is the development issuer's.
func devToken(args []string) error {
	fs := flag.NewFlagSet("dev-token", flag.ContinueOnError)
	keyFile := fs.String("key", "", "development issuer private key file (base64 Ed25519)")
	keyID := fs.String("key-id", "", "issuer key ID")
	sub := fs.String("sub", "", "identity ID")
	tenant := fs.String("tenant", "", "tenant")
	aud := fs.String("aud", "", "audience, for example fga-storage")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime, at most 1h")
	if err := fs.Parse(args); err != nil || *keyFile == "" || *keyID == "" || *sub == "" || *tenant == "" || *aud == "" {
		return errors.New("dev-token needs -key, -key-id, -sub, -tenant and -aud")
	}
	priv, err := readPrivateKey(*keyFile)
	if err != nil {
		return err
	}
	iss, err := authn.NewIssuer("fga-dev", *keyID, priv, time.Now)
	if err != nil {
		return err
	}
	tok, err := iss.Issue(*sub, *tenant, *aud, *ttl)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("the key file must hold a base64 Ed25519 private key")
	}
	return priv, nil
}

func signBundle(b *release.Bundle, keyID string, priv ed25519.PrivateKey) error {
	digest, err := b.Digest()
	if err != nil {
		return err
	}
	b.KeyID = keyID
	b.Signature = ed25519.Sign(priv, release.SigningBytes(b.Epoch, digest))
	return nil
}

type noEpochs struct{}

func (noEpochs) RequiredEpoch(context.Context, string) (uint64, error) { return 0, nil }

func httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
