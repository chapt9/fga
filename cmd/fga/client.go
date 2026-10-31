package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fga/internal/cryptowire"
	"fga/sdk/go/client"
	"fga/sdk/go/crypto"
)

// The client commands use a key directory (-dir, default $FGA_KEY_DIR)
// holding the development profile's local custody (D-08 open):
//
//	recipient.key  the recipient keyset, in the clear, mode 0600
//	signing.key    the content-signing key (base64 Ed25519), mode 0600
//	key_version    the recipient key's version once enrolled
//	trust.json     pinned recipients and trusted signers (RCP-002)
//
// Endpoints and tokens come from $FGA_STORAGE_URL, $FGA_KEYS_URL,
// $FGA_TOKEN (storage audience) and $FGA_KEYS_TOKEN (keys audience).
//
//	fga keys init      [-dir D]          create the key directory and print its public keys
//	fga keys enroll    -tenant T -principal P
//	fga trust add      [-recipient B64] [-signer B64]
//	fga put            -bucket B -key K -in FILE [-to FP,...] [-if-none-match]
//	fga get            -bucket B -key K -out FILE [-version V]
//	fga ls             -bucket B [-prefix P]
//	fga rm             -bucket B -key K [-version V]
//	fga share          -bucket B -key K -to FP -key-version N [-generation G] [-version V]

type trustFile struct {
	Recipients map[string]string `json:"recipients"`
	Signers    map[string]string `json:"signers"`
}

type fileTrust struct {
	recipients map[cryptowire.Digest][]byte
	signers    map[cryptowire.Digest]ed25519.PublicKey
}

func (t fileTrust) Recipient(fp cryptowire.Digest) ([]byte, bool) {
	k, ok := t.recipients[fp]
	return k, ok
}
func (t fileTrust) Signer(fp cryptowire.Digest) (ed25519.PublicKey, bool) {
	k, ok := t.signers[fp]
	return k, ok
}

func readTrust(dir string) (trustFile, error) {
	tf := trustFile{Recipients: map[string]string{}, Signers: map[string]string{}}
	raw, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if errors.Is(err, os.ErrNotExist) {
		return tf, nil
	}
	if err != nil {
		return tf, err
	}
	return tf, json.Unmarshal(raw, &tf)
}

func writeTrust(dir string, tf trustFile) error {
	b, _ := json.MarshalIndent(tf, "", "  ")
	return os.WriteFile(filepath.Join(dir, "trust.json"), append(b, '\n'), 0o600)
}

func (tf trustFile) store() (fileTrust, error) {
	t := fileTrust{recipients: map[cryptowire.Digest][]byte{}, signers: map[cryptowire.Digest]ed25519.PublicKey{}}
	for fp, b64 := range tf.Recipients {
		d, err1 := cryptowire.ParseDigest(fp)
		k, err2 := base64.StdEncoding.DecodeString(b64)
		if err := errors.Join(err1, err2); err != nil || cryptowire.RecipientFingerprint(cryptowire.Suite1, k) != d {
			return t, fmt.Errorf("trust.json: recipient %s does not match its key", fp)
		}
		t.recipients[d] = k
	}
	for fp, b64 := range tf.Signers {
		d, err1 := cryptowire.ParseDigest(fp)
		k, err2 := base64.StdEncoding.DecodeString(b64)
		if err := errors.Join(err1, err2); err != nil || cryptowire.SigningKeyFingerprint(k) != d {
			return t, fmt.Errorf("trust.json: signer %s does not match its key", fp)
		}
		t.signers[d] = k
	}
	return t, nil
}

func keysInit(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "recipient.key")); err == nil {
		return fmt.Errorf("%s already holds keys", dir)
	}
	rk, err := crypto.NewRecipientKey()
	if err != nil {
		return err
	}
	raw, err := rk.MarshalPrivateInsecure()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "recipient.key"), raw, 0o600); err != nil {
		return err
	}
	sk, err := crypto.NewSigningKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.key"), []byte(base64.StdEncoding.EncodeToString(sk.Private)+"\n"), 0o600); err != nil {
		return err
	}
	pub := sk.Private.Public().(ed25519.PublicKey)
	tf := trustFile{Recipients: map[string]string{rk.Fingerprint().String(): base64.StdEncoding.EncodeToString(rk.PublicKey())},
		Signers: map[string]string{sk.Fingerprint.String(): base64.StdEncoding.EncodeToString(pub)}}
	if err := writeTrust(dir, tf); err != nil {
		return err
	}
	fmt.Printf("recipient %s %s\nsigner %s %s\n", rk.Fingerprint(), base64.StdEncoding.EncodeToString(rk.PublicKey()),
		sk.Fingerprint, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadClient(dir string) (*client.Client, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "recipient.key"))
	if err != nil {
		return nil, err
	}
	rk, err := crypto.ParseRecipientKeyInsecure(raw)
	if err != nil {
		return nil, err
	}
	priv, err := readPrivateKey(filepath.Join(dir, "signing.key"))
	if err != nil {
		return nil, err
	}
	tf, err := readTrust(dir)
	if err != nil {
		return nil, err
	}
	trust, err := tf.store()
	if err != nil {
		return nil, err
	}
	var version uint64
	if b, err := os.ReadFile(filepath.Join(dir, "key_version")); err == nil {
		version, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	return &client.Client{StorageURL: os.Getenv("FGA_STORAGE_URL"), KeysURL: os.Getenv("FGA_KEYS_URL"), HTTP: httpClient(),
		StorageToken: os.Getenv("FGA_TOKEN"), KeysToken: os.Getenv("FGA_KEYS_TOKEN"), Recipient: rk, KeyVersion: version,
		Signer: crypto.SigningKeyFromPrivate(priv), Trust: trust, TempDir: dir}, nil
}

func clientCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", os.Getenv("FGA_KEY_DIR"), "key directory")
	bucket := fs.String("bucket", "", "bucket")
	key := fs.String("key", "", "object key")
	version := fs.String("version", "", "version ID")
	in := fs.String("in", "", "input file")
	out := fs.String("out", "", "output file")
	to := fs.String("to", "", "recipient fingerprints, comma-separated")
	keyVersion := fs.Uint64("key-version", 1, "target recipient key version")
	generation := fs.Uint64("generation", 1, "envelope generation")
	prefix := fs.String("prefix", "", "key prefix")
	ifNoneMatch := fs.Bool("if-none-match", false, "fail if the key has a current version")
	tenant := fs.String("tenant", "", "tenant")
	principal := fs.String("principal", "", "principal")
	recipient := fs.String("recipient", "", "base64 recipient public key to pin")
	signer := fs.String("signer", "", "base64 signer public key to trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir or $FGA_KEY_DIR is required")
	}
	if cmd == "keys init" {
		return keysInit(*dir)
	}
	if cmd == "trust add" {
		tf, err := readTrust(*dir)
		if err != nil {
			return err
		}
		if *recipient != "" {
			k, err := base64.StdEncoding.DecodeString(*recipient)
			if err != nil {
				return err
			}
			tf.Recipients[cryptowire.RecipientFingerprint(cryptowire.Suite1, k).String()] = *recipient
		}
		if *signer != "" {
			k, err := base64.StdEncoding.DecodeString(*signer)
			if err != nil || len(k) != ed25519.PublicKeySize {
				return errors.New("-signer must be a base64 Ed25519 public key")
			}
			tf.Signers[cryptowire.SigningKeyFingerprint(k).String()] = *signer
		}
		return writeTrust(*dir, tf)
	}
	c, err := loadClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	switch cmd {
	case "keys enroll":
		v, err := c.Enroll(ctx, *tenant, *principal)
		if err != nil {
			return err
		}
		fmt.Println(c.Recipient.Fingerprint(), "key version", v)
		return os.WriteFile(filepath.Join(*dir, "key_version"), []byte(strconv.FormatUint(v, 10)+"\n"), 0o600)
	case "put":
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		recipients := []crypto.Recipient{{Fingerprint: c.Recipient.Fingerprint(), KeyVersion: c.KeyVersion}}
		for _, fp := range split(*to) {
			d, err := cryptowire.ParseDigest(fp)
			if err != nil {
				return err
			}
			recipients = append(recipients, crypto.Recipient{Fingerprint: d, KeyVersion: *keyVersion})
		}
		p, err := c.Put(ctx, *bucket, *key, f, recipients, client.PutOptions{IfNoneMatch: *ifNoneMatch})
		if err != nil {
			return err
		}
		fmt.Printf("published %s version %s etag %s\n", *key, p.Version, p.ETag)
		return nil
	case "get":
		tmp := *out + ".partial"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		v, err := c.Get(ctx, *bucket, *key, *version, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		fmt.Printf("verified and decrypted version %s\n", v.Version)
		return os.Rename(tmp, *out)
	case "ls":
		cont := ""
		for {
			entries, next, err := c.List(ctx, *bucket, *prefix, 100, cont)
			if err != nil {
				return err
			}
			for _, e := range entries {
				fmt.Printf("%s\t%d\t%s\n", e.Key, e.CiphertextLength, e.Version)
			}
			if next == "" {
				return nil
			}
			cont = next
		}
	case "rm":
		return c.Delete(ctx, *bucket, *key, *version)
	case "share":
		d, err := cryptowire.ParseDigest(*to)
		if err != nil {
			return err
		}
		id, err := c.Share(ctx, *bucket, *key, *version, crypto.Recipient{Fingerprint: d, KeyVersion: *keyVersion}, *generation)
		if err == nil {
			fmt.Println("envelope", id)
		}
		return err
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
