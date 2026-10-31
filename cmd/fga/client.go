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
	"fga/internal/keyfile"
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
// The two private-key files may be protected with a passphrase
// (docs/design/key-files.md). The passphrase comes from -passphrase-file or
// $FGA_KEY_PASSPHRASE and is used only when a protected key is opened.
//
//	fga keys init      [-dir D] [-encrypt]  create the key directory and print its public keys
//	fga keys protect   [-dir D]          encrypt recipient.key and signing.key with a passphrase
//	fga keys unprotect [-dir D]          write them back in the clear
//	fga keys enroll    -tenant T -principal P
//	fga trust add      [-recipient B64] [-signer B64]
//	fga put            -bucket B -key K -in FILE [-to FP,...] [-if-none-match] [-label L]
//	fga put-document   -bucket B -key K -in FILE [-to FP,...]   UTF-8 text, one unit per paragraph
//	fga get            -bucket B -key K -out FILE [-version V]
//	fga ls             -bucket B [-prefix P]
//	fga rm             -bucket B -key K [-version V] [-approval A]
//	fga share          -bucket B -key K -to FP -key-version N [-generation G] [-version V]
//	fga label          -bucket B -key K -label L [-approval A]
//	fga propose-label  -bucket B -key K -label L -classifier C
//	fga approvals                        list approvals the caller may decide
//	fga approve|reject ID
//	fga finalize       -intent I -request FILE -approval A   finish a put that needed an approval
//
// An operation that needs an approval prints the approval's ID; once an
// approver has approved it, repeat the command with -approval ID. A put
// keeps its staged ciphertext and saves its finalize request in the key
// directory for fga finalize.

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

// privateFiles are the key directory's private-key files.
var privateFiles = []string{"recipient.key", "signing.key"}

// writePrivate writes a private-key file, protected when passphrase is set.
func writePrivate(path string, data, passphrase []byte) error {
	if passphrase != nil {
		sealed, err := keyfile.Seal(data, passphrase)
		if err != nil {
			return err
		}
		data = sealed
	}
	return keyfile.Write(path, data)
}

func keysInit(dir string, passphrase []byte) error {
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
	if err := writePrivate(filepath.Join(dir, "recipient.key"), raw, passphrase); err != nil {
		return err
	}
	sk, err := crypto.NewSigningKey()
	if err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(dir, "signing.key"), []byte(base64.StdEncoding.EncodeToString(sk.Private)+"\n"), passphrase); err != nil {
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

func loadClient(dir string, passphrase func() ([]byte, error)) (*client.Client, error) {
	raw, err := keyfile.Read(filepath.Join(dir, "recipient.key"), passphrase)
	if err != nil {
		return nil, err
	}
	rk, err := crypto.ParseRecipientKeyInsecure(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	signing, err := keyfile.Read(filepath.Join(dir, "signing.key"), passphrase)
	if err != nil {
		return nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signing)))
	clear(signing)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("signing.key does not hold a base64 Ed25519 private key")
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
	encrypt := fs.Bool("encrypt", false, "protect the new private keys with a passphrase")
	passphraseFile := fs.String("passphrase-file", "", "file holding the key passphrase (default $FGA_KEY_PASSPHRASE)")
	label := fs.String("label", "", "label (put: explicit label of a new key)")
	classifier := fs.String("classifier", "", "classifier that proposes a label")
	approvalID := fs.String("approval", "", "approval to present when repeating an operation that needed one")
	intent := fs.String("intent", "", "upload intent to finalize")
	request := fs.String("request", "", "file holding a kept finalize request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir or $FGA_KEY_DIR is required")
	}
	passphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_KEY_PASSPHRASE", *passphraseFile) }
	switch cmd {
	case "keys init":
		var p []byte
		if *encrypt {
			var err error
			if p, err = passphrase(); err != nil {
				return err
			}
		}
		return keysInit(*dir, p)
	case "keys protect", "keys unprotect":
		p, err := passphrase()
		if err != nil {
			return err
		}
		defer clear(p)
		for _, name := range privateFiles {
			path := filepath.Join(*dir, name)
			data, err := keyfile.Read(path, func() ([]byte, error) { return p, nil })
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if cmd == "keys unprotect" {
				err = keyfile.Write(path, data)
			} else {
				err = writePrivate(path, data, p)
			}
			clear(data)
			if err != nil {
				return err
			}
		}
		return nil
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
	c, err := loadClient(*dir, passphrase)
	if err != nil {
		return err
	}
	c.Approval = *approvalID
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
		p, err := c.Put(ctx, *bucket, *key, f, recipients, client.PutOptions{IfNoneMatch: *ifNoneMatch, Label: *label})
		var need *client.ApprovalRequired
		if errors.As(err, &need) {
			// The ciphertext stays staged; only the finalize request is
			// repeated with the approval.
			path := filepath.Join(*dir, "pending-"+need.Intent+".json")
			if err := os.WriteFile(path, need.Finalize, 0o600); err != nil {
				return err
			}
			fmt.Printf("approval required: %s\nafter approval: fga finalize -intent %s -request %s -approval %s\n", need.ID, need.Intent, path, need.ID)
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("published %s version %s etag %s\n", *key, p.Version, p.ETag)
		return nil
	case "put-document":
		text, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		recipients := []crypto.Recipient{{Fingerprint: c.Recipient.Fingerprint(), KeyVersion: c.KeyVersion}}
		for _, fp := range split(*to) {
			d, err := cryptowire.ParseDigest(fp)
			if err != nil {
				return err
			}
			recipients = append(recipients, crypto.Recipient{Fingerprint: d, KeyVersion: *keyVersion})
		}
		p, err := c.PutDocument(ctx, *bucket, *key, text, recipients)
		if err != nil {
			return err
		}
		fmt.Printf("published document %s version %s: %d units, manifest %s\n", *key, p.DocumentVersion, p.Units, p.ManifestDigest)
		return nil
	case "finalize":
		body, err := os.ReadFile(*request)
		if err != nil {
			return err
		}
		p, err := c.FinalizeUpload(ctx, *intent, body)
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("published version %s etag %s\n", p.Version, p.ETag)
		return os.Remove(*request)
	case "label":
		o, err := c.Label(ctx, *bucket, *key, *label)
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("label %s (was %s), metadata revision %d\n", o.Label, o.Previous, o.MetadataRevision)
		return nil
	case "propose-label":
		p, err := c.ProposeLabel(ctx, *bucket, *key, *label, *classifier)
		if err == nil {
			fmt.Printf("proposal %s recorded (advisory, authoritative=%t)\n", p.ID, p.Authoritative)
		}
		return err
	case "approvals":
		after := ""
		for {
			list, next, err := c.Approvals(ctx, after, 100)
			if err != nil {
				return err
			}
			for _, a := range list {
				changes, _ := json.Marshal(a.Plan.Changes)
				fmt.Printf("%s\t%s\t%s by %s\ttargets %v\tchanges %s\texpires %s\n", a.ID, a.Operation, a.Plan.Action, a.RequestedBy,
					a.Plan.Targets, changes, a.ExpiresAt.Format(time.RFC3339))
			}
			if next == "" {
				return nil
			}
			after = next
		}
	case "approve", "reject":
		if fs.NArg() != 1 {
			return errors.New(cmd + " needs an approval ID")
		}
		a, err := c.DecideApproval(ctx, fs.Arg(0), cmd == "approve")
		if err == nil {
			fmt.Printf("%s %s\n", a.ID, a.State)
		}
		return err
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
		return approvalHint(c.Delete(ctx, *bucket, *key, *version))
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

// approvalHint turns a 202 answer into instructions: an approver decides
// the approval, then the same command is repeated with -approval.
func approvalHint(err error) error {
	var need *client.ApprovalRequired
	if errors.As(err, &need) {
		return fmt.Errorf("approval required: %s; repeat the command with -approval %s once it is approved", need.ID, need.ID)
	}
	return err
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
