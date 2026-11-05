package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

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
// $FGA_TOKEN (storage audience) and $FGA_KEYS_TOKEN (keys audience), or,
// with both unset, tokens the account signs itself with DIR/signin.key
// (signin.go).
//
// The two private-key files may be protected with a passphrase
// (docs/design/key-files.md). The passphrase comes from -passphrase-file or
// $FGA_KEY_PASSPHRASE and is used only when a protected key is opened.
//
//	fga keys init      [-dir D] [-encrypt]  create the key directory and print its public keys
//	fga keys protect   [-dir D]          encrypt recipient.key and signing.key with a passphrase
//	fga keys unprotect [-dir D]          write them back in the clear
//	fga keys enroll    -tenant T -principal P
//	fga keys enroll-signer -tenant T -principal P   enroll the content-signing key with a possession proof
//	fga trust add      [-recipient B64] [-signer B64]
//	fga put            -bucket B -key K -in FILE [-to FP,...] [-if-none-match] [-label L]
//	                   in a server-mode bucket the server encrypts; -to does not apply, policy decides who reads
//	                   [-sources TYPE:ID:VERSION,...]   a derived output with that lineage (in client mode, for the caller only)
//	fga get-derived    -bucket B -key K -out FILE [-version V]   either mode
//	fga search         -bucket B [-prefix P] [-project P] [-label MAX]   documents the caller may discover, by metadata
//	fga put-document   -bucket B -key K -in FILE [-to FP,...] [-original FILE | -collection]   UTF-8 text, one unit
//	                   (with -collection, one text entry) per paragraph
//	fga append         -bucket B -key K -in FILE [-to FP,...]   append paragraphs to a text collection; needs read on
//	                   every entry, whose keys come from the caller's own envelopes
//	fga get-original   -bucket B -key K -out FILE [-version V]   needs raw-read and read on every unit
//	fga get            -bucket B -key K -out FILE [-version V]   either mode; the version's mode picks the route
//	fga get-document   -bucket B -key K -out FILE [-version V]   the units the caller may read
//	fga ls             -bucket B [-prefix P]
//	fga rm             -bucket B -key K [-version V] [-document] [-approval A]
//	fga share          -bucket B -key K -to FP -key-version N [-generation G] [-version V]
//	fga label          -bucket B -key K -label L [-unit U | -derived] [-approval A]
//	fga set-encryption -bucket B -encryption server|client [-approval A]   for uploads begun afterwards
//	fga grant          -bucket B [-key K [-version V | -unit U]] -grantee P -actions A,... -expires 24h [-approval A]
//	                   a share grant on the bucket, object, document version, unit or derived output; it takes
//	                   effect only where a policy rule honors resource.attributes.shared_with
//	fga ungrant        -bucket B [-key K [-version V | -unit U]] -grantee P [-approval A]
//	fga grants         -bucket B [-key K [-version V | -unit U]]   the unexpired grants (needs share)
//	fga propose-label  -bucket B -key K -label L -classifier C
//	fga approvals                        list approvals the caller may decide
//	fga approve|reject ID
//	fga finalize       -intent I [-request FILE | -document] -approval A   finish a put that needed an approval (in server mode,
//	                   -request only for a derived output; -document for a server-mode document)
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
	c := &client.Client{StorageURL: os.Getenv("FGA_STORAGE_URL"), KeysURL: os.Getenv("FGA_KEYS_URL"), HTTP: httpClient(),
		StorageToken: os.Getenv("FGA_TOKEN"), KeysToken: os.Getenv("FGA_KEYS_TOKEN"), Recipient: rk, KeyVersion: version,
		Signer: crypto.SigningKeyFromPrivate(priv), Trust: trust, TempDir: dir}
	// Without fixed tokens, the account signs its own with its sign-in
	// key, when the directory holds one (signin.go).
	if c.StorageToken == "" && c.KeysToken == "" {
		signer, err := loadSigner(dir, "fga", passphrase)
		if err != nil {
			return nil, err
		}
		if signer != nil {
			c.Tokens = signer
		}
	}
	return c, nil
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
	source := fs.String("source", "", "source of readings (post-reading)")
	tool := fs.String("tool", "", "data-tool: the data tool to call; without it, list the tools")
	toolArgs := fs.String("args", "", "data-tool: the call's arguments as a JSON object")
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
	originalFile := fs.String("original", "", "put-document: the original file to publish encrypted beside the units")
	encryption := fs.String("encryption", "", "set-encryption: the bucket's new encryption mode, server or client")
	collection := fs.Bool("collection", false, "put-document: create a text collection, one entry per paragraph")
	sources := fs.String("sources", "", "put: publish a derived output with this lineage, type:id:version,...")
	project := fs.String("project", "", "search: project")
	unit := fs.String("unit", "", "label, grant: a unit or entry of the document at -key")
	derivedOut := fs.Bool("derived", false, "label: the derived output at -key")
	documentKey := fs.Bool("document", false, "rm: the document at -key (with -version, withdraw that document version); finalize: a document intent")
	grantee := fs.String("grantee", "", "grant, ungrant: the principal the grant names")
	actions := fs.String("actions", "", "grant: actions from the resource type's read set, comma-separated")
	expires := fs.Duration("expires", 0, "grant: how long the grant lasts, such as 24h")
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
	case "keys enroll-signer":
		if err := c.EnrollSigner(ctx, *tenant, *principal); err != nil {
			return err
		}
		fmt.Println(c.Signer.Fingerprint, "ACTIVE")
		return nil
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
		lineage, err := parseSources(*sources)
		if err != nil {
			return err
		}
		if serverMode(ctx, c, *bucket) {
			if *to != "" {
				return errors.New("a server-mode bucket takes no recipients: policy decides who reads")
			}
			st, err := f.Stat()
			if err != nil {
				return err
			}
			p, err := c.PutPlain(ctx, *bucket, *key, f, st.Size(), client.PutOptions{IfNoneMatch: *ifNoneMatch, Label: *label, Lineage: lineage})
			var need *client.ApprovalRequired
			switch {
			case errors.As(err, &need) && need.Finalize != nil:
				// A derived output's lineage is repeated with the approval.
				path := filepath.Join(*dir, "pending-"+need.Intent+".json")
				if err := os.WriteFile(path, need.Finalize, 0o600); err != nil {
					return err
				}
				fmt.Printf("approval required: %s\nafter approval: fga finalize -intent %s -request %s -approval %s\n", need.ID, need.Intent, path, need.ID)
				return nil
			case errors.As(err, &need):
				fmt.Printf("approval required: %s\nafter approval: fga finalize -intent %s -approval %s\n", need.ID, need.Intent, need.ID)
				return nil
			case err != nil:
				return err
			}
			fmt.Printf("published %s object %s version %s etag %s (server-encrypted)\n", *key, p.Object, p.Version, p.ETag)
			return nil
		}
		recipients := []crypto.Recipient{{Fingerprint: c.Recipient.Fingerprint(), KeyVersion: c.KeyVersion}}
		for _, fp := range split(*to) {
			d, err := cryptowire.ParseDigest(fp)
			if err != nil {
				return err
			}
			recipients = append(recipients, crypto.Recipient{Fingerprint: d, KeyVersion: *keyVersion})
		}
		opts := client.PutOptions{IfNoneMatch: *ifNoneMatch, Label: *label, Lineage: lineage}
		if lineage != nil && *to != "" {
			return errors.New("a derived output is encrypted for its owner only; share it afterwards")
		}
		p, err := c.Put(ctx, *bucket, *key, f, recipients, opts)
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
		fmt.Printf("published %s object %s version %s etag %s\n", *key, p.Object, p.Version, p.ETag)
		return nil
	case "search":
		results, err := c.SearchDocuments(ctx, *bucket, *prefix, *project, *label)
		if err != nil {
			return err
		}
		for _, r := range results {
			fmt.Printf("%s\t%s\t%s\n", printable(r.Key), r.DocumentVersion, r.CreatedAt.Format(time.RFC3339))
		}
		return nil
	case "get-derived":
		tmp := *out + ".partial"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		// The server route first; a client-mode output answers
		// ENCRYPTION_MODE, and nothing was written.
		id, err := c.GetDerivedPlain(ctx, *bucket, *key, *version, f)
		var e *client.Error
		if errors.As(err, &e) && e.Code == "ENCRYPTION_MODE" {
			var v client.VersionInfo
			v, err = c.GetDerived(ctx, *bucket, *key, *version, f)
			id = v.Version + " (verified and decrypted)"
		} else if err == nil {
			id += " (server-encrypted)"
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		fmt.Printf("read derived version %s\n", id)
		return os.Rename(tmp, *out)
	case "post-reading":
		// A JSON reading of a source, in its source's mode (ING-002, ING-010):
		// -principal names the caller for a source keyed by it.
		payload, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		p, err := c.PostReading(ctx, *source, payload, *principal, "")
		if err != nil {
			return err
		}
		fmt.Printf("published reading version %s of document %s\n", p.DocumentVersion, p.Document)
		return nil
	case "data-tool":
		// The data tools the caller may discover, or a call of -tool
		// (DTL-004, DTL-009): a client-mode tool's packages are opened with
		// the caller's own key and projected here.
		if *tool == "" {
			tools, err := c.ListDataTools(ctx)
			if err != nil {
				return err
			}
			for _, t := range tools {
				line, _ := json.Marshal(t)
				fmt.Println(string(line))
			}
			return nil
		}
		v := 0
		if *version != "" {
			var err error
			if v, err = strconv.Atoi(*version); err != nil {
				return fmt.Errorf("-version: %w", err)
			}
		}
		ans, err := c.CallDataTool(ctx, *tool, json.RawMessage(*toolArgs), v)
		if err != nil {
			return err
		}
		fmt.Println(string(ans))
		return nil
	case "put-document", "append":
		text, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		if serverMode(ctx, c, *bucket) {
			if *to != "" {
				return errors.New("a server-mode bucket takes no recipients: policy decides who reads")
			}
			var p client.DocumentPublished
			switch {
			case cmd == "append":
				p, err = c.AppendText(ctx, *bucket, *key, text)
			case *originalFile != "":
				f, ferr := os.Open(*originalFile)
				if ferr != nil {
					return ferr
				}
				defer f.Close()
				p, err = c.PutDocumentTextWithOriginal(ctx, *bucket, *key, text, f)
			default:
				p, err = c.PutDocumentText(ctx, *bucket, *key, text, *collection)
			}
			var need *client.ApprovalRequired
			if errors.As(err, &need) {
				fmt.Printf("approval required: %s\nafter approval: fga finalize -document -intent %s -approval %s\n", need.ID, need.Intent, need.ID)
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Printf("published %s version %s: %d units (server-encrypted)\n", *key, p.DocumentVersion, p.Units)
			return nil
		}
		recipients := []crypto.Recipient{{Fingerprint: c.Recipient.Fingerprint(), KeyVersion: c.KeyVersion}}
		for _, fp := range split(*to) {
			d, err := cryptowire.ParseDigest(fp)
			if err != nil {
				return err
			}
			recipients = append(recipients, crypto.Recipient{Fingerprint: d, KeyVersion: *keyVersion})
		}
		var p client.DocumentPublished
		switch {
		case cmd == "append":
			p, err = c.AppendCollection(ctx, *bucket, *key, text, recipients)
		case *collection && *originalFile != "":
			return errors.New("a text collection has no original file")
		case *collection:
			p, err = c.PutCollection(ctx, *bucket, *key, text, recipients)
		}
		if err != nil {
			return err
		}
		if cmd == "append" || *collection {
			fmt.Printf("published collection %s version %s: %d entries, manifest %s\n", *key, p.DocumentVersion, p.Units, p.ManifestDigest)
			return nil
		}
		var original io.Reader
		if *originalFile != "" {
			f, err := os.Open(*originalFile)
			if err != nil {
				return err
			}
			defer f.Close()
			original = f
		}
		p, err = c.PutDocumentWithOriginal(ctx, *bucket, *key, text, original, recipients)
		if err != nil {
			return err
		}
		fmt.Printf("published document %s version %s: %d units, manifest %s\n", *key, p.DocumentVersion, p.Units, p.ManifestDigest)
		return nil
	case "get-original":
		tmp := *out + ".partial"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		// The server-mode route first; a client-mode original answers it
		// ENCRYPTION_MODE, after authorization.
		server := true
		err = c.GetOriginalPlain(ctx, *bucket, *key, *version, f)
		var apiErr *client.Error
		if errors.As(err, &apiErr) && apiErr.Code == "ENCRYPTION_MODE" {
			server = false
			if _, err = f.Seek(0, io.SeekStart); err == nil {
				err = c.GetOriginal(ctx, *bucket, *key, *version, f)
			}
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		if server {
			fmt.Println("read the original file (server-encrypted)")
		} else {
			fmt.Println("verified and decrypted the original file")
		}
		return os.Rename(tmp, *out)
	case "get-document":
		tmp := *out + ".partial"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		n, err := c.GetDocument(ctx, *bucket, *key, *version, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		fmt.Printf("read %d permitted units\n", n)
		return os.Rename(tmp, *out)
	case "finalize":
		if *documentKey {
			p, err := c.FinalizeDocument(ctx, *intent)
			if err != nil {
				return approvalHint(err)
			}
			fmt.Printf("published document version %s: %d units\n", p.DocumentVersion, p.Units)
			return nil
		}
		var body []byte
		if *request != "" {
			var err error
			if body, err = os.ReadFile(*request); err != nil {
				return err
			}
		}
		p, err := c.FinalizeUpload(ctx, *intent, body)
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("published version %s etag %s\n", p.Version, p.ETag)
		if *request == "" {
			return nil
		}
		return os.Remove(*request)
	case "label":
		var o client.LabelOutcome
		var err error
		switch {
		case *unit != "":
			o, err = c.LabelUnit(ctx, *bucket, *key, *unit, *label)
		case *derivedOut:
			o, err = c.LabelDerived(ctx, *bucket, *key, *label)
		default:
			o, err = c.Label(ctx, *bucket, *key, *label)
		}
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("label %s (was %s), metadata revision %d\n", o.Label, o.Previous, o.MetadataRevision)
		return nil
	case "set-encryption":
		o, err := c.SetBucketEncryption(ctx, *bucket, *encryption)
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("bucket encryption %s (was %s), metadata revision %d\n", o.Encryption, o.Previous, o.MetadataRevision)
		return nil
	case "grant":
		if *grantee == "" || *actions == "" || *expires <= 0 {
			return errors.New("grant needs -grantee, -actions and -expires")
		}
		o, err := c.RecordGrant(ctx, *bucket, client.GrantTarget{Key: *key, Version: *version, Unit: *unit}, *grantee, split(*actions),
			time.Now().Add(*expires))
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("grant %s: %s may %s on %s %s until %s (effective only where a policy rule honors it)\n", o.Grant.ID, o.Grant.Grantee,
			strings.Join(o.Grant.Actions, ","), o.Grant.ResourceType, o.Grant.ResourceID, o.Grant.ExpiresAt.Format(time.RFC3339))
		return nil
	case "ungrant":
		if *grantee == "" {
			return errors.New("ungrant needs -grantee")
		}
		o, err := c.RemoveGrant(ctx, *bucket, client.GrantTarget{Key: *key, Version: *version, Unit: *unit}, *grantee)
		if err != nil {
			return approvalHint(err)
		}
		fmt.Printf("removed grant %s of %s on %s %s\n", o.Grant.ID, o.Grant.Grantee, o.Grant.ResourceType, o.Grant.ResourceID)
		return nil
	case "grants":
		gs, err := c.Grants(ctx, *bucket, client.GrantTarget{Key: *key, Version: *version, Unit: *unit})
		if err != nil {
			return err
		}
		for _, g := range gs {
			fmt.Printf("%s\t%s\t%s\t%s\n", g.Grantee, strings.Join(g.Actions, ","), g.ExpiresAt.UTC().Format(time.RFC3339), g.Grantor)
		}
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
		if serverVersion(ctx, c, *bucket, *key, *version) {
			v, err := c.GetPlain(ctx, *bucket, *key, *version, f)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				os.Remove(tmp)
				return err
			}
			fmt.Printf("read version %s (server-encrypted)\n", v)
			return os.Rename(tmp, *out)
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
				fmt.Printf("%s\t%d\t%s\n", printable(e.Key), e.CiphertextLength, e.Version)
			}
			if next == "" {
				return nil
			}
			cont = next
		}
	case "rm":
		if *documentKey {
			return approvalHint(c.DeleteDocument(ctx, *bucket, *key, *version))
		}
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

// parseSources reads -sources, type:id:version,...; none is nil.
func parseSources(s string) ([]cryptowire.LineageSource, error) {
	var out []cryptowire.LineageSource
	for _, src := range split(s) {
		parts := strings.Split(src, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("-sources entry %q is not type:id:version", src)
		}
		out = append(out, cryptowire.LineageSource{Type: parts[0], ID: parts[1], Version: parts[2]})
	}
	return out, nil
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

// serverMode reports whether bucket is in server mode (D-12). A caller
// who may not list the bucket is answered as for client mode; the storage
// role still refuses a route of the other mode (ENC-002).
func serverMode(ctx context.Context, c *client.Client, bucket string) bool {
	mode, err := c.BucketEncryption(ctx, bucket)
	return err == nil && mode == "server"
}

// serverVersion reports whether a version is in server mode, which picks
// its read route: a bucket's versions keep the mode they were published
// under when the bucket's mode changes (ENC-002). A caller who may not
// stat it is answered as for client mode, whose route then refuses it.
func serverVersion(ctx context.Context, c *client.Client, bucket, key, version string) bool {
	info, err := c.Stat(ctx, bucket, key, version)
	return err == nil && info.Encryption == "server"
}

// printable returns key as it is when every character prints, else quoted:
// a key is any UTF-8, so one may hold terminal escapes or bidi controls
// that the terminal would act on (security review of 4 November 2026,
// finding 7).
func printable(key string) string {
	for _, r := range key {
		if !unicode.IsPrint(r) {
			return strconv.Quote(key)
		}
	}
	return key
}
