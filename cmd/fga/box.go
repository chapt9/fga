package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fga/internal/cryptowire"
	"fga/internal/keyfile"
	"fga/sdk/go/client"
	"fga/sdk/go/crypto"
	"fga/sdk/go/keybox"
)

// The person's key box (mosaic-key-store docs/key-box.md, docs/sign-in.md):
// one box holds the sign-in, opening and content-signing keys and the trust
// list, shared by the person's fga program and their browser add-on. In box
// mode a key directory holds only
//
//	keybox      the locked box
//	unlock.key  this program's unlock key (X25519, base64), protected with
//	            a passphrase when made with -protect
//	unlock.id   the ID of the box's unlocker for that key
//
// and every client command works from the box, signing its own tokens with
// the box's sign-in key as the box's owner.
//
//	fga box init -dir D [-id ID] [-protect] [-tenant T -principal P]
//	             put an enrolled key directory's keys in a box, opened by a
//	             new unlock key of this program; the separate key files go
//	fga box unlock-key -dir D -id ID [-protect]
//	             make this program's unlock key, for a program that has the
//	             box to lock it for; prints the public key and fingerprint
//	fga box add-unlock-key -dir D -id ID -public-key B64 -out FILE
//	             let another program's unlock key open the box, and write the
//	             box for it to FILE
//	fga box import -dir D -in FILE [-tenant T -principal P]
//	             take the box another program locked for this one's key,
//	             only when it is the box of P in T, the person's own;
//	             -tenant and -principal default to $FGA_TENANT and
//	             $FGA_PRINCIPAL
//	fga box show -dir D
//	fga box remove-unlocker -dir D -id ID
//
// An MCP account or a push account has keys of its own, outside any
// person's box: a key directory with signin.key (signin.go).

const (
	boxFile      = "keybox"
	unlockFile   = "unlock.key"
	unlockIDFile = "unlock.id"
)

func boxMode(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, boxFile))
	return err == nil
}

// openedBox is a box opened with this program's unlock key.
type openedBox struct {
	box      *keybox.Box
	key      [32]byte
	contents *keybox.Contents
	id       []byte
}

func (o *openedBox) clear() {
	clear(o.key[:])
	if o.contents != nil {
		o.contents.Clear()
	}
}

func readUnlockKey(dir string, passphrase func() ([]byte, error)) ([]byte, []byte, error) {
	raw, err := keyfile.Read(filepath.Join(dir, unlockFile), passphrase)
	if err != nil {
		return nil, nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(priv) != 32 {
		return nil, nil, fmt.Errorf("%s does not hold a base64 X25519 private key", unlockFile)
	}
	id, err := os.ReadFile(filepath.Join(dir, unlockIDFile))
	if err != nil {
		return nil, nil, err
	}
	return priv, []byte(strings.TrimSpace(string(id))), nil
}

func openBox(dir string, passphrase func() ([]byte, error)) (*openedBox, error) {
	raw, err := os.ReadFile(filepath.Join(dir, boxFile))
	if err != nil {
		return nil, err
	}
	b, err := keybox.Parse(raw)
	if err != nil {
		return nil, err
	}
	priv, id, err := readUnlockKey(dir, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	o := &openedBox{box: b, id: id}
	if o.key, err = b.BoxKeyWithKey(id, priv); err != nil {
		return nil, err
	}
	if o.contents, err = b.Contents(&o.key); err != nil {
		o.clear()
		return nil, err
	}
	return o, nil
}

// reseal writes the box again with its contents and unlockers.
func (o *openedBox) reseal(dir string) error {
	b, err := keybox.Seal(o.box.Owner, &o.key, o.contents, o.box.Unlockers)
	if err != nil {
		return err
	}
	o.box = b
	return writeBox(filepath.Join(dir, boxFile), b)
}

func writeBox(path string, b *keybox.Box) error {
	enc, err := b.Encode()
	if err != nil {
		return err
	}
	return keyfile.Write(path, enc)
}

// boxClient is loadClient in box mode.
func boxClient(dir string, passphrase func() ([]byte, error)) (*client.Client, error) {
	o, err := openBox(dir, passphrase)
	if err != nil {
		return nil, err
	}
	defer o.clear()
	c := o.contents
	rk, err := crypto.RecipientKeyFromRawInsecure(c.RecipientPrivate[:])
	if err != nil {
		return nil, err
	}
	signing := ed25519.NewKeyFromSeed(c.SigningSeed[:])
	trust := fileTrust{recipients: map[cryptowire.Digest][]byte{rk.Fingerprint(): rk.PublicKey()},
		signers: map[cryptowire.Digest]ed25519.PublicKey{cryptowire.SigningKeyFingerprint(signing.Public().(ed25519.PublicKey)): signing.Public().(ed25519.PublicKey)}}
	for _, t := range c.Trust {
		if t.Kind == keybox.TrustRecipient {
			trust.recipients[t.Fingerprint()] = append([]byte{}, t.Public[:]...)
		} else {
			trust.signers[t.Fingerprint()] = ed25519.PublicKey(append([]byte{}, t.Public[:]...))
		}
	}
	cl := &client.Client{StorageURL: os.Getenv("FGA_STORAGE_URL"), KeysURL: os.Getenv("FGA_KEYS_URL"), HTTP: httpClient(),
		StorageToken: os.Getenv("FGA_TOKEN"), KeysToken: os.Getenv("FGA_KEYS_TOKEN"), Recipient: rk, KeyVersion: uint64(c.RecipientKeyVersion),
		Signer: crypto.SigningKeyFromPrivate(signing), Trust: trust, TempDir: dir}
	if cl.StorageToken == "" && cl.KeysToken == "" {
		cl.Tokens = newKeySigner(ed25519.NewKeyFromSeed(c.SignInSeed[:]), o.box.Owner.Tenant, o.box.Owner.Principal, "fga")
	}
	return cl, nil
}

func boxCommand(cmd string, args []string) error {
	fs := flag.NewFlagSet("box "+cmd, flag.ContinueOnError)
	dir := fs.String("dir", os.Getenv("FGA_KEY_DIR"), "key directory")
	id := fs.String("id", "", "the unlocker's ID, such as \"fga program, dana-laptop\"")
	protect := fs.Bool("protect", false, "protect this program's unlock key with a passphrase")
	passphraseFile := fs.String("passphrase-file", "", "file holding the passphrase (default $FGA_KEY_PASSPHRASE)")
	tenant := fs.String("tenant", os.Getenv("FGA_TENANT"), "init, import: the box owner's tenant")
	principal := fs.String("principal", os.Getenv("FGA_PRINCIPAL"), "init, import: the box owner")
	publicKey := fs.String("public-key", "", "add-unlock-key: the other program's unlock public key (base64)")
	in := fs.String("in", "", "import: the box file")
	out := fs.String("out", "", "add-unlock-key: where to write the box for the other program")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir or $FGA_KEY_DIR is required")
	}
	passphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_KEY_PASSPHRASE", *passphraseFile) }
	switch cmd {
	case "init":
		if *id == "" {
			*id = "fga program"
		}
		return boxInit(*dir, *id, *tenant, *principal, *protect, passphrase)
	case "unlock-key":
		if *id == "" {
			return errors.New("box unlock-key needs -id, the name the other program gives this one's unlocker")
		}
		pub, err := newUnlockKey(*dir, *id, *protect, passphrase)
		if err != nil {
			return err
		}
		fmt.Printf("unlock key %s %s id %q\n", keybox.UnlockKeyFingerprint(pub), base64.StdEncoding.EncodeToString(pub), *id)
		fmt.Println("In the program that has the box, add this key after comparing the fingerprint, and bring the box file back here (fga box import).")
		return nil
	case "add-unlock-key":
		pub, err := base64.StdEncoding.DecodeString(*publicKey)
		if err != nil || len(pub) != 32 || *id == "" || *out == "" {
			return errors.New("box add-unlock-key needs -id, -public-key (base64, 32 bytes) and -out")
		}
		o, err := openBox(*dir, passphrase)
		if err != nil {
			return err
		}
		defer o.clear()
		for _, u := range o.box.Unlockers {
			if string(u.ID) == *id {
				return fmt.Errorf("the box has an unlocker %q", *id)
			}
		}
		u, err := keybox.WrapForKey(o.box.Owner, &o.key, []byte(*id), pub)
		if err != nil {
			return err
		}
		o.box.Unlockers = append(o.box.Unlockers, u)
		if err := o.reseal(*dir); err != nil {
			return err
		}
		if err := writeBox(*out, o.box); err != nil {
			return err
		}
		fmt.Printf("added unlock key %s as %q; the box for it is %s\n", keybox.UnlockKeyFingerprint(pub), *id, *out)
		return nil
	case "import":
		if *in == "" || *tenant == "" || *principal == "" {
			return errors.New("box import needs -in, and -tenant and -principal (or $FGA_TENANT and $FGA_PRINCIPAL): whose box it must be")
		}
		if boxMode(*dir) {
			return fmt.Errorf("%s holds a box already", *dir)
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		b, err := keybox.Parse(raw)
		if err != nil {
			return err
		}
		// Only the person's own box is taken, before it is opened or kept:
		// a box locked for this program's unlock key may be anyone's, and
		// every command would then work as its owner (security review of 5
		// November 2026, finding 2).
		if b.Owner.Tenant != *tenant || b.Owner.Principal != *principal {
			return fmt.Errorf("%w: the box belongs to %q of %q, not to %q of %q; import only your own box", keybox.ErrBinding,
				b.Owner.Principal, b.Owner.Tenant, *principal, *tenant)
		}
		priv, uid, err := readUnlockKey(*dir, passphrase)
		if err != nil {
			return fmt.Errorf("make this program's unlock key first (fga box unlock-key): %w", err)
		}
		defer clear(priv)
		key, err := b.BoxKeyWithKey(uid, priv)
		if err != nil {
			return err
		}
		defer clear(key[:])
		c, err := b.Contents(&key)
		if err != nil {
			return err
		}
		c.Clear()
		if err := writeBox(filepath.Join(*dir, boxFile), b); err != nil {
			return err
		}
		fmt.Printf("imported the key box of %s (%s)\n", b.Owner.Principal, b.Owner.Tenant)
		return nil
	case "show":
		o, err := openBox(*dir, passphrase)
		if err != nil {
			return err
		}
		defer o.clear()
		b, c := o.box, o.contents
		fmt.Printf("owner      %s (%s)\nsign-in    %s\nopening    %s (version %d)\nsigning    %s\n", b.Owner.Principal, b.Owner.Tenant,
			b.Owner.SignInFingerprint, b.Owner.RecipientFingerprint, c.RecipientKeyVersion, b.Owner.SigningFingerprint)
		for _, u := range b.Unlockers {
			kind := "secret"
			if u.ForPublicKey() {
				kind = "unlock key"
			}
			mark := ""
			if string(u.ID) == string(o.id) {
				mark = "  (this program)"
			}
			fmt.Printf("unlocker   %q, %s%s\n", u.ID, kind, mark)
		}
		for _, t := range c.Trust {
			kind := "recipient"
			if t.Kind == keybox.TrustSigner {
				kind = "signer"
			}
			fmt.Printf("trusted    %s %s of %s\n", kind, t.Fingerprint(), t.Owner)
		}
		return nil
	case "remove-unlocker":
		o, err := openBox(*dir, passphrase)
		if err != nil {
			return err
		}
		defer o.clear()
		if *id == "" || *id == string(o.id) {
			return errors.New("box remove-unlocker needs -id of another unlocker than this program's")
		}
		kept := o.box.Unlockers[:0]
		for _, u := range o.box.Unlockers {
			if string(u.ID) != *id {
				kept = append(kept, u)
			}
		}
		if len(kept) == len(o.box.Unlockers) {
			return fmt.Errorf("the box has no unlocker %q", *id)
		}
		o.box.Unlockers = kept
		return o.reseal(*dir)
	}
	return errors.New("box needs init, unlock-key, add-unlock-key, import, show or remove-unlocker")
}

// newUnlockKey makes this program's unlock key and records its unlocker ID.
func newUnlockKey(dir, id string, protect bool, passphrase func() ([]byte, error)) ([]byte, error) {
	if _, err := os.Stat(filepath.Join(dir, unlockFile)); err == nil {
		return nil, fmt.Errorf("%s has an unlock key", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var p []byte
	if protect {
		var err error
		if p, err = passphrase(); err != nil {
			return nil, err
		}
		defer clear(p)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writePrivate(filepath.Join(dir, unlockFile), []byte(base64.StdEncoding.EncodeToString(k.Bytes())+"\n"), p); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, unlockIDFile), []byte(id+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// boxInit puts an enrolled key directory's keys in a box and removes the
// separate key files once the box opens with the same keys.
func boxInit(dir, id, tenant, principal string, protect bool, passphrase func() ([]byte, error)) error {
	if boxMode(dir) {
		return fmt.Errorf("%s holds a box already", dir)
	}
	if tenant == "" || principal == "" {
		return errors.New("box init needs -tenant and -principal (or $FGA_TENANT and $FGA_PRINCIPAL)")
	}
	if _, err := os.Stat(filepath.Join(dir, "key_version")); err != nil {
		return errors.New("enroll the keys first (fga keys enroll and keys enroll-signer): the box records the opening key's version")
	}
	c, err := keyFilesClient(dir, passphrase)
	if err != nil {
		return err
	}
	signIn, err := loadSignerFor(dir, tenant, principal, "fga", passphrase)
	if err != nil {
		return err
	}
	if signIn == nil {
		return errors.New("make and register a sign-in key first (fga sign-in-key new)")
	}
	raw, err := c.Recipient.RawPrivateInsecure()
	if err != nil {
		return err
	}
	contents := &keybox.Contents{RecipientKeyVersion: uint32(c.KeyVersion)}
	copy(contents.RecipientPrivate[:], raw)
	clear(raw)
	copy(contents.SigningSeed[:], c.Signer.Private.Seed())
	copy(contents.SignInSeed[:], signIn.priv.Seed())
	defer contents.Clear()
	tf, err := readTrust(dir)
	if err != nil {
		return err
	}
	own := map[string]bool{c.Recipient.Fingerprint().String(): true, c.Signer.Fingerprint.String(): true}
	for kind, m := range map[keybox.TrustKind]map[string]string{keybox.TrustRecipient: tf.Recipients, keybox.TrustSigner: tf.Signers} {
		for fp, b64 := range m {
			pub, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(pub) != 32 || own[fp] {
				continue
			}
			e := keybox.TrustEntry{Kind: kind, Owner: "unknown"}
			copy(e.Public[:], pub)
			contents.Trust = append(contents.Trust, e)
		}
	}
	owner, err := keybox.OwnerOf(tenant, principal, contents)
	if err != nil {
		return err
	}
	pub, err := newUnlockKey(dir, id, protect, passphrase)
	if err != nil {
		return err
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	defer clear(key[:])
	u, err := keybox.WrapForKey(owner, &key, []byte(id), pub)
	if err != nil {
		return err
	}
	b, err := keybox.Seal(owner, &key, contents, []keybox.Unlocker{u})
	if err != nil {
		return err
	}
	if err := writeBox(filepath.Join(dir, boxFile), b); err != nil {
		return err
	}
	// The box must open with the same keys before the files go.
	o, err := openBox(dir, passphrase)
	if err != nil {
		return fmt.Errorf("the new box does not open, so the key files stay: %w", err)
	}
	same := o.box.Owner.RecipientFingerprint == c.Recipient.Fingerprint() && o.box.Owner.SigningFingerprint == c.Signer.Fingerprint &&
		o.box.Owner.SignInFingerprint.String() == signIn.fingerprint
	o.clear()
	if !same {
		return errors.New("the new box holds other keys, so the key files stay")
	}
	for _, name := range []string{"recipient.key", "signing.key", signInFile, "trust.json", "key_version"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	fmt.Printf("the keys of %s (%s) are in %s, opened by this program's unlock key %q\n", principal, tenant, filepath.Join(dir, boxFile), id)
	return nil
}

// boxTrustAdd pins a recipient or signer key in the box's trust list, as
// trust add does in a key directory without a box; -principal names whose
// key it is.
func boxTrustAdd(dir, recipient, signer, owner string, keyVersion uint64, passphrase func() ([]byte, error)) error {
	if owner == "" {
		return errors.New("trust add in a key box needs -principal, whose key it is")
	}
	o, err := openBox(dir, passphrase)
	if err != nil {
		return err
	}
	defer o.clear()
	add := func(kind keybox.TrustKind, b64 string, version uint32) error {
		pub, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(pub) != 32 {
			return errors.New("a trusted key is a base64 32-byte public key")
		}
		e := keybox.TrustEntry{Kind: kind, KeyVersion: version, Owner: owner}
		copy(e.Public[:], pub)
		kept := o.contents.Trust[:0]
		for _, t := range o.contents.Trust {
			if t.Kind != kind || t.Public != e.Public {
				kept = append(kept, t)
			}
		}
		o.contents.Trust = append(kept, e)
		fmt.Printf("trusted %s of %s\n", e.Fingerprint(), owner)
		return nil
	}
	if recipient != "" {
		if err := add(keybox.TrustRecipient, recipient, uint32(keyVersion)); err != nil {
			return err
		}
	}
	if signer != "" {
		if err := add(keybox.TrustSigner, signer, 0); err != nil {
			return err
		}
	}
	return o.reseal(dir)
}
