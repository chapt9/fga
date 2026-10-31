// Command fga-admin is the local administrator's tool (specification 2.5,
// ADM-002, ADM-003, AVL-008, KEY-017). It works directly on the catalog,
// the blob directory and the security journal, outside every API path, and
// is meant for the operator of a local deployment.
//
//	fga-admin -db URL [-journal DIR] [-blobs DIR] COMMAND [flags]
//
// Commands:
//
//	bucket create      -tenant T -name N [-project P] [-label L] [-scope S] [-encryption server|client]
//	mcp enable         -tenant T                   register the MCP service's tools for the tenant (policy decides who uses them)
//	identity put       -tenant T -id ID [-roles a,b] [-attrs JSON]
//	identity disable   -tenant T -id ID                      (journaled)
//	grant              -tenant T -actor ID [-type T -actions a,b | -preset storage|approver]
//	signing-key add    -tenant T -principal ID -public-key B64
//	signing-key retire|compromise -tenant T -fingerprint FP  (compromise is journaled)
//	recipient revoke   -tenant T -fingerprint FP             (journaled)
//	delegation add     -tenant T -id ID -actor A -subject S -audience ADAPTER -grants 'type:a,b;type:c' -expires 24h [-parent ID]
//	                   lets agent A act for S, presented through ADAPTER (the MCP role's workload, say), within the grants
//	delegation revoke  -tenant T -id ID                      (journaled)
//	epoch raise        -tenant T -epoch N                    (journaled)
//	backup-key generate -out FILE [-encrypt]        create a backup key (keep it apart from catalog and backups)
//	key protect|unprotect -file FILE                encrypt a backup key file with a passphrase, or decrypt it
//	kek init           -file FILE [-encrypt]        create the ring of server-mode key-encryption keys (development custody, D-13)
//	kek rotate         -tenant T -file FILE         add the tenant's next KEK version and reseal its data keys under it
//
// A protected backup key is opened with the passphrase from
// -passphrase-file or $FGA_BACKUP_KEY_PASSPHRASE (docs/design/key-files.md),
// a protected KEK ring with -passphrase-file or $FGA_KEK_PASSPHRASE.
//
//	backup             -backup-key FILE -out DIR [-allow-missing]   encrypted backup (AVL-005); fails when a live blob
//	                   cannot be read, unless -allow-missing lists it in the manifest as missing
//	journal init                          create the security journal once, at setup
//	restore            -backup-key FILE -from DIR [-accept-journal-loss]
//	reconcile          [-accept-journal-loss | -journal-complete] [-kek-file FILE]
//	                   -journal-complete: after a restore without the catalog's record of the journal (onto an empty
//	                   catalog), the operator states, audited, that the journal holds every change since the backup
//	                   -kek-file is needed when the catalog holds server-mode
//	                   data keys: each must open under the ring, or its version is quarantined (SSE-006)
//	reclaim                                          retire withdrawn versions; destroys their server-mode data keys
//	audit export       -dir D [-follow]             drain the audit outbox into D
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/auditexport"
	"fga/internal/backupcrypt"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/delegation"
	"fga/internal/journal"
	"fga/internal/kek"
	"fga/internal/keyfile"
	"fga/internal/recovery"
	"fga/internal/registry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fga-admin:", err)
		os.Exit(1)
	}
}

// StoragePreset is the capability set of an ordinary storage user (DLG-004).
var StoragePreset = map[string][]string{
	"storage.bucket": {"create-object", "list", "share"},
	"storage.object": {"read", "stat", "discover", "read-history", "discover-history", "new-version", "delete", "delete-version", "share",
		"label", "relabel", "propose-label", "export"},
	"crypto.envelope":    {"create", "release", "retire"},
	"document.version":   {"read-units", "raw-read", "discover", "share", "export"},
	"document.text_unit": {"read", "share", "label", "relabel", "propose-label", "export-key"},
	"document.derived":   {"deliver", "declassify", "label", "relabel", "new-version", "share"},
	"text.entry":         {"read", "use-in-model", "update", "share"},
	"crypto.recipient":   {"enroll", "activate", "receive-key", "revoke", "discover"},
	"crypto.signing-key": {"discover"},
	"agent.tool":         {"discover", "invoke"},
}

// ApproverPreset lets an actor decide approvals (ruling 6); policies still
// say on which resources.
var ApproverPreset = map[string][]string{
	"storage.bucket":     {"approve"},
	"storage.object":     {"approve"},
	"document.text_unit": {"approve"},
	"document.derived":   {"approve"},
	"document.version":   {"approve"},
	"text.entry":         {"approve"},
}

type env struct {
	ctx     context.Context
	store   *catalog.Store
	pool    *pgxpool.Pool
	journal func() (*journal.Journal, error)
	blobs   func() (*blob.Store, error)
}

func run(args []string) error {
	global := flag.NewFlagSet("fga-admin", flag.ContinueOnError)
	db := global.String("db", os.Getenv("FGA_DATABASE_URL"), "PostgreSQL URL (default $FGA_DATABASE_URL)")
	journalDir := global.String("journal", "", "security journal directory")
	blobDir := global.String("blobs", "", "blob directory")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 || *db == "" {
		return errors.New("usage: fga-admin -db URL [-journal DIR] [-blobs DIR] COMMAND [flags]; see the package documentation")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := catalog.Migrate(ctx, pool); err != nil {
		return err
	}
	e := env{ctx: ctx, store: catalog.New(pool, 100_000), pool: pool,
		journal: func() (*journal.Journal, error) {
			if *journalDir == "" {
				return nil, errors.New("this command needs -journal")
			}
			return journal.Open(*journalDir, time.Now)
		},
		blobs: func() (*blob.Store, error) {
			if *blobDir == "" {
				return nil, errors.New("this command needs -blobs")
			}
			return blob.Open(*blobDir)
		}}
	cmd, sub := rest[0], rest[1:]
	if len(sub) > 0 && !strings.HasPrefix(sub[0], "-") {
		cmd, sub = cmd+" "+sub[0], sub[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant")
	id := fs.String("id", "", "identity or delegation ID")
	name := fs.String("name", "", "bucket name")
	project := fs.String("project", "", "bucket default project")
	label := fs.String("label", "internal", "bucket default label")
	scope := fs.String("scope", "", "bucket policy scope")
	encryption := fs.String("encryption", "server", "bucket encryption mode: server (the default) or client (ENC-001)")
	roles := fs.String("roles", "", "comma-separated roles")
	attrs := fs.String("attrs", "{}", "identity attributes as a JSON object")
	actor := fs.String("actor", "", "actor identity")
	typ := fs.String("type", "", "resource type")
	actions := fs.String("actions", "", "comma-separated actions")
	preset := fs.String("preset", "", "capability preset: storage or approver")
	subject := fs.String("subject", "", "delegation add: the identity the actor acts for")
	audience := fs.String("audience", "", "delegation add: the workload that presents the delegation, such as the MCP role's")
	grantList := fs.String("grants", "", "delegation add: resource types and actions, as 'type:a,b;type:c' (* for every action)")
	expires := fs.Duration("expires", 24*time.Hour, "delegation add: lifetime")
	parentID := fs.String("parent", "", "delegation add: the delegation this one narrows")
	principal := fs.String("principal", "", "principal identity")
	publicKey := fs.String("public-key", "", "base64 public key")
	fingerprint := fs.String("fingerprint", "", "key fingerprint")
	epoch := fs.Uint64("epoch", 0, "policy epoch")
	out := fs.String("out", "", "backup directory or key file to create")
	backupKeyFile := fs.String("backup-key", "", "backup key file")
	encrypt := fs.Bool("encrypt", false, "protect the new key file with a passphrase")
	keyFile := fs.String("file", "", "key file to protect or unprotect")
	passphraseFile := fs.String("passphrase-file", "", "file holding the key passphrase (default $FGA_BACKUP_KEY_PASSPHRASE)")
	dir := fs.String("dir", "", "audit export directory")
	follow := fs.Bool("follow", false, "keep exporting until interrupted")
	from := fs.String("from", "", "backup directory to restore")
	kekFile := fs.String("kek-file", "", "reconcile: the KEK ring to check server-mode data keys against")
	journalComplete := fs.Bool("journal-complete", false,
		"reconcile: state that the journal holds every change since the backup (needed after a restore onto an empty catalog; audited)")
	allowMissing := fs.Bool("allow-missing", false, "backup: complete although blobs of live versions cannot be read, listing them as missing")
	acceptJournalLoss := fs.Bool("accept-journal-loss", false,
		"restore or reconcile although the security journal cannot be shown complete; changes after the backup may be lost")
	if err := fs.Parse(sub); err != nil {
		return err
	}
	need := func(vals ...string) error {
		for _, v := range vals {
			if v == "" {
				return fmt.Errorf("%s: missing a required flag", cmd)
			}
		}
		return nil
	}
	passphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_BACKUP_KEY_PASSPHRASE", *passphraseFile) }
	kekPassphrase := func() ([]byte, error) { return keyfile.Passphrase("FGA_KEK_PASSPHRASE", *passphraseFile) }
	backupKey := func() (*backupcrypt.Key, error) {
		if *backupKeyFile == "" {
			return nil, errors.New("backups are encrypted: -backup-key is required")
		}
		raw, err := keyfile.Read(*backupKeyFile, passphrase)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		return backupcrypt.Load(raw)
	}
	journaled := func(kind, subject string, change func() error) error {
		j, err := e.journal()
		if err != nil {
			return err
		}
		// The journal entry is durable before the catalog change commits,
		// and the catalog records the journal's state (review finding 1).
		if err := j.Append(kind, *tenant, subject); err != nil {
			return err
		}
		js, err := j.State()
		if err != nil {
			return err
		}
		if err := catalog.RecordJournal(ctx, pool, js.ID, js.Chains); err != nil {
			return err
		}
		return change()
	}

	switch cmd {
	case "journal init":
		// Once, at setup: a new journal bound to this catalog. A catalog
		// already bound to another journal refuses it.
		if *journalDir == "" {
			return errors.New("journal init needs -journal")
		}
		j, err := journal.Init(*journalDir, time.Now)
		if err != nil {
			return err
		}
		if err := catalog.RecordJournal(ctx, pool, j.ID(), nil); err != nil {
			return err
		}
		fmt.Println("journal", j.ID())
		return nil
	case "mcp enable":
		if err := need(*tenant); err != nil {
			return err
		}
		if err := e.store.EnableMCP(ctx, *tenant); err != nil {
			return err
		}
		fmt.Printf("tenant %s: %d MCP tools registered\n", *tenant, len(registry.MCPTools))
		return nil
	case "bucket create":
		if err := need(*tenant, *name); err != nil {
			return err
		}
		bid, err := e.store.CreateBucket(ctx, *tenant, catalog.Bucket{Name: *name, Project: *project, Label: *label, Scope: *scope,
			Encryption: *encryption})
		if err == nil {
			fmt.Println(bid, *encryption)
		}
		return err
	case "identity put":
		if err := need(*tenant, *id); err != nil {
			return err
		}
		var a map[string]any
		if err := json.Unmarshal([]byte(*attrs), &a); err != nil {
			return fmt.Errorf("-attrs: %w", err)
		}
		return e.store.PutIdentity(ctx, *tenant, *id, split(*roles), a, nil)
	case "identity disable":
		if err := need(*tenant, *id); err != nil {
			return err
		}
		return journaled(journal.IdentityDisabled, *id, func() error { return e.store.DisableIdentity(ctx, *tenant, *id) })
	case "grant":
		if err := need(*tenant, *actor); err != nil {
			return err
		}
		set := map[string][]string{}
		switch {
		case *preset == "storage":
			set = StoragePreset
		case *preset == "approver":
			set = ApproverPreset
		case *typ != "" && *actions != "":
			set[*typ] = split(*actions)
		default:
			return errors.New("grant needs -preset storage|approver or -type and -actions")
		}
		return e.store.GrantCapabilities(ctx, *tenant, *actor, set)
	case "signing-key add":
		if err := need(*tenant, *principal, *publicKey); err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(*publicKey)
		if err != nil {
			return err
		}
		fp, err := e.store.AddSigningKey(ctx, *tenant, *principal, pub)
		if err == nil {
			fmt.Println(fp)
		}
		return err
	case "signing-key retire":
		if err := need(*tenant, *fingerprint); err != nil {
			return err
		}
		return e.store.SetSigningKeyStatus(ctx, *tenant, *fingerprint, "RETIRED")
	case "signing-key compromise":
		if err := need(*tenant, *fingerprint); err != nil {
			return err
		}
		return journaled(journal.SignerCompromised, *fingerprint, func() error {
			return e.store.SetSigningKeyStatus(ctx, *tenant, *fingerprint, "COMPROMISED")
		})
	case "recipient revoke":
		if err := need(*tenant, *fingerprint); err != nil {
			return err
		}
		return journaled(journal.RecipientRevoked, *fingerprint, func() error { return e.store.RevokeRecipientKey(ctx, *tenant, *fingerprint) })
	case "delegation add":
		if err := need(*tenant, *id, *actor, *subject, *audience, *grantList); err != nil {
			return err
		}
		d := delegation.Delegation{ID: delegation.ID(*id), Tenant: *tenant, Actor: *actor, Subject: *subject, Audience: *audience,
			ExpiresAt: time.Now().Add(*expires), Parent: delegation.ID(*parentID)}
		types := registry.CoreTypes()
		for _, part := range strings.Split(*grantList, ";") {
			typ, acts, ok := strings.Cut(strings.TrimSpace(part), ":")
			if !ok || !types.HasResourceType(typ) {
				return fmt.Errorf("delegation add: %q is not resource-type:actions of a known type", part)
			}
			g := delegation.Grant{ResourceType: typ, Actions: split(acts)}
			for _, a := range g.Actions {
				if a != delegation.AllActions && !types.HasAction(typ, a) {
					return fmt.Errorf("delegation add: %s has no action %q", typ, a)
				}
			}
			d.Grants = append(d.Grants, g)
		}
		if err := e.store.PutDelegation(ctx, d, time.Now()); err != nil {
			return err
		}
		fmt.Printf("delegation %s: %s acts for %s through %s until %s\n", *id, *actor, *subject, *audience, d.ExpiresAt.Format(time.RFC3339))
		return nil
	case "delegation revoke":
		if err := need(*tenant, *id); err != nil {
			return err
		}
		return journaled(journal.DelegationRevoked, *id, func() error { return e.store.RevokeDelegation(ctx, *tenant, *id) })
	case "epoch raise":
		if err := need(*tenant); err != nil || *epoch == 0 {
			return errors.New("epoch raise needs -tenant and -epoch")
		}
		return journaled(journal.EpochRaised, strconv.FormatUint(*epoch, 10), func() error { return e.store.RaiseEpoch(ctx, *tenant, *epoch) })
	case "backup-key generate":
		if err := need(*out); err != nil {
			return err
		}
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s already exists", *out)
		}
		raw, err := backupcrypt.Generate()
		if err != nil {
			return err
		}
		defer clear(raw)
		if *encrypt {
			p, err := passphrase()
			if err != nil {
				return err
			}
			if raw, err = keyfile.Seal(raw, p); err != nil {
				return err
			}
		}
		return keyfile.Write(*out, raw)
	case "kek init":
		if err := need(*keyFile); err != nil {
			return err
		}
		unlock, err := kek.Lock(*keyFile)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Stat(*keyFile); err == nil {
			return fmt.Errorf("%s already exists", *keyFile)
		}
		var p []byte
		if *encrypt {
			var err error
			if p, err = kekPassphrase(); err != nil {
				return err
			}
			defer clear(p)
		}
		return kek.WriteRing(*keyFile, kek.NewRing(), p)
	case "kek rotate":
		if err := need(*tenant, *keyFile); err != nil {
			return err
		}
		// One rotation at a time per ring, from reading it to the catalog
		// step, so no rotation overwrites another's version (review v3 F07).
		unlock, err := kek.Lock(*keyFile)
		if err != nil {
			return err
		}
		defer unlock()
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		var p []byte
		if keyfile.Protected(raw) {
			if p, err = kekPassphrase(); err != nil {
				return err
			}
			defer clear(p)
		}
		ring, err := kek.ReadRing(*keyFile, func() ([]byte, error) { return slices.Clone(p), nil })
		if err != nil {
			return err
		}
		// The ring gets the new version first: if the catalog step fails,
		// the ring holds an unused version and nothing refers to it.
		v, err := ring.Add(*tenant, time.Now())
		if err != nil {
			return err
		}
		if err := kek.WriteRing(*keyFile, ring, p); err != nil {
			return err
		}
		n, err := e.store.RotateKEK(ctx, *tenant, v, time.Now(), func(k catalog.SealedKey) ([]byte, error) {
			return ring.Reseal(*tenant, k.KEKVersion, v, k.Sealed,
				kek.Binding{Tenant: k.Tenant, Object: k.Object, Version: k.Version, CryptoVersion: k.CryptoVersion, Blob: k.Blob})
		})
		if err != nil {
			return err
		}
		fmt.Printf("tenant %s: KEK version %d is active; %d data keys resealed\n", *tenant, v, n)
		return nil
	case "key protect", "key unprotect":
		if err := need(*keyFile); err != nil {
			return err
		}
		p, err := passphrase()
		if err != nil {
			return err
		}
		defer clear(p)
		data, err := keyfile.Read(*keyFile, func() ([]byte, error) { return p, nil })
		if err != nil {
			return err
		}
		defer clear(data)
		if cmd == "key protect" {
			if data, err = keyfile.Seal(data, p); err != nil {
				return err
			}
		}
		return keyfile.Write(*keyFile, data)
	case "backup":
		blobs, err := e.blobs()
		if err != nil || need(*out) != nil {
			return errors.Join(err, need(*out))
		}
		key, err := backupKey()
		if err != nil {
			return err
		}
		m, err := recovery.BackupWith(ctx, pool, blobs, *out, key, backupcrypt.Scheme, recovery.BackupOptions{AllowMissing: *allowMissing})
		if err != nil {
			return err
		}
		fmt.Printf("backup %s: incarnation %d, %d tables, %d blobs\n", *out, m.Incarnation, len(m.Tables), len(m.Blobs))
		if len(m.Missing) > 0 {
			fmt.Printf("%d blobs could not be read and are not in the backup; the manifest lists them\n", len(m.Missing))
		}
		return nil
	case "restore":
		blobs, err := e.blobs()
		if err != nil {
			return err
		}
		j, err := e.journal()
		if err != nil || need(*from) != nil {
			return errors.Join(err, need(*from))
		}
		key, err := backupKey()
		if err != nil {
			return err
		}
		inc, err := recovery.RestoreWith(ctx, pool, blobs, j, *from, key, recovery.Options{AcceptJournalLoss: *acceptJournalLoss})
		if err == nil {
			fmt.Printf("restored %s as incarnation %d; admission is closed until reconcile\n", *from, inc)
		}
		return err
	case "reconcile":
		blobs, err := e.blobs()
		if err != nil {
			return err
		}
		j, err := e.journal()
		if err != nil {
			return err
		}
		opts := recovery.Options{AcceptJournalLoss: *acceptJournalLoss, JournalComplete: *journalComplete}
		if *kekFile != "" {
			if opts.KEKs, err = kek.ReadRing(*kekFile, kekPassphrase); err != nil {
				return err
			}
		}
		rep, err := recovery.ReconcileWith(ctx, e.store, blobs, j, opts)
		if err != nil {
			return err
		}
		if len(rep.MissingKEKs) > 0 {
			fmt.Printf("KEK versions missing from the ring: %s; their data keys do not open\n", strings.Join(rep.MissingKEKs, ", "))
		}
		fmt.Printf("replayed %d journal entries, checked %d server-mode data keys, quarantined %d versions; admission is open\n",
			rep.Replayed, rep.KeysChecked, rep.Quarantined)
		return nil
	case "audit export":
		if err := need(*dir); err != nil {
			return err
		}
		x, err := auditexport.New(pool, *dir, 1000)
		if err != nil {
			return err
		}
		for {
			n, err := x.Drain(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("exported %d audit events to %s\n", n, *dir)
			if !*follow {
				return nil
			}
			time.Sleep(5 * time.Second)
		}
	case "reclaim":
		blobs, err := e.blobs()
		if err != nil {
			return err
		}
		got, err := recovery.Reclaim(ctx, pool, blobs, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("retired %d withdrawn versions, aborted %d expired uploads\n", got.Retired, got.Aborted)
		if got.KeysDestroyed > 0 {
			fmt.Printf("destroyed %d server-mode data keys; backups taken before %s still hold them, so that content stays recoverable"+
				" until every such backup is deleted\n", got.KeysDestroyed, got.At.UTC().Format(time.RFC3339))
		}
		return nil
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
