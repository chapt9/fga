// Command fga-admin is the local administrator's tool (specification 2.5,
// ADM-002, ADM-003, AVL-008, KEY-017). It works directly on the catalog,
// the blob directory and the security journal, outside every API path, and
// is meant for the operator of a local deployment.
//
//	fga-admin -db URL [-journal DIR] [-blobs DIR] COMMAND [flags]
//
// Commands:
//
//	bucket create      -tenant T -name N [-project P] [-label L] [-scope S]
//	identity put       -tenant T -id ID [-roles a,b] [-attrs JSON]
//	identity disable   -tenant T -id ID                      (journaled)
//	grant              -tenant T -actor ID [-type T -actions a,b | -preset storage]
//	signing-key add    -tenant T -principal ID -public-key B64
//	signing-key retire|compromise -tenant T -fingerprint FP  (compromise is journaled)
//	recipient revoke   -tenant T -fingerprint FP             (journaled)
//	delegation revoke  -tenant T -id ID                      (journaled)
//	epoch raise        -tenant T -epoch N                    (journaled)
//	backup             -out DIR
//	restore            -from DIR
//	reconcile
//	reclaim
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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/auditexport"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/journal"
	"fga/internal/recovery"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fga-admin:", err)
		os.Exit(1)
	}
}

// StoragePreset is the capability set of an ordinary storage user (DLG-004).
var StoragePreset = map[string][]string{
	"storage.bucket":   {"create-object", "list"},
	"storage.object":   {"read", "stat", "discover", "read-history", "discover-history", "new-version", "delete", "delete-version", "share"},
	"crypto.envelope":  {"create", "release", "retire"},
	"crypto.recipient": {"enroll", "activate", "receive-key", "revoke"},
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
	roles := fs.String("roles", "", "comma-separated roles")
	attrs := fs.String("attrs", "{}", "identity attributes as a JSON object")
	actor := fs.String("actor", "", "actor identity")
	typ := fs.String("type", "", "resource type")
	actions := fs.String("actions", "", "comma-separated actions")
	preset := fs.String("preset", "", "capability preset: storage")
	principal := fs.String("principal", "", "principal identity")
	publicKey := fs.String("public-key", "", "base64 public key")
	fingerprint := fs.String("fingerprint", "", "key fingerprint")
	epoch := fs.Uint64("epoch", 0, "policy epoch")
	out := fs.String("out", "", "backup directory to create")
	dir := fs.String("dir", "", "audit export directory")
	follow := fs.Bool("follow", false, "keep exporting until interrupted")
	from := fs.String("from", "", "backup directory to restore")
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
	journaled := func(kind, subject string, change func() error) error {
		j, err := e.journal()
		if err != nil {
			return err
		}
		// The journal entry is durable before the catalog change commits.
		if err := j.Append(kind, *tenant, subject); err != nil {
			return err
		}
		return change()
	}

	switch cmd {
	case "bucket create":
		if err := need(*tenant, *name); err != nil {
			return err
		}
		bid, err := e.store.CreateBucket(ctx, *tenant, catalog.Bucket{Name: *name, Project: *project, Label: *label, Scope: *scope})
		if err == nil {
			fmt.Println(bid)
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
		case *typ != "" && *actions != "":
			set[*typ] = split(*actions)
		default:
			return errors.New("grant needs -preset storage or -type and -actions")
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
	case "backup":
		blobs, err := e.blobs()
		if err != nil || need(*out) != nil {
			return errors.Join(err, need(*out))
		}
		m, err := recovery.Backup(ctx, pool, blobs, *out)
		if err == nil {
			fmt.Printf("backup %s: incarnation %d, %d tables, %d blobs\n", *out, m.Incarnation, len(m.Tables), len(m.Blobs))
		}
		return err
	case "restore":
		blobs, err := e.blobs()
		if err != nil {
			return err
		}
		j, err := e.journal()
		if err != nil || need(*from) != nil {
			return errors.Join(err, need(*from))
		}
		inc, err := recovery.Restore(ctx, pool, blobs, j, *from)
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
		rep, err := recovery.Reconcile(ctx, e.store, blobs, j)
		if err == nil {
			fmt.Printf("replayed %d journal entries, quarantined %d versions; admission is open\n", rep.Replayed, rep.Quarantined)
		}
		return err
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
		if err == nil {
			fmt.Printf("retired %d withdrawn versions, aborted %d expired uploads\n", got.Retired, got.Aborted)
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
