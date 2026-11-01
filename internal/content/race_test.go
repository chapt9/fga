package content_test

import (
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/envelope"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/sdk/go/crypto"
)

// TestOverwriteDuringReadKeepsHistoryRule is the regression test of review
// finding 2: whether the requested version is current was decided before
// the decision, so an overwrite in between let an old version be read
// with plain read, without read-history. The head the operation selected
// is now rechecked against the decision's binding.
func TestOverwriteDuringReadKeepsHistoryRule(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1") // read, stat; no read-history
	if _, err := alice.Put("reports", "doc", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	overwrite := func() {
		st.BeforeDecide = func(req decisionsvc.Request) {
			if req.Operation == registry.OpRead || req.Operation == registry.OpStat {
				st.BeforeDecide = nil
				if _, err := alice.Put("reports", "doc", []byte("v2")); err != nil {
					t.Error(err)
				}
			}
		}
	}
	overwrite()
	if s, err := st.Content.ReadCiphertext(ctx, bob.Caller, "reports", "doc", ""); err == nil {
		b, _ := io.ReadAll(s)
		s.Close()
		t.Fatalf("an overwritten version was read as current without read-history (%d bytes, current=%t)", len(b), s.Version.Current)
	} else if !errors.Is(err, content.ErrConflict) {
		t.Fatalf("read across an overwrite: %v, want a conflict", err)
	}
	overwrite()
	if _, err := st.Content.ReadPackage(ctx, bob.Caller, "reports", "doc", "", bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("package across an overwrite: %v, want a conflict", err)
	}
	overwrite()
	if _, err := st.Content.Stat(ctx, bob.Caller, "reports", "doc", ""); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("stat across an overwrite: %v, want a conflict", err)
	}
	// Without a concurrent write, the current version reads normally.
	if _, err := st.Content.Stat(ctx, bob.Caller, "reports", "doc", ""); err != nil {
		t.Fatal(err)
	}
}

// TestOriginalDeliveryBindsUnits is the regression test of review finding
// 3: the original's envelope was released by a keys-role decision that
// did not bind the per-unit read checks, so a unit's label raised after
// the storage role's checks still let the envelope out. The unit checks
// now reach the keys role's delivery fence.
func TestOriginalDeliveryBindsUnits(t *testing.T) {
	policies := map[string]string{}
	for name, doc := range r1test.Policies {
		policies[name] = doc
	}
	policies["documents.json"] = strings.Replace(policies["documents.json"], `"actions":["read-units","discover"],"roles":["member"]`,
		`"actions":["read-units","discover","raw-read"],"roles":["member"]`, 1)
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	up, err := alice.PrepareDocumentWithOriginal("reports", "q3.pdf", []string{"a", "b"}, []byte("original"), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	unit := up.Intent.Units[1].Unit
	st.BeforeDecide = func(req decisionsvc.Request) {
		if req.Operation == registry.OpDocGetOriginalEnvelope {
			st.BeforeDecide = nil
			if _, err := st.Pool.Exec(ctx, `UPDATE resources SET attributes = attributes || '{"label":"restricted"}',
			                                metadata_revision = metadata_revision + 1 WHERE id = $1`, unit); err != nil {
				t.Error(err)
			}
		}
	}
	if _, err := st.Content.OriginalPackage(ctx, bob.Caller, "reports", "q3.pdf", "", bob.Recipient.Fingerprint().String()); err == nil {
		t.Fatal("the original's envelope was delivered after bob lost read on a unit")
	}
	if _, err := st.Content.OriginalPackage(ctx, bob.Caller, "reports", "q3.pdf", "", bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("a fresh request after the change: %v", err)
	}
}

// TestCompromisedSignerCannotCommit is the regression test of review
// finding 6: the signer's status was checked while preparing a
// publication but not where it commits, so a key marked compromised in
// between still published. Object publication, document publication and
// sharing now recheck the signer inside the fence. Each case marks the
// key compromised after the pre-checks, while the decision is requested.
func TestCompromisedSignerCannotCommit(t *testing.T) {
	setup := func(t *testing.T) (*r1test.Stack, *r1test.Client, *r1test.Client) {
		st := r1test.New(t)
		st.Bucket("reports", "p1")
		alice := st.Client("alice", []string{"member"}, "p1")
		bob := st.Client("bob", []string{"member"}, "p1")
		alice.Pin(bob)
		return st, alice, bob
	}
	compromiseAt := func(t *testing.T, st *r1test.Stack, alice *r1test.Client, op string) {
		st.BeforeDecide = func(req decisionsvc.Request) {
			if req.Operation == op {
				st.BeforeDecide = nil
				if err := st.Catalog.SetSigningKeyStatus(ctx, r1test.Tenant, alice.Signer.Fingerprint.String(), "COMPROMISED"); err != nil {
					t.Error(err)
				}
			}
		}
	}
	t.Run("object", func(t *testing.T) {
		st, alice, _ := setup(t)
		u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "k1"}, []byte("x"), alice)
		if err != nil {
			t.Fatal(err)
		}
		compromiseAt(t, st, alice, registry.OpPublishCreate)
		if _, err := alice.Finalize(u); err == nil {
			t.Fatal("an object publication committed after its signer was compromised")
		}
	})
	t.Run("document", func(t *testing.T) {
		st, alice, _ := setup(t)
		up, err := alice.PrepareDocument("reports", "q3.md", []string{"a"}, nil, alice)
		if err != nil {
			t.Fatal(err)
		}
		compromiseAt(t, st, alice, registry.OpDocPublishCreate)
		if _, err := alice.FinalizeDocument(up); err == nil {
			t.Fatal("a document publication committed after its signer was compromised")
		}
	})
	t.Run("share", func(t *testing.T) {
		st, alice, bob := setup(t)
		if _, err := alice.Put("reports", "doc", []byte("x")); err != nil {
			t.Fatal(err)
		}
		pkg, err := st.Content.ReadPackage(ctx, alice.Caller, "reports", "doc", "", alice.Recipient.Fingerprint().String())
		if err != nil {
			t.Fatal(err)
		}
		env, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
			Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
			alice.Recipient, alice.Trust, crypto.Recipient{Fingerprint: bob.Recipient.Fingerprint(), KeyVersion: bob.KeyVersion}, 1, alice.Signer, *st.Clock)
		if err != nil {
			t.Fatal(err)
		}
		compromiseAt(t, st, alice, registry.OpPublishEnvelope)
		if _, err := st.Envelopes.Publish(ctx, st.KeysCaller("alice"), "reports", "doc", pkg.Version.Version,
			envelope.EnvelopeIn{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature}); err == nil {
			t.Fatal("a share committed after its signer was compromised")
		}
	})
}

// TestFinalizeVerifiesStagedBlob covers the second half of review finding
// 5: a staged upload whose ciphertext is gone from the blob store is not
// published.
func TestFinalizeVerifiesStagedBlob(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: "k1"}, []byte("x"), alice)
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	_ = filepath.WalkDir(filepath.Join(st.BlobDir, "blobs"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(d.Name(), u.Intent.Blob.String()) {
			removed++
			return os.Remove(path)
		}
		return nil
	})
	if removed != 1 {
		t.Fatalf("removed %d blob files", removed)
	}
	if _, err := alice.Finalize(u); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("finalize without the staged ciphertext: %v", err)
	}
}

// TestServerDocumentVerifiesStagedBlobs covers review v5 F08: a staged
// server-mode document whose unit or original ciphertext is gone from the
// blob store while it waits for an approval is not published.
func TestServerDocumentVerifiesStagedBlobs(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["buckets.json"] = `{"format":"fga.policy/v1","set":"business","resource":"storage.bucket","scope":"","rules":[
	  {"id":"members-use-bucket","effect":"allow","actions":["list"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"members-create-with-approval","effect":"allow","actions":["create-object"],"roles":["member"],"requires":["approval"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"leads-approve-buckets","effect":"allow","actions":["approve"],"roles":["lead"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.User("lena", []string{"lead"}, "p1")
	for _, kind := range []string{"unit", "original"} {
		r := content.TextRequest{Bucket: "vault", Key: kind + ".md", IdempotencyKey: kind}
		if kind == "original" {
			r.Original = strings.NewReader("the original file")
		}
		_, err := st.Content.PutDocumentText(ctx, alice.Caller, r, []byte("Summary.\n\nDetails.\n"))
		var staged *content.StagedApproval
		if !errors.As(err, &staged) {
			t.Fatalf("%s: publication without approval: %v", kind, err)
		}
		if _, err := st.Content.DecideApproval(ctx, lena, staged.ID, true); err != nil {
			t.Fatal(err)
		}
		var blobID string
		if err := st.Pool.QueryRow(ctx, `SELECT blob::text FROM upload_intents WHERE document_intent::text = $1 AND kind = $2 LIMIT 1`,
			staged.Intent, kind).Scan(&blobID); err != nil {
			t.Fatal(err)
		}
		removed := 0
		_ = filepath.WalkDir(st.BlobDir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.Contains(d.Name(), blobID) {
				removed++
				return os.Remove(path)
			}
			return nil
		})
		if removed != 1 {
			t.Fatalf("%s: removed %d blob files", kind, removed)
		}
		if _, err := st.Content.FinalizeDocument(ctx, withApproval(alice.Caller, staged.ID), staged.Intent, content.DocumentFinalizeRequest{}); !errors.Is(err, content.ErrConflict) {
			t.Errorf("%s: finalize without the staged ciphertext: %v", kind, err)
		}
	}
	if n := st.Count(`SELECT count(*) FROM document_versions`); n != 0 {
		t.Fatalf("%d document versions published without their ciphertext", n)
	}
}
