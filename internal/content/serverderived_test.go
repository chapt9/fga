package content_test

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
)

// TestServerDerived covers DRV-001, DRV-002, DRV-007 and DRV-009 in server
// mode (S4b): an output's lineage is declared in the request and recorded
// without a signature; its label is the lineage maximum; a member reads it
// by deliver and their own read of every source, loses it when a source
// rises out of their reach, and a lead then reads it by declassification;
// each route serves its own mode.
func TestServerDerived(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	lena := st.Client("lena", []string{"member", "lead"}, "p1")
	obj, err := putPlain(st, alice.Caller, "vault", "data.csv", "", []byte("a,b\n1,2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "notes.md", IdempotencyKey: "n1"},
		[]byte("Public part.\n\nSensitive part.")); err != nil {
		t.Fatal(err)
	}
	page, err := st.Content.ListUnits(ctx, alice.Caller, "vault", "notes.md", "", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	sensitive := page.Units[1]
	sources := []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: obj.Object, Version: obj.Version},
		{Type: cryptowire.SourceUnit, ID: sensitive.Unit, Version: sensitive.UnitVersion}}
	req := content.BeginRequest{Bucket: "vault", Key: "summary.txt", IdempotencyKey: "d1"}
	p, err := st.Content.PutDerivedPlain(ctx, alice.Caller, req, sources, -1, strings.NewReader("the summary"))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := st.Content.PutDerivedPlain(ctx, alice.Caller, req, sources, -1, strings.NewReader("ignored")); err != nil || again != p {
		t.Fatalf("a retry: %+v %v", again, err)
	}
	var sig *string
	var label string
	if err := st.Pool.QueryRow(ctx, `SELECT lineage_signature, effective_label FROM derived_versions WHERE version::text = $1`, p.Version).
		Scan(&sig, &label); err != nil || sig != nil || label != "internal" {
		t.Fatalf("derived version: signature %v, label %q, %v", sig, label, err)
	}
	read := func(c content.Caller) (string, error) {
		s, err := st.Content.ReadDerivedPlain(ctx, c, "vault", "summary.txt", "")
		if err != nil {
			return "", err
		}
		defer s.Close()
		b, err := io.ReadAll(s)
		return string(b), err
	}
	if got, err := read(bob.Caller); err != nil || got != "the summary" {
		t.Fatalf("bob reads by his reader path: %q %v", got, err)
	}

	// A source rises out of bob's reach (DRV-009): his path is gone; the
	// lead reads by declassification.
	if _, err := st.Content.SetUnitLabel(ctx, alice.Caller, "vault", "notes.md", "", sensitive.Unit, "restricted"); err != nil {
		t.Fatal(err)
	}
	if _, err := read(bob.Caller); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("bob after the source was restricted: %v", err)
	}
	if got, err := read(lena.Caller); err != nil || got != "the summary" {
		t.Fatalf("the lead reads by declassification: %q %v", got, err)
	}
	if got, err := read(alice.Caller); err != nil || got != "the summary" {
		t.Fatalf("the owner: %q %v", got, err)
	}

	// Each route serves its own mode.
	if _, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "reports", Key: "s.txt", IdempotencyKey: "d2"},
		sources, 3, bytes.NewReader([]byte("abc"))); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("a server derived output to a client-mode bucket: %v", err)
	}
	if _, err := st.Content.ReadDerivedCiphertext(ctx, alice.Caller, "vault", "summary.txt", "", alice.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrEncryptionMode) {
		t.Fatalf("a server-mode output through the client route: %v", err)
	}
	if _, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "s2.txt", IdempotencyKey: "d3"},
		nil, 3, bytes.NewReader([]byte("abc"))); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("an output without lineage: %v", err)
	}
}

// TestServerDerivedApproval covers APR-001 and APR-002 for a server-mode
// derived output: a publication that needs an approval keeps the staged
// upload and names its intent; once a lead approves, finalizing it with the
// declared lineage publishes it, and another lineage is another plan the
// approval does not cover.
func TestServerDerivedApproval(t *testing.T) {
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
	approve := func(err error) (*content.StagedApproval, cryptowire.UUID) {
		t.Helper()
		var staged *content.StagedApproval
		if !errors.As(err, &staged) || staged.Intent == "" {
			t.Fatalf("publication without approval: %v", err)
		}
		if _, err := st.Content.DecideApproval(ctx, lena, staged.ID, true); err != nil {
			t.Fatal(err)
		}
		intent, err := cryptowire.ParseUUID(staged.Intent)
		if err != nil {
			t.Fatal(err)
		}
		return staged, intent
	}
	source := func(key string) cryptowire.LineageSource {
		t.Helper()
		_, err := putPlain(st, alice.Caller, "vault", key, key, []byte(key))
		staged, intent := approve(err)
		p, err := st.Content.Finalize(ctx, withApproval(alice.Caller, staged.ID), intent, content.FinalizeRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return cryptowire.LineageSource{Type: cryptowire.SourceObject, ID: p.Object, Version: p.Version}
	}
	a, b := source("a.txt"), source("b.txt")
	_, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "out.txt", IdempotencyKey: "o1"},
		[]cryptowire.LineageSource{a}, -1, strings.NewReader("derived"))
	staged, intent := approve(err)
	if n := count(t, st, `SELECT count(*) FROM derived_versions`); n != 0 {
		t.Fatal("published before the approval")
	}
	approved := withApproval(alice.Caller, staged.ID)
	if _, err := st.Content.FinalizeDerivedPlain(ctx, approved, intent, []cryptowire.LineageSource{b}); !errors.Is(err, content.ErrApprovalNotUsable) {
		t.Fatalf("finalize with another lineage: %v", err)
	}
	p, err := st.Content.FinalizeDerivedPlain(ctx, approved, intent, []cryptowire.LineageSource{a})
	if err != nil {
		t.Fatalf("finalize with the approval: %v", err)
	}
	if again, err := st.Content.FinalizeDerivedPlain(ctx, alice.Caller, intent, []cryptowire.LineageSource{a}); err != nil || again != p {
		t.Fatalf("a repeated finalize: %+v %v", again, err)
	}
	s, err := st.Content.ReadDerivedPlain(ctx, alice.Caller, "vault", "out.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := io.ReadAll(s); err != nil || string(got) != "derived" {
		t.Fatalf("the approved output: %q %v", got, err)
	}
}
