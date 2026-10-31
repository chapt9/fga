package content_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
	"fga/internal/registry"
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

// TestServerApprovals covers APR-001 and APR-002 for server-mode
// publications, objects and derived outputs: a publication that needs an
// approval keeps the staged upload, publishes nothing and names its intent;
// once a lead approves, finalizing the intent publishes it. A derived
// output's declared lineage is part of the plan: another lineage is another
// plan the approval does not cover.
func TestServerApprovals(t *testing.T) {
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
		if n := st.Count(`SELECT count(*) FROM object_versions o JOIN objects b ON b.id = o.object WHERE b.key = $1`, key); n != 0 {
			t.Fatalf("%s published before the approval", key)
		}
		staged, intent := approve(err)
		p, err := st.Content.Finalize(ctx, withApproval(alice.Caller, staged.ID), intent, content.FinalizeRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if got, _, err := readPlain(st, alice.Caller, "vault", key, p.Version); err != nil || string(got) != key {
			t.Fatalf("the approved object %s: %q %v", key, got, err)
		}
		return cryptowire.LineageSource{Type: cryptowire.SourceObject, ID: p.Object, Version: p.Version}
	}
	a, b := source("a.txt"), source("b.txt")
	_, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "out.txt", IdempotencyKey: "o1"},
		[]cryptowire.LineageSource{a}, -1, strings.NewReader("derived"))
	staged, intent := approve(err)
	if n := st.Count(`SELECT count(*) FROM derived_versions`); n != 0 {
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

// TestDerivedVersionKeepsRaisedLabel is the regression test of review v3
// finding F06: a new derived version's label was computed from the
// output's label saved at begin and from source labels read before the
// decisions, and the commit checked only the generation, so a raise of
// the output or of a source in between was lowered again by publication.
// The commit now recomputes the label from current state and refuses a
// publication whose label it no longer matches; a retry publishes at the
// higher label.
func TestDerivedVersionKeepsRaisedLabel(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	src, err := putPlain(st, alice.Caller, "vault", "src.txt", "", []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	sources := []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: src.Object, Version: src.Version}}
	put := func(key, idem string) error {
		_, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: key, IdempotencyKey: idem},
			sources, -1, strings.NewReader("derived "+idem))
		return err
	}
	for _, key := range []string{"out.txt", "out2.txt"} {
		if err := put(key, key+"/v1"); err != nil {
			t.Fatal(err)
		}
	}
	label := func(key string) string {
		var l string
		if err := st.Pool.QueryRow(ctx, `SELECT r.attributes->>'label' FROM resources r JOIN objects o ON o.tenant = r.tenant AND o.id::text = r.id
		                                   WHERE o.key = $1`, key).Scan(&l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	for _, c := range []struct {
		name, idem string
		raise      func() error
		key, want  string
	}{
		{"the output raised", "v2", func() error {
			_, err := st.Content.SetDerivedLabel(ctx, alice.Caller, "vault", "out.txt", "restricted")
			return err
		}, "out.txt", "restricted"},
		{"a source raised", "v3", func() error {
			_, err := st.Content.SetLabel(ctx, alice.Caller, "vault", "src.txt", "confidential")
			return err
		}, "out2.txt", "confidential"},
	} {
		raised := false
		st.BeforeDecide = func(req decisionsvc.Request) {
			if req.Operation == registry.OpDerivedPublishServerVersion && !raised {
				raised = true
				if err := c.raise(); err != nil {
					t.Errorf("%s: %v", c.name, err)
				}
			}
		}
		if err := put(c.key, c.idem); !errors.Is(err, content.ErrConflict) {
			t.Fatalf("%s before the publication decision: %v", c.name, err)
		}
		st.BeforeDecide = nil
		if got := label(c.key); got == "internal" && c.key == "out.txt" || c.key == "out2.txt" && got != "internal" {
			t.Fatalf("%s: the refused publication changed the output's label to %s", c.name, got)
		}
		if err := put(c.key, c.idem); err != nil {
			t.Fatalf("%s: the retry: %v", c.name, err)
		}
		if got := label(c.key); got != c.want {
			t.Fatalf("%s: after the retry the output's label is %s, want %s", c.name, got, c.want)
		}
	}
}

// TestConcurrentDerivedVersions covers review v3 F13 case A: two
// publications of new versions of one derived output both held the output
// for share and then both updated it, so they could deadlock. The fence
// now locks the output for update from the start: one waits, and each
// either publishes or meets a conflict.
func TestConcurrentDerivedVersions(t *testing.T) {
	st := r1test.New(t)
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	src, err := putPlain(st, alice.Caller, "vault", "src.txt", "", []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	sources := []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: src.Object, Version: src.Version}}
	put := func(idem string) error {
		_, err := st.Content.PutDerivedPlain(ctx, alice.Caller, content.BeginRequest{Bucket: "vault", Key: "out.txt", IdempotencyKey: idem},
			sources, -1, strings.NewReader(idem))
		return err
	}
	if err := put("v0"); err != nil {
		t.Fatal(err)
	}
	for round := range 5 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for w := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[w] = put(fmt.Sprintf("r%d-w%d", round, w))
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil && !errors.Is(err, content.ErrConflict) {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
}
