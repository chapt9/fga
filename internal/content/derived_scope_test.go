package content_test

import (
	"errors"
	"maps"
	"testing"

	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/r1test"
	"fga/sdk/go/crypto"
)

// TestSharedDerivedEnvelopeKeepsScope is the regression test of audit
// finding F-CNT-1: an envelope shared for a derived output with
// ShareDerived was registered without the output's scope, while the
// output's initial envelopes carry it, so a scoped rule on envelopes did
// not reach the shared one. Here a rule of the bucket's scope denies the
// release of any envelope to lena; the envelope alice shares with her is
// in that scope, and the rule holds.
func TestSharedDerivedEnvelopeKeepsScope(t *testing.T) {
	const scope = "p1.restricted"
	policies := maps.Clone(r1test.Policies)
	policies["envelopes-scoped.json"] = `{"format":"fga.policy/v1","set":"business","resource":"crypto.envelope","scope":"` + scope + `","rules":[
	  {"id":"no-release-to-lena","effect":"deny","actions":["release"],"roles":["*"],"when":"principal.id == \"lena\""}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	if _, err := st.Catalog.CreateBucket(ctx, r1test.Tenant,
		catalog.Bucket{Name: "reports", Project: "p1", Label: "public", Scope: scope, Encryption: "client"}); err != nil {
		t.Fatal(err)
	}
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.Client("lena", []string{"member", "lead"}, "p1")
	alice.Pin(lena)
	lena.Pin(alice)
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "src.md", []string{"u1", "u2"},
		[]content.DocumentUnitSpec{{Label: "internal"}, {Label: "restricted"}}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	p, err := alice.PutDerived("reports", "summary", []byte("summary"), unitSources(up), "")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := st.Content.DerivedPackage(ctx, alice.Caller, "reports", "summary", "", alice.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatalf("the owner's own envelope: %v", err)
	}
	env, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		alice.Recipient, alice.Trust, crypto.Recipient{Fingerprint: lena.Recipient.Fingerprint(), KeyVersion: lena.KeyVersion}, 1, alice.Signer, *st.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.ShareDerived(ctx, alice.Caller, "reports", "summary", p.Version,
		content.EnvelopeIn{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature}); err != nil {
		t.Fatalf("share to a declassified recipient: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM resources WHERE tenant = $1 AND type = 'crypto.envelope' AND scope <> $2`, r1test.Tenant, scope); n != 0 {
		t.Fatalf("%d envelope resources outside the output's scope %q", n, scope)
	}
	if n := st.Count(`SELECT count(*) FROM resources WHERE tenant = $1 AND type = 'crypto.envelope' AND scope = $2`, r1test.Tenant, scope); n < 2 {
		t.Fatalf("%d envelope resources in scope %q, want the initial one and the shared one", n, scope)
	}
	if got, err := readDerived(t, st, lena, "summary"); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("the scoped rule did not reach the shared envelope: %q, %v", got, err)
	}
}
