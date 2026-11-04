package content_test

import (
	"errors"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/envelope"
	"fga/internal/r1test"
)

// craftedEnvelope is an envelope of ec signed by c, with ciphertext the
// keys role cannot open: it exercises the checks that come before the
// decision, nothing after it.
func craftedEnvelope(t *testing.T, c *r1test.Client, ec cryptowire.EnvelopeContext) content.EnvelopeIn {
	t.Helper()
	ec.Sharer = c.Signer.Fingerprint
	b, err := ec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ct := []byte("not an hpke ciphertext")
	sig, err := c.Signer.Sign(cryptowire.TypeEnvelope, cryptowire.EnvelopeSigningInput(b, ct))
	if err != nil {
		t.Fatal(err)
	}
	return content.EnvelopeIn{Context: b, Ciphertext: ct, Signature: sig}
}

// TestStateRefusalsNeedAuthorization is the regression test of the
// security review of 4 November 2026, finding 1: a refusal that depends on
// a key's state (its kind, its label, its current version, a version's
// bindings, a recipient key's version) is answered only to a caller the
// decision role allows; anyone else gets the ordinary not-found, as for an
// absent key (CNT-004, DEC-010). The outsider is a member of another
// project.
func TestStateRefusalsNeedAuthorization(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	carol := st.Client("carol", []string{"member"}, "p2")
	alice.Pin(bob)
	u, err := alice.Prepare(content.BeginRequest{Bucket: "reports", Key: "doc"}, []byte("one"), alice)
	if err != nil {
		t.Fatal(err)
	}
	v, err := alice.Finalize(u)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := alice.PrepareDocument("reports", "q3.md", []string{"a", "b"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(doc); err != nil {
		t.Fatal(err)
	}
	coll, err := alice.PrepareCollection("reports", "chat", []string{"x"}, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(coll); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PutDerived("reports", "summary", []byte("s"), unitSources(doc), ""); err != nil {
		t.Fatal(err)
	}
	fresh := func() string { return cryptowire.NewUUID().String() }
	bound := cryptowire.EnvelopeContext{Tenant: u.Intent.Tenant, Object: u.Intent.Object, LogicalVersion: u.Intent.LogicalVersion,
		CryptoVersion: u.Intent.CryptoVersion, Suite: cryptowire.Suite1, Format: cryptowire.Format1, CiphertextSHA256: u.Sealed.CiphertextSHA256,
		CiphertextLength: u.Sealed.CiphertextLength, Recipient: bob.Recipient.Fingerprint(), RecipientKeyVersion: bob.KeyVersion, Generation: 1,
		CreatedAt: *st.Clock}
	otherLength, otherKeyVersion := bound, bound
	otherLength.CiphertextLength++
	otherKeyVersion.RecipientKeyVersion++
	for _, c := range []struct {
		name string
		call func(c *r1test.Client) error
		want error
	}{
		{"an existing key with another label", func(c *r1test.Client) error {
			_, err := st.Content.Begin(ctx, c.Caller, content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: fresh(), Label: "restricted"})
			return err
		}, content.ErrInvalid},
		{"a derived begin on an object key", func(c *r1test.Client) error {
			_, err := st.Content.Begin(ctx, c.Caller, content.BeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: fresh(), Derived: true})
			return err
		}, content.ErrConflict},
		{"a derived begin with If-Match on a derived output", func(c *r1test.Client) error {
			_, err := st.Content.Begin(ctx, c.Caller, content.BeginRequest{Bucket: "reports", Key: "summary", IdempotencyKey: fresh(), Derived: true, IfMatch: "x"})
			return err
		}, content.ErrConflict},
		{"a label below the floor on a new key", func(c *r1test.Client) error {
			_, err := st.Content.Begin(ctx, c.Caller, content.BeginRequest{Bucket: "reports", Key: "new-" + fresh(), IdempotencyKey: fresh(), Label: "public"})
			return err
		}, content.ErrInvalid},
		{"a document begun on an object key", func(c *r1test.Client) error {
			_, err := st.Content.BeginDocument(ctx, c.Caller, content.DocumentBeginRequest{Bucket: "reports", Key: "doc", IdempotencyKey: fresh(),
				Units: []content.DocumentUnitSpec{{}}})
			return err
		}, content.ErrConflict},
		{"a collection begun on a document key", func(c *r1test.Client) error {
			_, err := st.Content.BeginDocument(ctx, c.Caller, content.DocumentBeginRequest{Bucket: "reports", Key: "q3.md", IdempotencyKey: fresh(),
				Units: []content.DocumentUnitSpec{{}}, Collection: true})
			return err
		}, content.ErrInvalid},
		{"a stale base version", func(c *r1test.Client) error {
			_, err := st.Content.BeginDocument(ctx, c.Caller, content.DocumentBeginRequest{Bucket: "reports", Key: "q3.md", IdempotencyKey: fresh(),
				Units: []content.DocumentUnitSpec{{}}, BaseVersion: v.Version})
			return err
		}, content.ErrConflict},
		{"a unit label below the floor", func(c *r1test.Client) error {
			_, err := st.Content.BeginDocument(ctx, c.Caller, content.DocumentBeginRequest{Bucket: "reports", Key: "new-" + fresh(), IdempotencyKey: fresh(),
				Units: []content.DocumentUnitSpec{{Label: "public"}}})
			return err
		}, content.ErrInvalid},
		{"a label below the floor", func(c *r1test.Client) error {
			_, err := st.Content.SetLabel(ctx, c.Caller, "reports", "doc", "public")
			return err
		}, content.ErrInvalid},
		{"a label outside the order", func(c *r1test.Client) error {
			_, err := st.Content.SetLabel(ctx, c.Caller, "reports", "doc", "secret")
			return err
		}, content.ErrInvalid},
		{"a label on a collection entry", func(c *r1test.Client) error {
			_, err := st.Content.SetUnitLabel(ctx, c.Caller, "reports", "chat", "", coll.Intent.Units[0].Unit, "confidential")
			return err
		}, content.ErrInvalid},
		{"an envelope whose bindings differ", func(c *r1test.Client) error {
			_, err := st.Envelopes.Publish(ctx, st.KeysCaller(c.Caller.Principal), "reports", "doc", v.Version, craftedEnvelope(t, c, otherLength))
			return err
		}, envelope.ErrInvalid},
		{"an envelope for another recipient key version", func(c *r1test.Client) error {
			_, err := st.Envelopes.Publish(ctx, st.KeysCaller(c.Caller.Principal), "reports", "doc", v.Version, craftedEnvelope(t, c, otherKeyVersion))
			return err
		}, envelope.ErrInvalid},
	} {
		if err := c.call(alice); !errors.Is(err, c.want) {
			t.Errorf("%s, by the owner: %v, want %v", c.name, err, c.want)
		}
		if err := c.call(carol); !errors.Is(err, content.ErrNotFound) && !errors.Is(err, envelope.ErrNotFound) {
			t.Errorf("%s, by an outsider: %v, want not found", c.name, err)
		}
	}
	if n := st.Count(`SELECT (SELECT count(*) FROM upload_intents WHERE state = 'RESERVED') + (SELECT count(*) FROM document_intents WHERE state = 'RESERVED')`); n != 0 {
		t.Fatalf("%d intents reserved by refused begins", n)
	}
}
