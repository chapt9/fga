package r1test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/signing"
	"fga/sdk/go/crypto"
)

// Trust is an in-memory client trust store (RCP-002).
type Trust struct {
	Recipients map[cryptowire.Digest][]byte
	Signers    map[cryptowire.Digest]ed25519.PublicKey
}

// Recipient implements crypto.TrustStore.
func (t *Trust) Recipient(fp cryptowire.Digest) ([]byte, bool) {
	k, ok := t.Recipients[fp]
	return k, ok
}

// Signer implements crypto.TrustStore.
func (t *Trust) Signer(fp cryptowire.Digest) (ed25519.PublicKey, bool) {
	k, ok := t.Signers[fp]
	return k, ok
}

// Client is a user with a recipient key, a content-signing key and a trust
// store, using the content service as the native API would.
type Client struct {
	st         *Stack
	Caller     content.Caller
	Recipient  *crypto.RecipientKey
	KeyVersion uint64
	Signer     crypto.SigningKey
	Trust      *Trust
}

// Client creates a user with the given roles and projects, provisions its
// keys and pins them in its own trust store.
func (st *Stack) Client(id string, roles []string, projects ...string) *Client {
	st.T.Helper()
	ctx := context.Background()
	c := &Client{st: st, Caller: st.User(id, roles, projects...)}
	var err error
	if c.Recipient, err = crypto.NewRecipientKey(); err != nil {
		st.T.Fatal(err)
	}
	if _, c.KeyVersion, err = st.Catalog.AddRecipientKey(ctx, Tenant, id, c.Recipient.PublicKey()); err != nil {
		st.T.Fatal(err)
	}
	if c.Signer, err = crypto.NewSigningKey(); err != nil {
		st.T.Fatal(err)
	}
	if _, err := st.Catalog.AddSigningKey(ctx, Tenant, id, c.Signer.Private.Public().(ed25519.PublicKey)); err != nil {
		st.T.Fatal(err)
	}
	c.Trust = &Trust{Recipients: map[cryptowire.Digest][]byte{}, Signers: map[cryptowire.Digest]ed25519.PublicKey{}}
	c.Pin(c)
	return c
}

// Pin trusts other's recipient key and content signer.
func (c *Client) Pin(other *Client) {
	c.Trust.Recipients[other.Recipient.Fingerprint()] = other.Recipient.PublicKey()
	c.Trust.Signers[other.Signer.Fingerprint] = other.Signer.Private.Public().(ed25519.PublicKey)
}

// Upload is a begun and encrypted upload that has not been finalized.
type Upload struct {
	Intent     content.Intent
	Ciphertext []byte
	Sealed     crypto.Sealed
}

// Prepare begins an upload, encrypts plaintext for the given recipients and
// stages the ciphertext.
func (c *Client) Prepare(req content.BeginRequest, plaintext []byte, to ...*Client) (Upload, error) {
	ctx := context.Background()
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = cryptowire.NewUUID().String()
	}
	in, err := c.st.Content.Begin(ctx, c.Caller, req)
	if err != nil {
		return Upload{}, err
	}
	var recipients []crypto.Recipient
	for _, r := range to {
		recipients = append(recipients, crypto.Recipient{Fingerprint: r.Recipient.Fingerprint(), KeyVersion: r.KeyVersion})
	}
	var ct bytes.Buffer
	sealed, err := crypto.Encrypt(&ct, bytes.NewReader(plaintext), crypto.Params{Tenant: in.Tenant, Object: in.Object,
		LogicalVersion: in.LogicalVersion, CryptoVersion: in.CryptoVersion, Blob: in.Blob, Attempt: in.Attempt},
		recipients, c.Signer, c.Trust, *c.st.Clock)
	if err != nil {
		return Upload{}, err
	}
	if _, err := c.st.Content.PutCiphertext(ctx, c.Caller, in.IntentID, int64(ct.Len()), sealed.CiphertextSHA256, bytes.NewReader(ct.Bytes())); err != nil {
		return Upload{}, err
	}
	return Upload{Intent: in, Ciphertext: ct.Bytes(), Sealed: sealed}, nil
}

// Finalize publishes a prepared upload.
func (c *Client) Finalize(u Upload) (content.Published, error) {
	req := content.FinalizeRequest{Descriptor: u.Sealed.Descriptor, DescriptorSignature: u.Sealed.DescriptorSignature}
	for _, e := range u.Sealed.Envelopes {
		req.Envelopes = append(req.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
	}
	return c.st.Content.Finalize(context.Background(), c.Caller, u.Intent.IntentID, req)
}

// Put uploads plaintext to bucket/key for the recipients (the uploader
// itself when none are given).
func (c *Client) Put(bucket, key string, plaintext []byte, to ...*Client) (content.Published, error) {
	if len(to) == 0 {
		to = []*Client{c}
	}
	u, err := c.Prepare(content.BeginRequest{Bucket: bucket, Key: key}, plaintext, to...)
	if err != nil {
		return content.Published{}, err
	}
	return c.Finalize(u)
}

// Get reads and decrypts a version (the current one when version is "").
func (c *Client) Get(bucket, key, version string) ([]byte, error) {
	ctx := context.Background()
	pkg, err := c.st.Content.ReadPackage(ctx, c.Caller, bucket, key, version, c.Recipient.Fingerprint().String())
	if err != nil {
		return nil, err
	}
	stream, err := c.st.Content.ReadCiphertext(ctx, c.Caller, bucket, key, pkg.Version.Version)
	if err != nil {
		return nil, err
	}
	ct, err := io.ReadAll(stream)
	stream.Close()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = crypto.Decrypt(&out, bytes.NewReader(ct), crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		c.Recipient, c.Trust)
	return out.Bytes(), err
}

// DeliveryDecision asks the decision service, as the storage role, for a
// GetRecipientEnvelope decision for c on the current version of
// bucket/key and its envelope for recipient. op and audience can be
// overridden to build decisions a keys role must refuse.
func (c *Client) DeliveryDecision(bucket, key, recipient, op, audience string) (signing.Signed, string, error) {
	resp, envelopeID, err := c.DeliveryResponse(bucket, key, recipient, op, audience)
	if err != nil {
		return signing.Signed{}, "", err
	}
	if resp.Outcome != "ALLOW" {
		return signing.Signed{}, "", fmt.Errorf("decision %s %s", resp.Outcome, resp.Reason)
	}
	payload, _ := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	return signing.Signed{Payload: payload, JWS: resp.Signed.JWS}, envelopeID, nil
}

// DeliveryResponse is DeliveryDecision's raw decision response, whatever
// its outcome.
func (c *Client) DeliveryResponse(bucket, key, recipient, op, audience string) (decisionsvc.Response, string, error) {
	ctx := context.Background()
	var objectID, versionID, envelopeID string
	err := c.st.Pool.QueryRow(ctx, `
		SELECT o.id::text, o.current_version::text, e.id::text FROM objects o
		  JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
		  JOIN envelopes e ON e.tenant = o.tenant AND e.version = o.current_version AND e.recipient = $3 AND e.status = 'ACTIVE'
		 WHERE o.tenant = $4 AND b.name = $1 AND o.key = $2`, bucket, key, recipient, Tenant).Scan(&objectID, &versionID, &envelopeID)
	if err != nil {
		return decisionsvc.Response{}, "", err
	}
	id, err := c.st.Catalog.GetIdentity(ctx, Tenant, c.Caller.Principal)
	if err != nil {
		return decisionsvc.Response{}, "", err
	}
	obj := decisionsvc.Alias{Type: "storage.object", ID: objectID}
	req := decisionsvc.Request{RequestID: "r", Tenant: Tenant, Operation: op, OperationID: cryptowire.NewUUID().String(), OperationDigest: "sha256:t",
		Audience: audience, SingleUse: true, Actor: decisionsvc.Ref{ID: c.Caller.Principal, Revision: id.Revision}, Evidence: c.Caller.Token,
		Checks: []decisionsvc.Check{
			{ID: "object", Role: "object", Action: "read", Resource: obj, Version: versionID},
			{ID: "envelope", Role: "envelope", Action: "release", Resource: decisionsvc.Alias{Type: "crypto.envelope", ID: envelopeID}, Version: versionID},
			{ID: "recipient-read", Role: "recipient-read", Action: "read", Kind: "RECIPIENT_ELIGIBILITY", PrincipalBinding: recipient, Resource: obj, Version: versionID},
			{ID: "recipient-key", Role: "recipient-key", Action: "receive-key", Kind: "RECIPIENT_ELIGIBILITY", PrincipalBinding: recipient,
				Resource: decisionsvc.Alias{Type: "crypto.recipient", ID: recipient}},
		}}
	if op == "storage.object.read" {
		req.Checks = req.Checks[:1]
	}
	return c.st.Decisions.Decide(ctx, StorageAdapter, req), envelopeID, nil
}

// Share publishes a new envelope for to on the given version (the current
// one when version is ""), made from c's own envelope (KEY-012).
func (c *Client) Share(bucket, key, version string, to *Client, generation uint64) (string, error) {
	ctx := context.Background()
	pkg, err := c.st.Content.ReadPackage(ctx, c.Caller, bucket, key, version, c.Recipient.Fingerprint().String())
	if err != nil {
		return "", err
	}
	env, err := crypto.Reshare(crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
		Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
		c.Recipient, c.Trust, crypto.Recipient{Fingerprint: to.Recipient.Fingerprint(), KeyVersion: to.KeyVersion}, generation, c.Signer, *c.st.Clock)
	if err != nil {
		return "", err
	}
	ref, err := c.st.Envelopes.Publish(ctx, c.st.KeysCaller(c.Caller.Principal), bucket, key, pkg.Version.Version,
		content.EnvelopeIn{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature})
	return ref.ID, err
}
