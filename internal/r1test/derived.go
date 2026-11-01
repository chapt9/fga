package r1test

import (
	"bytes"
	"context"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

// PutDerived publishes plaintext as a derived output at bucket/key with
// signed lineage naming sources, encrypted for c itself; label is an
// optional proposed label.
func (c *Client) PutDerived(bucket, key string, plaintext []byte, sources []cryptowire.LineageSource, label string) (content.Published, error) {
	in, err := c.BeginDerived(content.BeginRequest{Bucket: bucket, Key: key, IdempotencyKey: cryptowire.NewUUID().String(), Label: label})
	if err != nil {
		return content.Published{}, err
	}
	return c.FinishDerived(in, plaintext, sources)
}

// BeginDerived begins a derived output upload of r.
func (c *Client) BeginDerived(r content.BeginRequest) (content.Intent, error) {
	r.Derived = true
	return c.st.Content.Begin(context.Background(), c.Caller, r)
}

// FinishDerived stages plaintext encrypted for c itself under in and
// publishes it with signed lineage naming sources.
func (c *Client) FinishDerived(in content.Intent, plaintext []byte, sources []cryptowire.LineageSource) (content.Published, error) {
	ctx := context.Background()
	var ct bytes.Buffer
	sealed, err := crypto.Encrypt(&ct, bytes.NewReader(plaintext), crypto.Params{Tenant: in.Tenant, Object: in.Object,
		LogicalVersion: in.LogicalVersion, CryptoVersion: in.CryptoVersion, Blob: in.Blob, Attempt: in.Attempt},
		[]crypto.Recipient{{Fingerprint: c.Recipient.Fingerprint(), KeyVersion: c.KeyVersion}}, c.Signer, c.Trust, *c.st.Clock)
	if err != nil {
		return content.Published{}, err
	}
	if _, err := c.st.Content.PutCiphertext(ctx, c.Caller, in.IntentID, int64(ct.Len()), sealed.CiphertextSHA256, bytes.NewReader(ct.Bytes())); err != nil {
		return content.Published{}, err
	}
	l, err := cryptowire.Lineage{TenantID: in.Tenant.String(), ObjectID: in.Object.String(), VersionID: in.LogicalVersion.String(),
		Sources: sources, Signer: c.Signer.Fingerprint.String(), CreatedAt: *c.st.Clock}.Marshal()
	if err != nil {
		return content.Published{}, err
	}
	sig, err := c.Signer.Sign(cryptowire.TypeLineage, l)
	if err != nil {
		return content.Published{}, err
	}
	req := content.FinalizeRequest{Descriptor: sealed.Descriptor, DescriptorSignature: sealed.DescriptorSignature}
	for _, e := range sealed.Envelopes {
		req.Envelopes = append(req.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
	}
	return c.st.Content.FinalizeDerived(ctx, c.Caller, in.IntentID, req, l, sig)
}
