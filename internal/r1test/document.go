package r1test

import (
	"bytes"
	"context"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

// DocumentUpload is a begun document whose new units are encrypted and
// staged and whose manifest, descriptors and envelopes are sealed, but not
// finalized.
type DocumentUpload struct {
	Intent   content.DocumentIntent
	Units    []*crypto.SealedUnit
	Original *crypto.SealedOriginal
	Sealed   crypto.SealedDocument
}

// Request is the finalize request of a document upload.
func (u DocumentUpload) Request() content.DocumentFinalizeRequest {
	r := content.DocumentFinalizeRequest{Manifest: u.Sealed.Manifest, ManifestSignature: u.Sealed.ManifestSignature}
	for _, f := range u.Sealed.Units {
		uf := content.UnitFinal{Descriptor: f.Descriptor, DescriptorSignature: f.DescriptorSignature}
		for _, e := range f.Envelopes {
			uf.Envelopes = append(uf.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		}
		r.Units = append(r.Units, uf)
	}
	if o := u.Sealed.Original; o != nil {
		of := content.UnitFinal{Descriptor: o.Descriptor, DescriptorSignature: o.DescriptorSignature}
		for _, e := range o.Envelopes {
			of.Envelopes = append(of.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		}
		r.Original = &of
	}
	return r
}

// PrepareDocument begins a document version of bucket/key with one unit
// per paragraph (reused units are passed in reuse, keyed by position, with
// their spec in specs), encrypts and stages the new units, and seals the
// document for the recipients.
func (c *Client) PrepareDocument(bucket, key string, paragraphs []string, reuse map[int]*crypto.SealedUnit, to ...*Client) (DocumentUpload, error) {
	ctx := context.Background()
	specs := make([]content.DocumentUnitSpec, len(paragraphs))
	for i := range paragraphs {
		if u, ok := reuse[i]; ok {
			specs[i] = content.DocumentUnitSpec{ReuseUnit: u.Params.Unit.String(), ReuseVersion: u.Params.UnitVersion.String()}
		}
	}
	return c.PrepareDocumentSpecs(ctx, bucket, key, paragraphs, specs, reuse, to...)
}

// PrepareDocumentWithOriginal is PrepareDocument with an encrypted
// original file.
func (c *Client) PrepareDocumentWithOriginal(bucket, key string, paragraphs []string, original []byte, to ...*Client) (DocumentUpload, error) {
	return c.PrepareDocumentFull(context.Background(), bucket, key, paragraphs, make([]content.DocumentUnitSpec, len(paragraphs)), nil, original, to...)
}

// PrepareDocumentSpecs is PrepareDocument with explicit unit specs.
func (c *Client) PrepareDocumentSpecs(ctx context.Context, bucket, key string, paragraphs []string, specs []content.DocumentUnitSpec,
	reuse map[int]*crypto.SealedUnit, to ...*Client) (DocumentUpload, error) {
	return c.PrepareDocumentFull(ctx, bucket, key, paragraphs, specs, reuse, nil, to...)
}

// PrepareDocumentFull prepares a document with unit specs, reused units
// and an optional original file (nil for none).
func (c *Client) PrepareDocumentFull(ctx context.Context, bucket, key string, paragraphs []string, specs []content.DocumentUnitSpec,
	reuse map[int]*crypto.SealedUnit, original []byte, to ...*Client) (DocumentUpload, error) {
	in, err := c.st.Content.BeginDocument(ctx, c.Caller, content.DocumentBeginRequest{Bucket: bucket, Key: key,
		IdempotencyKey: cryptowire.NewUUID().String(), Units: specs, Original: original != nil})
	if err != nil {
		return DocumentUpload{}, err
	}
	up := DocumentUpload{Intent: in}
	tenant := must(cryptowire.ParseUUID(in.Tenant))
	for i, u := range in.Units {
		if u.Reused {
			up.Units = append(up.Units, reuse[i])
			continue
		}
		p := crypto.UnitParams{Unit: must(cryptowire.ParseUUID(u.Unit)), UnitVersion: must(cryptowire.ParseUUID(u.UnitVersion)),
			CryptoVersion: must(cryptowire.ParseUUID(u.CryptoVersion)), Blob: must(cryptowire.ParseUUID(u.Blob))}
		var ct bytes.Buffer
		sealed, err := crypto.EncryptUnit(&ct, bytes.NewReader([]byte(paragraphs[i])), tenant, p)
		if err != nil {
			return DocumentUpload{}, err
		}
		if _, err := c.st.Content.PutCiphertext(ctx, c.Caller, must(cryptowire.ParseUUID(u.IntentID)), int64(ct.Len()), sealed.CiphertextSHA256,
			bytes.NewReader(ct.Bytes())); err != nil {
			return DocumentUpload{}, err
		}
		up.Units = append(up.Units, sealed)
	}
	params := crypto.DocumentParams{Tenant: tenant, Document: must(cryptowire.ParseUUID(in.Document)),
		DocumentVersion: must(cryptowire.ParseUUID(in.DocumentVersion)), NormalizationVersion: crypto.NormalizationVersion}
	if o := in.Original; o != nil {
		p := crypto.OriginalParams{Object: must(cryptowire.ParseUUID(o.Unit)), Version: must(cryptowire.ParseUUID(o.UnitVersion)),
			CryptoVersion: must(cryptowire.ParseUUID(o.CryptoVersion)), Blob: must(cryptowire.ParseUUID(o.Blob)), Attempt: must(cryptowire.ParseUUID(o.Attempt))}
		var ct bytes.Buffer
		if up.Original, err = crypto.EncryptOriginal(&ct, bytes.NewReader(original), tenant, p); err != nil {
			return DocumentUpload{}, err
		}
		if _, err := c.st.Content.PutCiphertext(ctx, c.Caller, must(cryptowire.ParseUUID(o.IntentID)), int64(ct.Len()), up.Original.CiphertextSHA256,
			bytes.NewReader(ct.Bytes())); err != nil {
			return DocumentUpload{}, err
		}
		params.Original = up.Original
	}
	var recipients []crypto.Recipient
	for _, r := range to {
		recipients = append(recipients, crypto.Recipient{Fingerprint: r.Recipient.Fingerprint(), KeyVersion: r.KeyVersion})
	}
	up.Sealed, err = crypto.SealDocument(params, up.Units, recipients, c.Signer, c.Trust, *c.st.Clock)
	return up, err
}

// FinalizeDocument publishes a prepared document.
func (c *Client) FinalizeDocument(u DocumentUpload) (content.DocumentPublished, error) {
	return c.st.Content.FinalizeDocument(context.Background(), c.Caller, u.Intent.IntentID, u.Request())
}

func must(u cryptowire.UUID, err error) cryptowire.UUID {
	if err != nil {
		panic(err)
	}
	return u
}
