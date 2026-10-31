package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

// DocumentPublished is the result of a document publication.
type DocumentPublished struct {
	Document        string `json:"document_id"`
	DocumentVersion string `json:"document_version_id"`
	ManifestDigest  string `json:"manifest_digest"`
	Generation      uint64 `json:"generation"`
	Units           int    `json:"units"`
}

// PutDocument publishes text as a new version of the document at
// bucket/key (DOC-001 to DOC-004): it splits the text into paragraphs on
// the client (crypto.SplitText), encrypts each paragraph as a unit with its
// own key, stages every unit, and finalizes the signed manifest with each
// unit's descriptor and envelopes for the recipients (each pinned in
// Trust). The server never sees the text.
func (c *Client) PutDocument(ctx context.Context, bucket, key string, text []byte, recipients []crypto.Recipient) (DocumentPublished, error) {
	return c.PutDocumentWithOriginal(ctx, bucket, key, text, nil, recipients)
}

// PutDocumentWithOriginal is PutDocument that also publishes original, the
// file the text was extracted from, as a separately encrypted original
// (CNT-003). Every recipient then needs raw-read on the version. original
// nil publishes none.
func (c *Client) PutDocumentWithOriginal(ctx context.Context, bucket, key string, text []byte, original io.Reader, recipients []crypto.Recipient) (DocumentPublished, error) {
	paragraphs, err := crypto.SplitText(text)
	if err != nil {
		return DocumentPublished{}, err
	}
	specs := make([]map[string]string, len(paragraphs))
	for i := range specs {
		specs[i] = map[string]string{}
	}
	var in struct {
		IntentID        string           `json:"intent_id"`
		Tenant          string           `json:"tenant_id"`
		Document        string           `json:"document_id"`
		DocumentVersion string           `json:"document_version_id"`
		Units           []unitIntentJSON `json:"units"`
		Original        *unitIntentJSON  `json:"original"`
	}
	begin := map[string]any{"key": key, "idempotency_key": cryptowire.NewUUID().String(), "units": specs}
	if original != nil {
		begin["original"] = true
	}
	body, n := jsonBody(begin)
	if _, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/documents", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &in); err != nil {
		return DocumentPublished{}, err
	}
	if len(in.Units) != len(paragraphs) {
		return DocumentPublished{}, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
	}
	var p crypto.DocumentParams
	ids := []struct {
		dst *cryptowire.UUID
		s   string
	}{{&p.Tenant, in.Tenant}, {&p.Document, in.Document}, {&p.DocumentVersion, in.DocumentVersion}}
	for _, f := range ids {
		if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
			return DocumentPublished{}, err
		}
	}
	p.NormalizationVersion = crypto.NormalizationVersion
	var units []*crypto.SealedUnit
	defer func() {
		for _, u := range units {
			u.Close()
		}
	}()
	for i, u := range in.Units {
		var up crypto.UnitParams
		for _, f := range []struct {
			dst *cryptowire.UUID
			s   string
		}{{&up.Unit, u.Unit}, {&up.UnitVersion, u.UnitVersion}, {&up.CryptoVersion, u.CryptoVersion}, {&up.Blob, u.Blob}} {
			if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
				return DocumentPublished{}, err
			}
		}
		var ct bytes.Buffer
		sealed, err := crypto.EncryptUnit(&ct, bytes.NewReader([]byte(paragraphs[i])), p.Tenant, up)
		if err != nil {
			return DocumentPublished{}, err
		}
		units = append(units, sealed)
		if _, err := c.do(ctx, http.MethodPut, c.StorageURL+"/v1/uploads/"+url.PathEscape(u.IntentID)+"/ciphertext", c.StorageToken,
			bytes.NewReader(ct.Bytes()), int64(ct.Len()), map[string]string{"Content-Type": "application/octet-stream",
				"Fga-Ciphertext-Sha256": sealed.CiphertextSHA256.String()}, &map[string]any{}); err != nil {
			return DocumentPublished{}, err
		}
	}
	if o := in.Original; o != nil && original != nil {
		var op crypto.OriginalParams
		for _, f := range []struct {
			dst *cryptowire.UUID
			s   string
		}{{&op.Object, o.Unit}, {&op.Version, o.UnitVersion}, {&op.CryptoVersion, o.CryptoVersion}, {&op.Blob, o.Blob}, {&op.Attempt, o.Attempt}} {
			if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
				return DocumentPublished{}, err
			}
		}
		tmp, err := os.CreateTemp(c.TempDir, "fga-original-*")
		if err != nil {
			return DocumentPublished{}, err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		so, err := crypto.EncryptOriginal(tmp, original, p.Tenant, op)
		if err != nil {
			return DocumentPublished{}, err
		}
		defer so.Close()
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return DocumentPublished{}, err
		}
		if _, err := c.do(ctx, http.MethodPut, c.StorageURL+"/v1/uploads/"+url.PathEscape(o.IntentID)+"/ciphertext", c.StorageToken, tmp,
			int64(so.CiphertextLength), map[string]string{"Content-Type": "application/octet-stream",
				"Fga-Ciphertext-Sha256": so.CiphertextSHA256.String()}, &map[string]any{}); err != nil {
			return DocumentPublished{}, err
		}
		p.Original = so
	}
	sealed, err := crypto.SealDocument(p, units, recipients, c.Signer, c.Trust, c.now())
	if err != nil {
		return DocumentPublished{}, err
	}
	type unitFinal struct {
		Descriptor          []byte         `json:"descriptor"`
		DescriptorSignature string         `json:"descriptor_signature"`
		Envelopes           []envelopeJSON `json:"envelopes"`
	}
	fin := struct {
		Manifest          []byte      `json:"manifest"`
		ManifestSignature string      `json:"manifest_signature"`
		Units             []unitFinal `json:"units"`
		Original          *unitFinal  `json:"original,omitempty"`
	}{Manifest: sealed.Manifest, ManifestSignature: sealed.ManifestSignature}
	if o := sealed.Original; o != nil {
		f := unitFinal{Descriptor: o.Descriptor, DescriptorSignature: o.DescriptorSignature}
		for _, e := range o.Envelopes {
			f.Envelopes = append(f.Envelopes, envelopeJSON{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		}
		fin.Original = &f
	}
	for _, u := range sealed.Units {
		f := unitFinal{Descriptor: u.Descriptor, DescriptorSignature: u.DescriptorSignature}
		for _, e := range u.Envelopes {
			f.Envelopes = append(f.Envelopes, envelopeJSON{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
		}
		fin.Units = append(fin.Units, f)
	}
	var out DocumentPublished
	body, n = jsonBody(fin)
	_, err = c.do(ctx, http.MethodPost, c.StorageURL+"/v1/document-uploads/"+url.PathEscape(in.IntentID)+"/finalize", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

type unitIntentJSON struct {
	IntentID      string `json:"intent_id"`
	Unit          string `json:"unit_id"`
	UnitVersion   string `json:"unit_version_id"`
	CryptoVersion string `json:"crypto_version_id"`
	Blob          string `json:"blob_id"`
	Attempt       string `json:"attempt_id"`
}

// GetOriginal writes a document version's original file to dst after
// verifying it (crypto.DecryptOriginal). It needs raw-read on the version
// and read on every unit.
func (c *Client) GetOriginal(ctx context.Context, bucket, key, version string, dst io.Writer) error {
	var p packageJSON
	extra := url.Values{"recipient": {c.Recipient.Fingerprint().String()}}
	if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/original/package", key, version, extra), c.StorageToken, nil, -1, nil, &p); err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/original/ciphertext", key, version, nil), c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(c.TempDir, "fga-original-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, p.Version.CiphertextLength+1))
	if err != nil || n != p.Version.CiphertextLength {
		return fmt.Errorf("fga: incomplete original transfer: %v", err)
	}
	trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
	_, err = crypto.DecryptOriginal(dst, tmp, crypto.Package{Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
		Envelope: crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
		c.Recipient, trust)
	return err
}

// UnitEntry is a disclosed unit's identity and signed descriptor.
type UnitEntry struct {
	Unit                string `json:"unit_id"`
	UnitVersion         string `json:"unit_version_id"`
	CiphertextLength    int64  `json:"ciphertext_length"`
	Descriptor          []byte `json:"descriptor"`
	DescriptorSignature string `json:"descriptor_signature"`
}

func documentURL(base, bucket, path, key, version string, extra url.Values) string {
	q := url.Values{"key": {key}}
	if version != "" {
		q.Set("version", version)
	}
	for k, v := range extra {
		q[k] = v
	}
	return base + "/v1/buckets/" + url.PathEscape(bucket) + "/document" + path + "?" + q.Encode()
}

// Units lists the units of a document version the caller may read, in
// document order: an authorized subset without hidden IDs or counts.
func (c *Client) Units(ctx context.Context, bucket, key, version string) ([]UnitEntry, error) {
	var all []UnitEntry
	cont := ""
	for {
		extra := url.Values{"limit": {"100"}}
		if cont != "" {
			extra.Set("continuation", cont)
		}
		var page struct {
			Units        []UnitEntry `json:"units"`
			Continuation string      `json:"continuation"`
		}
		if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/units", key, version, extra), c.StorageToken, nil, -1, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Units...)
		if page.Continuation == "" {
			return all, nil
		}
		cont = page.Continuation
	}
}

// GetUnit fetches one unit's package and ciphertext and writes its
// verified plaintext to dst (crypto.DecryptUnit), withdrawing trust from a
// signer the keys role reports as compromised.
func (c *Client) GetUnit(ctx context.Context, bucket, key, version, unit string, dst io.Writer) error {
	var p struct {
		Unit     UnitEntry    `json:"unit"`
		Envelope envelopeJSON `json:"envelope"`
	}
	extra := url.Values{"unit": {unit}, "recipient": {c.Recipient.Fingerprint().String()}}
	if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/unit/package", key, version, extra), c.StorageToken, nil, -1, nil, &p); err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/unit/ciphertext", key, version, url.Values{"unit": {unit}}),
		c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var ct bytes.Buffer
	n, err := io.Copy(&ct, io.LimitReader(resp.Body, p.Unit.CiphertextLength+1))
	if err != nil || n != p.Unit.CiphertextLength {
		return fmt.Errorf("fga: incomplete unit transfer: %v", err)
	}
	trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
	_, err = crypto.DecryptUnit(dst, bytes.NewReader(ct.Bytes()), crypto.UnitPackage{Descriptor: p.Unit.Descriptor,
		DescriptorSignature: p.Unit.DescriptorSignature,
		Envelope:            crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
		c.Recipient, trust)
	return err
}

// GetDocument writes every unit of a document version the caller may
// read, in document order, separated by blank lines. Units it may not read
// are left out without a trace, so the result is complete only for a
// caller who may read every unit.
func (c *Client) GetDocument(ctx context.Context, bucket, key, version string, dst io.Writer) (int, error) {
	units, err := c.Units(ctx, bucket, key, version)
	if err != nil {
		return 0, err
	}
	for i, u := range units {
		var plain bytes.Buffer
		if err := c.GetUnit(ctx, bucket, key, version, u.Unit, &plain); err != nil {
			return i, err
		}
		if i > 0 {
			if _, err := io.WriteString(dst, "\n\n"); err != nil {
				return i, err
			}
		}
		if _, err := dst.Write(plain.Bytes()); err != nil {
			return i, err
		}
	}
	return len(units), nil
}
