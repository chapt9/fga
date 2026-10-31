package client

import (
	"bytes"
	"context"
	"net/http"
	"net/url"

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
	paragraphs, err := crypto.SplitText(text)
	if err != nil {
		return DocumentPublished{}, err
	}
	specs := make([]map[string]string, len(paragraphs))
	for i := range specs {
		specs[i] = map[string]string{}
	}
	var in struct {
		IntentID        string `json:"intent_id"`
		Tenant          string `json:"tenant_id"`
		Document        string `json:"document_id"`
		DocumentVersion string `json:"document_version_id"`
		Units           []struct {
			IntentID      string `json:"intent_id"`
			Unit          string `json:"unit_id"`
			UnitVersion   string `json:"unit_version_id"`
			CryptoVersion string `json:"crypto_version_id"`
			Blob          string `json:"blob_id"`
		} `json:"units"`
	}
	body, n := jsonBody(map[string]any{"key": key, "idempotency_key": cryptowire.NewUUID().String(), "units": specs})
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
	}{Manifest: sealed.Manifest, ManifestSignature: sealed.ManifestSignature}
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
