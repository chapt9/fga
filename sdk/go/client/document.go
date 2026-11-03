package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	return c.putDocument(ctx, bucket, key, nil, "", paragraphs, original, recipients, false)
}

// PutCollection creates a text collection at bucket/key (DOC-005) whose
// entries are the paragraphs of text.
func (c *Client) PutCollection(ctx context.Context, bucket, key string, text []byte, recipients []crypto.Recipient) (DocumentPublished, error) {
	paragraphs, err := crypto.SplitText(text)
	if err != nil {
		return DocumentPublished{}, err
	}
	return c.putDocument(ctx, bucket, key, nil, "", paragraphs, nil, recipients, true)
}

// AppendCollection appends the paragraphs of text to the text collection
// at bucket/key: a new version that keeps every current entry and adds
// the new ones. It needs the full manifest, which the server returns only
// to a caller who may read every entry, so no entry is dropped silently;
// each kept entry's key is recovered from the caller's own envelope and
// sealed again for the recipients.
func (c *Client) AppendCollection(ctx context.Context, bucket, key string, text []byte, recipients []crypto.Recipient) (DocumentPublished, error) {
	paragraphs, err := crypto.SplitText(text)
	if err != nil {
		return DocumentPublished{}, err
	}
	var m struct {
		Manifest          []byte `json:"manifest"`
		ManifestSignature string `json:"manifest_signature"`
	}
	if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/manifest", key, "", nil), c.StorageToken, nil, -1, nil, &m); err != nil {
		return DocumentPublished{}, err
	}
	trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
	if _, err := cryptowire.Verify(cryptowire.TypeManifest, m.ManifestSignature, m.Manifest, func(kid string) (ed25519.PublicKey, error) {
		fp, err := cryptowire.ParseDigest(kid)
		if err != nil {
			return nil, err
		}
		pub, ok := trust.Signer(fp)
		if !ok {
			return nil, crypto.ErrUntrusted
		}
		return pub, nil
	}); err != nil {
		return DocumentPublished{}, err
	}
	manifest, err := cryptowire.ParseManifest(m.Manifest)
	if err != nil {
		return DocumentPublished{}, err
	}
	var kept []*crypto.SealedUnit
	defer func() {
		for _, u := range kept {
			u.Close()
		}
	}()
	for _, e := range manifest.Units {
		var p struct {
			Unit     UnitEntry    `json:"unit"`
			Envelope envelopeJSON `json:"envelope"`
		}
		extra := url.Values{"unit": {e.UnitID}, "recipient": {c.Recipient.Fingerprint().String()}}
		if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/unit/package", key, manifest.DocumentVersionID, extra),
			c.StorageToken, nil, -1, nil, &p); err != nil {
			return DocumentPublished{}, err
		}
		u, err := crypto.UnitFromPackage(crypto.UnitPackage{Descriptor: p.Unit.Descriptor, DescriptorSignature: p.Unit.DescriptorSignature,
			Envelope: crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}}, c.Recipient, trust)
		if err != nil {
			return DocumentPublished{}, err
		}
		if u.Params.Unit.String() != e.UnitID || u.Params.UnitVersion.String() != e.UnitVersionID {
			u.Close()
			return DocumentPublished{}, ErrIdentity
		}
		kept = append(kept, u)
	}
	// The server refuses the append if another version committed since
	// this manifest, rather than dropping its entries.
	return c.putDocument(ctx, bucket, key, kept, manifest.DocumentVersionID, paragraphs, nil, recipients, true)
}

// putDocument publishes a document or collection version whose units are
// the kept units, reused as they are from the version base, followed by
// new units for the paragraphs.
func (c *Client) putDocument(ctx context.Context, bucket, key string, kept []*crypto.SealedUnit, base string, paragraphs []string,
	original io.Reader, recipients []crypto.Recipient, collection bool) (DocumentPublished, error) {
	var err error
	specs := make([]map[string]string, 0, len(kept)+len(paragraphs))
	for _, u := range kept {
		specs = append(specs, map[string]string{"reuse_unit": u.Params.Unit.String(), "reuse_version": u.Params.UnitVersion.String()})
	}
	for range paragraphs {
		specs = append(specs, map[string]string{})
	}
	var in documentIntentJSON
	begin := map[string]any{"key": key, "idempotency_key": cryptowire.NewUUID().String(), "units": specs}
	if original != nil {
		begin["original"] = true
	}
	if collection {
		begin["collection"] = true
	}
	if base != "" {
		begin["base_version"] = base
	}
	body, n := jsonBody(begin)
	if _, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/documents", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &in); err != nil {
		return DocumentPublished{}, err
	}
	if len(in.Units) != len(specs) {
		return DocumentPublished{}, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
	}
	p, err := in.params()
	if err != nil {
		return DocumentPublished{}, err
	}
	p.NormalizationVersion = crypto.NormalizationVersion
	var units, fresh []*crypto.SealedUnit
	defer func() {
		for _, u := range fresh {
			u.Close()
		}
	}()
	for i, u := range in.Units {
		if i < len(kept) {
			if !u.Reused || u.Unit != kept[i].Params.Unit.String() {
				return DocumentPublished{}, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
			}
			units = append(units, kept[i])
			continue
		}
		sealed, err := c.stageUnit(ctx, p.Tenant, u, []byte(paragraphs[i-len(kept)]))
		if err != nil {
			return DocumentPublished{}, err
		}
		units, fresh = append(units, sealed), append(fresh, sealed)
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
	return c.finalizeDocument(ctx, in.IntentID, sealed)
}

// documentIntentJSON is a document begin's answer.
type documentIntentJSON struct {
	IntentID        string           `json:"intent_id"`
	Tenant          string           `json:"tenant_id"`
	Document        string           `json:"document_id"`
	DocumentVersion string           `json:"document_version_id"`
	Units           []unitIntentJSON `json:"units"`
	Original        *unitIntentJSON  `json:"original"`
}

// params are the document version's identifiers for sealing.
func (in documentIntentJSON) params() (crypto.DocumentParams, error) {
	var p crypto.DocumentParams
	var err error
	for _, f := range []struct {
		dst *cryptowire.UUID
		s   string
	}{{&p.Tenant, in.Tenant}, {&p.Document, in.Document}, {&p.DocumentVersion, in.DocumentVersion}} {
		if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
			return p, err
		}
	}
	return p, nil
}

// stageUnit encrypts plaintext as the unit of intent u under a fresh key
// and stages its ciphertext.
func (c *Client) stageUnit(ctx context.Context, tenant cryptowire.UUID, u unitIntentJSON, plaintext []byte) (*crypto.SealedUnit, error) {
	var up crypto.UnitParams
	var err error
	for _, f := range []struct {
		dst *cryptowire.UUID
		s   string
	}{{&up.Unit, u.Unit}, {&up.UnitVersion, u.UnitVersion}, {&up.CryptoVersion, u.CryptoVersion}, {&up.Blob, u.Blob}} {
		if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
			return nil, err
		}
	}
	var ct bytes.Buffer
	sealed, err := crypto.EncryptUnit(&ct, bytes.NewReader(plaintext), tenant, up)
	if err != nil {
		return nil, err
	}
	if _, err := c.do(ctx, http.MethodPut, c.StorageURL+"/v1/uploads/"+url.PathEscape(u.IntentID)+"/ciphertext", c.StorageToken,
		bytes.NewReader(ct.Bytes()), int64(ct.Len()), map[string]string{"Content-Type": "application/octet-stream",
			"Fga-Ciphertext-Sha256": sealed.CiphertextSHA256.String()}, &map[string]any{}); err != nil {
		sealed.Close()
		return nil, err
	}
	return sealed, nil
}

// finalizeDocument publishes a sealed document version through its intent.
func (c *Client) finalizeDocument(ctx context.Context, intentID string, sealed crypto.SealedDocument) (DocumentPublished, error) {
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
	body, n := jsonBody(fin)
	_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/document-uploads/"+url.PathEscape(intentID)+"/finalize", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

type unitIntentJSON struct {
	Reused        bool   `json:"reused"`
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
	// The envelope names the document version the original belongs to; it
	// must be the requested one (review finding 8), and the ciphertext is
	// fetched from it, not from whatever is current by then (review v4
	// F13).
	ectx, err := cryptowire.ParseEnvelopeContext(p.Envelope.Context)
	if err != nil {
		return err
	}
	if ectx.DocumentVersion.IsZero() || version != "" && ectx.DocumentVersion.String() != version {
		return ErrIdentity
	}
	resp, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/original/ciphertext", key, ectx.DocumentVersion.String(), nil),
		c.StorageToken, nil, -1, nil, nil)
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
	if err := checkVersion(p.Descriptor, p.Version.Version, ""); err != nil {
		return ErrIdentity
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
	units, _, err := c.units(ctx, bucket, key, version)
	return units, err
}

// units is Units with the document version the server listed; every page
// after the first is listed from that version.
func (c *Client) units(ctx context.Context, bucket, key, version string) ([]UnitEntry, string, error) {
	var all []UnitEntry
	cont := ""
	for {
		extra := url.Values{"limit": {"100"}}
		if cont != "" {
			extra.Set("continuation", cont)
		}
		var page struct {
			Units           []UnitEntry `json:"units"`
			Continuation    string      `json:"continuation"`
			DocumentVersion string      `json:"document_version_id"`
		}
		if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/units", key, version, extra), c.StorageToken, nil, -1, nil, &page); err != nil {
			return nil, "", err
		}
		if version == "" {
			version = page.DocumentVersion
		}
		all = append(all, page.Units...)
		if page.Continuation == "" {
			return all, version, nil
		}
		cont = page.Continuation
	}
}

// PutDocumentText publishes text to a server-mode bucket as a document
// version, or as a text collection when collection is set (D-12, S4a): the
// storage role splits it into units under fga.text/nfc-paragraphs-v1 and
// encrypts each under its own data key. When the publication needs an
// approval, the ApprovalRequired error names the staged upload's Intent;
// finish it with FinalizeDocument(Intent) once it is given.
func (c *Client) PutDocumentText(ctx context.Context, bucket, key string, text []byte, collection bool) (DocumentPublished, error) {
	extra := url.Values{}
	if collection {
		extra.Set("collection", "1")
	}
	return c.putText(ctx, bucket, key, text, extra)
}

// PutDocumentTextWithOriginal is PutDocumentText with the original file the
// text was taken from, sent as multipart/form-data and streamed: the
// storage role encrypts it under its own data key, and discloses it only
// with complete-content permission (CNT-003).
func (c *Client) PutDocumentTextWithOriginal(ctx context.Context, bucket, key string, text []byte, original io.Reader) (DocumentPublished, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			tw, err := mw.CreateFormField("text")
			if err != nil {
				return err
			}
			if _, err := tw.Write(text); err != nil {
				return err
			}
			ow, err := mw.CreateFormFile("original", "original")
			if err != nil {
				return err
			}
			if _, err := io.Copy(ow, original); err != nil {
				return err
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	q := url.Values{"key": {key}}
	var out DocumentPublished
	_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/documents/text?"+q.Encode(), c.StorageToken, pr, -1,
		map[string]string{"Content-Type": mw.FormDataContentType(), "Idempotency-Key": cryptowire.NewUUID().String()}, &out)
	pr.CloseWithError(err)
	return out, err
}

// GetOriginalPlain writes a server-mode document version's original file
// to dst; it needs raw-read on the version and read on every unit.
func (c *Client) GetOriginalPlain(ctx context.Context, bucket, key, version string, dst io.Writer) error {
	_, err := c.plain(ctx, documentURL(c.StorageURL, bucket, "/original/content", key, version, nil), dst)
	return err
}

// UnitText is one exported server-mode unit.
type UnitText struct {
	Unit        string `json:"unit_id"`
	UnitVersion string `json:"unit_version_id"`
	Text        string `json:"text"`
}

// ExportUnitsPlain exports the plaintext of selected units of a
// server-mode document version; it needs export and read-units on the
// version and read and export-key on every unit, or nothing is exported.
func (c *Client) ExportUnitsPlain(ctx context.Context, bucket, key, version string, units []string) ([]UnitText, error) {
	var out struct {
		Units []UnitText `json:"units"`
	}
	body, n := jsonBody(map[string][]string{"units": units})
	_, err := c.doLimit(ctx, http.MethodPost, documentURL(c.StorageURL, bucket, "/export/content", key, version, nil), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out, maxExportResponse)
	return out.Units, err
}

// AppendText appends the paragraphs of text to the server-mode text
// collection at bucket/key: a new version that keeps every entry, with no
// client keys. The server refuses it unless the caller may read every
// entry, so none is dropped silently.
func (c *Client) AppendText(ctx context.Context, bucket, key string, text []byte) (DocumentPublished, error) {
	return c.putText(ctx, bucket, key, text, url.Values{"append": {"1"}})
}

func (c *Client) putText(ctx context.Context, bucket, key string, text []byte, extra url.Values) (DocumentPublished, error) {
	var out DocumentPublished
	extra.Set("key", key)
	target := c.StorageURL + "/v1/buckets/" + url.PathEscape(bucket) + "/documents/text?" + extra.Encode()
	_, err := c.do(ctx, http.MethodPost, target, c.StorageToken, bytes.NewReader(text),
		int64(len(text)), map[string]string{"Content-Type": "text/plain; charset=utf-8", "Idempotency-Key": cryptowire.NewUUID().String()}, &out)
	return out, err
}

// FinalizeDocument publishes a staged server-mode document version, such as
// one whose publication waited for an approval.
func (c *Client) FinalizeDocument(ctx context.Context, intent string) (DocumentPublished, error) {
	var out DocumentPublished
	_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/document-uploads/"+url.PathEscape(intent)+"/finalize", c.StorageToken,
		strings.NewReader("{}"), 2, map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// GetUnitPlain writes one server-mode unit's or entry's plaintext to dst.
func (c *Client) GetUnitPlain(ctx context.Context, bucket, key, version, unit string, dst io.Writer) error {
	_, err := c.plain(ctx, documentURL(c.StorageURL, bucket, "/unit/content", key, version, url.Values{"unit": {unit}}), dst)
	return err
}

// GetUnit fetches one unit's package and ciphertext and writes its
// verified plaintext to dst (crypto.DecryptUnit), withdrawing trust from a
// signer the keys role reports as compromised.
func (c *Client) GetUnit(ctx context.Context, bucket, key, version, unit string, dst io.Writer) error {
	_, err := c.getUnit(ctx, bucket, key, version, unit, dst)
	return err
}

// getUnit is GetUnit; it returns the unit's signed document version. The
// signed unit and unit version, and the document version when one was
// requested, must be what was asked for (review finding 8).
func (c *Client) getUnit(ctx context.Context, bucket, key, version, unit string, dst io.Writer) (string, error) {
	var p struct {
		Unit     UnitEntry    `json:"unit"`
		Envelope envelopeJSON `json:"envelope"`
	}
	extra := url.Values{"unit": {unit}, "recipient": {c.Recipient.Fingerprint().String()}}
	if _, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/unit/package", key, version, extra), c.StorageToken, nil, -1, nil, &p); err != nil {
		return "", err
	}
	d, err := cryptowire.ParseUnitDescriptor(p.Unit.Descriptor)
	if err != nil {
		return "", err
	}
	if d.UnitID != unit || d.UnitVersionID != p.Unit.UnitVersion || version != "" && d.DocumentVersionID != version {
		return "", ErrIdentity
	}
	resp, err := c.do(ctx, http.MethodGet, documentURL(c.StorageURL, bucket, "/unit/ciphertext", key, d.DocumentVersionID, url.Values{"unit": {unit}}),
		c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var ct bytes.Buffer
	n, err := io.Copy(&ct, io.LimitReader(resp.Body, p.Unit.CiphertextLength+1))
	if err != nil || n != p.Unit.CiphertextLength {
		return "", fmt.Errorf("fga: incomplete unit transfer: %v", err)
	}
	trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
	_, err = crypto.DecryptUnit(dst, bytes.NewReader(ct.Bytes()), crypto.UnitPackage{Descriptor: p.Unit.Descriptor,
		DescriptorSignature: p.Unit.DescriptorSignature,
		Envelope:            crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
		c.Recipient, trust)
	return d.DocumentVersionID, err
}

// GetDocument writes every unit of a document version the caller may
// read, in document order, separated by blank lines. Units it may not read
// are left out without a trace, so the result is complete only for a
// caller who may read every unit.
func (c *Client) GetDocument(ctx context.Context, bucket, key, version string, dst io.Writer) (int, error) {
	units, listed, err := c.units(ctx, bucket, key, version)
	if err != nil {
		return 0, err
	}
	// Every unit is read from the version listed, never from whatever is
	// current by the time it is fetched (review v4 F13): a client-mode
	// unit's signed descriptor must name that version. A server-mode unit
	// has no client descriptor and is read as plaintext; its content is the
	// server's word, as in all of server mode (N-09).
	for i, u := range units {
		var plain bytes.Buffer
		if len(u.Descriptor) == 0 {
			if err := c.GetUnitPlain(ctx, bucket, key, listed, u.Unit, &plain); err != nil {
				return i, err
			}
		} else if _, err := c.getUnit(ctx, bucket, key, listed, u.Unit, &plain); err != nil {
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

// GetDerived downloads, verifies and decrypts a derived output's version
// (the current one when version is "") for the client's own key. The
// server delivers it only if the client may read every source of its
// lineage or it was declassified to the client (DRV-002).
func (c *Client) GetDerived(ctx context.Context, bucket, key, version string, dst io.Writer) (VersionInfo, error) {
	fp := c.Recipient.Fingerprint().String()
	derivedURL := func(path, version string) string {
		q := url.Values{"key": {key}, "recipient": {fp}}
		if version != "" {
			q.Set("version", version)
		}
		return c.StorageURL + "/v1/buckets/" + url.PathEscape(bucket) + "/derived" + path + "?" + q.Encode()
	}
	var p packageJSON
	if _, err := c.do(ctx, http.MethodGet, derivedURL("/package", version), c.StorageToken, nil, -1, nil, &p); err != nil {
		return VersionInfo{}, err
	}
	if err := checkVersion(p.Descriptor, p.Version.Version, version); err != nil {
		return VersionInfo{}, err
	}
	resp, err := c.do(ctx, http.MethodGet, derivedURL("/ciphertext", p.Version.Version), c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return VersionInfo{}, err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(c.TempDir, "fga-derived-*")
	if err != nil {
		return VersionInfo{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, p.Version.CiphertextLength+1))
	if err != nil || n != p.Version.CiphertextLength {
		return VersionInfo{}, fmt.Errorf("fga: incomplete ciphertext transfer: %v", err)
	}
	trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
	err = crypto.Decrypt(dst, tmp, crypto.Package{Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
		Envelope: crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
		c.Recipient, trust)
	return p.Version, err
}

// SearchResult is one discoverable document.
type SearchResult struct {
	Key             string    `json:"key"`
	Document        string    `json:"document_id"`
	DocumentVersion string    `json:"document_version_id"`
	CreatedAt       time.Time `json:"created_at"`
}

// SearchDocuments lists the documents of a bucket the caller may discover
// that match catalog metadata only (key prefix, project, highest label);
// the server searches no plaintext (SRH-001).
func (c *Client) SearchDocuments(ctx context.Context, bucket, prefix, project, maxLabel string) ([]SearchResult, error) {
	var all []SearchResult
	cont := ""
	for {
		q := url.Values{"prefix": {prefix}, "project": {project}, "max_label": {maxLabel}, "limit": {"100"}}
		if cont != "" {
			q.Set("continuation", cont)
		}
		var page struct {
			Results      []SearchResult `json:"results"`
			Continuation string         `json:"continuation"`
		}
		if _, err := c.do(ctx, http.MethodGet, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/documents/search?"+q.Encode(),
			c.StorageToken, nil, -1, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Results...)
		if page.Continuation == "" {
			return all, nil
		}
		cont = page.Continuation
	}
}

// ExportedUnit is one unit of an export package for a target recipient.
type ExportedUnit struct {
	Unit             UnitEntry    `json:"unit"`
	Ciphertext       []byte       `json:"ciphertext"`
	EnvelopeID       string       `json:"envelope_id"`
	Envelope         envelopeJSON `json:"envelope"`
	Receipt          []byte       `json:"receipt"`
	ReceiptSignature string       `json:"receipt_signature"`
}

// Export fetches an encrypted export package of the named units for the
// target recipient key: ciphertext and the target's existing envelopes,
// which only the target can open (crypto.DecryptUnit).
func (c *Client) Export(ctx context.Context, bucket, key, version string, units []string, recipient cryptowire.Digest) ([]ExportedUnit, error) {
	var out struct {
		Units []ExportedUnit `json:"units"`
	}
	body, n := jsonBody(map[string]any{"unit_ids": units, "recipient": recipient.String()})
	_, err := c.doLimit(ctx, http.MethodPost, documentURL(c.StorageURL, bucket, "/export", key, version, nil), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out, maxExportResponse)
	return out.Units, err
}

// DeleteDocument deletes a document key (version "") or withdraws one
// document version, with the units no live version references any more.
func (c *Client) DeleteDocument(ctx context.Context, bucket, key, version string) error {
	_, err := c.do(ctx, http.MethodDelete, documentURL(c.StorageURL, bucket, "", key, version, nil), c.StorageToken, nil, -1, nil, &map[string]any{})
	return err
}

// ExportedObject is an export package of one object version for a target
// recipient: descriptor, exact ciphertext and the target's envelope.
type ExportedObject struct {
	packageJSON
	Ciphertext []byte `json:"ciphertext"`
}

// ExportObject fetches an encrypted export package of an object version
// (the current one when version is "") for the target recipient key, which
// must already have an envelope; only the target can open it.
func (c *Client) ExportObject(ctx context.Context, bucket, key, version string, recipient cryptowire.Digest) (ExportedObject, error) {
	var out ExportedObject
	body, n := jsonBody(map[string]string{"recipient": recipient.String()})
	_, err := c.doLimit(ctx, http.MethodPost, objectURL(c.StorageURL, bucket, "/export", key, version, nil), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out, maxExportResponse)
	if err == nil {
		err = checkVersion(out.Descriptor, out.Version.Version, version)
	}
	return out, err
}
