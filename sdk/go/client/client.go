// Package client is the Go client of the native storage API and the keys
// role (docs/design/native-api.md). It encrypts before upload and decrypts
// after download with sdk/go/crypto (specification 2.5, CRY-006, RCP-007:
// the native encrypted-package client required in R1-B). Plaintext and
// keys never leave the client.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"fga/internal/cryptowire"
	"fga/internal/opplan"
	"fga/sdk/go/crypto"
)

// Error is a redacted API error.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s", e.Status, e.Code) }

// ErrIdentity means the endpoint returned a correctly signed package of
// something other than what was requested (review finding 8). No
// plaintext is released.
var ErrIdentity = errors.New("fga: the package is not the requested version")

// checkVersion compares a package's signed descriptor with the version the
// package claims and the version that was requested ("" for the current
// one). The descriptor's signature is verified on the same bytes before
// any plaintext is released.
func checkVersion(descriptor []byte, claimed, requested string) error {
	d, err := cryptowire.ParseDescriptor(descriptor)
	if err != nil {
		return err
	}
	if d.LogicalVersionID != claimed || requested != "" && d.LogicalVersionID != requested {
		return ErrIdentity
	}
	return nil
}

// ApprovalRequired is returned when the storage role answers 202: the
// operation needs an approval. Repeat it with Client.Approval set to ID
// once an approver has approved it. For a put, the upload is kept and only
// the finalize step is repeated: pass Intent and Finalize to
// FinalizeUpload.
type ApprovalRequired struct {
	ID       string
	Intent   string
	Finalize []byte
}

func (e *ApprovalRequired) Error() string { return "approval required: " + e.ID }

// Client calls one deployment's storage and keys roles as one user.
type Client struct {
	StorageURL   string
	KeysURL      string
	HTTP         *http.Client
	StorageToken string
	KeysToken    string
	// Approval is presented with every request when set (the Fga-Approval
	// header); operations that need one use it.
	Approval   string
	Recipient  *crypto.RecipientKey
	KeyVersion uint64
	Signer     crypto.SigningKey
	Trust      crypto.TrustStore
	// TempDir holds ciphertext while it is uploaded or verified; files are
	// private (0600) and removed afterwards (CRY-006).
	TempDir string
	Now     func() time.Time
}

func (c *Client) do(ctx context.Context, method, url, token string, body io.Reader, length int64, header map[string]string, out any) (*http.Response, error) {
	return c.doLimit(ctx, method, url, token, body, length, header, out, maxResponse)
}

// maxResponse bounds a JSON response; maxExportResponse an export's, whose
// content of up to cryptowire.MaxExportBytes travels base64 encoded (4/3
// of it) or as JSON text, with descriptors and envelopes besides (review
// v4 F12).
const (
	maxResponse       = 16 << 20
	maxExportResponse = 2*cryptowire.MaxExportBytes + 8<<20
)

// doLimit is do with a bound on the JSON response it decodes.
func (c *Client) doLimit(ctx context.Context, method, url, token string, body io.Reader, length int64, header map[string]string, out any,
	limit int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if c.Approval != "" {
		req.Header.Set("Fga-Approval", c.Approval)
	}
	if length >= 0 && body != nil {
		req.ContentLength = length
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusAccepted {
		defer resp.Body.Close()
		var a struct {
			ApprovalID string `json:"approval_id"`
			IntentID   string `json:"intent_id"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&a)
		return nil, &ApprovalRequired{ID: a.ApprovalID, Intent: a.IntentID}
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return nil, &Error{Status: resp.StatusCode, Code: e.Error}
	}
	if out == nil {
		return resp, nil
	}
	defer resp.Body.Close()
	return resp, json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out)
}

func jsonBody(v any) (io.Reader, int64) {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b), int64(len(b))
}

func objectURL(base, bucket, path, key, version string, extra url.Values) string {
	q := url.Values{"key": {key}}
	if version != "" {
		q.Set("version", version)
	}
	for k, v := range extra {
		q[k] = v
	}
	return base + "/v1/buckets/" + url.PathEscape(bucket) + "/object" + path + "?" + q.Encode()
}

// Published is the result of a put.
type Published struct {
	Object     string `json:"object_id"`
	Version    string `json:"version_id"`
	ETag       string `json:"etag"`
	Generation uint64 `json:"generation"`
}

// PutOptions are a put's preconditions and idempotency key.
type PutOptions struct {
	IfMatch        string
	IfNoneMatch    bool
	IdempotencyKey string
	// Label is an explicit label for a new key; empty takes the bucket's
	// default. For a derived output it is a proposal that can only raise
	// the label its lineage gives.
	Label string
	// Lineage, when set, publishes a derived output (DRV-001): the exact
	// sources the content was derived from. In client mode it is signed
	// with the client's key and the output is encrypted only for the
	// client itself; in server mode (PutPlain) it is declared in the
	// request and policy decides who reads.
	Lineage []cryptowire.LineageSource
}

type envelopeJSON struct {
	Context    []byte `json:"context"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// Put encrypts src for the recipients (each must be pinned in Trust) and
// publishes it as a new version of bucket/key.
func (c *Client) Put(ctx context.Context, bucket, key string, src io.Reader, recipients []crypto.Recipient, opts PutOptions) (Published, error) {
	if opts.IdempotencyKey == "" {
		opts.IdempotencyKey = cryptowire.NewUUID().String()
	}
	begin := map[string]any{"key": key, "idempotency_key": opts.IdempotencyKey}
	if opts.IfMatch != "" {
		begin["if_match"] = opts.IfMatch
	}
	if opts.IfNoneMatch {
		begin["if_none_match"] = "*"
	}
	if opts.Label != "" {
		begin["label"] = opts.Label
	}
	if opts.Lineage != nil {
		begin["derived"] = true
	}
	var in struct {
		IntentID, TenantID, ObjectID, LogicalVersionID, CryptoVersionID, BlobID, AttemptID string
		MaxCiphertextLength                                                                int64
	}
	var raw map[string]any
	body, n := jsonBody(begin)
	if _, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/uploads", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &raw); err != nil {
		return Published{}, err
	}
	get := func(k string) string { s, _ := raw[k].(string); return s }
	in.IntentID, in.TenantID, in.ObjectID = get("intent_id"), get("tenant_id"), get("object_id")
	in.LogicalVersionID, in.CryptoVersionID, in.BlobID, in.AttemptID = get("logical_version_id"), get("crypto_version_id"), get("blob_id"), get("attempt_id")
	var p crypto.Params
	var err error
	for _, f := range []struct {
		dst *cryptowire.UUID
		s   string
	}{{&p.Tenant, in.TenantID}, {&p.Object, in.ObjectID}, {&p.LogicalVersion, in.LogicalVersionID}, {&p.CryptoVersion, in.CryptoVersionID},
		{&p.Blob, in.BlobID}, {&p.Attempt, in.AttemptID}} {
		if *f.dst, err = cryptowire.ParseUUID(f.s); err != nil {
			return Published{}, fmt.Errorf("fga: begin response: %w", err)
		}
	}
	tmp, err := os.CreateTemp(c.TempDir, "fga-upload-*")
	if err != nil {
		return Published{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	sealed, err := crypto.Encrypt(tmp, src, p, recipients, c.Signer, c.Trust, c.now())
	if err != nil {
		return Published{}, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Published{}, err
	}
	if _, err := c.do(ctx, http.MethodPut, c.StorageURL+"/v1/uploads/"+in.IntentID+"/ciphertext", c.StorageToken, tmp,
		int64(sealed.CiphertextLength), map[string]string{"Content-Type": "application/octet-stream",
			"Fga-Ciphertext-Sha256": sealed.CiphertextSHA256.String()}, &map[string]any{}); err != nil {
		return Published{}, err
	}
	fin := map[string]any{"descriptor": sealed.Descriptor, "descriptor_signature": sealed.DescriptorSignature}
	var envs []envelopeJSON
	for _, e := range sealed.Envelopes {
		envs = append(envs, envelopeJSON{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
	}
	fin["envelopes"] = envs
	if opts.Lineage != nil {
		l, err := cryptowire.Lineage{TenantID: p.Tenant.String(), ObjectID: p.Object.String(), VersionID: p.LogicalVersion.String(),
			Sources: opts.Lineage, Signer: c.Signer.Fingerprint.String(), CreatedAt: c.now()}.Marshal()
		if err != nil {
			return Published{}, err
		}
		sig, err := c.Signer.Sign(cryptowire.TypeLineage, l)
		if err != nil {
			return Published{}, err
		}
		fin["lineage"], fin["lineage_signature"] = l, sig
	}
	request, _ := json.Marshal(fin)
	out, err := c.FinalizeUpload(ctx, in.IntentID, request)
	var need *ApprovalRequired
	if errors.As(err, &need) {
		need.Intent, need.Finalize = in.IntentID, request
	}
	return out, err
}

// FinalizeUpload sends a finalize request for a staged upload, such as one
// an ApprovalRequired error kept.
//
// A server-mode upload has no finalize request; pass nil.
func (c *Client) FinalizeUpload(ctx context.Context, intent string, request []byte) (Published, error) {
	if request == nil {
		request = []byte("{}")
	}
	var out Published
	_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/uploads/"+url.PathEscape(intent)+"/finalize", c.StorageToken,
		bytes.NewReader(request), int64(len(request)), map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// VersionInfo is a version's permitted metadata.
type VersionInfo struct {
	Version          string    `json:"version_id"`
	ETag             string    `json:"etag"`
	Current          bool      `json:"current"`
	CiphertextLength int64     `json:"ciphertext_length"`
	CiphertextSHA256 string    `json:"ciphertext_sha256"`
	Suite            uint16    `json:"suite"`
	Format           uint16    `json:"format"`
	CreatedAt        time.Time `json:"created_at"`
	// Encryption is the version's mode; a server-mode version has its
	// plaintext Length.
	Encryption string `json:"encryption"`
	Length     int64  `json:"length,omitempty"`
}

// BucketEncryption returns a bucket's encryption mode, "server" or
// "client" (ENC-001); it needs list on the bucket.
func (c *Client) BucketEncryption(ctx context.Context, bucket string) (string, error) {
	var out struct {
		Encryption string `json:"encryption"`
	}
	_, err := c.do(ctx, http.MethodGet, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/encryption", c.StorageToken, nil, -1, nil, &out)
	return out.Encryption, err
}

// PutPlain uploads length bytes of plaintext from src to a server-mode
// bucket (D-12, SSE-005): the storage role encrypts it under a data key
// the keys role seals for the upload; no recipient key is involved. With
// opts.Lineage it publishes a derived output, streamed with no length
// known in advance (length is then ignored). When the publication needs an
// approval, the ApprovalRequired error names the staged upload's Intent
// and its Finalize request; repeat with FinalizeUpload(Intent, Finalize)
// once it is given.
func (c *Client) PutPlain(ctx context.Context, bucket, key string, src io.Reader, length int64, opts PutOptions) (Published, error) {
	if opts.Lineage != nil {
		return c.putDerivedPlain(ctx, bucket, key, src, opts)
	}
	h := map[string]string{"Content-Type": "application/octet-stream", "Idempotency-Key": opts.IdempotencyKey}
	if h["Idempotency-Key"] == "" {
		h["Idempotency-Key"] = cryptowire.NewUUID().String()
	}
	if opts.IfMatch != "" {
		h["If-Match"] = opts.IfMatch
	}
	if opts.IfNoneMatch {
		h["If-None-Match"] = "*"
	}
	if opts.Label != "" {
		h["Fga-Label"] = opts.Label
	}
	var out Published
	_, err := c.do(ctx, http.MethodPut, objectURL(c.StorageURL, bucket, "", key, "", nil), c.StorageToken, src, length, h, &out)
	return out, err
}

// putDerivedPlain sends a server-mode derived output as multipart/form-data:
// its lineage, then its content, streamed.
func (c *Client) putDerivedPlain(ctx context.Context, bucket, key string, src io.Reader, opts PutOptions) (Published, error) {
	lineage, err := json.Marshal(map[string][]cryptowire.LineageSource{"sources": opts.Lineage})
	if err != nil {
		return Published{}, err
	}
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			lw, err := mw.CreateFormField("lineage")
			if err != nil {
				return err
			}
			if _, err := lw.Write(lineage); err != nil {
				return err
			}
			cw, err := mw.CreateFormFile("content", "content")
			if err != nil {
				return err
			}
			if _, err := io.Copy(cw, src); err != nil {
				return err
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	h := map[string]string{"Content-Type": mw.FormDataContentType(), "Idempotency-Key": opts.IdempotencyKey}
	if h["Idempotency-Key"] == "" {
		h["Idempotency-Key"] = cryptowire.NewUUID().String()
	}
	if opts.IfMatch != "" {
		h["If-Match"] = opts.IfMatch
	}
	if opts.IfNoneMatch {
		h["If-None-Match"] = "*"
	}
	if opts.Label != "" {
		h["Fga-Label"] = opts.Label
	}
	q := url.Values{"key": {key}}
	var out Published
	_, err = c.do(ctx, http.MethodPost, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/derived/content?"+q.Encode(), c.StorageToken, pr, -1,
		h, &out)
	pr.CloseWithError(err)
	var need *ApprovalRequired
	if errors.As(err, &need) {
		need.Finalize, _ = json.Marshal(map[string][]cryptowire.LineageSource{"sources": opts.Lineage})
	}
	return out, err
}

// GetDerivedPlain writes a server-mode derived version's plaintext (the
// current one when version is "") to dst. The server delivers it only if
// the caller may read every source of its lineage or it was declassified
// to the caller (DRV-002).
func (c *Client) GetDerivedPlain(ctx context.Context, bucket, key, version string, dst io.Writer) (string, error) {
	q := url.Values{"key": {key}}
	if version != "" {
		q.Set("version", version)
	}
	return c.plain(ctx, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/derived/content?"+q.Encode(), dst)
}

// GetPlain writes a server-mode version's plaintext (the current one when
// version is "") to dst. A stream the server aborts, or one shorter than
// the length announced, is an error; what dst received must then be
// discarded.
func (c *Client) GetPlain(ctx context.Context, bucket, key, version string, dst io.Writer) (string, error) {
	return c.plain(ctx, objectURL(c.StorageURL, bucket, "/content", key, version, nil), dst)
}

// ExportPlain is GetPlain under the export permission.
func (c *Client) ExportPlain(ctx context.Context, bucket, key, version string, dst io.Writer) (string, error) {
	return c.plain(ctx, objectURL(c.StorageURL, bucket, "/export", key, version, nil), dst)
}

func (c *Client) plain(ctx context.Context, target string, dst io.Writer) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, target, c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	n, err := io.Copy(dst, resp.Body)
	if err != nil || resp.ContentLength < 0 || n != resp.ContentLength {
		return "", fmt.Errorf("fga: incomplete transfer: %v", err)
	}
	return resp.Header.Get("Fga-Version-Id"), nil
}

// Stat returns a version's metadata.
func (c *Client) Stat(ctx context.Context, bucket, key, version string) (VersionInfo, error) {
	var v VersionInfo
	_, err := c.do(ctx, http.MethodGet, objectURL(c.StorageURL, bucket, "", key, version, nil), c.StorageToken, nil, -1, nil, &v)
	return v, err
}

type packageJSON struct {
	Version             VersionInfo  `json:"version"`
	Descriptor          []byte       `json:"descriptor"`
	DescriptorSignature string       `json:"descriptor_signature"`
	EnvelopeID          string       `json:"envelope_id"`
	Envelope            envelopeJSON `json:"envelope"`
	Receipt             []byte       `json:"receipt"`
	ReceiptSignature    string       `json:"receipt_signature"`
}

func (c *Client) pkg(ctx context.Context, bucket, key, version string) (packageJSON, error) {
	var p packageJSON
	_, err := c.do(ctx, http.MethodGet, objectURL(c.StorageURL, bucket, "/package", key, version,
		url.Values{"recipient": {c.Recipient.Fingerprint().String()}}), c.StorageToken, nil, -1, nil, &p)
	return p, err
}

// Get downloads, verifies and decrypts a version (the current one when
// version is "") into dst. The complete ciphertext is stored in a private
// temporary file and checked against the signed descriptor before any
// plaintext is written (CRY-006), and a signer reported compromised is not
// trusted (RCP-011). On error, what dst received must be discarded.
func (c *Client) Get(ctx context.Context, bucket, key, version string, dst io.Writer) (VersionInfo, error) {
	p, err := c.pkg(ctx, bucket, key, version)
	if err != nil {
		return VersionInfo{}, err
	}
	if err := checkVersion(p.Descriptor, p.Version.Version, version); err != nil {
		return VersionInfo{}, err
	}
	resp, err := c.do(ctx, http.MethodGet, objectURL(c.StorageURL, bucket, "/ciphertext", key, p.Version.Version, nil), c.StorageToken, nil, -1, nil, nil)
	if err != nil {
		return VersionInfo{}, err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(c.TempDir, "fga-download-*")
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

// SignerStatus asks the keys role for a content signer's current status.
// The client uses it only to withdraw trust (RCP-011).
func (c *Client) SignerStatus(ctx context.Context, fp cryptowire.Digest) (string, error) {
	var rec struct {
		Status string `json:"status"`
	}
	_, err := c.do(ctx, http.MethodGet, c.KeysURL+"/v1/signing-keys/"+url.PathEscape(fp.String()), c.KeysToken, nil, -1, nil, &rec)
	return rec.Status, err
}

// Entry is one listed object.
type Entry struct {
	Key              string    `json:"key"`
	Version          string    `json:"version_id"`
	CiphertextLength int64     `json:"ciphertext_length"`
	CreatedAt        time.Time `json:"created_at"`
}

// List returns one page of visible objects.
func (c *Client) List(ctx context.Context, bucket, prefix string, limit int, continuation string) ([]Entry, string, error) {
	q := url.Values{"prefix": {prefix}, "limit": {strconv.Itoa(limit)}}
	if continuation != "" {
		q.Set("continuation", continuation)
	}
	var page struct {
		Entries      []Entry `json:"entries"`
		Continuation string  `json:"continuation"`
	}
	_, err := c.do(ctx, http.MethodGet, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/objects?"+q.Encode(), c.StorageToken, nil, -1, nil, &page)
	return page.Entries, page.Continuation, err
}

// LabelOutcome reports a label change.
type LabelOutcome struct {
	Object           string `json:"object_id"`
	Label            string `json:"label"`
	Previous         string `json:"previous_label"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

// Label sets a key's label. Lowering it may need an approval.
func (c *Client) Label(ctx context.Context, bucket, key, label string) (LabelOutcome, error) {
	return c.putLabel(ctx, objectURL(c.StorageURL, bucket, "/label", key, "", nil), label)
}

// LabelUnit sets the label of one unit of the document at bucket/key.
func (c *Client) LabelUnit(ctx context.Context, bucket, key, unit, label string) (LabelOutcome, error) {
	q := url.Values{"key": {key}, "unit": {unit}}
	return c.putLabel(ctx, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/document/unit/label?"+q.Encode(), label)
}

// LabelDerived sets the label of the derived output at bucket/key.
func (c *Client) LabelDerived(ctx context.Context, bucket, key, label string) (LabelOutcome, error) {
	q := url.Values{"key": {key}}
	return c.putLabel(ctx, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/derived/label?"+q.Encode(), label)
}

func (c *Client) putLabel(ctx context.Context, target, label string) (LabelOutcome, error) {
	var out LabelOutcome
	body, n := jsonBody(map[string]string{"label": label})
	_, err := c.do(ctx, http.MethodPut, target, c.StorageToken, body, n, map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// EncryptionOutcome reports a bucket's encryption mode change.
type EncryptionOutcome struct {
	Bucket           string `json:"bucket_id"`
	Encryption       string `json:"encryption"`
	Previous         string `json:"previous_encryption"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

// SetBucketEncryption changes a bucket's encryption mode, "server" or
// "client", for uploads begun afterwards (ENC-001). It needs manage on the
// bucket and may need an approval; existing versions keep their mode.
func (c *Client) SetBucketEncryption(ctx context.Context, bucket, mode string) (EncryptionOutcome, error) {
	var out EncryptionOutcome
	body, n := jsonBody(map[string]string{"encryption": mode})
	_, err := c.do(ctx, http.MethodPut, c.StorageURL+"/v1/buckets/"+url.PathEscape(bucket)+"/encryption", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// Proposal is an advisory label proposal; it never changes the label.
type Proposal struct {
	ID            string `json:"proposal_id"`
	Label         string `json:"label"`
	Classifier    string `json:"classifier"`
	Authoritative bool   `json:"authoritative"`
}

// ProposeLabel records a classifier's label proposal for a key.
func (c *Client) ProposeLabel(ctx context.Context, bucket, key, label, classifier string) (Proposal, error) {
	var out Proposal
	// The classifier's key is the client's signing key, which the
	// administrator registered for the classifier; it signs the proposal
	// for the object's current version.
	v, err := c.Stat(ctx, bucket, key, "")
	if err != nil {
		return out, err
	}
	sig, err := c.Signer.Sign(cryptowire.TypeLabelProposal, cryptowire.LabelProposalInput("storage.object", v.Version, label, classifier))
	if err != nil {
		return out, err
	}
	body, n := jsonBody(map[string]string{"label": label, "classifier": classifier, "signature": sig})
	_, err = c.do(ctx, http.MethodPost, objectURL(c.StorageURL, bucket, "/label-proposals", key, "", nil), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// Approval is a pending approval as an approver sees it: the plan the
// platform rendered.
type Approval struct {
	ID          string         `json:"approval_id"`
	Operation   string         `json:"operation"`
	Plan        opplan.Summary `json:"plan"`
	RequestedBy string         `json:"requested_by"`
	State       string         `json:"state"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

// Approvals lists pending approvals the caller may decide.
func (c *Client) Approvals(ctx context.Context, after string, limit int) ([]Approval, string, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var page struct {
		Approvals []Approval `json:"approvals"`
		Next      string     `json:"next"`
	}
	_, err := c.do(ctx, http.MethodGet, c.StorageURL+"/v1/approvals?"+q.Encode(), c.StorageToken, nil, -1, nil, &page)
	return page.Approvals, page.Next, err
}

// DecideApproval approves or rejects a pending approval.
func (c *Client) DecideApproval(ctx context.Context, id string, approve bool) (Approval, error) {
	decision := "reject"
	if approve {
		decision = "approve"
	}
	var out Approval
	body, n := jsonBody(map[string]string{"decision": decision})
	_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/approvals/"+url.PathEscape(id), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// Delete deletes a key (version "") or withdraws one version.
func (c *Client) Delete(ctx context.Context, bucket, key, version string) error {
	_, err := c.do(ctx, http.MethodDelete, objectURL(c.StorageURL, bucket, "", key, version, nil), c.StorageToken, nil, -1, nil, &map[string]any{})
	return err
}

// Share publishes an envelope of a version for target, made from the
// caller's own envelope (CreateRecipientEnvelope and
// PublishRecipientEnvelope). generation is the target's next envelope
// generation for the version, 1 for a first share.
func (c *Client) Share(ctx context.Context, bucket, key, version string, target crypto.Recipient, generation uint64) (string, error) {
	p, err := c.pkg(ctx, bucket, key, version)
	if err != nil {
		return "", err
	}
	if err := checkVersion(p.Descriptor, p.Version.Version, version); err != nil {
		return "", err
	}
	env, err := crypto.Reshare(crypto.Package{Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
		Envelope: crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
		c.Recipient, c.Trust, target, generation, c.Signer, c.now())
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"envelope_id"`
	}
	body, n := jsonBody(map[string]any{"bucket": bucket, "key": key, "version": p.Version.Version,
		"envelope": envelopeJSON{Context: env.Context, Ciphertext: env.Ciphertext, Signature: env.Signature}})
	_, err = c.do(ctx, http.MethodPost, c.KeysURL+"/v1/envelopes", c.KeysToken, body, n, map[string]string{"Content-Type": "application/json"}, &out)
	return out.ID, err
}

// Enroll enrolls and activates the client's recipient key with a
// possession proof (RCP-002) and returns its key version.
func (c *Client) Enroll(ctx context.Context, tenant, principal string) (uint64, error) {
	var ch struct {
		ID              string `json:"challenge_id"`
		Fingerprint     string `json:"fingerprint"`
		KeyVersion      uint64 `json:"key_version"`
		Nonce           []byte `json:"nonce"`
		EphemeralPublic []byte `json:"ephemeral_public_key"`
	}
	body, n := jsonBody(map[string]any{"public_key": c.Recipient.PublicKey()})
	if _, err := c.do(ctx, http.MethodPost, c.KeysURL+"/v1/recipients", c.KeysToken, body, n, map[string]string{"Content-Type": "application/json"}, &ch); err != nil {
		return 0, err
	}
	if ch.Fingerprint != c.Recipient.Fingerprint().String() {
		return 0, errors.New("fga: the keys role answered for another key")
	}
	proof, err := c.Recipient.Prove(ch.EphemeralPublic, ch.Nonce, ch.ID, tenant, principal)
	if err != nil {
		return 0, err
	}
	body, n = jsonBody(map[string]string{"challenge_id": ch.ID, "proof": base64.StdEncoding.EncodeToString(proof)})
	if _, err := c.do(ctx, http.MethodPost, c.KeysURL+"/v1/recipients/"+url.PathEscape(ch.Fingerprint)+"/activate", c.KeysToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &map[string]any{}); err != nil {
		return 0, err
	}
	return ch.KeyVersion, nil
}

// EnrollSigner enrolls and activates the client's content-signing key
// with a possession proof (RCP-002), so that it may sign publications.
func (c *Client) EnrollSigner(ctx context.Context, tenant, principal string) error {
	var ch struct {
		ID          string `json:"challenge_id"`
		Fingerprint string `json:"fingerprint"`
		Nonce       []byte `json:"nonce"`
	}
	public := c.Signer.Private.Public().(ed25519.PublicKey)
	body, n := jsonBody(map[string]any{"public_key": []byte(public)})
	if _, err := c.do(ctx, http.MethodPost, c.KeysURL+"/v1/signing-keys", c.KeysToken, body, n, map[string]string{"Content-Type": "application/json"}, &ch); err != nil {
		return err
	}
	if ch.Fingerprint != c.Signer.Fingerprint.String() {
		return errors.New("fga: the keys role answered for another key")
	}
	proof, err := c.Signer.ProveSigningKey(ch.ID, tenant, principal, ch.Nonce)
	if err != nil {
		return err
	}
	body, n = jsonBody(map[string]string{"challenge_id": ch.ID, "proof": proof})
	_, err = c.do(ctx, http.MethodPost, c.KeysURL+"/v1/signing-keys/"+url.PathEscape(ch.Fingerprint)+"/activate", c.KeysToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &map[string]any{})
	return err
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
