// Package client is the Go client of the native storage API and the keys
// role (docs/design/native-api.md). It encrypts before upload and decrypts
// after download with sdk/go/crypto (specification 2.5, CRY-006, RCP-007:
// the native encrypted-package client required in R1-B). Plaintext and
// keys never leave the client.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"fga/internal/cryptowire"
	"fga/sdk/go/crypto"
)

// Error is a redacted API error.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s", e.Status, e.Code) }

// Client calls one deployment's storage and keys roles as one user.
type Client struct {
	StorageURL   string
	KeysURL      string
	HTTP         *http.Client
	StorageToken string
	KeysToken    string
	Recipient    *crypto.RecipientKey
	KeyVersion   uint64
	Signer       crypto.SigningKey
	Trust        crypto.TrustStore
	// TempDir holds ciphertext while it is uploaded or verified; files are
	// private (0600) and removed afterwards (CRY-006).
	TempDir string
	Now     func() time.Time
}

func (c *Client) do(ctx context.Context, method, url, token string, body io.Reader, length int64, header map[string]string, out any) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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
	return resp, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
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
	begin := map[string]string{"key": key, "idempotency_key": opts.IdempotencyKey}
	if opts.IfMatch != "" {
		begin["if_match"] = opts.IfMatch
	}
	if opts.IfNoneMatch {
		begin["if_none_match"] = "*"
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
	var out Published
	body, n = jsonBody(fin)
	_, err = c.do(ctx, http.MethodPost, c.StorageURL+"/v1/uploads/"+in.IntentID+"/finalize", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
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

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
