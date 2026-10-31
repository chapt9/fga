package nativeapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fga/internal/admission"
	"fga/internal/cryptowire"
	"fga/internal/datakeysapi"
	"fga/internal/keysapi"
	"fga/internal/nativeapi"
	"fga/internal/r1test"
	"fga/internal/rpc"
	"fga/sdk/go/client"
	"fga/sdk/go/crypto"
)

type deployment struct {
	st      *r1test.Stack
	storage *httptest.Server
	keys    *httptest.Server
}

func deploy(t *testing.T) *deployment { return deployWith(t, admission.DefaultLimits) }

func deployWith(t *testing.T, limits admission.Limits) *deployment {
	t.Helper()
	st := r1test.New(t)
	workloadOf := func(r *http.Request) (string, error) { return r.Header.Get("X-Test-Workload"), nil }
	keys := httptest.NewServer(keysapi.Keys(st.Envelopes, st.Tokens, workloadOf, r1test.StorageAdapter, func() bool { return true },
		admission.New(admission.DefaultLimits), datakeysapi.Register(st.DataKeys, workloadOf, r1test.StorageAdapter)))
	t.Cleanup(keys.Close)
	// The storage role reaches the keys role over HTTP as its workload,
	// for envelopes and for server-mode data keys.
	keysClient := rpc.KeysClient{BaseURL: keys.URL, HTTP: &http.Client{Transport: workload{r1test.StorageAdapter}}}
	st.Keys, st.DataKeysVia = keysClient, keysClient
	storage := httptest.NewServer(nativeapi.Storage(st.Content, st.Tokens, func() bool { return true }, admission.New(limits)))
	t.Cleanup(storage.Close)
	return &deployment{st: st, storage: storage, keys: keys}
}

type workload struct{ name string }

func (w workload) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Workload", w.name)
	return http.DefaultTransport.RoundTrip(r)
}

func (d *deployment) client(t *testing.T, c *r1test.Client) *client.Client {
	t.Helper()
	return &client.Client{StorageURL: d.storage.URL, KeysURL: d.keys.URL, HTTP: http.DefaultClient,
		StorageToken: c.Caller.Token, KeysToken: d.st.KeysCaller(c.Caller.Principal).Token,
		Recipient: c.Recipient, KeyVersion: c.KeyVersion, Signer: c.Signer, Trust: c.Trust, TempDir: t.TempDir(), Now: func() time.Time { return *d.st.Clock }}
}

// TestNativeAPI runs the R1-B operations over HTTP with the SDK client
// (CNT-009): put, stat, get, list, share, delete, with MCP, models and
// tools absent.
func TestNativeAPI(t *testing.T) {
	d := deploy(t)
	ctx := context.Background()
	d.st.Bucket("reports", "p1")
	a := d.st.Client("alice", []string{"member"}, "p1")
	b := d.st.Client("bob", []string{"member"}, "p1")
	a.Pin(b)
	b.Pin(a)
	alice, bob := d.client(t, a), d.client(t, b)

	plaintext := bytes.Repeat([]byte("quarterly "), 300_000)
	pub, err := alice.Put(ctx, "reports", "q3/report.bin", bytes.NewReader(plaintext),
		[]crypto.Recipient{{Fingerprint: a.Recipient.Fingerprint(), KeyVersion: a.KeyVersion}}, client.PutOptions{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := alice.Stat(ctx, "reports", "q3/report.bin", "")
	if err != nil || info.Version != pub.Version || info.ETag != pub.ETag {
		t.Fatalf("stat = %+v, %v", info, err)
	}
	var out bytes.Buffer
	if _, err := alice.Get(ctx, "reports", "q3/report.bin", "", &out); err != nil || !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("get: %v (%d bytes)", err, out.Len())
	}
	entries, _, err := bob.List(ctx, "reports", "q3/", 10, "")
	if err != nil || len(entries) != 1 || entries[0].Key != "q3/report.bin" {
		t.Fatalf("list = %+v, %v", entries, err)
	}
	var apiErr *client.Error
	if _, err := bob.Get(ctx, "reports", "q3/report.bin", "", io.Discard); !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Code != "NOT_FOUND" {
		t.Fatalf("bob without an envelope: %v", err)
	}
	if _, err := alice.Share(ctx, "reports", "q3/report.bin", "", crypto.Recipient{Fingerprint: b.Recipient.Fingerprint(), KeyVersion: b.KeyVersion}, 1); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := bob.Get(ctx, "reports", "q3/report.bin", "", &out); err != nil || !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("bob after sharing: %v", err)
	}
	if err := alice.Delete(ctx, "reports", "q3/report.bin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Stat(ctx, "reports", "q3/report.bin", ""); !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("stat after delete: %v", err)
	}
	if _, err := alice.Put(ctx, "reports", "q3/report.bin", strings.NewReader("x"), nil, client.PutOptions{}); err == nil {
		t.Fatal("a put without recipients succeeded")
	}
}

// TestHTTPBoundaries covers ADP-001 and CNT-004: requests are
// authenticated, keys travel only as query parameters, range requests are
// refused, absent and denied look the same, and only the storage workload
// can call internal delivery.
func TestHTTPBoundaries(t *testing.T) {
	d := deploy(t)
	d.st.Bucket("reports", "p1")
	a := d.st.Client("alice", []string{"member"}, "p1")
	if _, err := a.Put("reports", "doc", []byte("x")); err != nil {
		t.Fatal(err)
	}
	carol := d.st.Client("carol", []string{"member"}, "p2")
	get := func(url, token string, header map[string]string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	stat := d.storage.URL + "/v1/buckets/reports/object?key=doc"
	for name, tc := range map[string]struct {
		url, token string
		header     map[string]string
		status     int
		body       string
	}{
		"no token":        {stat, "", nil, 401, `{"error":"UNAUTHENTICATED"}`},
		"keys-role token": {stat, d.st.KeysCaller("alice").Token, nil, 401, `{"error":"UNAUTHENTICATED"}`},
		"owner":           {stat, a.Caller.Token, nil, 200, ""},
		"denied":          {stat, carol.Caller.Token, nil, 404, `{"error":"NOT_FOUND"}`},
		"absent":          {d.storage.URL + "/v1/buckets/reports/object?key=nothing", carol.Caller.Token, nil, 404, `{"error":"NOT_FOUND"}`},
		"absent bucket":   {d.storage.URL + "/v1/buckets/secret/object?key=doc", carol.Caller.Token, nil, 404, `{"error":"NOT_FOUND"}`},
		"no key":          {d.storage.URL + "/v1/buckets/reports/object", a.Caller.Token, nil, 400, `{"error":"INVALID_REQUEST"}`},
		"two keys":        {stat + "&key=x", a.Caller.Token, nil, 400, `{"error":"INVALID_REQUEST"}`},
		"range request":   {d.storage.URL + "/v1/buckets/reports/object/ciphertext?key=doc", a.Caller.Token, map[string]string{"Range": "bytes=0-1"}, 400, `{"error":"INVALID_REQUEST"}`},
	} {
		status, body := get(tc.url, tc.token, tc.header)
		if status != tc.status || (tc.body != "" && body != tc.body) {
			t.Errorf("%s: %d %s, want %d %s", name, status, body, tc.status, tc.body)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, d.keys.URL+"/internal/v1/deliver", strings.NewReader(`{}`))
	req.Header.Set("X-Test-Workload", "someone-else")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("internal delivery from another workload: %d", resp.StatusCode)
	}
}

// TestTenantStreamLimit covers AVL-006 over HTTP: while one tenant's
// ciphertext download is in progress, a second stream of that tenant is
// refused with 429. That other tenants keep their own bounds is covered by
// the limiter's unit test.
func TestTenantStreamLimit(t *testing.T) {
	d := deployWith(t, admission.Limits{TenantRequests: 4, TenantStreams: 1, TotalRequests: 16})
	d.st.Bucket("reports", "p1")
	a := d.st.Client("alice", []string{"member"}, "p1")
	if _, err := a.Put("reports", "big", bytes.Repeat([]byte("x"), 16<<20)); err != nil {
		t.Fatal(err)
	}
	get := func(token string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, d.storage.URL+"/v1/buckets/reports/object/ciphertext?key=big", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := get(a.Caller.Token)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first stream: %d", first.StatusCode)
	}
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(first.Body, buf); err != nil {
		t.Fatal(err)
	}
	second := get(d.st.Caller("alice").Token)
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") == "" {
		t.Fatalf("second stream of the tenant: %d", second.StatusCode)
	}
	first.Body.Close()
}

// TestServerModeHTTP covers the server-mode routes over HTTP with the SDK
// (D-12, S3): the client learns the bucket's mode, uploads plaintext the
// storage role encrypts under a data key the keys role seals over its
// internal route, and another member reads it by policy alone; the client
// route refuses the bucket; a corrupted blob aborts the stream instead of
// completing it (SSE-005).
func TestServerModeHTTP(t *testing.T) {
	d := deploy(t)
	ctx := context.Background()
	d.st.ModeBucket("vault", "p1", "internal", "server")
	a := d.st.Client("alice", []string{"member"}, "p1")
	b := d.st.Client("bob", []string{"member"}, "p1")
	alice, bob := d.client(t, a), d.client(t, b)
	if mode, err := bob.BucketEncryption(ctx, "vault"); err != nil || mode != "server" {
		t.Fatalf("mode = %q, %v", mode, err)
	}
	plaintext := bytes.Repeat([]byte("server mode "), 200_000)
	pub, err := alice.PutPlain(ctx, "vault", "q3/report.bin", bytes.NewReader(plaintext), int64(len(plaintext)), client.PutOptions{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if v, err := bob.GetPlain(ctx, "vault", "q3/report.bin", "", &out); err != nil || v != pub.Version || !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("bob reads by policy: %v (%d bytes)", err, out.Len())
	}
	if info, err := bob.Stat(ctx, "vault", "q3/report.bin", ""); err != nil || info.Encryption != "server" || info.Length != int64(len(plaintext)) {
		t.Fatalf("stat = %+v, %v", info, err)
	}
	var apiErr *client.Error
	_, err = alice.Put(ctx, "vault", "other.bin", strings.NewReader("x"),
		[]crypto.Recipient{{Fingerprint: a.Recipient.Fingerprint(), KeyVersion: a.KeyVersion}}, client.PutOptions{})
	if !errors.As(err, &apiErr) || apiErr.Status != 409 || apiErr.Code != "ENCRYPTION_MODE" {
		t.Fatalf("client upload to a server-mode bucket: %v", err)
	}
	var blobID string
	if err := d.st.Pool.QueryRow(ctx, `SELECT blob::text FROM object_versions WHERE id::text = $1`, pub.Version).Scan(&blobID); err != nil {
		t.Fatal(err)
	}
	var path string
	_ = filepath.WalkDir(d.st.BlobDir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() && e.Name() == blobID {
			path = p
		}
		return nil
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-5] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := bob.GetPlain(ctx, "vault", "q3/report.bin", "", &out); err == nil {
		t.Fatalf("a corrupted payload completed with %d bytes", out.Len())
	}
}

// TestServerDocumentsHTTP covers server-mode documents and collections over
// HTTP with the SDK (D-12, S4a): text in, units out by policy alone, and an
// append that needs no client keys.
func TestServerDocumentsHTTP(t *testing.T) {
	d := deploy(t)
	ctx := context.Background()
	d.st.ModeBucket("vault", "p1", "internal", "server")
	a := d.st.Client("alice", []string{"member"}, "p1")
	b := d.st.Client("bob", []string{"member"}, "p1")
	alice, bob := d.client(t, a), d.client(t, b)
	if p, err := alice.PutDocumentText(ctx, "vault", "q3/notes.md", []byte("First.\n\nSecond,\nwith a break.\n\nThird."), false); err != nil || p.Units != 3 {
		t.Fatalf("put text: %+v %v", p, err)
	}
	var out bytes.Buffer
	if n, err := bob.GetDocument(ctx, "vault", "q3/notes.md", "", &out); err != nil || n != 3 || out.String() != "First.\n\nSecond,\nwith a break.\n\nThird." {
		t.Fatalf("bob reads the document: %d %q %v", n, out.String(), err)
	}
	if _, err := alice.PutDocumentText(ctx, "vault", "chat", []byte("hello\n\nhow are you?"), true); err != nil {
		t.Fatal(err)
	}
	if p, err := alice.AppendText(ctx, "vault", "chat", []byte("fine, thanks")); err != nil || p.Units != 3 {
		t.Fatalf("append: %+v %v", p, err)
	}
	out.Reset()
	if _, err := bob.GetDocument(ctx, "vault", "chat", "", &out); err != nil || out.String() != "hello\n\nhow are you?\n\nfine, thanks" {
		t.Fatalf("bob reads the collection: %q %v", out.String(), err)
	}
	var apiErr *client.Error
	if _, err := bob.AppendText(ctx, "vault", "chat", []byte("me too")); !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("bob appends: %v", err)
	}

	// An original file, streamed beside the text (S4b).
	original := bytes.Repeat([]byte("original bytes "), 100_000)
	if _, err := alice.PutDocumentTextWithOriginal(ctx, "vault", "q3/report.md", []byte("Short.\n\nText."), bytes.NewReader(original)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := alice.GetOriginalPlain(ctx, "vault", "q3/report.md", "", &out); err != nil || !bytes.Equal(out.Bytes(), original) {
		t.Fatalf("alice reads the original: %d bytes, %v", out.Len(), err)
	}
	if err := bob.GetOriginalPlain(ctx, "vault", "q3/report.md", "", io.Discard); !errors.As(err, &apiErr) || apiErr.Status != 404 {
		t.Fatalf("bob without raw-read: %v", err)
	}
	units, err := alice.Units(ctx, "vault", "q3/report.md", "")
	if err != nil {
		t.Fatal(err)
	}
	x, err := alice.ExportUnitsPlain(ctx, "vault", "q3/report.md", "", []string{units[1].Unit})
	if err != nil || len(x) != 1 || x[0].Text != "Text." {
		t.Fatalf("export: %+v %v", x, err)
	}
}

// TestServerDerivedHTTP covers the server-mode derived routes and SDK (S4b):
// a multi-segment output streamed with its lineage, read by another member
// through her own reader path; a repeated finalize by sources; malformed
// uploads; the upload route refuses a client-mode bucket.
func TestServerDerivedHTTP(t *testing.T) {
	d := deploy(t)
	ctx := context.Background()
	d.st.ModeBucket("vault", "p1", "internal", "server")
	d.st.Bucket("reports", "p1")
	a := d.st.Client("alice", []string{"member"}, "p1")
	b := d.st.Client("bob", []string{"member"}, "p1")
	alice, bob := d.client(t, a), d.client(t, b)
	src, err := alice.PutPlain(ctx, "vault", "data.csv", strings.NewReader("a,b\n1,2\n"), 8, client.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lineage := []cryptowire.LineageSource{{Type: cryptowire.SourceObject, ID: src.Object, Version: src.Version}}
	summary := bytes.Repeat([]byte("derived "), 300_000)
	p, err := alice.PutPlain(ctx, "vault", "summary.txt", bytes.NewReader(summary), -1, client.PutOptions{IdempotencyKey: "s1", Lineage: lineage})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if v, err := bob.GetDerivedPlain(ctx, "vault", "summary.txt", "", &out); err != nil || v != p.Version || !bytes.Equal(out.Bytes(), summary) {
		t.Fatalf("bob reads the output: %q %d bytes, %v", v, out.Len(), err)
	}
	var intent string
	if err := d.st.Pool.QueryRow(ctx, `SELECT id::text FROM upload_intents WHERE idempotency_key = 's1'`).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"sources": lineage})
	if again, err := alice.FinalizeUpload(ctx, intent, request); err != nil || again.Version != p.Version {
		t.Fatalf("a repeated finalize: %+v %v", again, err)
	}
	var apiErr *client.Error
	mixed, _ := json.Marshal(map[string]any{"sources": lineage, "lineage": []byte("{}")})
	if _, err := alice.FinalizeUpload(ctx, intent, mixed); !errors.As(err, &apiErr) || apiErr.Status != 400 {
		t.Fatalf("a finalize with sources and a signed lineage: %v", err)
	}

	// Malformed uploads: no lineage part, or content first.
	post := func(parts ...string) int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for i := 0; i+1 < len(parts); i += 2 {
			w, _ := mw.CreateFormField(parts[i])
			w.Write([]byte(parts[i+1]))
		}
		mw.Close()
		req, _ := http.NewRequest(http.MethodPost, d.storage.URL+"/v1/buckets/vault/derived/content?key=bad.txt", &body)
		req.Header.Set("Authorization", "Bearer "+a.Caller.Token)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good, _ := json.Marshal(map[string]any{"sources": lineage})
	for name, parts := range map[string][]string{
		"no lineage":       {"content", "x"},
		"content first":    {"content", "x", "lineage", string(good)},
		"unknown field":    {"lineage", `{"sources":[],"signer":"x"}`, "content", "x"},
		"no content":       {"lineage", string(good)},
		"lineage as array": {"lineage", "[]", "content", "x"},
	} {
		if code := post(parts...); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code := post("lineage", string(good), "content", "x"); code != 200 {
		t.Fatalf("a well-formed upload: %d", code)
	}

	if _, err := alice.PutPlain(ctx, "reports", "s.txt", strings.NewReader("x"), -1, client.PutOptions{Lineage: lineage}); !errors.As(err, &apiErr) || apiErr.Code != "ENCRYPTION_MODE" {
		t.Fatalf("a server-mode output to a client-mode bucket: %v", err)
	}
}
