package nativeapi_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func deploy(t *testing.T) *deployment {
	t.Helper()
	st := r1test.New(t)
	keys := httptest.NewServer(keysapi.Keys(st.Envelopes, st.Tokens, func(r *http.Request) (string, error) {
		return r.Header.Get("X-Test-Workload"), nil
	}, r1test.StorageAdapter, func() bool { return true }))
	t.Cleanup(keys.Close)
	// The storage role reaches the keys role over HTTP as its workload.
	st.Keys = rpc.KeysClient{BaseURL: keys.URL, HTTP: &http.Client{Transport: workload{r1test.StorageAdapter}}}
	storage := httptest.NewServer(nativeapi.Storage(st.Content, st.Tokens, func() bool { return true }))
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
