package connector

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"fga/internal/tools"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func destination(t *testing.T, srv *httptest.Server) tools.Destination {
	t.Helper()
	cred := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(cred, []byte("dest-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return tools.Destination{ID: "expenses", BaseURL: srv.URL, AllowedCIDRs: loopback, CredentialFile: cred, ReconcilePath: "/idempotency/{key}"}
}

func call() Call {
	return Call{Method: "POST", Path: "/expenses", Body: []byte(`{"vendor":"Rail Co"}`), IdempotencyKey: "inv-1", IfMatch: `"v7"`}
}

func TestSuccessCarriesCredentialKeyAndPrecondition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer dest-secret" || r.Header.Get("Idempotency-Key") != "inv-1" ||
			r.Header.Get("If-Match") != `"v7"` || string(body) != `{"vendor":"Rail Co"}` || r.URL.Path != "/expenses" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Receipt", "exp-991")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	res := New(time.Second).Do(context.Background(), destination(t, srv), call())
	if res.Outcome != Succeeded || res.Receipt != "exp-991" {
		t.Fatalf("result = %+v", res)
	}
}

func TestOutcomeByAnswer(t *testing.T) {
	for status, want := range map[int]Outcome{
		http.StatusUnprocessableEntity: Failed,
		http.StatusConflict:            Failed,
		http.StatusInternalServerError: Unknown,
		http.StatusBadGateway:          Unknown,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		if got := New(time.Second).Do(context.Background(), destination(t, srv), call()); got.Outcome != want {
			t.Errorf("status %d: outcome %v, want %v", status, got.Outcome, want)
		}
		srv.Close()
	}
}

// TestRedirectIsNotFollowed covers V-032: the other host is never contacted
// and the outcome is UNKNOWN, since the first destination may have acted.
func TestRedirectIsNotFollowed(t *testing.T) {
	var contacted atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted.Store(true) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer srv.Close()
	res := New(time.Second).Do(context.Background(), destination(t, srv), call())
	if res.Outcome != Unknown || contacted.Load() {
		t.Fatalf("result %+v, other host contacted: %v", res, contacted.Load())
	}
}

// TestAddressPolicy covers AGT-005: a destination whose name resolves
// outside its allowed ranges is never contacted, even if an earlier answer
// was inside them (rebinding).
func TestAddressPolicy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	h := New(time.Second)
	answers := map[string][]netip.Addr{"expenses.test": {netip.MustParseAddr("169.254.169.254")}}
	h.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		return []netip.Addr{netip.MustParseAddr(host)}, nil
	}
	d := destination(t, srv)
	d.BaseURL = "http://expenses.test:" + port
	if res := h.Do(context.Background(), d, call()); res.Outcome != Failed || hits.Load() != 0 {
		t.Fatalf("disallowed address: %+v, hits %d", res, hits.Load())
	}

	answers["expenses.test"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if res := h.Do(context.Background(), d, call()); res.Outcome != Succeeded || hits.Load() != 1 {
		t.Fatalf("allowed address: %+v, hits %d", res, hits.Load())
	}

	d.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if res := h.Do(context.Background(), d, call()); res.Outcome != Failed || hits.Load() != 1 {
		t.Fatalf("address outside the ranges: %+v, hits %d", res, hits.Load())
	}
}

// TestLostAnswerIsUnknown covers V-042: the request reached the destination
// but the answer did not come back.
func TestLostAnswerIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer srv.Close()
	if res := New(time.Second).Do(context.Background(), destination(t, srv), call()); res.Outcome != Unknown {
		t.Fatalf("result = %+v, want UNKNOWN", res)
	}
}

func TestNotSentIsFailed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens any more
	d := tools.Destination{ID: "gone", BaseURL: "http://" + addr, AllowedCIDRs: loopback}
	if res := New(time.Second).Do(context.Background(), d, call()); res.Outcome != Failed {
		t.Fatalf("result = %+v, want FAILED", res)
	}
}

func TestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/idempotency/inv-1":
			_, _ = w.Write([]byte(`{"status":"succeeded"}`))
		case "/idempotency/inv-3":
			_, _ = w.Write([]byte(`{"status":"failed"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h, d := New(time.Second), destination(t, srv)
	// A key the destination has no record of is NotReceived, not a failure:
	// a call sent in time may still arrive (review v4 F02).
	for key, want := range map[string]Outcome{"inv-1": Succeeded, "inv-2": NotReceived, "inv-3": Failed} {
		if got, supported, err := h.Status(context.Background(), d, key); got != want || !supported || err != nil {
			t.Errorf("%s: %v %v %v, want %v", key, got, supported, err, want)
		}
	}
	d.ReconcilePath = ""
	if _, supported, _ := h.Status(context.Background(), d, "inv-1"); supported {
		t.Error("a destination without a reconcile path reported support")
	}
}
