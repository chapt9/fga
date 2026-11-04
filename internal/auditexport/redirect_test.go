package auditexport_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"fga/internal/auditexport"
	"fga/internal/r1test"
)

// TestCollectorRedirectIsNoAcknowledgement is the regression test of the
// security review of 4 November 2026, finding 9: a collector that
// redirects does not receive the file, and the file is not marked shipped.
func TestCollectorRedirectIsNoAcknowledgement(t *testing.T) {
	st := r1test.New(t)
	_, key := newKey(t)
	var received atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	defer target.Close()
	redirecting := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirecting.Close()
	dir := t.TempDir()
	x := newExporter(t, st, dir, 1, key, func(o *auditexport.Options) {
		o.Collector = &auditexport.Collector{URL: redirecting.URL}
	})
	appendEvents(t, st, "e", 2)
	if _, err := x.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := x.Ship(ctx); err == nil || n != 0 {
		t.Fatalf("a redirect acknowledged a file: %d, %v", n, err)
	}
	if received.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
	if shipped, _ := filepath.Glob(filepath.Join(dir, "*.shipped")); len(shipped) != 0 {
		t.Fatalf("files marked shipped: %v", shipped)
	}
}
