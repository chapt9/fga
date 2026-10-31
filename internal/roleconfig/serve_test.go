package roleconfig_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"fga/internal/roleconfig"
)

// TestServeGuardsPanics covers fault isolation inside a role: a request
// that panics is answered 500, and the role goes on serving the next one
// (internal/guard).
func TestServeGuardsPanics(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) { panic("a broken handler") })
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- roleconfig.Common{Listen: addr}.Serve(ctx, &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: time.Second})
	}()
	defer func() {
		cancel()
		<-done
	}()
	get := func(path string) (int, error) {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := get("/ok"); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, err := get("/panic"); err != nil || code != http.StatusInternalServerError {
		t.Fatalf("a panicking request: %d %v", code, err)
	}
	if code, err := get("/ok"); err != nil || code != http.StatusOK {
		t.Fatalf("the next request: %d %v", code, err)
	}
}
