package guard

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func quiet() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// TestHandler covers a panicking request: it is answered 500 UNAVAILABLE
// and logged with its stack, and the server goes on serving; a panic
// after the response began aborts that response; streaming still flushes
// through the wrapper.
func TestHandler(t *testing.T) {
	log, logged := quiet()
	mux := http.NewServeMux()
	mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) {
		var m map[string]int
		m["boom"]++ // a nil map write: a runtime panic, not a fatal error
	})
	mux.HandleFunc("/late", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		http.NewResponseController(w).Flush()
		panic("after the response began")
	})
	mux.HandleFunc("/flush", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "one")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush through the guard: %v", err)
		}
		_, _ = io.WriteString(w, "two")
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := httptest.NewServer(Handler(log, mux))
	defer srv.Close()

	get := func(path string) (int, string, error) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), err
	}
	if code, body, err := get("/panic"); err != nil || code != http.StatusInternalServerError || !strings.Contains(body, "UNAVAILABLE") {
		t.Fatalf("panicking request: %d %q %v", code, body, err)
	}
	if !strings.Contains(logged.String(), "GET /panic") || !strings.Contains(logged.String(), "guard_test.go") {
		t.Fatalf("the panic was not logged with its stack: %s", logged)
	}
	if _, _, err := get("/late"); err == nil {
		t.Fatal("a response that panicked after it began completed")
	}
	if code, body, err := get("/flush"); err != nil || code != http.StatusOK || body != "onetwo" {
		t.Fatalf("streaming: %d %q %v", code, body, err)
	}
	if code, body, err := get("/ok"); err != nil || code != http.StatusOK || body != "ok" {
		t.Fatalf("after the panics: %d %q %v", code, body, err)
	}
}

// TestGo covers a panicking goroutine: the process lives on and onPanic
// gets the value, to fail closed with.
func TestGo(t *testing.T) {
	log, _ := quiet()
	got := make(chan any, 1)
	Go(log, "test", func() { panic("boom") }, func(v any) { got <- v })
	select {
	case v := <-got:
		if v != "boom" {
			t.Fatalf("onPanic got %v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onPanic was not called")
	}
}

// TestRecover covers a deferred Recover turning a panic into the
// function's error, and passing http.ErrAbortHandler through.
func TestRecover(t *testing.T) {
	log, _ := quiet()
	f := func(v any) (err error) {
		defer Recover(log, "f", func(any) { err = io.ErrUnexpectedEOF })
		panic(v)
	}
	if err := f("boom"); err != io.ErrUnexpectedEOF {
		t.Fatalf("f = %v", err)
	}
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	_ = f(http.ErrAbortHandler)
}
