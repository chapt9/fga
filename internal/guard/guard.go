// Package guard keeps a panic inside the request or goroutine it happens
// in, so that one failure does not end a role's process
// (docs/design/fault-isolation.md). It catches panics only. A fatal
// runtime error (out of memory, a concurrent map write, stack exhaustion)
// still ends the process, which the role's supervisor restarts; that is
// why every role is a process of its own.
//
// A caught panic is logged with its stack and fails closed: the request
// is refused, or the work the goroutine guarded is treated as failed.
// Code must still release locks and transactions with defer, so that a
// panic leaves nothing held.
package guard

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recover, deferred directly, catches a panic of the calling function:
// it logs the panic as a failure of what and calls onPanic with its
// value. An http.ErrAbortHandler panic is not caught: net/http uses it to
// abort a response.
//
//	defer guard.Recover(log, "lease check", func(any) { failed = true })
func Recover(log *slog.Logger, what string, onPanic func(v any)) {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler {
		panic(v)
	}
	if log == nil {
		log = slog.Default()
	}
	log.Error("panic caught", "in", what, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
	if onPanic != nil {
		onPanic(v)
	}
}

// Go runs f in a new goroutine. A panic in f is logged and passed to
// onPanic instead of ending the process; onPanic must fail closed for
// whatever f was doing.
func Go(log *slog.Logger, what string, f func(), onPanic func(v any)) {
	go func() {
		defer Recover(log, what, onPanic)
		f()
	}()
}

// Handler returns h with each request's panic caught. A request that
// panics before its response began is answered 500 UNAVAILABLE; one whose
// response had begun is aborted, so the client sees a broken response
// rather than a short one. The process goes on serving other requests.
func Handler(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &tracked{ResponseWriter: w}
		defer Recover(log, r.Method+" "+r.URL.Path, func(any) {
			if tw.wrote {
				panic(http.ErrAbortHandler)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"UNAVAILABLE"}`+"\n")
		})
		h.ServeHTTP(tw, r)
	})
}

// tracked records whether a response has begun. It passes Flush through
// and unwraps for http.ResponseController, which streaming handlers use.
type tracked struct {
	http.ResponseWriter
	wrote bool
}

func (t *tracked) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *tracked) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *tracked) Flush() {
	t.wrote = true
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (t *tracked) Unwrap() http.ResponseWriter { return t.ResponseWriter }
