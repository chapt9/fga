package guard

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// IOIdle and IOMinRate bound a slow client (fga-audit F-13): each read
// of a request body and each response write must complete within IOIdle,
// and once IOIdle has passed a request body must have arrived at
// IOMinRate bytes a second on average. Otherwise a client holds its
// admission slot for as long as it trickles. Responses may pause between
// writes, as an event stream does.
const (
	IOIdle    = 30 * time.Second
	IOMinRate = 1024
)

// ErrTooSlow ends a request body that arrives below IOMinRate.
var ErrTooSlow = errors.New("request body arrives too slowly")

// Progress returns h with IOIdle and IOMinRate applied to every request.
func Progress(h http.Handler) http.Handler { return ProgressWith(h, IOIdle, IOMinRate) }

// ProgressWith is Progress with other bounds.
func ProgressWith(h http.Handler, idle time.Duration, minRate float64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &slowBody{ReadCloser: r.Body, rc: rc, idle: idle, minRate: minRate, start: time.Now()}
		}
		h.ServeHTTP(&slowWriter{ResponseWriter: w, rc: rc, idle: idle}, r)
		// The rest of the response is flushed after the handler returns.
		_ = rc.SetWriteDeadline(time.Now().Add(idle))
	})
}

type slowBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	idle    time.Duration
	minRate float64
	start   time.Time
	n       int64
}

func (b *slowBody) Read(p []byte) (int, error) {
	if since := time.Since(b.start); since > b.idle && float64(b.n) < b.minRate*since.Seconds() {
		return 0, ErrTooSlow
	}
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	if err == io.EOF {
		// The server goes on reading the connection to notice a client
		// that leaves; a deadline would cancel the request.
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

type slowWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (w *slowWriter) Write(p []byte) (int, error) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	return w.ResponseWriter.Write(p)
}

func (w *slowWriter) Flush() { _ = w.FlushError() }

func (w *slowWriter) FlushError() error {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	return w.rc.Flush()
}

func (w *slowWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
