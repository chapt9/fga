package content

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// TestLeaseCheckPanic covers a panic in a stream's authority recheck: the
// stream ends as on a failed check, and the role goes on (internal/guard,
// CNT-008).
func TestLeaseCheckPanic(t *testing.T) {
	l := &leased{r: io.NopCloser(strings.NewReader("ciphertext")), validUntil: time.Now().Add(time.Hour), now: time.Now,
		every: 10 * time.Millisecond, done: make(chan struct{})}
	l.lastOK = time.Now()
	defer l.Close()
	l.watch(func(context.Context) error { panic("a broken check") }, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := l.Read(make([]byte, 1))
		if errors.Is(err, ErrLease) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stream went on after the check panicked: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
