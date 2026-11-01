package guard_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fga/internal/guard"
)

// TestProgress covers fga-audit F-13: a request body that stalls or
// trickles below the minimum rate, and a response the client does not
// take, end the request, so the client holds no admission slot; a
// prompt body is read whole.
func TestProgress(t *testing.T) {
	const idle = 300 * time.Millisecond
	ended := make(chan error, 1)
	srv := httptest.NewServer(guard.ProgressWith(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			chunk := make([]byte, 1<<20)
			var err error
			for i := 0; i < 256 && err == nil; i++ {
				_, err = w.Write(chunk)
			}
			ended <- err
			return
		}
		b, err := io.ReadAll(r.Body)
		if err == nil && len(b) != 4000 {
			err = fmt.Errorf("read %d bytes", len(b))
		}
		ended <- err
	}), idle, 1000))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	upload := func(send func(net.Conn)) error {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprint(conn, "POST /upload HTTP/1.1\r\nHost: role\r\nContent-Length: 4000\r\n\r\n")
		go send(conn)
		select {
		case err := <-ended:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("the request did not end")
			return nil
		}
	}
	if err := upload(func(c net.Conn) { c.Write([]byte("x")) }); err == nil {
		t.Error("a stalled body was read whole")
	}
	trickle := func(c net.Conn) {
		for i := 0; i < 4000; i++ {
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(idle / 4)
		}
	}
	if err := upload(trickle); !errors.Is(err, guard.ErrTooSlow) {
		t.Errorf("a trickling body: %v, want %v", err, guard.ErrTooSlow)
	}
	if err := upload(func(c net.Conn) { c.Write([]byte(strings.Repeat("x", 4000))) }); err != nil {
		t.Errorf("a prompt body: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /download HTTP/1.1\r\nHost: role\r\n\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil { // then never read again
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		if err == nil {
			t.Error("a response nobody took was written whole")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the download did not end")
	}
}
