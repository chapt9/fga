package authn

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRemoteJWKSFetchDoesNotStallKnownKeys is the regression test of the
// security review of 4 November 2026, finding 3: while a fetch of the key
// set is in flight, a key at hand is answered at once; an unknown key
// waits for the set the fetch brings.
func TestRemoteJWKSFetchDoesNotStallKnownKeys(t *testing.T) {
	p := newProvider(t)
	var mu sync.Mutex
	served := jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey})
	var blocking atomic.Bool
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if blocking.Load() {
			entered <- struct{}{}
			<-release
		}
		mu.Lock()
		defer mu.Unlock()
		w.Write(served)
	}))
	defer srv.Close()
	defer unblock()
	clock := time.Now()
	r := NewRemoteJWKS(srv.URL, srv.Client(), func() time.Time { return clock })
	if _, ok := r.Key("rsa"); !ok {
		t.Fatal("the first fetch brought no key")
	}
	// An hour on, the set is due for a refresh: the next lookup starts a
	// fetch that hangs.
	clock = clock.Add(jwksRefresh + time.Second)
	blocking.Store(true)
	first := make(chan bool, 1)
	go func() { _, ok := r.Key("rsa"); first <- ok }()
	<-entered
	prompt := make(chan bool, 1)
	go func() { _, ok := r.Key("rsa"); prompt <- ok }()
	select {
	case ok := <-prompt:
		if !ok {
			t.Fatal("the key at hand was not answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a key at hand waited for the fetch in flight")
	}
	mu.Lock()
	served = jwks(t, map[string]crypto.PublicKey{"rsa": &p.rsa.PublicKey, "ec": &p.ec.PublicKey})
	mu.Unlock()
	unknown := make(chan bool, 1)
	go func() { _, ok := r.Key("ec"); unknown <- ok }()
	select {
	case ok := <-unknown:
		t.Fatalf("an unknown key did not wait for the fetch in flight (found %v)", ok)
	case <-time.After(200 * time.Millisecond):
	}
	unblock()
	if !<-first {
		t.Fatal("the lookup that fetched lost its key")
	}
	if !<-unknown {
		t.Fatal("the key the fetch brought was not answered")
	}
}
