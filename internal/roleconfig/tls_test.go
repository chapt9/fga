package roleconfig_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/keysapi"
	"fga/internal/r1test"
	"fga/internal/roleconfig"
	"fga/internal/rpc"
)

// pki is a throwaway certificate authority with files on disk.
type pki struct {
	dir    string
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newPKI(t *testing.T, name string) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := &pki{dir: t.TempDir(), caKey: key, caCert: cert}
	p.write(t, "ca.pem", "CERTIFICATE", der)
	return p
}

func (p *pki) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// issue writes a certificate and key for name: a server certificate for
// 127.0.0.1, or a workload client certificate.
func (p *pki) issue(t *testing.T, name string, server bool) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return p.write(t, name+".pem", "CERTIFICATE", der), p.write(t, name+"-key.pem", "EC PRIVATE KEY", keyDER)
}

func (p *pki) ca() string { return filepath.Join(p.dir, "ca.pem") }

// serve starts handler with TLS settings from roleconfig and the given
// client-certificate policy.
func serve(t *testing.T, p *pki, handler http.Handler, cfg *tls.Config) *httptest.Server {
	t.Helper()
	certFile, keyFile := p.issue(t, "server", true)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{cert}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestRolesOverMutualTLS covers TRU-001, TRU-002 and DEC-007 with the
// production transport: the storage role reaches the decision and keys
// roles over mutual TLS, each identifies the workload by its verified
// certificate, and a put and a get complete end to end. A certificate from
// another authority, no certificate, and another workload's certificate on
// the internal delivery route are refused.
func TestRolesOverMutualTLS(t *testing.T) {
	st := r1test.New(t)
	p := newPKI(t, "fga-workloads")
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)

	decision := serve(t, p, st.Decisions.Handler(decisionsvc.AdapterFromClientCert),
		&tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})

	serverCert, serverKey := p.issue(t, "keys-server", true)
	common := roleconfig.Common{Listen: "127.0.0.1:0", TLS: &roleconfig.TLS{CertFile: serverCert, KeyFile: serverKey, ClientCAFile: p.ca()}}
	keysServer, adapterOf, err := common.Server(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := serve(t, p, keysapi.Keys(st.Envelopes, st.Tokens, adapterOf, r1test.StorageAdapter, func() bool { return true }), keysServer.TLSConfig)

	storageCert, storageKey := p.issue(t, r1test.StorageAdapter, false)
	storageHTTP, err := roleconfig.Peer{URL: decision.URL, CertFile: storageCert, KeyFile: storageKey, CAFile: p.ca()}.Client()
	if err != nil {
		t.Fatal(err)
	}
	tokenKey := make([]byte, 32)
	_, _ = rand.Read(tokenKey)
	st.Content, err = content.New(content.Deps{Catalog: st.Catalog, Blobs: st.Blobs, Fence: st.Fence,
		Decider: rpc.DecisionClient{BaseURL: decision.URL, HTTP: storageHTTP}, Verifier: st.Verifier(content.Audience),
		Keys: rpc.KeysClient{BaseURL: keys.URL, HTTP: storageHTTP}, TokenKey: tokenKey, Limits: content.DefaultLimits,
		Now: func() time.Time { return *st.Clock }})
	if err != nil {
		t.Fatal(err)
	}

	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("over mutual TLS")); err != nil {
		t.Fatalf("put over mutual TLS: %v", err)
	}
	if got, err := alice.Get("reports", "doc", ""); err != nil || string(got) != "over mutual TLS" {
		t.Fatalf("get over mutual TLS: %q, %v", got, err)
	}

	other := newPKI(t, "intruders")
	intruderCert, intruderKey := other.issue(t, r1test.StorageAdapter, false)
	intruder, _ := roleconfig.Peer{URL: decision.URL, CertFile: intruderCert, KeyFile: intruderKey, CAFile: p.ca()}.Client()
	if resp, err := intruder.Post(decision.URL+"/v1/decide-batch", "application/json", strings.NewReader("{}")); err == nil {
		resp.Body.Close()
		t.Fatal("the decision role accepted a certificate from another authority")
	}
	anonymous, _ := roleconfig.Peer{URL: decision.URL, CAFile: p.ca()}.Client()
	anonymous.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if resp, err := anonymous.Post(decision.URL+"/v1/decide-batch", "application/json", strings.NewReader("{}")); err == nil {
		resp.Body.Close()
		t.Fatal("the decision role accepted a client without a certificate")
	}
	keysCert, keysKey := p.issue(t, "keys-1", false)
	keysWorkload, _ := roleconfig.Peer{URL: keys.URL, CertFile: keysCert, KeyFile: keysKey, CAFile: p.ca()}.Client()
	resp, err := keysWorkload.Post(keys.URL+"/internal/v1/deliver", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("internal delivery by another workload: %d, want 401", resp.StatusCode)
	}
}
