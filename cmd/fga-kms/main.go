// Command fga-kms is the local key management role (D-13): the only
// process that holds the key-encryption keys of server mode. It reads the
// KEK ring, which production requires to be sealed at rest under a
// passphrase from a file, and seals and opens data keys for the keys role
// over mutual TLS (internal/kms). The administrator's tool rotates the ring
// on this host (fga-admin kek rotate); the role picks up a new version
// without a restart.
//
//	fga-kms -config kms.json
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"fga/internal/guard"
	"fga/internal/kek"
	"fga/internal/keyfile"
	"fga/internal/kms"
	"fga/internal/strictjson"
)

// Config is the role's configuration. Unknown fields are rejected.
type Config struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Listen  string `json:"listen"`
	// TLS serves mutual TLS; Clients are the workloads (client certificate
	// URI SAN, else common name) that may seal and open: the keys role.
	TLS     *TLSConfig `json:"tls,omitempty"`
	Clients []string   `json:"clients"`
	// DevClient is, without TLS in development, the one client every
	// loopback caller is taken to be.
	DevClient string `json:"dev_client,omitempty"`
	// KEKFile is the ring; a protected ring is opened with
	// KEKPassphraseFile, or $FGA_KEK_PASSPHRASE in development.
	KEKFile           string `json:"kek_file"`
	KEKPassphraseFile string `json:"kek_passphrase_file,omitempty"`
}

// TLSConfig names the server certificate and the CA of client workloads.
type TLSConfig struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

// Validate reports every configuration problem. Production needs mutual
// TLS, a ring sealed under a passphrase and that passphrase from a file.
func (c Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		fail("version must be 1")
	}
	if c.Listen == "" || c.KEKFile == "" || len(c.Clients) == 0 {
		fail("listen, kek_file and clients are required")
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "") {
		fail("tls needs cert_file, key_file and client_ca_file")
	}
	switch c.Profile {
	case "production":
		if c.TLS == nil || c.DevClient != "" {
			fail("production requires tls and no dev_client")
		}
		if c.KEKPassphraseFile == "" {
			fail("production opens the ring with kek_passphrase_file")
		}
		if raw, err := os.ReadFile(c.KEKFile); err == nil && !keyfile.Protected(raw) {
			fail("production requires a passphrase-protected ring (fga-admin kek init -encrypt)")
		}
	case "development":
		if c.TLS == nil && (!slices.Contains(c.Clients, c.DevClient) || !loopback(c.Listen)) {
			fail("development without tls needs a dev_client among clients and a loopback listen address")
		}
	default:
		fail("profile must be production or development")
	}
	return errors.Join(errs...)
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err == nil && (host == "localhost" || ip != nil && ip.IsLoopback())
}

// workload names the caller by its verified client certificate, as the
// other roles name an adapter.
func workload(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("no verified client certificate")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String(), nil
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName, nil
	}
	return "", errors.New("client certificate names no workload")
}

func main() {
	path := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("fga-kms stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := strictjson.Decode(raw, &cfg); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	keks, err := kek.Load(cfg.KEKFile, func() ([]byte, error) { return keyfile.Passphrase("FGA_KEK_PASSPHRASE", cfg.KEKPassphraseFile) })
	if err != nil {
		return err
	}
	clients := map[string]bool{}
	for _, c := range cfg.Clients {
		clients[c] = true
	}
	who := workload
	if cfg.TLS == nil {
		dev := cfg.DevClient
		who = func(*http.Request) (string, error) { return dev, nil }
	}
	server := &http.Server{Addr: cfg.Listen, Handler: guard.Handler(nil, kms.Handler(keks, who, clients)),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	if cfg.TLS != nil {
		pem, err := os.ReadFile(cfg.TLS.ClientCAFile)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("client_ca_file holds no certificates")
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			errc <- server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errc <- server.ListenAndServe()
		}
	}()
	slog.Info("fga-kms listening", "addr", cfg.Listen, "profile", cfg.Profile)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
