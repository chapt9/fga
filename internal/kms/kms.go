// Package kms is the protocol of the local key management role, fga-kms
// (D-13): that role alone holds the key-encryption keys of server mode,
// sealed at rest under a passphrase, and seals and opens data keys for the
// keys role over mutual TLS. The keys role holds no KEK; it has already
// authorized each release under its fence before it asks (SSE-002).
package kms

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"fga/internal/cryptowire"
	"fga/internal/kek"
	"fga/internal/strictjson"
)

// Sealer seals and opens data keys under a tenant's KEK versions.
type Sealer interface {
	Seal(tenant string, version uint32, dataKey []byte, b kek.Binding) ([]byte, error)
	Open(tenant string, version uint32, sealed []byte, b kek.Binding) ([]byte, error)
}

// maxRequest bounds a request: a key of at most a few hundred bytes and a
// binding.
const maxRequest = 4 << 10

// request asks to seal a data key (Key) or open a sealed one.
type request struct {
	Tenant  string  `json:"tenant"`
	Version uint32  `json:"version"`
	Key     []byte  `json:"key"`
	Binding binding `json:"binding"`
}

type binding struct {
	Tenant        string `json:"tenant"`
	Object        string `json:"object"`
	Version       string `json:"version"`
	CryptoVersion string `json:"crypto_version"`
	Blob          string `json:"blob"`
}

func wire(b kek.Binding) binding {
	return binding{Tenant: b.Tenant.String(), Object: b.Object.String(), Version: b.Version.String(),
		CryptoVersion: b.CryptoVersion.String(), Blob: b.Blob.String()}
}

func (b binding) kek() (kek.Binding, error) {
	var out kek.Binding
	for _, f := range []struct {
		s string
		u *cryptowire.UUID
	}{{b.Tenant, &out.Tenant}, {b.Object, &out.Object}, {b.Version, &out.Version}, {b.CryptoVersion, &out.CryptoVersion}, {b.Blob, &out.Blob}} {
		u, err := cryptowire.ParseUUID(f.s)
		if err != nil {
			return kek.Binding{}, err
		}
		*f.u = u
	}
	return out, nil
}

type response struct {
	Key []byte `json:"key"`
}

// Handler serves POST /v1/seal and POST /v1/open to the workloads in
// clients, and GET /healthz. Every other caller is refused.
func Handler(keks Sealer, workloadOf func(*http.Request) (string, error), clients map[string]bool) http.Handler {
	mux := http.NewServeMux()
	serve := func(do func(request, kek.Binding) ([]byte, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if who, err := workloadOf(r); err != nil || !clients[who] {
				http.Error(w, "not a client of this role", http.StatusForbidden)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
			if err != nil {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			var req request
			if err := strictjson.Decode(raw, &req); err != nil || req.Tenant == "" || req.Version == 0 || len(req.Key) == 0 {
				http.Error(w, "malformed request", http.StatusBadRequest)
				return
			}
			b, err := req.Binding.kek()
			if err != nil {
				http.Error(w, "malformed binding", http.StatusBadRequest)
				return
			}
			key, err := do(req, b)
			clear(req.Key)
			switch {
			case errors.Is(err, kek.ErrNoKey):
				http.Error(w, "no such key-encryption key", http.StatusNotFound)
				return
			case errors.Is(err, kek.ErrOpen):
				http.Error(w, "the sealed key does not open", http.StatusUnprocessableEntity)
				return
			case err != nil:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			defer clear(key)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response{Key: key})
		}
	}
	mux.HandleFunc("POST /v1/seal", serve(func(req request, b kek.Binding) ([]byte, error) {
		return keks.Seal(req.Tenant, req.Version, req.Key, b)
	}))
	mux.HandleFunc("POST /v1/open", serve(func(req request, b kek.Binding) ([]byte, error) {
		return keks.Open(req.Tenant, req.Version, req.Key, b)
	}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// Client seals and opens data keys through an fga-kms role. It is the
// keys role's Sealer when production custody is configured.
type Client struct {
	URL  string
	HTTP *http.Client
}

// Seal implements Sealer.
func (c Client) Seal(tenant string, version uint32, dataKey []byte, b kek.Binding) ([]byte, error) {
	return c.call("/v1/seal", request{Tenant: tenant, Version: version, Key: dataKey, Binding: wire(b)})
}

// Open implements Sealer.
func (c Client) Open(tenant string, version uint32, sealed []byte, b kek.Binding) ([]byte, error) {
	return c.call("/v1/open", request{Tenant: tenant, Version: version, Key: sealed, Binding: wire(b)})
}

func (c Client) call(path string, req request) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	resp, err := c.HTTP.Post(c.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, kek.ErrNoKey
	case http.StatusUnprocessableEntity:
		return nil, kek.ErrOpen
	default:
		return nil, fmt.Errorf("kms: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequest))
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	defer clear(raw)
	var out response
	if err := strictjson.Decode(raw, &out); err != nil || len(out.Key) == 0 {
		return nil, errors.New("kms: malformed response")
	}
	return out.Key, nil
}
