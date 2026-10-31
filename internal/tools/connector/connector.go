// Package connector performs tool calls against registered HTTP
// destinations (specification 2.5, AGT-005, AGT-006, INV-005). Part of the
// optional R2 executor (feature executor).
//
// The connector reaches a destination only at addresses inside its allowed
// ranges, checked when connecting, so a DNS answer cannot redirect it. It
// never follows redirects or uses a proxy, it authenticates with the
// destination's own credential, never an agent's, and it sends an
// idempotency key with every call.
//
// Outcome rules. A call that was never written is FAILED. Once written, a
// 2xx answer is SUCCEEDED; a 4xx answer is FAILED, on the contract that a
// destination does not act on a request it answers with 4xx; anything else
// (timeout, broken connection, 3xx, 5xx) is UNKNOWN, because the effect may
// have happened.
package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"fga/internal/tools"
)

// Outcome of a call.
type Outcome int

const (
	Unknown Outcome = iota
	Succeeded
	Failed
	// NotReceived is a destination's answer that it has no record of an
	// idempotency key. It shows a failure only once no earlier dispatch
	// can still arrive (INV-003).
	NotReceived
)

func (o Outcome) String() string {
	return [...]string{"UNKNOWN", "SUCCEEDED", "FAILED", "NOT_RECEIVED"}[o]
}

// Call is one request to a destination.
type Call struct {
	Method         string
	Path           string
	Body           []byte
	IdempotencyKey string
	// IfMatch carries a state precondition when the target supports one
	// (AGT-006).
	IfMatch string
}

// Result of a call.
type Result struct {
	Outcome Outcome
	Status  int
	// Receipt identifies the downstream result: its receipt header, or the
	// SHA-256 of the response body.
	Receipt string
	Detail  string
}

// MaxResponseBytes bounds what the connector reads from a destination.
const MaxResponseBytes = 64 << 10

// HTTP is the HTTP connector.
type HTTP struct {
	timeout time.Duration
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
}

// New returns a connector with a per-call timeout.
func New(timeout time.Duration) *HTTP {
	return &HTTP{timeout: timeout, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
}

// client builds an HTTP client that connects only to allowed addresses and
// never follows redirects.
func (h *HTTP) client(d tools.Destination) *http.Client {
	dialer := &net.Dialer{Timeout: h.timeout}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs, err := h.lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if allowed(d.AllowedCIDRs, a.Unmap()) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
				}
			}
			return nil, fmt.Errorf("no address of %s is inside the destination's allowed ranges", host)
		},
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       h.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func allowed(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Do performs a call. It never returns an error: every failure maps to an
// outcome with a detail.
func (h *HTTP) Do(ctx context.Context, d tools.Destination, call Call) Result {
	target, err := url.JoinPath(d.BaseURL, call.Path)
	if err != nil {
		return Result{Outcome: Failed, Detail: "invalid destination URL"}
	}
	req, err := http.NewRequestWithContext(ctx, call.Method, target, bytes.NewReader(call.Body))
	if err != nil {
		return Result{Outcome: Failed, Detail: "invalid request"}
	}
	if err := authorize(req, d); err != nil {
		return Result{Outcome: Failed, Detail: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", call.IdempotencyKey)
	if call.IfMatch != "" {
		req.Header.Set("If-Match", call.IfMatch)
	}

	var written bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { written = true },
	}))
	resp, err := h.client(d).Do(req)
	if err != nil {
		if !written {
			return Result{Outcome: Failed, Detail: "not sent: " + err.Error()}
		}
		return Result{Outcome: Unknown, Detail: "sent, no answer: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	res := Result{Status: resp.StatusCode, Receipt: receipt(resp, body)}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.Outcome = Succeeded
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		res.Outcome, res.Detail = Failed, "rejected by the destination"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		res.Outcome, res.Detail = Unknown, "redirect not followed"
	default:
		res.Outcome, res.Detail = Unknown, "destination error"
	}
	return res
}

func authorize(req *http.Request, d tools.Destination) error {
	if d.CredentialFile == "" {
		return nil
	}
	secret, err := os.ReadFile(d.CredentialFile)
	if err != nil {
		return errors.New("destination credential unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(secret)))
	return nil
}

func receipt(resp *http.Response, body []byte) string {
	if r := resp.Header.Get("X-Receipt"); r != "" {
		return r
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Status asks the destination for the outcome of an idempotency key, for
// reconciling a dispatch whose answer was lost (INV-003). supported is false
// when the destination has no reconcile endpoint. A 404 means the
// destination has no record of the key (NotReceived): the call has not
// taken effect so far, which is a failure only if it can no longer arrive.
func (h *HTTP) Status(ctx context.Context, d tools.Destination, key string) (outcome Outcome, supported bool, err error) {
	if d.ReconcilePath == "" {
		return Unknown, false, nil
	}
	target, err := url.JoinPath(d.BaseURL, strings.ReplaceAll(d.ReconcilePath, "{key}", url.PathEscape(key)))
	if err != nil {
		return Unknown, true, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Unknown, true, err
	}
	if err := authorize(req, d); err != nil {
		return Unknown, true, err
	}
	resp, err := h.client(d).Do(req)
	if err != nil {
		return Unknown, true, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return NotReceived, true, nil
	case http.StatusOK:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, MaxResponseBytes)).Decode(&body); err != nil {
			return Unknown, true, err
		}
		switch body.Status {
		case "succeeded":
			return Succeeded, true, nil
		case "failed":
			return Failed, true, nil
		}
	}
	return Unknown, true, nil
}
