package mcpsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxListing bounds a listing response from the storage role.
const maxListing = 4 << 20

// storageGet calls a native API route as the MCP workload, with the
// user's MCP decision in place of a token (TB3), and returns the response
// for a 200. Refusals map to the role's errors.
func (s *Service) storageGet(ctx context.Context, evidence, path string, q url.Values) (*http.Response, error) {
	return s.storageCall(ctx, http.MethodGet, evidence, path, q, nil)
}

// storageCall is storageGet for any method, with body, if set, sent as
// JSON.
func (s *Service) storageCall(ctx context.Context, method, evidence, path string, q url.Values, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.d.Storage.URL+path+"?"+q.Encode(), rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(decisionHeader, evidence)
	resp, err := s.d.Storage.HTTP.Do(req)
	if err != nil {
		return nil, errUnavailable
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	var refusal struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&refusal)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNotFound
	case resp.StatusCode == http.StatusConflict && refusal.Error == "ENCRYPTION_MODE":
		return nil, errClientMode
	case resp.StatusCode == http.StatusConflict, resp.StatusCode == http.StatusPreconditionFailed:
		return nil, errConflict
	case resp.StatusCode == http.StatusBadRequest:
		return nil, errInvalid
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, errNotAllowed
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return nil, errTooLarge
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errOverloaded
	}
	return nil, errUnavailable
}

// storageJSON decodes a native API JSON response into out; with body,
// the request is a POST of body as JSON.
func (s *Service) storageJSON(ctx context.Context, evidence, path string, q url.Values, body, out any) error {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	resp, err := s.storageCall(ctx, method, evidence, path, q, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// An export response carries ciphertext inline, base64.
	if json.NewDecoder(io.LimitReader(resp.Body, maxListing+2*s.d.Limits.MaxBytes)).Decode(out) != nil {
		return errUnavailable
	}
	return nil
}

// storageBytes reads a native API content response of at most max bytes.
func (s *Service) storageBytes(ctx context.Context, evidence, path string, q url.Values, max int64) ([]byte, error) {
	resp, err := s.storageGet(ctx, evidence, path, q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > max {
		return nil, errTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	switch {
	case err != nil:
		return nil, errUnavailable
	case int64(len(b)) > max:
		return nil, errTooLarge
	}
	return b, nil
}

// bucketPath is the native API path of a bucket route.
func bucketPath(bucket, rest string) string {
	return "/v1/buckets/" + url.PathEscape(bucket) + rest
}

// resourceURI names an object, document or text collection: fga://bucket/key.
func resourceURI(bucket, key string) string {
	return (&url.URL{Scheme: "fga", Host: bucket, Path: "/" + key}).String()
}

// target is a parsed resource URI.
type target struct {
	bucket, key, version, unit string
}

// parseURI parses fga://bucket/key[?version=V][&unit=U].
func parseURI(raw string) (target, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "fga" || u.Host == "" || u.User != nil || u.Fragment != "" || len(u.Path) < 2 {
		return target{}, false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return target{}, false
	}
	for k, v := range q {
		if k != "version" && k != "unit" || len(v) != 1 || v[0] == "" {
			return target{}, false
		}
	}
	return target{bucket: u.Host, key: strings.TrimPrefix(u.Path, "/"), version: q.Get("version"), unit: q.Get("unit")}, true
}
