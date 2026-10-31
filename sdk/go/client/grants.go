package client

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Share grants (specification 2.6.1, SHR-001 to SHR-003). A grant names a
// principal of the tenant who may be allowed actions from the resource
// type's read set until it expires, where a policy rule honors it. In
// server mode an honored grant lets the grantee read through the server;
// in client mode it only makes the grantee eligible as a recipient, and
// an envelope must still be shared.

// GrantTarget names the resource in a bucket: the bucket itself (no Key);
// the object or derived output at Key; or, for a document at Key, a
// document version (Version, or the current one) or one of its units or
// collection entries (Unit).
type GrantTarget struct {
	Key     string
	Version string
	Unit    string
}

// Grant is a recorded share grant.
type Grant struct {
	ID           string    `json:"grant_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Grantee      string    `json:"grantee"`
	Actions      []string  `json:"actions"`
	ExpiresAt    time.Time `json:"expires_at"`
	Grantor      string    `json:"grantor"`
	CreatedAt    time.Time `json:"created_at"`
}

// GrantOutcome reports a recorded or removed grant and the resource's new
// metadata revision.
type GrantOutcome struct {
	Grant            Grant  `json:"grant"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

func grantsURL(base, bucket string, t GrantTarget, extra url.Values) string {
	q := url.Values{}
	for k, v := range map[string]string{"key": t.Key, "version": t.Version, "unit": t.Unit} {
		if v != "" {
			q.Set(k, v)
		}
	}
	for k, v := range extra {
		q[k] = v
	}
	return base + "/v1/buckets/" + url.PathEscape(bucket) + "/grants?" + q.Encode()
}

// RecordGrant grants grantee actions on the target until expires; it
// needs share on the resource. A grant to the same grantee replaces the
// earlier one.
func (c *Client) RecordGrant(ctx context.Context, bucket string, t GrantTarget, grantee string, actions []string, expires time.Time) (GrantOutcome, error) {
	body, n := jsonBody(map[string]any{"grantee": grantee, "actions": actions, "expires_at": expires.UTC()})
	var out GrantOutcome
	_, err := c.do(ctx, http.MethodPost, grantsURL(c.StorageURL, bucket, t, nil), c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &out)
	return out, err
}

// RemoveGrant removes grantee's grant on the target; it needs share on the
// resource.
func (c *Client) RemoveGrant(ctx context.Context, bucket string, t GrantTarget, grantee string) (GrantOutcome, error) {
	var out GrantOutcome
	_, err := c.do(ctx, http.MethodDelete, grantsURL(c.StorageURL, bucket, t, url.Values{"grantee": {grantee}}), c.StorageToken, nil, -1, nil, &out)
	return out, err
}

// Grants lists the unexpired grants on the target; it needs share on the
// resource.
func (c *Client) Grants(ctx context.Context, bucket string, t GrantTarget) ([]Grant, error) {
	var out struct {
		Grants []Grant `json:"grants"`
	}
	_, err := c.do(ctx, http.MethodGet, grantsURL(c.StorageURL, bucket, t, nil), c.StorageToken, nil, -1, nil, &out)
	return out.Grants, err
}
