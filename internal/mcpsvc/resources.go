package mcpsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// filter serves resources/list and filters tools/list; every other method
// passes through.
func (s *Service) filter(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list":
			res, err := next(ctx, method, req)
			if err != nil {
				return nil, err
			}
			list, ok := res.(*mcp.ListToolsResult)
			c, cerr := callerOf(req.GetExtra())
			if !ok || cerr != nil {
				return nil, errUnauthenticated
			}
			// Only tools the user may discover are shown (MCP-003); a new
			// slice, since the result may share the server's.
			allowed := s.discoverable(ctx, c, served)
			kept := make([]*mcp.Tool, 0, len(list.Tools))
			for _, t := range list.Tools {
				if allowed[t.Name] {
					kept = append(kept, t)
				}
			}
			list.Tools = kept
			return list, nil
		case "resources/list":
			lr, ok := req.(*mcp.ListResourcesRequest)
			if !ok {
				return nil, errInvalid
			}
			return s.listResources(ctx, lr)
		}
		return next(ctx, method, req)
	}
}

// listCursor is where resources/list goes on: a bucket of Deps.Buckets,
// objects or documents, and the storage role's continuation there.
type listCursor struct {
	Bucket    int    `json:"b"`
	Documents bool   `json:"d,omitempty"`
	Storage   string `json:"c,omitempty"`
}

// listResources returns one page of the objects, then the documents and
// text collections, of each configured bucket that the user may discover:
// one storage listing page per MCP page. A bucket the user may not list
// is passed over without a trace.
func (s *Service) listResources(ctx context.Context, req *mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	c, err := callerOf(req.Extra)
	if err != nil {
		return nil, err
	}
	var cur listCursor
	if p := req.Params; p != nil && p.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(p.Cursor)
		if err != nil || json.Unmarshal(raw, &cur) != nil || cur.Bucket < 0 || cur.Bucket >= len(s.d.Buckets) {
			return nil, errInvalid
		}
	}
	out := &mcp.ListResourcesResult{Resources: []*mcp.Resource{}}
	out.TTLMs, out.CacheScope = 0, "private"
	if len(s.d.Buckets) == 0 {
		return out, nil
	}
	ev, err := s.authorize(ctx, c, ToolResourcesList)
	if err != nil {
		return nil, err
	}
	bucket := s.d.Buckets[cur.Bucket]
	q := url.Values{"limit": {itoa(100)}}
	if cur.Storage != "" {
		q.Set("continuation", cur.Storage)
	}
	var next string
	if !cur.Documents {
		var page struct {
			Entries []struct {
				Key       string    `json:"key"`
				Version   string    `json:"version_id"`
				CreatedAt time.Time `json:"created_at"`
			} `json:"entries"`
			Continuation string `json:"continuation"`
		}
		err = s.storageJSON(ctx, ev, bucketPath(bucket, "/objects"), q, nil, &page)
		for _, e := range page.Entries {
			out.Resources = append(out.Resources, &mcp.Resource{URI: resourceURI(bucket, e.Key), Name: e.Key,
				Meta: mcp.Meta{"fga/kind": "object", "fga/version": e.Version}})
		}
		next = page.Continuation
	} else {
		var page struct {
			Results []struct {
				Key             string `json:"key"`
				DocumentVersion string `json:"document_version_id"`
			} `json:"results"`
			Continuation string `json:"continuation"`
		}
		err = s.storageJSON(ctx, ev, bucketPath(bucket, "/documents/search"), q, nil, &page)
		for _, r := range page.Results {
			out.Resources = append(out.Resources, &mcp.Resource{URI: resourceURI(bucket, r.Key), Name: r.Key, MIMEType: "text/plain",
				Meta: mcp.Meta{"fga/kind": "document", "fga/version": r.DocumentVersion}})
		}
		next = page.Continuation
	}
	if err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	switch {
	case err == nil && next != "":
		cur.Storage = next
	case !cur.Documents:
		cur = listCursor{Bucket: cur.Bucket, Documents: true}
	case cur.Bucket+1 < len(s.d.Buckets):
		cur = listCursor{Bucket: cur.Bucket + 1}
	default:
		return out, nil
	}
	raw, _ := json.Marshal(cur)
	out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	return out, nil
}

// readResource serves resources/read for fga://bucket/key: an object's
// content, or the text of the document's or collection's units the user
// may read; with ?unit=, that one unit or entry. It uses the same native
// read routes, and so the same storage checks, as any other client
// (MCP-003, MCP-005, V-002, V-050).
func (s *Service) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	c, err := callerOf(req.Extra)
	if err != nil {
		return nil, err
	}
	uri := req.Params.URI
	t, ok := parseURI(uri)
	if !ok {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	ev, err := s.authorize(ctx, c, ToolResourcesRead)
	if err != nil {
		return nil, err
	}
	text := func(s string) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "text/plain", Text: s}}}, nil
	}
	notFound := func(err error) (*mcp.ReadResourceResult, error) {
		if errors.Is(err, errNotFound) {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		return nil, err
	}
	if t.unit != "" {
		out, err := s.readUnits(ctx, ev, t, []string{t.unit}, "")
		if err != nil {
			return notFound(err)
		}
		return text(out.Units[0].Text)
	}
	q := url.Values{"key": {t.key}}
	if t.version != "" {
		q.Set("version", t.version)
	}
	b, err := s.storageBytes(ctx, ev, bucketPath(t.bucket, "/object/content"), q, s.d.Limits.MaxBytes)
	switch {
	case err == nil && utf8.Valid(b):
		return text(string(b))
	case err == nil:
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/octet-stream", Blob: b}}}, nil
	case !errors.Is(err, errNotFound):
		return nil, err
	}
	// Not an object the user may read: a document or text collection.
	out, err := s.readUnits(ctx, ev, t, nil, "")
	if err != nil {
		return notFound(err)
	}
	texts := make([]string, len(out.Units))
	for i, u := range out.Units {
		texts[i] = u.Text
	}
	return text(strings.Join(texts, "\n\n"))
}
