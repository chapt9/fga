package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"fga/internal/cryptowire"
	"fga/internal/jsonunits"
	"fga/internal/sources"
	"fga/sdk/go/crypto"
)

// Readings of sources in client mode (docs/design/mcp-data-tools.md,
// ING-010, ING-011): the client splits a reading with its source's layout,
// encrypts each field group as a unit for the recipients that group names,
// and publishes it as a document version. fga sees the key, the groups and
// the fields present, never a value.

// SourceLayout is a source's active version as GET /v1/sources/{source}
// answers it, with per group the active keys of the recipients it names.
type SourceLayout struct {
	Source     string          `json:"source"`
	Version    int             `json:"version"`
	Digest     string          `json:"digest"`
	Encryption string          `json:"encryption"`
	Definition json.RawMessage `json:"definition"`
	Recipients [][]struct {
		Principal   string `json:"principal"`
		Fingerprint string `json:"fingerprint"`
		KeyVersion  uint64 `json:"key_version"`
	} `json:"recipients"`
}

// SourceLayout reads a source's active layout; the caller needs
// post-reading on its bucket.
func (c *Client) SourceLayout(ctx context.Context, source string) (SourceLayout, error) {
	var l SourceLayout
	_, err := c.do(ctx, http.MethodGet, c.StorageURL+"/v1/sources/"+url.PathEscape(source), c.StorageToken, nil, -1, nil, &l)
	return l, err
}

// PostReading posts payload as a reading of source. In client mode the
// client splits and encrypts it; principal
// is the caller's identity, needed only for a source keyed by the posting
// principal; idempotencyKey may be empty. Each group is sealed only for
// keys pinned in Trust: the layout's fingerprints come from the server,
// which is no trust anchor (RCP-002), and the server publishes the reading
// only with envelopes for exactly the active keys of each group's
// recipients.
func (c *Client) PostReading(ctx context.Context, source string, payload []byte, principal, idempotencyKey string) (DocumentPublished, error) {
	l, err := c.SourceLayout(ctx, source)
	if err != nil {
		return DocumentPublished{}, err
	}
	if l.Encryption == "server" {
		// The server splits and encrypts a server-mode reading.
		var out DocumentPublished
		_, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/sources/"+url.PathEscape(source)+"/readings", c.StorageToken,
			bytes.NewReader(payload), int64(len(payload)), map[string]string{"Content-Type": "application/json", "Idempotency-Key": idempotencyKey}, &out)
		return out, err
	}
	def, err := sources.Parse(l.Definition)
	if err != nil || def.ID != source || len(l.Recipients) != len(def.Groups) {
		return DocumentPublished{}, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
	}
	splitter, err := def.Layout().Compile()
	if err != nil {
		return DocumentPublished{}, err
	}
	reading, err := splitter.Split(payload, principal)
	if err != nil {
		return DocumentPublished{}, err
	}
	if idempotencyKey == "" {
		idempotencyKey = cryptowire.NewUUID().String()
	}
	declared := make([]map[string][]string, len(reading.Fields))
	for i, f := range reading.Fields {
		declared[i] = map[string][]string{"fields": f}
	}
	body, n := jsonBody(map[string]any{"source_version": l.Version, "key": reading.Key, "idempotency_key": idempotencyKey, "units": declared})
	var in documentIntentJSON
	if _, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/sources/"+url.PathEscape(source)+"/readings/begin", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &in); err != nil {
		return DocumentPublished{}, err
	}
	if len(in.Units) != len(reading.Units) {
		return DocumentPublished{}, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
	}
	p, err := in.params()
	if err != nil {
		return DocumentPublished{}, err
	}
	p.NormalizationVersion, p.ExtractionVersion = jsonunits.Profile, fmt.Sprintf("%s:%s:%d", sources.Format, def.ID, l.Version)
	var units []*crypto.SealedUnit
	defer func() {
		for _, u := range units {
			u.Close()
		}
	}()
	perUnit := make([][]crypto.Recipient, len(in.Units))
	for i, u := range in.Units {
		sealed, err := c.stageUnit(ctx, p.Tenant, u, reading.Units[i])
		if err != nil {
			return DocumentPublished{}, err
		}
		units = append(units, sealed)
		for _, k := range l.Recipients[i] {
			fp, err := cryptowire.ParseDigest(k.Fingerprint)
			if err != nil {
				return DocumentPublished{}, err
			}
			perUnit[i] = append(perUnit[i], crypto.Recipient{Fingerprint: fp, KeyVersion: k.KeyVersion})
		}
	}
	sealed, err := crypto.SealReading(p, units, perUnit, c.Signer, c.Trust, c.now())
	if err != nil {
		return DocumentPublished{}, err
	}
	return c.finalizeDocument(ctx, in.IntentID, sealed)
}
