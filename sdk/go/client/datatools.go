package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"fga/internal/cryptowire"
	"fga/internal/jsonunits"
	"fga/sdk/go/crypto"
)

// Data tools (docs/design/mcp-data-tools.md, DTL-004, DTL-009). Over a
// client-mode source a call answers the caller's unit packages; the client
// opens them with its own key and applies the tool's projection, which
// gives the answer a server-mode tool gives.

// DataTool is a data tool the caller may discover.
type DataTool struct {
	Name         string          `json:"name"`
	Version      int             `json:"version"`
	Description  string          `json:"description"`
	Encryption   string          `json:"encryption"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema"`
}

// ListDataTools lists every data tool the caller may discover.
func (c *Client) ListDataTools(ctx context.Context) ([]DataTool, error) {
	var out []DataTool
	for continuation := ""; ; {
		var page struct {
			Tools        []DataTool `json:"tools"`
			Continuation string     `json:"continuation"`
		}
		u := c.StorageURL + "/v1/data-tools"
		if continuation != "" {
			u += "?continuation=" + url.QueryEscape(continuation)
		}
		if _, err := c.do(ctx, http.MethodGet, u, c.StorageToken, nil, -1, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Tools...)
		if continuation = page.Continuation; continuation == "" {
			return out, nil
		}
	}
}

// toolPackage is one unit of a client-mode reading for the caller's key.
type toolPackage struct {
	Unit       UnitEntry    `json:"unit"`
	Envelope   envelopeJSON `json:"envelope"`
	Ciphertext []byte       `json:"ciphertext"`
}

// toolReading is a reading as a call answers it.
type toolReading struct {
	Reading  json.RawMessage `json:"reading,omitempty"`
	Origin   json.RawMessage `json:"origin"`
	Packages []toolPackage   `json:"packages,omitempty"`
}

// toolAnswer is a call's answer as the server sends it.
type toolAnswer struct {
	Tool       string                `json:"tool"`
	Version    int                   `json:"version"`
	Encrypted  bool                  `json:"encrypted,omitempty"`
	Projection *jsonunits.Projection `json:"projection,omitempty"`
	Reading    json.RawMessage       `json:"reading,omitempty"`
	Origin     json.RawMessage       `json:"origin,omitempty"`
	Packages   []toolPackage         `json:"packages,omitempty"`
	Readings   *[]toolReading        `json:"readings,omitempty"`
}

// CallDataTool calls data tool name with args, a JSON object or nil, at
// its active version or the pinned version, and returns the answer as
// JSON: for a latest tool {"tool", "version", "reading", "origin"}, for a
// history tool {"tool", "version", "readings": [{"reading", "origin"}]}.
// For a tool over client-mode readings the client opens each package with
// its own key, checks that the unit's signed descriptor names the
// reading's version, and applies the tool's projection.
func (c *Client) CallDataTool(ctx context.Context, name string, args json.RawMessage, version int) (json.RawMessage, error) {
	call := map[string]any{}
	if len(args) > 0 {
		call["arguments"] = args
	}
	if version > 0 {
		call["version"] = version
	}
	if c.Recipient != nil {
		call["recipient"] = c.Recipient.Fingerprint().String()
	}
	body, n := jsonBody(call)
	var ans toolAnswer
	if _, err := c.do(ctx, http.MethodPost, c.StorageURL+"/v1/data-tools/"+url.PathEscape(name)+"/call", c.StorageToken, body, n,
		map[string]string{"Content-Type": "application/json"}, &ans); err != nil {
		return nil, err
	}
	if ans.Encrypted {
		if ans.Projection == nil || c.Recipient == nil {
			return nil, &Error{Status: http.StatusBadGateway, Code: "UNEXPECTED_RESPONSE"}
		}
		trust := crypto.StatusTrust{TrustStore: c.Trust, Status: func(fp cryptowire.Digest) (string, error) { return c.SignerStatus(ctx, fp) }}
		open := func(r *toolReading) (bool, error) {
			var origin struct {
				DocumentVersion string `json:"document_version_id"`
			}
			if err := json.Unmarshal(r.Origin, &origin); err != nil {
				return false, err
			}
			units := map[string][]byte{}
			for _, p := range r.Packages {
				var plain bytes.Buffer
				d, err := crypto.DecryptUnit(&plain, bytes.NewReader(p.Ciphertext), crypto.UnitPackage{Descriptor: p.Unit.Descriptor,
					DescriptorSignature: p.Unit.DescriptorSignature,
					Envelope:            crypto.Envelope{Context: p.Envelope.Context, Ciphertext: p.Envelope.Ciphertext, Signature: p.Envelope.Signature}},
					c.Recipient, trust)
				if err != nil {
					return false, err
				}
				if d.UnitID != p.Unit.Unit || d.UnitVersionID != p.Unit.UnitVersion || d.DocumentVersionID != origin.DocumentVersion {
					return false, ErrIdentity
				}
				group, _, err := jsonunits.ParseUnit(plain.Bytes())
				if err != nil {
					return false, err
				}
				units[group] = plain.Bytes()
			}
			projected, ok, err := ans.Projection.Apply(units)
			if err != nil || !ok {
				return false, err
			}
			r.Reading, err = json.Marshal(projected)
			r.Packages = nil
			return true, err
		}
		if ans.Readings == nil {
			r := toolReading{Origin: ans.Origin, Packages: ans.Packages}
			ok, err := open(&r)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, &Error{Status: http.StatusNotFound, Code: "NOT_FOUND"}
			}
			ans.Reading, ans.Packages = r.Reading, nil
		} else {
			kept := []toolReading{}
			for i := range *ans.Readings {
				ok, err := open(&(*ans.Readings)[i])
				if err != nil {
					return nil, err
				}
				if ok {
					kept = append(kept, (*ans.Readings)[i])
				}
			}
			ans.Readings = &kept
		}
		ans.Encrypted, ans.Projection = false, nil
	}
	return json.Marshal(ans)
}
