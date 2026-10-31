package mcpsvc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/mcpwire"
)

// recipientOf returns the recipient key the session's client declared
// with the encrypted-package capability, or "" (MCP-005).
func recipientOf(ss *mcp.ServerSession) string {
	if ss == nil {
		return ""
	}
	p := ss.InitializeParams()
	if p == nil || p.Capabilities == nil {
		return ""
	}
	c, ok := mcpwire.ParseCapability(p.Capabilities.Experimental)
	if !ok {
		return ""
	}
	return c.Recipient
}

// delivered is an envelope delivery as the native package routes return
// it; binary fields stay base64.
type delivered struct {
	EnvelopeID       string           `json:"envelope_id"`
	Envelope         mcpwire.Envelope `json:"envelope"`
	Receipt          string           `json:"receipt"`
	ReceiptSignature string           `json:"receipt_signature"`
}

func (d delivered) delivery() mcpwire.Delivery {
	return mcpwire.Delivery{EnvelopeID: d.EnvelopeID, Envelope: d.Envelope, Receipt: d.Receipt, ReceiptSignature: d.ReceiptSignature}
}

// objectPackage is the client-mode form of an object read: the version's
// package for recipient (GET …/object/package) and its exact ciphertext
// (GET …/object/ciphertext of that version), within MaxBytes. The storage
// role decides the read and the envelope delivery as for a native client;
// nothing here can open the envelope.
func (s *Service) objectPackage(ctx context.Context, ev string, t target, recipient string) (*mcpwire.Package, error) {
	q := url.Values{"key": {t.key}, "recipient": {recipient}}
	if t.version != "" {
		q.Set("version", t.version)
	}
	var p struct {
		Version struct {
			Version          string `json:"version_id"`
			CiphertextLength int64  `json:"ciphertext_length"`
		} `json:"version"`
		Descriptor          string `json:"descriptor"`
		DescriptorSignature string `json:"descriptor_signature"`
		delivered
	}
	if err := s.storageJSON(ctx, ev, bucketPath(t.bucket, "/object/package"), q, nil, &p); err != nil {
		return nil, err
	}
	if p.Version.CiphertextLength > s.d.Limits.MaxBytes {
		return nil, errTooLarge
	}
	ct, err := s.ciphertext(ctx, ev, bucketPath(t.bucket, "/object/ciphertext"), url.Values{"key": {t.key}, "version": {p.Version.Version}},
		p.Version.CiphertextLength)
	if err != nil {
		return nil, err
	}
	return &mcpwire.Package{Profile: mcpwire.Profile, Bucket: t.bucket, Key: t.key, Recipient: recipient,
		Object: &mcpwire.ObjectPackage{Version: p.Version.Version, Descriptor: p.Descriptor, DescriptorSignature: p.DescriptorSignature,
			Delivery: p.delivery(), Ciphertext: ct}}, nil
}

// unitPackages is the client-mode form of a document read: each unit's
// package for recipient (GET …/document/unit/package) and its exact
// ciphertext, all of one version, within MaxBytes together.
func (s *Service) unitPackages(ctx context.Context, ev string, t target, version string, units []listedUnit, recipient string) (*mcpwire.Package, error) {
	pkg := &mcpwire.Package{Profile: mcpwire.Profile, Bucket: t.bucket, Key: t.key, Recipient: recipient, DocumentVersion: version,
		Units: []mcpwire.UnitPackage{}}
	budget := s.d.Limits.MaxBytes
	for _, u := range units {
		var p struct {
			Unit struct {
				Unit                string `json:"unit_id"`
				UnitVersion         string `json:"unit_version_id"`
				CiphertextLength    int64  `json:"ciphertext_length"`
				Descriptor          string `json:"descriptor"`
				DescriptorSignature string `json:"descriptor_signature"`
			} `json:"unit"`
			delivered
		}
		q := url.Values{"key": {t.key}, "version": {version}, "unit": {u.Unit}, "recipient": {recipient}}
		if err := s.storageJSON(ctx, ev, bucketPath(t.bucket, "/document/unit/package"), q, nil, &p); err != nil {
			return nil, err
		}
		switch {
		case p.Unit.Unit != u.Unit:
			return nil, errConflict
		case p.Unit.CiphertextLength > budget:
			return nil, errTooLarge
		}
		ct, err := s.ciphertext(ctx, ev, bucketPath(t.bucket, "/document/unit/ciphertext"),
			url.Values{"key": {t.key}, "version": {version}, "unit": {u.Unit}}, p.Unit.CiphertextLength)
		if err != nil {
			return nil, err
		}
		budget -= p.Unit.CiphertextLength
		pkg.Units = append(pkg.Units, mcpwire.UnitPackage{Unit: p.Unit.Unit, UnitVersion: p.Unit.UnitVersion, Descriptor: p.Unit.Descriptor,
			DescriptorSignature: p.Unit.DescriptorSignature, Delivery: p.delivery(), Ciphertext: ct})
	}
	return pkg, nil
}

// ciphertext reads exactly length bytes of ciphertext, as base64.
func (s *Service) ciphertext(ctx context.Context, ev, path string, q url.Values, length int64) (string, error) {
	b, err := s.storageBytes(ctx, ev, path, q, length)
	if err != nil {
		return "", err
	}
	if int64(len(b)) != length {
		return "", errConflict
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// describe is the text an MCP client sees for a package: what it is, and
// that the service returns no plaintext of it.
func describe(p *mcpwire.Package) string {
	what := "an object version"
	if p.Object == nil {
		what = fmt.Sprintf("%d unit(s) of document version %s", len(p.Units), p.DocumentVersion)
	}
	return fmt.Sprintf("Client-mode content, encrypted for recipient %s: %s of fga://%s/%s (%s). A client with the %s capability "+
		"verifies and decrypts it; the MCP service returns no plaintext of client-mode content.", p.Recipient, what, p.Bucket, p.Key,
		p.Profile, mcpwire.Capability)
}
