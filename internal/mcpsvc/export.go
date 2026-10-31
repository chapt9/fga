package mcpsvc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fga/internal/mcpwire"
)

// ExportInput is the input of documents.export.
type ExportInput struct {
	Bucket    string   `json:"bucket" jsonschema:"the bucket"`
	Key       string   `json:"key" jsonschema:"the object's or document's key"`
	Version   string   `json:"version,omitempty" jsonschema:"a version ID; the current version when absent"`
	Units     []string `json:"units,omitempty" jsonschema:"for a document: up to 100 unit IDs; every readable unit when absent"`
	Recipient string   `json:"recipient,omitempty" jsonschema:"for client-mode content: the fingerprint of the recipient key to export for; your declared key when absent"`
}

// ExportOutput is a complete export. Server mode: the plaintext of the
// exported units, or of the object (base64). Client mode: Package, the
// ciphertext and the recipient's existing envelopes, which only that
// recipient's client can open; the server never rewraps or decrypts.
type ExportOutput struct {
	DocumentVersion string           `json:"document_version_id,omitempty"`
	Units           []UnitText       `json:"units,omitempty"`
	Object          string           `json:"object,omitempty"`
	Package         *mcpwire.Package `json:"package,omitempty"`
}

var errNeedRecipient = errors.New("a client-mode export needs a recipient: pass recipient, or declare the " + mcpwire.Capability + " capability")

// export is documents.export: the native export routes and their checks,
// export on the version and export-key on every unit besides the reads
// (the compound export operation of the specification's key operations).
// Each mode's route refuses the other mode; the tool then takes the other.
func (s *Service) export(ctx context.Context, req *mcp.CallToolRequest, in ExportInput) (*mcp.CallToolResult, ExportOutput, error) {
	c, err := callerOf(req.Extra)
	if err != nil {
		return nil, ExportOutput{}, err
	}
	if in.Bucket == "" || in.Key == "" {
		return nil, ExportOutput{}, errInvalid
	}
	ev, err := s.authorize(ctx, c, ToolExport)
	if err != nil {
		return nil, ExportOutput{}, err
	}
	t := target{bucket: in.Bucket, key: in.Key, version: in.Version}
	recipient := in.Recipient
	if recipient == "" {
		recipient = recipientOf(req.Session)
	}
	result := func(out ExportOutput, text string) (*mcp.CallToolResult, ExportOutput, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	}

	if in.Units == nil {
		q := url.Values{"key": {t.key}}
		if t.version != "" {
			q.Set("version", t.version)
		}
		b, err := s.storageBytes(ctx, ev, bucketPath(t.bucket, "/object/export"), q, s.d.Limits.MaxBytes)
		switch {
		case err == nil:
			text := fmt.Sprintf("%d bytes of binary content, in the structured result (base64)", len(b))
			if utf8.Valid(b) {
				text = string(b)
			}
			return result(ExportOutput{Object: base64.StdEncoding.EncodeToString(b)}, text)
		case errors.Is(err, errClientMode):
			if recipient == "" {
				return nil, ExportOutput{}, errNeedRecipient
			}
			pkg, err := s.exportObjectPackage(ctx, ev, t, recipient)
			if err != nil {
				return nil, ExportOutput{}, err
			}
			return result(ExportOutput{Package: pkg}, describe(pkg))
		case !errors.Is(err, errNotFound):
			return nil, ExportOutput{}, err
		}
	}

	// A document: the named units, or every readable one.
	units, version := in.Units, t.version
	if units == nil {
		listed, v, err := s.listUnits(ctx, ev, t, "document", false, maxSelect)
		if err != nil {
			return nil, ExportOutput{}, err
		}
		for _, u := range listed {
			units = append(units, u.Unit)
		}
		version = v
	}
	if len(units) == 0 {
		return nil, ExportOutput{}, errNotFound
	}
	if len(units) > maxSelect {
		return nil, ExportOutput{}, errTooLarge
	}
	q := url.Values{"key": {t.key}}
	if version != "" {
		q.Set("version", version)
	}
	var plain struct {
		DocumentVersion string     `json:"document_version_id"`
		Units           []UnitText `json:"units"`
	}
	err = s.storageJSON(ctx, ev, bucketPath(t.bucket, "/document/export/content"), q, map[string][]string{"units": units}, &plain)
	switch {
	case err == nil:
		return result(ExportOutput{DocumentVersion: plain.DocumentVersion, Units: plain.Units}, joined(plain.Units))
	case !errors.Is(err, errClientMode):
		return nil, ExportOutput{}, err
	case recipient == "":
		return nil, ExportOutput{}, errNeedRecipient
	}
	var x struct {
		DocumentVersion string `json:"document_version_id"`
		Recipient       string `json:"recipient"`
		Units           []struct {
			Unit struct {
				Unit                string `json:"unit_id"`
				UnitVersion         string `json:"unit_version_id"`
				Descriptor          string `json:"descriptor"`
				DescriptorSignature string `json:"descriptor_signature"`
			} `json:"unit"`
			Ciphertext string `json:"ciphertext"`
			delivered
		} `json:"units"`
	}
	if err := s.storageJSON(ctx, ev, bucketPath(t.bucket, "/document/export"), q,
		map[string]any{"unit_ids": units, "recipient": recipient}, &x); err != nil {
		return nil, ExportOutput{}, err
	}
	pkg := &mcpwire.Package{Profile: mcpwire.Profile, Bucket: t.bucket, Key: t.key, Recipient: x.Recipient, DocumentVersion: x.DocumentVersion,
		Units: []mcpwire.UnitPackage{}}
	for _, u := range x.Units {
		pkg.Units = append(pkg.Units, mcpwire.UnitPackage{Unit: u.Unit.Unit, UnitVersion: u.Unit.UnitVersion, Descriptor: u.Unit.Descriptor,
			DescriptorSignature: u.Unit.DescriptorSignature, Delivery: u.delivery(), Ciphertext: u.Ciphertext})
	}
	return result(ExportOutput{Package: pkg}, describe(pkg))
}

// exportObjectPackage is the client-mode object export for recipient
// (POST …/object/export): its existing envelope only.
func (s *Service) exportObjectPackage(ctx context.Context, ev string, t target, recipient string) (*mcpwire.Package, error) {
	q := url.Values{"key": {t.key}}
	if t.version != "" {
		q.Set("version", t.version)
	}
	var x struct {
		Version struct {
			Version string `json:"version_id"`
		} `json:"version"`
		Descriptor          string `json:"descriptor"`
		DescriptorSignature string `json:"descriptor_signature"`
		Ciphertext          string `json:"ciphertext"`
		delivered
	}
	if err := s.storageJSON(ctx, ev, bucketPath(t.bucket, "/object/export"), q, map[string]string{"recipient": recipient}, &x); err != nil {
		return nil, err
	}
	if base64.StdEncoding.DecodedLen(len(x.Ciphertext)) > int(s.d.Limits.MaxBytes)+3 {
		return nil, errTooLarge
	}
	return &mcpwire.Package{Profile: mcpwire.Profile, Bucket: t.bucket, Key: t.key, Recipient: recipient,
		Object: &mcpwire.ObjectPackage{Version: x.Version.Version, Descriptor: x.Descriptor, DescriptorSignature: x.DescriptorSignature,
			Delivery: x.delivery(), Ciphertext: x.Ciphertext}}, nil
}
