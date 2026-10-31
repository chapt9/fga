// Package mcpwire is the encrypted-package profile that the MCP role and a
// client-side MCP bridge share (MCP-005, RCP-007, docs/design/mcp-role.md):
// how an MCP client declares that it verifies and decrypts client-mode
// content itself, and the form in which the MCP role then returns such
// content. It holds formats only: no keys and no cryptography, so both
// sides may link it.
//
// Every binary field is standard base64, as the native API sends it. The
// MCP role passes descriptors, envelopes and receipts through unchanged,
// and only the recipient's client can open the envelope.
package mcpwire

import (
	"encoding/json"
	"strings"
)

// Capability is the experimental MCP client capability, declared at
// initialize, of a client that verifies and decrypts client-mode content
// itself. Its value is a ClientCapability.
const Capability = "fga.encrypted-package"

// Version is the profile version this package describes.
const Version = 1

// Profile names the profile in a Package.
const Profile = "fga.encrypted-package/v1"

// MIMEType is the type of a resources/read content that holds a Package
// as JSON text.
const MIMEType = "application/vnd.fga.encrypted-package+json"

// ClientCapability is the value of Capability: the profile version the
// client speaks and the fingerprint of the recipient key it decrypts with.
type ClientCapability struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"`
}

// Experimental returns the capability as an entry of the MCP client
// capabilities' experimental map.
func (c ClientCapability) Experimental() map[string]any {
	return map[string]any{Capability: map[string]any{"version": c.Version, "recipient": c.Recipient}}
}

// ParseCapability reads the capability from a client's experimental
// capabilities. It reports false unless the client declared this version
// with a recipient fingerprint.
func ParseCapability(experimental map[string]any) (ClientCapability, bool) {
	raw, ok := experimental[Capability]
	if !ok {
		return ClientCapability{}, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return ClientCapability{}, false
	}
	var c ClientCapability
	if json.Unmarshal(b, &c) != nil || c.Version != Version || !strings.HasPrefix(c.Recipient, "sha256:") {
		return ClientCapability{}, false
	}
	return c, true
}

// Envelope is a recipient envelope as its creating client signed it.
type Envelope struct {
	Context    string `json:"context"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// Delivery is an envelope the keys role delivered for the recipient, with
// its signed delivery receipt.
type Delivery struct {
	EnvelopeID       string   `json:"envelope_id"`
	Envelope         Envelope `json:"envelope"`
	Receipt          string   `json:"receipt"`
	ReceiptSignature string   `json:"receipt_signature"`
}

// ObjectPackage is one client-mode object version for the recipient: its
// signed descriptor, the delivered envelope and the exact ciphertext.
type ObjectPackage struct {
	Version             string   `json:"version_id"`
	Descriptor          string   `json:"descriptor"`
	DescriptorSignature string   `json:"descriptor_signature"`
	Delivery            Delivery `json:"delivery"`
	Ciphertext          string   `json:"ciphertext"`
}

// UnitPackage is one client-mode unit or entry for the recipient.
type UnitPackage struct {
	Unit                string   `json:"unit_id"`
	UnitVersion         string   `json:"unit_version_id"`
	Descriptor          string   `json:"descriptor"`
	DescriptorSignature string   `json:"descriptor_signature"`
	Delivery            Delivery `json:"delivery"`
	Ciphertext          string   `json:"ciphertext"`
}

// Package is the encrypted form of one MCP read or export: an object
// version, or units of one document version, for Recipient.
type Package struct {
	Profile         string         `json:"profile"`
	Bucket          string         `json:"bucket"`
	Key             string         `json:"key"`
	Recipient       string         `json:"recipient"`
	Object          *ObjectPackage `json:"object,omitempty"`
	DocumentVersion string         `json:"document_version_id,omitempty"`
	Units           []UnitPackage  `json:"units,omitempty"`
}
