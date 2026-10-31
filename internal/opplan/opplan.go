// Package opplan holds the canonical plan of a protected operation as the
// platform renders it for an approver (specification 2.5, APR-005). It is
// neutral: storage, control and the optional executor describe their
// operations with it, so approvals depend on no tool-execution code
// (MOD-004).
package opplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Target is one exact resource an operation acts on.
type Target struct {
	Role    string `json:"role"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

// Summary is what an approver sees. Every field except UnverifiedNote is
// rendered by the platform from the canonical plan; a note supplied by an
// agent or model is kept apart and marked unverified (APR-005).
type Summary struct {
	// Operation names the registered operation.
	Operation       string   `json:"operation"`
	OperationDigest string   `json:"operation_digest"`
	Action          string   `json:"action"`
	Targets         []Target `json:"targets"`
	// Changes lists relevant metadata changes, field to new value.
	Changes       map[string]string `json:"changes,omitempty"`
	Preconditions []string          `json:"preconditions,omitempty"`
	// Destination, AmountMinor with Currency, and HighestLabel are set when
	// the operation has them.
	Destination  string `json:"destination,omitempty"`
	AmountMinor  int64  `json:"amount_minor,omitempty"`
	Currency     string `json:"currency,omitempty"`
	HighestLabel string `json:"highest_label,omitempty"`
	// Details holds the operation's canonical arguments, if any.
	Details        json.RawMessage `json:"details,omitempty"`
	UnverifiedNote string          `json:"unverified_note,omitempty"`
}

// Digest is the operation digest of a plan: SHA-256 over a domain prefix
// and the plan's JSON encoding without its digest field and unverified
// note (encoding/json writes struct fields in declaration order and map
// keys sorted, so the encoding is canonical). An approval binds this
// digest, so a plan must exclude identifiers allocated per attempt
// (APR-001).
func Digest(s Summary) string {
	s.OperationDigest, s.UnverifiedNote = "", ""
	b, err := json.Marshal(s)
	if err != nil {
		panic("opplan: a summary always encodes: " + err.Error())
	}
	h := sha256.New()
	h.Write([]byte("fga.opplan/v1\x00"))
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
