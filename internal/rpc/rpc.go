// Package rpc holds the clients one role uses to call another: the storage
// and keys roles' decision client (TB2) and the storage role's envelope
// delivery client (TB3). Workload identity is the HTTP client's TLS
// configuration, or the single development adapter on loopback.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/envelope"
	"fga/internal/keysapi"
	"fga/internal/signing"
	"fga/internal/strictjson"
)

// MaxResponse bounds a response body.
const MaxResponse = 1 << 20

// DecisionClient calls the decision role's adapter facade. It implements
// enforce.Decider.
type DecisionClient struct {
	BaseURL string
	HTTP    *http.Client
}

var _ enforce.Decider = DecisionClient{}

// Decide implements enforce.Decider.
func (c DecisionClient) Decide(ctx context.Context, req decisionsvc.Request) (decisionsvc.Response, error) {
	var resp decisionsvc.Response
	err := post(ctx, c.HTTP, c.BaseURL+"/v1/decide-batch", req, &resp)
	return resp, err
}

// KeysClient calls the keys role's internal delivery endpoint. It
// implements content.EnvelopeDelivery.
type KeysClient struct {
	BaseURL string
	HTTP    *http.Client
}

// SealDataKey asks the keys role for a server-mode upload intent's data key
// against a decision for storage.key.seal-create or seal-version (SSE-003).
// The caller owns the key and clears it after use (SSE-004).
func (c KeysClient) SealDataKey(ctx context.Context, d signing.Signed, intentID string) (envelope.DataKey, error) {
	var out keysapi.DataKeyBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/seal",
		keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, IntentID: intentID}, &out); err != nil {
		return envelope.DataKey{}, keysError(err)
	}
	return envelope.DataKey{Key: out.Key, Sealed: out.Sealed, KEKVersion: out.KEKVersion}, nil
}

// ReleaseDataKey asks the keys role for a server-mode version's data key
// against a decision for storage.key.release or release-history (SSE-003).
func (c KeysClient) ReleaseDataKey(ctx context.Context, d signing.Signed, versionID string) ([]byte, error) {
	var out keysapi.DataKeyBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/release",
		keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, VersionID: versionID}, &out); err != nil {
		return nil, keysError(err)
	}
	return out.Key, nil
}

// SealDocumentKeys asks the keys role for the data keys of every new unit
// of a server-mode document intent, against a decision for
// storage.key.seal-document-create or seal-document-version (SSE-003).
func (c KeysClient) SealDocumentKeys(ctx context.Context, d signing.Signed, docIntentID string) ([]envelope.DataKey, error) {
	var out keysapi.DataKeysBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/seal-document",
		keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, IntentID: docIntentID}, &out); err != nil {
		return nil, keysError(err)
	}
	keys := make([]envelope.DataKey, 0, len(out.Keys))
	for _, k := range out.Keys {
		keys = append(keys, envelope.DataKey{Key: k.Key, Sealed: k.Sealed, KEKVersion: k.KEKVersion, Intent: k.IntentID})
	}
	return keys, nil
}

// ReleaseUnitKey asks the keys role for a server-mode unit's or entry's
// data key in one document version, against a decision for
// storage.key.release-unit or release-entry (SSE-003).
func (c KeysClient) ReleaseUnitKey(ctx context.Context, d signing.Signed, documentVersionID, unitID string) ([]byte, error) {
	var out keysapi.DataKeyBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/release-unit",
		keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, VersionID: documentVersionID, UnitID: unitID}, &out); err != nil {
		return nil, keysError(err)
	}
	return out.Key, nil
}

// ReleaseOriginalKey asks the keys role for a server-mode original file's
// data key, against a decision for storage.key.release-original and the
// complete-content decisions extra (CNT-003, SSE-003).
func (c KeysClient) ReleaseOriginalKey(ctx context.Context, d signing.Signed, extra []signing.Signed, documentVersionID string) ([]byte, error) {
	body := keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, VersionID: documentVersionID}
	for _, x := range extra {
		body.Extra = append(body.Extra, keysapi.SignedBody{Payload: x.Payload, JWS: x.JWS})
	}
	var out keysapi.DataKeyBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/release-original", body, &out); err != nil {
		return nil, keysError(err)
	}
	return out.Key, nil
}

// ReleaseDerivedKey asks the keys role for a server-mode derived output's
// data key, against a decision for storage.key.release-derived and the
// reader path extra (DRV-002, SSE-003).
func (c KeysClient) ReleaseDerivedKey(ctx context.Context, d signing.Signed, extra []signing.Signed, versionID string) ([]byte, error) {
	body := keysapi.DataKeyRequest{Payload: d.Payload, JWS: d.JWS, VersionID: versionID}
	for _, x := range extra {
		body.Extra = append(body.Extra, keysapi.SignedBody{Payload: x.Payload, JWS: x.JWS})
	}
	var out keysapi.DataKeyBody
	if err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/data-keys/release-derived", body, &out); err != nil {
		return nil, keysError(err)
	}
	return out.Key, nil
}

// keysError maps the keys role's not-found to the shared one, so a denied
// and an absent target look the same to the caller (CNT-004).
func keysError(err error) error {
	var se statusError
	if errors.As(err, &se) && se == http.StatusNotFound {
		return enforce.ErrNotFound
	}
	return err
}

// ErrDelivery is returned when the keys role refuses a delivery.
var ErrDelivery = errors.New("rpc: the keys role refused the delivery")

// Deliver implements content.EnvelopeDelivery.
func (c KeysClient) Deliver(ctx context.Context, d signing.Signed, envelopeID string, extra ...signing.Signed) (envelope.Delivered, error) {
	var out keysapi.DeliveredBody
	body := keysapi.DeliverBody{Payload: d.Payload, JWS: d.JWS, EnvelopeID: envelopeID}
	for _, x := range extra {
		body.Extra = append(body.Extra, keysapi.SignedBody{Payload: x.Payload, JWS: x.JWS})
	}
	err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/deliver", body, &out)
	var se statusError
	if errors.As(err, &se) && se == http.StatusNotFound {
		return envelope.Delivered{}, enforce.ErrNotFound
	}
	if err != nil {
		return envelope.Delivered{}, err
	}
	return envelope.Delivered{EnvelopeID: out.EnvelopeID, Context: out.Envelope.Context, Ciphertext: out.Envelope.Ciphertext,
		Signature: out.Envelope.Signature, Receipt: out.Receipt, ReceiptSignature: out.ReceiptSignature}, nil
}

type statusError int

func (s statusError) Error() string { return fmt.Sprintf("rpc: status %d", int(s)) }

func post(ctx context.Context, client *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(resp.StatusCode)
	}
	if len(raw) > MaxResponse {
		return errors.New("rpc: response too large")
	}
	return strictjson.Decode(raw, out)
}
