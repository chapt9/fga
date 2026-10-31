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

// ErrDelivery is returned when the keys role refuses a delivery.
var ErrDelivery = errors.New("rpc: the keys role refused the delivery")

// Deliver implements content.EnvelopeDelivery.
func (c KeysClient) Deliver(ctx context.Context, d signing.Signed, envelopeID string) (envelope.Delivered, error) {
	var out keysapi.DeliveredBody
	err := post(ctx, c.HTTP, c.BaseURL+"/internal/v1/deliver", keysapi.DeliverBody{Payload: d.Payload, JWS: d.JWS, EnvelopeID: envelopeID}, &out)
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
