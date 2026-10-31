// Package enforce holds what every enforcing role does to obtain and accept
// a decision (specification 2.5, DEC-001, DEC-002, TRU-003): the caller, the
// decision client contract, planned checks, and Authorize, which asks the
// decision role for a registered operation and accepts only an ALLOW bound
// to exactly that operation. The storage and keys roles share it.
package enforce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/opplan"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Audiences of the storage and keys roles: of the decisions they enforce
// and of their users' tokens.
const (
	Audience     = "fga-storage"
	KeysAudience = "fga-keys"
)

// Errors of Authorize. A denial and an absent target are both
// ErrNotFound (DEC-010).
var (
	ErrNotFound    = errors.New("not found")
	ErrUnavailable = errors.New("a dependency is unavailable")
	// ErrConflict means the operation raced a change to what it relies
	// on; the caller may begin again.
	ErrConflict = errors.New("conflict")
	// ErrApprovalNotUsable means the approval the caller named is not
	// approved for exactly this operation (rejected, expired, consumed, or
	// requested for another operation, requester or resource state).
	ErrApprovalNotUsable = errors.New("the approval is not usable for this operation")
)

// ApprovalRequired is the error of an operation that every check allows
// once an approval is given (APR-001). ID names the pending approval;
// telling the caller tells them only that they could do this with an
// approval.
type ApprovalRequired struct {
	ID string
}

func (e *ApprovalRequired) Error() string { return "approval required: " + e.ID }

// Options are the optional inputs of an authorization.
type Options struct {
	// Plan is the operation's canonical plan (APR-005). With a plan, the
	// operation digest is the plan's, so an approval binds exactly the
	// planned operation, and a NEEDS_APPROVAL answer opens an approval.
	Plan *opplan.Summary
	// Approval names an approval the caller was given for this operation.
	Approval string
}

// Caller is an authenticated user: the subject of a verified access token,
// acting for itself (TB1).
type Caller struct {
	Tenant    string
	Principal string
	// Token is the user's access token, passed to the decision role as
	// first-hop evidence (TRU-003).
	Token string
	// Approval is the approval the caller presents with this request. Only
	// operations with a plan send it to the decision role.
	Approval string
}

// Decider obtains decisions from the decision role.
type Decider interface {
	Decide(ctx context.Context, req decisionsvc.Request) (decisionsvc.Response, error)
}

// Check is one check of a registered operation, as an enforcing role plans
// it.
type Check struct {
	ID       string
	Role     string
	Action   string
	Resource decisionsvc.Alias
	Version  string
	// Recipient is the key fingerprint of a recipient-eligibility check.
	Recipient string
}

// Authorize asks the decision role for a decision for operation op with
// checks, as caller, for audience, and returns the verified signed record.
// Only an ALLOW whose record is bound to exactly this operation counts
// (DEC-002); everything else is ErrNotFound, or ErrUnavailable for a
// failure. verifier verifies decisions for the enforcing role's own
// audience; a decision for another audience is only checked for integrity
// here and verified by that role.
func Authorize(ctx context.Context, d Decider, verifier *signing.Verifier, cat *catalog.Store, c Caller, op, audience string,
	singleUse bool, checks []Check) (signing.Signed, signing.Record, error) {
	return AuthorizeWith(ctx, d, verifier, cat, c, op, audience, singleUse, checks, Options{})
}

// AuthorizeWith is Authorize with a plan and an approval. A NEEDS_APPROVAL
// answer with an approval ID is *ApprovalRequired; an approval the decision
// role refuses is ErrApprovalNotUsable.
func AuthorizeWith(ctx context.Context, d Decider, verifier *signing.Verifier, cat *catalog.Store, c Caller, op, audience string,
	singleUse bool, checks []Check, o Options) (signing.Signed, signing.Record, error) {
	id, err := cat.GetIdentity(ctx, c.Tenant, c.Principal)
	if err != nil {
		return signing.Signed{}, signing.Record{}, ErrNotFound
	}
	req := decisionsvc.Request{RequestID: cryptowire.NewUUID().String(), Tenant: c.Tenant, Operation: op,
		OperationID: cryptowire.NewUUID().String(), Audience: audience, SingleUse: singleUse,
		Actor: decisionsvc.Ref{ID: c.Principal, Revision: id.Revision}, Evidence: c.Token}
	h := sha256.New()
	fmt.Fprintf(h, "fga.storage-operation/v1\n%s\n%s\n", op, c.Tenant)
	for _, ch := range checks {
		dc := decisionsvc.Check{ID: ch.ID, Role: ch.Role, Action: ch.Action, Resource: ch.Resource, Version: ch.Version}
		if ch.Recipient != "" {
			dc.Kind, dc.PrincipalBinding = string(registry.KindRecipientEligibility), ch.Recipient
		}
		req.Checks = append(req.Checks, dc)
		fmt.Fprintf(h, "%s %s %s %s/%s/%s/%s %s %s\n", ch.ID, ch.Role, ch.Action, ch.Resource.Namespace, ch.Resource.Name,
			ch.Resource.Type, ch.Resource.ID, ch.Version, ch.Recipient)
	}
	req.OperationDigest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	if o.Plan != nil {
		if o.Approval == "" {
			o.Approval = c.Approval
		}
		req.Approval = o.Approval
		plan := *o.Plan
		plan.Operation = op
		req.Plan, req.OperationDigest = &plan, opplan.Digest(plan)
	}

	resp, err := d.Decide(ctx, req)
	switch {
	case err != nil:
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision: %v", ErrUnavailable, err)
	case resp.Outcome == "ERROR":
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision %s", ErrUnavailable, resp.Reason)
	case resp.Outcome == "NEEDS_APPROVAL" && resp.ApprovalID != "":
		return signing.Signed{}, signing.Record{}, &ApprovalRequired{ID: resp.ApprovalID}
	case resp.Outcome == "DENY" && resp.Reason == string(decisionsvc.ReasonApprovalNotUsable) && o.Approval != "":
		return signing.Signed{}, signing.Record{}, ErrApprovalNotUsable
	case resp.Outcome != "ALLOW" || resp.Signed == nil:
		// Absent and denied look the same to the caller (DEC-010).
		return signing.Signed{}, signing.Record{}, ErrNotFound
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Signed.Payload)
	if err != nil {
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: malformed decision", ErrUnavailable)
	}
	signed := signing.Signed{Payload: payload, JWS: resp.Signed.JWS}
	var rec signing.Record
	if verifier.Audience() == audience {
		rec, err = verifier.Check(signed)
	} else {
		rec, err = verifier.Inspect(signed)
	}
	if err != nil || !bound(rec, req) || rec.Context.Approval.ID != "" && rec.Context.Approval.ID != o.Approval {
		return signing.Signed{}, signing.Record{}, fmt.Errorf("%w: decision does not verify", ErrUnavailable)
	}
	return signed, rec, nil
}

// bound reports whether rec is the decision for exactly req: tenant,
// actor, operation, digest and every check's role, action and version.
func bound(rec signing.Record, req decisionsvc.Request) bool {
	if rec.Tenant != req.Tenant || rec.Actor.ID != req.Actor.ID || rec.Operation != req.Operation ||
		rec.OperationDigest != req.OperationDigest || rec.SingleUse != req.SingleUse || len(rec.Checks) != len(req.Checks) {
		return false
	}
	for i, c := range req.Checks {
		r := rec.Checks[i]
		if r.ID != c.ID || r.Version != c.Version || r.PrincipalBinding != c.PrincipalBinding ||
			(c.Resource.ID != "" && r.ResourceID != c.Resource.ID) || (c.Resource.Type != "" && r.ResourceType != c.Resource.Type) {
			return false
		}
	}
	return true
}
