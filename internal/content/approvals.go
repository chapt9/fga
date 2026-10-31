package content

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/approval"
	"fga/internal/audit"
	"fga/internal/opplan"
	"fga/internal/registry"
)

// Approvals of storage operations (ruling 6, APR-001 to APR-005). The
// decision role opens an approval when a policy requires one; an approver
// is anyone whose policy allows approve on the approval's target, other
// than the requester and the acting agent.

// ApprovalView is what an approver, or the requester repeating the
// operation, is shown: the plan the platform rendered (APR-005).
type ApprovalView struct {
	ID          string         `json:"approval_id"`
	Operation   string         `json:"operation"`
	Plan        opplan.Summary `json:"plan"`
	RequestedBy string         `json:"requested_by"`
	State       string         `json:"state"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

func view(a approval.Approval) ApprovalView {
	return ApprovalView{ID: a.ID, Operation: a.Operation, Plan: a.Summary, RequestedBy: a.RequestedBy, State: string(a.State), ExpiresAt: a.ExpiresAt}
}

// approveCheck is the approver's check on an approval's target.
func approveCheck(a approval.Approval) (string, check, bool) {
	switch a.TargetType {
	case "storage.object":
		return registry.OpApproveObject, check{id: "object", role: registry.RoleObject, action: "approve", ref: canonical(a.TargetType, a.TargetID)}, true
	case "storage.bucket":
		return registry.OpApproveBucket, check{id: "bucket", role: registry.RoleBucket, action: "approve", ref: canonical(a.TargetType, a.TargetID)}, true
	}
	return "", check{}, false
}

// PendingApprovals lists up to limit pending approvals the caller may
// decide, after the approval named by after. Each candidate is shown only
// if a fresh approve decision on its target allows it, so the list says
// nothing about approvals the caller may not decide. next continues the
// scan; it is empty at the end.
func (s *Service) PendingApprovals(ctx context.Context, c Caller, after string, limit int) (views []ApprovalView, next string, err error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	cands, err := s.approvals.Pending(ctx, c.Tenant, c.Principal, after, limit)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	views = []ApprovalView{}
	for _, a := range cands {
		op, ch, ok := approveCheck(a)
		if !ok {
			continue
		}
		_, rec, err := s.decide(ctx, c, op, Audience, false, []check{ch})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if err := s.checked(ctx, rec); err != nil {
			continue
		}
		views = append(views, view(a))
	}
	if len(cands) == limit {
		next = cands[len(cands)-1].ID
	}
	return views, next, nil
}

// DecideApproval approves or rejects a pending approval. It needs a fresh
// approve decision on the approval's target, and the approval's transition
// commits in the same fenced transaction (APR-002). The requester and the
// acting agent cannot decide their own approval.
func (s *Service) DecideApproval(ctx context.Context, c Caller, id string, approve bool) (ApprovalView, error) {
	if id == "" || len(id) > 64 {
		return ApprovalView{}, ErrInvalid
	}
	a, err := s.approvals.Get(ctx, c.Tenant, id)
	if errors.Is(err, approval.ErrNotFound) {
		return ApprovalView{}, ErrNotFound
	}
	if err != nil {
		return ApprovalView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	op, ch, ok := approveCheck(a)
	if !ok {
		return ApprovalView{}, ErrNotFound
	}
	_, rec, err := s.decide(ctx, c, op, Audience, true, []check{ch})
	if err != nil {
		return ApprovalView{}, err
	}
	if a.RequestedBy == c.Principal || a.Actor == c.Principal {
		return ApprovalView{}, fmt.Errorf("%w: the requester cannot decide its own approval", ErrConflict)
	}
	outcome := "APPROVAL_REJECTED"
	if approve {
		outcome = "APPROVAL_GRANTED"
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		err := approval.DecideTx(ctx, tx, c.Tenant, id, c.Principal, approve, s.d.Now())
		switch {
		case errors.Is(err, approval.ErrSelfApproval), errors.Is(err, approval.ErrNotPending), errors.Is(err, approval.ErrExpired):
			return fmt.Errorf("%w: %w", ErrConflict, err)
		case err != nil:
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, outcome,
			audit.Target{Type: "platform.approval", ID: id}, audit.Target{Type: a.TargetType, ID: a.TargetID}))
	})
	if err != nil {
		return ApprovalView{}, err
	}
	if a, err = s.approvals.Get(ctx, c.Tenant, id); err != nil {
		return ApprovalView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return view(a), nil
}
