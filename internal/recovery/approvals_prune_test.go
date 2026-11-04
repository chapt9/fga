package recovery_test

import (
	"testing"
	"time"

	"fga/internal/approval"
	"fga/internal/r1test"
	"fga/internal/recovery"
)

// TestReclaimPrunesExpiredApprovals is the regression test of the security
// review of 4 November 2026, finding 4: an approval that expired more than
// PruneMargin ago is removed, a live one stays.
func TestReclaimPrunesExpiredApprovals(t *testing.T) {
	st := r1test.New(t)
	approvals := approval.New(st.Pool, func() time.Time { return *st.Clock })
	for name, expires := range map[string]time.Time{"expired": st.Clock.Add(-3 * time.Hour), "live": st.Clock.Add(time.Hour)} {
		if _, err := approvals.Request(ctx, approval.Approval{Tenant: r1test.Tenant, Operation: "storage.object.relabel",
			OperationDigest: "sha256:" + name, RequestedBy: "alice", Actor: "alice", ExpiresAt: expires,
			TargetType: "storage.object", TargetID: name}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := recovery.Reclaim(ctx, st.Pool, st.Blobs, *st.Clock)
	if err != nil || got.Pruned < 1 {
		t.Fatalf("reclaim = %+v, %v", got, err)
	}
	rows, err := st.Pool.Query(ctx, `SELECT target_id FROM approvals ORDER BY target_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var left []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if len(left) != 1 || left[0] != "live" {
		t.Fatalf("approvals left: %v, want only the live one", left)
	}
}
