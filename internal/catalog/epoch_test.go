package catalog

import (
	"context"
	"testing"

	"fga/internal/pgtest"
)

// TestActivatedEpochNeverFalls is the regression test of the security
// review of 4 November 2026, finding 6: the catalog records the highest
// policy epoch fga-decision activated and refuses a lower one, so a
// restart with an older bundle does not roll policy back.
func TestActivatedEpochNeverFalls(t *testing.T) {
	pool := pgtest.Pool(t, Migrate)
	s := New(pool, 10_000)
	ctx := context.Background()
	for _, epoch := range []uint64{3, 3, 5} {
		if err := s.RecordActivatedEpoch(ctx, epoch); err != nil {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
	}
	if err := s.RecordActivatedEpoch(ctx, 4); err == nil {
		t.Fatal("an older release was activated after a newer one")
	}
	var recorded uint64
	if err := pool.QueryRow(ctx, `SELECT activated_epoch FROM authority_state WHERE id = 1`).Scan(&recorded); err != nil || recorded != 5 {
		t.Fatalf("recorded epoch %d, %v, want 5", recorded, err)
	}
}
