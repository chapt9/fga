package audit

import (
	"context"
	"errors"
	"testing"
)

func event(id string) Event {
	return Event{ID: id, Kind: KindDecision, Tenant: "t-acme", Actor: "agent-7", Outcome: "ALLOW",
		Checks: []Check{{ID: "c1", Action: "read", ResourceType: "document.text_unit", ResourceID: "u-1", Effect: "ALLOW"}}}
}

// TestFullOutboxRefusesInsteadOfDropping covers the R1-A audit case of T-15:
// when the exporter falls behind, Append fails and nothing already recorded
// is lost (AUD-002).
func TestFullOutboxRefusesInsteadOfDropping(t *testing.T) {
	ctx := context.Background()
	o := NewMemoryOutbox(2)
	for _, id := range []string{"e1", "e2"} {
		if err := o.Append(ctx, event(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Append(ctx, event("e3")); !errors.Is(err, ErrFull) {
		t.Fatalf("Append to a full outbox = %v, want %v", err, ErrFull)
	}
	if s := o.Saturation(); s != 1 {
		t.Errorf("saturation = %v, want 1", s)
	}
	pending, _ := o.Pending(ctx, 10)
	if len(pending) != 2 || pending[0].ID != "e1" || pending[1].ID != "e2" {
		t.Fatalf("pending = %v, want e1 and e2 in order", pending)
	}

	// Once the exporter delivers, there is room again.
	if err := o.MarkDelivered(ctx, []string{"e1"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Append(ctx, event("e3")); err != nil {
		t.Fatalf("Append after delivery: %v", err)
	}
}

// TestDeliveryIsIdempotent covers AUD-003: retried appends and repeated
// delivery acknowledgements do not duplicate or lose events.
func TestDeliveryIsIdempotent(t *testing.T) {
	ctx := context.Background()
	o := NewMemoryOutbox(10)
	for _, id := range []string{"e1", "e1", "e2"} {
		if err := o.Append(ctx, event(id)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := o.MarkDelivered(ctx, []string{"e1", "unknown"}); err != nil {
			t.Fatal(err)
		}
	}
	pending, _ := o.Pending(ctx, 10)
	if len(pending) != 1 || pending[0].ID != "e2" {
		t.Fatalf("pending = %v, want only e2", pending)
	}
}

func TestPendingReturnsCopies(t *testing.T) {
	ctx := context.Background()
	o := NewMemoryOutbox(10)
	_ = o.Append(ctx, event("e1"))
	pending, _ := o.Pending(ctx, 10)
	pending[0].Checks[0].Effect = "DENY"
	again, _ := o.Pending(ctx, 10)
	if again[0].Checks[0].Effect != "ALLOW" {
		t.Fatal("a caller changed a recorded event through Pending")
	}
}
