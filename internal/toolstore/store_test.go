package toolstore

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/pgtest"
	"fga/internal/tools"
)

func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Pool(t, Migrate)
	pgtest.Exec(t, pool, `INSERT INTO identities VALUES ('t-acme','agent-7',12,false,'{agent}','{}')`)
	return New(pool), pool
}

func testTool() tools.Tool {
	return tools.Tool{ID: "expense.submit", Version: 1, Destination: "expenses-local",
		Endpoint:  tools.Endpoint{Method: "POST", Path: "/expenses"},
		Arguments: []tools.ArgSpec{{Name: "vendor", Type: tools.ArgString, Required: true}}, MaxHoldAge: "1h"}
}

// TestToolsNeedReview covers AGT-001 and V-034: an unreviewed record, or a
// record changed after review, is not usable.
func TestToolsNeedReview(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()
	tl := testTool()
	if err := s.PutTool(ctx, "t-acme", tl, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tool(ctx, "t-acme", tl.ID); !errors.Is(err, ErrToolNotReviewed) {
		t.Fatalf("unreviewed tool: %v", err)
	}
	if err := s.ReviewTool(ctx, "t-acme", tl.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Tool(ctx, "t-acme", tl.ID); err != nil || got.SchemaDigest() != tl.SchemaDigest() {
		t.Fatalf("reviewed tool = %+v, %v", got, err)
	}

	changed := tl
	changed.Endpoint.Path = "/expenses/fast-track"
	if err := s.PutTool(ctx, "t-acme", changed, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tool(ctx, "t-acme", tl.ID); !errors.Is(err, ErrToolNotReviewed) {
		t.Fatalf("changed tool: %v", err)
	}
	// An edit made directly in the database is caught as well.
	if err := s.PutTool(ctx, "t-acme", tl, true); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tools SET record = jsonb_set(record, '{endpoint,path}', '"/other"')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tool(ctx, "t-acme", tl.ID); !errors.Is(err, ErrToolNotReviewed) {
		t.Fatalf("record edited in the database: %v", err)
	}
	if _, err := s.Tool(ctx, "t-other", tl.ID); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("another tenant's tool: %v", err)
	}
}

func TestDestinations(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	d := tools.Destination{ID: "expenses-local", BaseURL: "http://127.0.0.1:9090",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, ReconcilePath: "/idempotency/{key}"}
	if err := s.PutDestination(ctx, "t-acme", d); err != nil {
		t.Fatal(err)
	}
	got, err := s.Destination(ctx, "t-acme", d.ID)
	if err != nil || got.BaseURL != d.BaseURL || len(got.AllowedCIDRs) != 1 || got.AllowedCIDRs[0] != d.AllowedCIDRs[0] {
		t.Fatalf("destination = %+v, %v", got, err)
	}
	if _, err := s.Destination(ctx, "t-other", d.ID); !errors.Is(err, ErrUnknownDestination) {
		t.Errorf("another tenant's destination: %v", err)
	}
}

// TestBudgetCurrency covers fga-audit F-15: a budget's currency changes
// only while nothing is reserved or spent in it.
func TestBudgetCurrency(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()
	if err := s.PutBudget(ctx, "t-acme", "travel", tools.Money{Currency: "EUR", Minor: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBudget(ctx, "t-acme", "travel", tools.Money{Currency: "USD", Minor: 1000}); err != nil {
		t.Fatalf("a change of currency while nothing is held: %v", err)
	}
	pgtest.Exec(t, pool, `UPDATE budgets SET reserved_minor = 100 WHERE tenant = 't-acme' AND id = 'travel'`)
	if err := s.PutBudget(ctx, "t-acme", "travel", tools.Money{Currency: "EUR", Minor: 1000}); !errors.Is(err, ErrCurrency) {
		t.Fatalf("a change of currency while an amount is held: %v", err)
	}
	if err := s.PutBudget(ctx, "t-acme", "travel", tools.Money{Currency: "USD", Minor: 2000}); err != nil {
		t.Fatalf("a new limit in the same currency: %v", err)
	}
}
