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

func TestAPIKeys(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	key, err := s.IssueKey(ctx, "t-acme", "agent-7")
	if err != nil {
		t.Fatal(err)
	}
	tenant, id, err := s.Authenticate(ctx, key)
	if err != nil || tenant != "t-acme" || id != "agent-7" {
		t.Fatalf("Authenticate = %s %s %v", tenant, id, err)
	}
	if _, _, err := s.Authenticate(ctx, key+"x"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("wrong key: %v", err)
	}
	if err := s.RevokeKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate(ctx, key); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("revoked key: %v", err)
	}
	var stored int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM agent_keys WHERE position(convert_to($1, 'UTF8') in key_hash) > 0`, key).Scan(&stored)
	if stored != 0 {
		t.Error("the key itself must not be stored")
	}
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
