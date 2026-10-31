// Package toolstore is the PostgreSQL store of the tools role: API keys,
// tool records, destinations and budgets (specification 2.5, AGT-001,
// APR-004). It is separate from the catalog so that the decision role does
// not link tool code (MOD-004). Part of the optional R2 executor (feature
// executor).
package toolstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/catalog"
	"fga/internal/strictjson"
	"fga/internal/tools"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate applies the core catalog migrations and then the executor's own
// (feature executor). Roles without the executor never create these tables.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if err := catalog.Migrate(ctx, pool); err != nil {
		return err
	}
	return catalog.ApplyMigrations(ctx, pool, migrations, "migrations", "executor/")
}

// Errors returned by the tool-side catalog.
var (
	ErrUnknownKey         = errors.New("unknown or revoked API key")
	ErrUnknownTool        = errors.New("unknown tool")
	ErrToolNotReviewed    = errors.New("tool record changed since it was reviewed")
	ErrUnknownDestination = errors.New("unknown destination")
)

// Store is the tools role's view of the catalog database.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a Store. The schema is created by catalog.Migrate.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// KeyPrefix marks platform API keys.
const KeyPrefix = "fga_"

// IssueKey creates an API key for an identity and stores only its hash. The
// key is returned once and cannot be recovered.
func (s *Store) IssueKey(ctx context.Context, tenant, identity string) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	key := KeyPrefix + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(key))
	if _, err := s.pool.Exec(ctx, `INSERT INTO agent_keys (key_hash, tenant, identity) VALUES ($1, $2, $3)`,
		hash[:], tenant, identity); err != nil {
		return "", err
	}
	return key, nil
}

// Authenticate returns the tenant and identity an API key belongs to.
func (s *Store) Authenticate(ctx context.Context, key string) (tenant, identity string, err error) {
	hash := sha256.Sum256([]byte(key))
	var revoked bool
	err = s.pool.QueryRow(ctx, `SELECT tenant, identity, revoked FROM agent_keys WHERE key_hash = $1`, hash[:]).
		Scan(&tenant, &identity, &revoked)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && revoked) {
		return "", "", ErrUnknownKey
	}
	return tenant, identity, err
}

// RevokeKey disables an API key.
func (s *Store) RevokeKey(ctx context.Context, key string) error {
	hash := sha256.Sum256([]byte(key))
	_, err := s.pool.Exec(ctx, `UPDATE agent_keys SET revoked = true WHERE key_hash = $1`, hash[:])
	return err
}

// PutTool stores a tool record. reviewed marks the current record as
// reviewed; otherwise the tool stays unusable until ReviewTool is called.
func (s *Store) PutTool(ctx context.Context, tenant string, t tools.Tool, reviewed bool) error {
	record, err := json.Marshal(t)
	if err != nil {
		return err
	}
	digest, approved := t.SchemaDigest(), ""
	if reviewed {
		approved = digest
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO tools (tenant, id, record, schema_digest, reviewed_digest) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant, id) DO UPDATE
		   SET record = EXCLUDED.record, schema_digest = EXCLUDED.schema_digest,
		       reviewed_digest = CASE WHEN $6 THEN EXCLUDED.reviewed_digest ELSE tools.reviewed_digest END`,
		tenant, t.ID, record, digest, approved, reviewed)
	return err
}

// ReviewTool records that the tool's current record was reviewed.
func (s *Store) ReviewTool(ctx context.Context, tenant, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tools SET reviewed_digest = schema_digest WHERE tenant = $1 AND id = $2`, tenant, id)
	return err
}

// Tool returns a usable tool. The digest is recomputed from the stored
// record, so a record edited behind the registry's back is not usable
// either (AGT-001, V-034).
func (s *Store) Tool(ctx context.Context, tenant, id string) (tools.Tool, error) {
	var record []byte
	var reviewed string
	err := s.pool.QueryRow(ctx, `SELECT record, reviewed_digest FROM tools WHERE tenant = $1 AND id = $2`, tenant, id).
		Scan(&record, &reviewed)
	if errors.Is(err, pgx.ErrNoRows) {
		return tools.Tool{}, ErrUnknownTool
	}
	if err != nil {
		return tools.Tool{}, err
	}
	var t tools.Tool
	if err := strictjson.Decode(record, &t); err != nil {
		return tools.Tool{}, fmt.Errorf("catalog: tool %q: %w", id, err)
	}
	if t.SchemaDigest() != reviewed {
		return tools.Tool{}, ErrToolNotReviewed
	}
	return t, nil
}

// ReviewedTools returns a tenant's usable tools: those whose stored record
// is the reviewed one (AGT-001), in ID order.
func (s *Store) ReviewedTools(ctx context.Context, tenant string) ([]tools.Tool, error) {
	rows, err := s.pool.Query(ctx, `SELECT record, reviewed_digest FROM tools WHERE tenant = $1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tools.Tool
	for rows.Next() {
		var record []byte
		var reviewed string
		if err := rows.Scan(&record, &reviewed); err != nil {
			return nil, err
		}
		var t tools.Tool
		if strictjson.Decode(record, &t) == nil && t.SchemaDigest() == reviewed {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// PutDestination stores a destination.
func (s *Store) PutDestination(ctx context.Context, tenant string, d tools.Destination) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO destinations (tenant, id, base_url, allowed_cidrs, credential_file, reconcile_path)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant, id) DO UPDATE SET base_url = EXCLUDED.base_url, allowed_cidrs = EXCLUDED.allowed_cidrs,
		    credential_file = EXCLUDED.credential_file, reconcile_path = EXCLUDED.reconcile_path`,
		tenant, d.ID, d.BaseURL, d.AllowedCIDRs, d.CredentialFile, d.ReconcilePath)
	return err
}

// Destination returns a registered destination.
func (s *Store) Destination(ctx context.Context, tenant, id string) (tools.Destination, error) {
	d := tools.Destination{ID: id}
	err := s.pool.QueryRow(ctx, `
		SELECT base_url, allowed_cidrs, credential_file, reconcile_path FROM destinations WHERE tenant = $1 AND id = $2`,
		tenant, id).Scan(&d.BaseURL, &d.AllowedCIDRs, &d.CredentialFile, &d.ReconcilePath)
	if errors.Is(err, pgx.ErrNoRows) {
		return tools.Destination{}, ErrUnknownDestination
	}
	return d, err
}

// PutBudget creates or replaces a budget's limit. Reserved and spent amounts
// are kept.
func (s *Store) PutBudget(ctx context.Context, tenant, id string, limit tools.Money) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO budgets (tenant, id, currency, limit_minor) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant, id) DO UPDATE SET currency = EXCLUDED.currency, limit_minor = EXCLUDED.limit_minor`,
		tenant, id, limit.Currency, limit.Minor)
	return err
}
