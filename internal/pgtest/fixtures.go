package pgtest

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Invocations inserts identities, a tool and one PREPARED invocation per ID
// for tests of the approval, reservation and invocation stores.
func Invocations(t testing.TB, pool *pgxpool.Pool, ids ...string) {
	t.Helper()
	Exec(t, pool,
		`INSERT INTO identities VALUES ('t-acme','user-42',88,false,'{reviewer}','{}'),('t-acme','agent-7',12,false,'{agent}','{}'),
		                               ('t-acme','finance-1',5,false,'{finance}','{}')`,
		`INSERT INTO tools (tenant, id, record, schema_digest, reviewed_digest) VALUES ('t-acme','expense.submit','{}','d','d')`,
		`INSERT INTO budgets (tenant, id, currency, limit_minor) VALUES ('t-acme','team-travel','EUR',100000)`)
	for _, id := range ids {
		Exec(t, pool, fmt.Sprintf(`INSERT INTO invocations (tenant, id, idempotency_key, operation_digest, tool, tool_version,
			arguments, actor, subject, delegation, state)
			VALUES ('t-acme','%[1]s','key-%[1]s','sha256:op-%[1]s','expense.submit',1,'{}','agent-7','user-42','dlg-5','PREPARED')`, id))
	}
}
