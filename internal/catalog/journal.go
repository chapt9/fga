package catalog

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrJournalMismatch means the catalog is bound to another security
// journal.
var ErrJournalMismatch = errors.New("catalog: the catalog is bound to another security journal")

// RecordJournal binds the catalog to journal id, on first use, and raises
// the recorded entry count. Every journaled change records the journal's
// state after its entry is durable, so a restore can tell a complete
// journal from a lost or older one (review finding 1).
func RecordJournal(ctx context.Context, q Querier, id string, entries int) error {
	tag, err := q.Exec(ctx, `
		INSERT INTO journal_state VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET entries = GREATEST(journal_state.entries, excluded.entries)
		 WHERE journal_state.journal_id = excluded.journal_id`, id, entries)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrJournalMismatch
	}
	return nil
}

// SetJournal binds the catalog to journal id with entries, replacing any
// earlier binding. Only recovery uses it, after continuity was shown or
// its loss explicitly accepted.
func SetJournal(ctx context.Context, q Querier, id string, entries int) error {
	_, err := q.Exec(ctx, `INSERT INTO journal_state VALUES (1, $1, $2)
	                       ON CONFLICT (id) DO UPDATE SET journal_id = excluded.journal_id, entries = excluded.entries`, id, entries)
	return err
}

// JournalState returns the recorded journal binding; ok is false when the
// catalog was never bound to a journal.
func JournalState(ctx context.Context, q Querier) (id string, entries int, ok bool, err error) {
	err = q.QueryRow(ctx, `SELECT journal_id, entries FROM journal_state WHERE id = 1`).Scan(&id, &entries)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, false, nil
	}
	return id, entries, err == nil, err
}
