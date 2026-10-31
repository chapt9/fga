package catalog

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrJournalMismatch means the catalog is bound to another security
// journal.
var ErrJournalMismatch = errors.New("catalog: the catalog is bound to another security journal")

// RecordJournal binds the catalog to journal id, on first use, and moves
// the recorded state forward to chains, the chain values of the journal's
// entries in order. Every journaled change records the journal's state
// after its entry is durable, so a restore can tell a complete journal
// from a lost or older one (review finding 1). The binding moves forward
// only along a chain that still holds the recorded head at its position:
// after an entry was lost, later entries never become the recorded
// history, and recovery refuses the journal (review v2 finding 1). The
// change being journaled still commits.
func RecordJournal(ctx context.Context, q Querier, id string, chains []string) error {
	for range 100 {
		var bound, head string
		var entries int
		err := q.QueryRow(ctx, `SELECT journal_id, entries, head FROM journal_state WHERE id = 1 FOR UPDATE`).Scan(&bound, &entries, &head)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err := q.Exec(ctx, `INSERT INTO journal_state (id, journal_id, entries, head) VALUES (1, $1, $2, $3) ON CONFLICT (id) DO NOTHING`,
				id, len(chains), last(chains)); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if bound != id {
			return ErrJournalMismatch
		}
		// A binding from before the chain (head "") is taken on trust once.
		extends := entries == 0 || head == "" || len(chains) >= entries && chains[entries-1] == head
		if len(chains) <= entries || !extends {
			return nil
		}
		// Outside a transaction another writer may move the binding in
		// between; then the state is read again.
		tag, err := q.Exec(ctx, `UPDATE journal_state SET entries = $1, head = $2 WHERE id = 1 AND entries = $3 AND head = $4`,
			len(chains), last(chains), entries, head)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
	}
	return errors.New("catalog: the journal binding keeps changing")
}

func last(chains []string) string {
	if len(chains) == 0 {
		return ""
	}
	return chains[len(chains)-1]
}

// SetJournal binds the catalog to journal id at chains, replacing any
// earlier binding. Only recovery uses it, after continuity was shown or
// its loss explicitly accepted.
func SetJournal(ctx context.Context, q Querier, id string, chains []string) error {
	_, err := q.Exec(ctx, `INSERT INTO journal_state (id, journal_id, entries, head) VALUES (1, $1, $2, $3)
	                       ON CONFLICT (id) DO UPDATE SET journal_id = excluded.journal_id, entries = excluded.entries, head = excluded.head`,
		id, len(chains), last(chains))
	return err
}

// JournalState returns the recorded journal binding: the journal, its
// entry count and the chain value of its last recorded entry. ok is false
// when the catalog was never bound to a journal.
func JournalState(ctx context.Context, q Querier) (id string, entries int, head string, ok bool, err error) {
	err = q.QueryRow(ctx, `SELECT journal_id, entries, head FROM journal_state WHERE id = 1`).Scan(&id, &entries, &head)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, "", false, nil
	}
	return id, entries, head, err == nil, err
}
