package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Reviewed records: sources and data tools (docs/design/mcp-data-tools.md,
// D-G). A record's versions hold its stored definition and digest; a
// version is a DRAFT until a review makes it ACTIVE and the earlier active
// one SUPERSEDED. The catalog stores definitions and does not read them.

var (
	// ErrDisabled refuses a change to a disabled source or data tool.
	ErrDisabled = errors.New("catalog: it is disabled")
	// ErrDraftConflict refuses a review of a version that is not the
	// draft, or not with the digest the reviewer saw.
	ErrDraftConflict = errors.New("catalog: that version is not the draft with that digest")
	// ErrSelfReview refuses a review by the draft's author (D-G).
	ErrSelfReview = errors.New("catalog: the author of a draft cannot review it")
)

// RecordVersion is one version of a source or a data tool.
type RecordVersion struct {
	Version    int             `json:"version"`
	State      string          `json:"state"`
	Digest     string          `json:"digest"`
	Definition json.RawMessage `json:"definition"`
	Author     string          `json:"author"`
	Reviewer   string          `json:"reviewer,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ReviewedAt *time.Time      `json:"reviewed_at,omitempty"`
}

// records names the tables of one kind of reviewed record: its rows, and
// its versions, whose column parent names the record. The names are
// constants, never input.
type records struct{ table, versions, parent string }

var (
	sourceRecords = records{table: "sources", versions: "source_versions", parent: "source"}
	toolRecords   = records{table: "data_tools", versions: "data_tool_versions", parent: "tool"}
)

// lock locks a record's row, the first step of every change to it.
func (r records) lock(ctx context.Context, tx pgx.Tx, tenant, id string) (disabled bool, err error) {
	err = tx.QueryRow(ctx, `SELECT disabled FROM `+r.table+` WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoRow
	}
	return disabled, err
}

// insertDraft stores version of a record as its draft.
func (r records) insertDraft(ctx context.Context, tx pgx.Tx, tenant, id string, version int, definition []byte, digest, author string,
	now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO `+r.versions+` (tenant, `+r.parent+`, version, definition, digest, state, author, created_at)
	                        VALUES ($1, $2, $3, $4, $5, 'DRAFT', $6, $7)`, tenant, id, version, string(definition), digest, author, now)
	return err
}

// putDraft adds an enabled record's next version as its draft; an earlier
// draft no one reviewed is superseded. It returns the new version.
func (r records) putDraft(ctx context.Context, tx pgx.Tx, tenant, id string, definition []byte, digest, author string, now time.Time) (int, error) {
	disabled, err := r.lock(ctx, tx, tenant, id)
	if err != nil {
		return 0, err
	}
	if disabled {
		return 0, ErrDisabled
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM `+r.versions+` WHERE tenant = $1 AND `+r.parent+` = $2`,
		tenant, id).Scan(&version); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+r.versions+` SET state = 'SUPERSEDED' WHERE tenant = $1 AND `+r.parent+` = $2 AND state = 'DRAFT'`,
		tenant, id); err != nil {
		return 0, err
	}
	return version, r.insertDraft(ctx, tx, tenant, id, version, definition, digest, author, now)
}

// reviewable locks an enabled record and returns the draft a review
// names: the version must be the draft and have the digest the reviewer
// saw, and the reviewer must not be its author unless allowSelf (the
// local administrator's tool, ADM-003).
func (r records) reviewable(ctx context.Context, tx pgx.Tx, tenant, id string, version int, digest, reviewer string,
	allowSelf bool) (RecordVersion, error) {
	disabled, err := r.lock(ctx, tx, tenant, id)
	if err != nil {
		return RecordVersion{}, err
	}
	if disabled {
		return RecordVersion{}, ErrDisabled
	}
	v, err := r.version(ctx, tx, tenant, id, version)
	switch {
	case errors.Is(err, ErrNoRow):
		return RecordVersion{}, ErrDraftConflict
	case err != nil:
		return RecordVersion{}, err
	case v.State != "DRAFT" || v.Digest != digest:
		return RecordVersion{}, ErrDraftConflict
	case v.Author == reviewer && !allowSelf:
		return RecordVersion{}, ErrSelfReview
	}
	return v, nil
}

// activate makes version the record's only active version.
func (r records) activate(ctx context.Context, tx pgx.Tx, tenant, id string, version int, reviewer string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE `+r.versions+` SET state = 'SUPERSEDED'
	                           WHERE tenant = $1 AND `+r.parent+` = $2 AND state = 'ACTIVE' AND version <> $3`, tenant, id, version); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+r.versions+` SET state = 'ACTIVE', reviewer = $4, reviewed_at = $5
	                           WHERE tenant = $1 AND `+r.parent+` = $2 AND version = $3`, tenant, id, version, reviewer, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE `+r.table+` SET active_version = $3 WHERE tenant = $1 AND id = $2`, tenant, id, version)
	return err
}

// version returns one version of a record.
func (r records) version(ctx context.Context, q Querier, tenant, id string, version int) (RecordVersion, error) {
	v := RecordVersion{Version: version}
	var def string
	var reviewer *string
	err := q.QueryRow(ctx, `SELECT state, digest, definition, author, reviewer, created_at, reviewed_at FROM `+r.versions+`
	                         WHERE tenant = $1 AND `+r.parent+` = $2 AND version = $3`, tenant, id, version).
		Scan(&v.State, &v.Digest, &def, &v.Author, &reviewer, &v.CreatedAt, &v.ReviewedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RecordVersion{}, ErrNoRow
	}
	if reviewer != nil {
		v.Reviewer = *reviewer
	}
	v.Definition = json.RawMessage(def)
	return v, err
}

// current returns a record's active and draft versions, each nil when it
// has none.
func (r records) current(ctx context.Context, q Querier, tenant, id string) (active, draft *RecordVersion, err error) {
	for _, state := range []string{"ACTIVE", "DRAFT"} {
		var version int
		err := q.QueryRow(ctx, `SELECT version FROM `+r.versions+` WHERE tenant = $1 AND `+r.parent+` = $2 AND state = $3`,
			tenant, id, state).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		v, err := r.version(ctx, q, tenant, id, version)
		if err != nil {
			return nil, nil, err
		}
		if state == "ACTIVE" {
			active = &v
		} else {
			draft = &v
		}
	}
	return active, draft, nil
}
