package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/cryptowire"
)

// Sources of JSON readings (docs/design/mcp-data-tools.md, ING-001,
// ING-008). A source owns one bucket, created with it. Its versions hold
// the stored record and its digest; a version is a DRAFT until another
// administrator reviews it, which makes it ACTIVE and the earlier active
// one SUPERSEDED. A review and a disable are journaled first: a restore
// must not bring back an older active version, which would label new
// readings by older groups, nor re-enable a source. The catalog stores the
// record and does not read it; fga-admin checks it (package sources).

var (
	// ErrSourceDisabled refuses a change to a disabled source.
	ErrSourceDisabled = errors.New("catalog: the source is disabled")
	// ErrSourceConflict refuses a review of a version that is not the
	// source's draft, or not with the digest the reviewer saw.
	ErrSourceConflict = errors.New("catalog: that version is not the source's draft with that digest")
	// ErrSelfReview refuses a review by the draft's author (D-G).
	ErrSelfReview = errors.New("catalog: the author of a draft cannot review it")
)

// Source is a source with its bucket and its active and draft versions.
type Source struct {
	ID         string         `json:"id"`
	Bucket     string         `json:"bucket"`
	BucketID   string         `json:"bucket_id"`
	Project    string         `json:"project"`
	Label      string         `json:"label"`
	Encryption string         `json:"encryption"`
	Disabled   bool           `json:"disabled"`
	CreatedAt  time.Time      `json:"created_at"`
	Active     *SourceVersion `json:"active,omitempty"`
	Draft      *SourceVersion `json:"draft,omitempty"`
}

// SourceVersion is one version of a source.
type SourceVersion struct {
	Version    int             `json:"version"`
	State      string          `json:"state"`
	Digest     string          `json:"digest"`
	Definition json.RawMessage `json:"definition"`
	Author     string          `json:"author"`
	Reviewer   string          `json:"reviewer,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ReviewedAt *time.Time      `json:"reviewed_at,omitempty"`
}

// SourceState is a source's active version as a review journals it.
// Reconcile makes it the active version again after a restore. Version 0
// records that no version is active.
type SourceState struct {
	Source     string          `json:"source"`
	Version    int             `json:"version"`
	Digest     string          `json:"digest,omitempty"`
	Definition json.RawMessage `json:"definition,omitempty"`
	Author     string          `json:"author,omitempty"`
	Reviewer   string          `json:"reviewer,omitempty"`
}

// CreateSource creates a source, its bucket and its draft version 1 in the
// change's transaction. The bucket names the source in its row and its
// resource's attributes.
func (a *Admin) CreateSource(ctx context.Context, tenant string, b Bucket, id string, definition []byte, digest, author string,
	now time.Time) (cryptowire.UUID, error) {
	b.Source = id
	bucket, err := createBucket(ctx, a.tx, tenant, b)
	if err != nil {
		return cryptowire.UUID{}, err
	}
	if _, err := a.tx.Exec(ctx, `INSERT INTO sources (tenant, id, bucket, disabled, created_at) VALUES ($1, $2, $3, false, $4)`,
		tenant, id, bucket, now); err != nil {
		return cryptowire.UUID{}, err
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO source_versions (tenant, source, version, definition, digest, state, author, created_at)
	                         VALUES ($1, $2, 1, $3, $4, 'DRAFT', $5, $6)`, tenant, id, string(definition), digest, author, now)
	return bucket, err
}

// lockSource locks a source's row, the first step of every change to it.
func (a *Admin) lockSource(ctx context.Context, tenant, id string) (disabled bool, err error) {
	err = a.tx.QueryRow(ctx, `SELECT disabled FROM sources WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNoRow
	}
	return disabled, err
}

// PutSourceDraft adds a source's next version as its draft; an earlier
// draft no one reviewed is superseded. It returns the new version.
func (a *Admin) PutSourceDraft(ctx context.Context, tenant, id string, definition []byte, digest, author string, now time.Time) (int, error) {
	disabled, err := a.lockSource(ctx, tenant, id)
	if err != nil {
		return 0, err
	}
	if disabled {
		return 0, ErrSourceDisabled
	}
	var version int
	if err := a.tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM source_versions WHERE tenant = $1 AND source = $2`,
		tenant, id).Scan(&version); err != nil {
		return 0, err
	}
	if _, err := a.tx.Exec(ctx, `UPDATE source_versions SET state = 'SUPERSEDED' WHERE tenant = $1 AND source = $2 AND state = 'DRAFT'`,
		tenant, id); err != nil {
		return 0, err
	}
	_, err = a.tx.Exec(ctx, `INSERT INTO source_versions (tenant, source, version, definition, digest, state, author, created_at)
	                         VALUES ($1, $2, $3, $4, $5, 'DRAFT', $6, $7)`, tenant, id, version, string(definition), digest, author, now)
	return version, err
}

// ReviewSource makes a source's draft its active version. The version must
// be the draft and have the digest the reviewer saw, and the reviewer must
// not be its author unless allowSelf (the local administrator's tool,
// ADM-003). The reviewed version is journaled first, so a restore makes it
// active again (ING-008).
func (a *Admin) ReviewSource(ctx context.Context, tenant, id string, version int, digest, reviewer string, allowSelf bool,
	now time.Time) (SourceVersion, error) {
	disabled, err := a.lockSource(ctx, tenant, id)
	if err != nil {
		return SourceVersion{}, err
	}
	if disabled {
		return SourceVersion{}, ErrSourceDisabled
	}
	v, err := sourceVersion(ctx, a.tx, tenant, id, version)
	if errors.Is(err, ErrNoRow) {
		return SourceVersion{}, ErrSourceConflict
	}
	if err != nil {
		return SourceVersion{}, err
	}
	if v.State != "DRAFT" || v.Digest != digest {
		return SourceVersion{}, ErrSourceConflict
	}
	if v.Author == reviewer && !allowSelf {
		return SourceVersion{}, ErrSelfReview
	}
	st, err := json.Marshal(SourceState{Source: id, Version: version, Digest: v.Digest, Definition: v.Definition, Author: v.Author,
		Reviewer: reviewer})
	if err != nil {
		return SourceVersion{}, err
	}
	a.sourced = append(a.sourced, identityRef{tenant, id})
	if err := a.Journal(ctx, a.journal.SourceSetKind, tenant, string(st)); err != nil {
		return SourceVersion{}, err
	}
	if err := activateSource(ctx, a.tx, tenant, id, version, reviewer, now); err != nil {
		return SourceVersion{}, err
	}
	v.State, v.Reviewer, v.ReviewedAt = "ACTIVE", reviewer, &now
	return v, nil
}

// activateSource makes version the source's only active version.
func activateSource(ctx context.Context, tx pgx.Tx, tenant, id string, version int, reviewer string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE source_versions SET state = 'SUPERSEDED'
	                           WHERE tenant = $1 AND source = $2 AND state = 'ACTIVE' AND version <> $3`, tenant, id, version); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE source_versions SET state = 'ACTIVE', reviewer = $4, reviewed_at = $5
	                           WHERE tenant = $1 AND source = $2 AND version = $3`, tenant, id, version, reviewer, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE sources SET active_version = $3 WHERE tenant = $1 AND id = $2`, tenant, id, version)
	return err
}

// DisableSource disables a source, journaled first, as DisableIdentity
// disables an identity: locked first, an unknown one refused and a
// disabled one left as it is. Its readings stay; none is accepted after.
func (a *Admin) DisableSource(ctx context.Context, tenant, id string) error {
	disabled, err := a.lockSource(ctx, tenant, id)
	if err != nil || disabled {
		return err
	}
	if err := a.Journal(ctx, a.journal.SourceDisabledKind, tenant, id); err != nil {
		return err
	}
	_, err = a.tx.Exec(ctx, `UPDATE sources SET disabled = true WHERE tenant = $1 AND id = $2`, tenant, id)
	return err
}

// restateSource journals a source's committed active version, read under
// its row lock, after a change that journaled another one failed.
func (s *Store) restateSource(ctx context.Context, j Journal, tenant, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var active *int
		err := tx.QueryRow(ctx, `SELECT active_version FROM sources WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&active)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		st := SourceState{Source: id}
		if active != nil {
			v, err := sourceVersion(ctx, tx, tenant, id, *active)
			if err != nil {
				return err
			}
			st = SourceState{Source: id, Version: v.Version, Digest: v.Digest, Definition: v.Definition, Author: v.Author, Reviewer: v.Reviewer}
		}
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return (&Admin{tx: tx, s: s, journal: j}).Journal(ctx, j.SourceSetKind, tenant, string(raw))
	})
}

// ApplySourceState makes a journaled version a source's active version,
// writing the version from the entry when the restored catalog lacks it
// or holds it otherwise, or leaves the source without one for version 0.
// A source the catalog does not hold, created after the backup with its
// bucket, is left unknown. Reconcile calls it in journal order.
func (s *Store) ApplySourceState(ctx context.Context, tenant string, st SourceState) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var found bool
		err := tx.QueryRow(ctx, `SELECT true FROM sources WHERE tenant = $1 AND id = $2 FOR UPDATE`, tenant, st.Source).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Version == 0 {
			if _, err := tx.Exec(ctx, `UPDATE source_versions SET state = 'SUPERSEDED' WHERE tenant = $1 AND source = $2 AND state = 'ACTIVE'`,
				tenant, st.Source); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE sources SET active_version = NULL WHERE tenant = $1 AND id = $2`, tenant, st.Source)
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO source_versions (tenant, source, version, definition, digest, state, author, created_at)
			VALUES ($1, $2, $3, $4, $5, 'SUPERSEDED', $6, now())
			ON CONFLICT (tenant, source, version) DO UPDATE SET definition = excluded.definition, digest = excluded.digest,
			       author = excluded.author, state = CASE WHEN source_versions.state = 'DRAFT' THEN 'SUPERSEDED' ELSE source_versions.state END
			 WHERE source_versions.digest <> excluded.digest OR source_versions.state = 'DRAFT'`,
			tenant, st.Source, st.Version, string(st.Definition), st.Digest, st.Author); err != nil {
			return err
		}
		return activateSource(ctx, tx, tenant, st.Source, st.Version, st.Reviewer, time.Now().UTC())
	})
}

func sourceVersion(ctx context.Context, q Querier, tenant, id string, version int) (SourceVersion, error) {
	v := SourceVersion{Version: version}
	var def string
	var reviewer *string
	err := q.QueryRow(ctx, `SELECT state, digest, definition, author, reviewer, created_at, reviewed_at FROM source_versions
	                         WHERE tenant = $1 AND source = $2 AND version = $3`, tenant, id, version).
		Scan(&v.State, &v.Digest, &def, &v.Author, &reviewer, &v.CreatedAt, &v.ReviewedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceVersion{}, ErrNoRow
	}
	if reviewer != nil {
		v.Reviewer = *reviewer
	}
	v.Definition = json.RawMessage(def)
	return v, err
}

// SourceVersion returns one version of a source.
func (s *Store) SourceVersion(ctx context.Context, tenant, id string, version int) (SourceVersion, error) {
	return sourceVersion(ctx, s.pool, tenant, id, version)
}

// Source returns a source with its bucket and its active and draft
// versions.
func (s *Store) Source(ctx context.Context, tenant, id string) (Source, error) {
	list, err := s.sources(ctx, tenant, id, "", 1)
	if err != nil {
		return Source{}, err
	}
	if len(list) == 0 {
		return Source{}, ErrNoRow
	}
	return list[0], nil
}

// ListSources returns a page of a tenant's sources in ID order.
func (s *Store) ListSources(ctx context.Context, tenant, after string, limit int) ([]Source, error) {
	return s.sources(ctx, tenant, "", after, limit)
}

func (s *Store) sources(ctx context.Context, tenant, only, after string, limit int) ([]Source, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, b.name, b.id::text, b.default_project, b.default_label, b.encryption, s.disabled, s.created_at
		  FROM sources s JOIN buckets b ON b.tenant = s.tenant AND b.id = s.bucket
		 WHERE s.tenant = $1 AND ($2::text = '' OR s.id = $2::text) AND s.id > $3::text ORDER BY s.id LIMIT $4`, tenant, only, after, limit)
	if err != nil {
		return nil, err
	}
	out := []Source{}
	for rows.Next() {
		var src Source
		if err := rows.Scan(&src.ID, &src.Bucket, &src.BucketID, &src.Project, &src.Label, &src.Encryption, &src.Disabled, &src.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, src)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		for _, state := range []string{"ACTIVE", "DRAFT"} {
			var version int
			err := s.pool.QueryRow(ctx, `SELECT version FROM source_versions WHERE tenant = $1 AND source = $2 AND state = $3`,
				tenant, out[i].ID, state).Scan(&version)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			v, err := sourceVersion(ctx, s.pool, tenant, out[i].ID, version)
			if err != nil {
				return nil, err
			}
			if state == "ACTIVE" {
				out[i].Active = &v
			} else {
				out[i].Draft = &v
			}
		}
	}
	return out, nil
}
