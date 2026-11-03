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
// ING-008), reviewed records (records.go). A source owns one bucket,
// created with it. A review and a disable are journaled first: a restore
// must not bring back an older active version, which would label new
// readings by older groups, nor re-enable a source. fga-admin checks the
// record (package sources).

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
	Active     *RecordVersion `json:"active,omitempty"`
	Draft      *RecordVersion `json:"draft,omitempty"`
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
	return bucket, sourceRecords.insertDraft(ctx, a.tx, tenant, id, 1, definition, digest, author, now)
}

// PutSourceDraft adds a source's next version as its draft; an earlier
// draft no one reviewed is superseded. It returns the new version.
func (a *Admin) PutSourceDraft(ctx context.Context, tenant, id string, definition []byte, digest, author string, now time.Time) (int, error) {
	return sourceRecords.putDraft(ctx, a.tx, tenant, id, definition, digest, author, now)
}

// ReviewSource makes the draft a review names a source's active version
// (records.reviewable). The reviewed version is journaled first, so a
// restore makes it active again (ING-008).
func (a *Admin) ReviewSource(ctx context.Context, tenant, id string, version int, digest, reviewer string, allowSelf bool,
	now time.Time) (RecordVersion, error) {
	v, err := sourceRecords.reviewable(ctx, a.tx, tenant, id, version, digest, reviewer, allowSelf)
	if err != nil {
		return RecordVersion{}, err
	}
	st, err := json.Marshal(SourceState{Source: id, Version: version, Digest: v.Digest, Definition: v.Definition, Author: v.Author,
		Reviewer: reviewer})
	if err != nil {
		return RecordVersion{}, err
	}
	a.sourced = append(a.sourced, identityRef{tenant, id})
	if err := a.Journal(ctx, a.journal.SourceSetKind, tenant, string(st)); err != nil {
		return RecordVersion{}, err
	}
	if err := sourceRecords.activate(ctx, a.tx, tenant, id, version, reviewer, now); err != nil {
		return RecordVersion{}, err
	}
	v.State, v.Reviewer, v.ReviewedAt = "ACTIVE", reviewer, &now
	return v, nil
}

// DisableSource disables a source, journaled first, as DisableIdentity
// disables an identity: locked first, an unknown one refused and a
// disabled one left as it is. Its readings stay; none is accepted after.
func (a *Admin) DisableSource(ctx context.Context, tenant, id string) error {
	disabled, err := sourceRecords.lock(ctx, a.tx, tenant, id)
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
			v, err := sourceRecords.version(ctx, tx, tenant, id, *active)
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
		return sourceRecords.activate(ctx, tx, tenant, st.Source, st.Version, st.Reviewer, time.Now().UTC())
	})
}

// SourceVersion returns one version of a source.
func (s *Store) SourceVersion(ctx context.Context, tenant, id string, version int) (RecordVersion, error) {
	return sourceRecords.version(ctx, s.pool, tenant, id, version)
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
		if out[i].Active, out[i].Draft, err = sourceRecords.current(ctx, s.pool, tenant, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}
