package catalog

import (
	"context"
	"fmt"
	"strings"
)

// Unreadable is how many client-mode files of a bucket a change would
// leave without a reader.
type Unreadable struct {
	Bucket string `json:"bucket"`
	Files  int    `json:"files"`
}

// LastReaderError refuses a change that would leave client-mode files no
// one can open, until it is confirmed. A client-mode file opens only with
// a recipient key it has an envelope for, and fga keeps no other copy of
// its key, so the loss could not be undone (owner's decision of 1
// November 2026). It names buckets and counts, never files.
type LastReaderError struct{ Unreadable []Unreadable }

func (e *LastReaderError) Error() string {
	parts := make([]string, len(e.Unreadable))
	n := 0
	for i, u := range e.Unreadable {
		parts[i] = fmt.Sprintf("%s: %d", u.Bucket, u.Files)
		n += u.Files
	}
	return fmt.Sprintf("catalog: %d client-mode files would have no reader left (%s)", n, strings.Join(parts, ", "))
}

// LastReaders counts, per bucket, the client-mode files that only the
// given readers can open: the keys of principal, or the key fingerprint
// (pass "" for the other). A file counts when one of its LIVE versions
// (for a document: a unit or the original of a LIVE document version)
// has ACTIVE envelopes for usable keys and all of them are the given
// readers'. A usable key is ACTIVE and its principal is not disabled.
func LastReaders(ctx context.Context, q Querier, tenant, principal, fingerprint string) ([]Unreadable, error) {
	rows, err := q.Query(ctx, `
		WITH readers AS (
		  SELECT e.object, e.version, e.document_version,
		         bool_or(k.principal = $2 OR k.fingerprint = $3) AS given,
		         bool_or(NOT (k.principal = $2 OR k.fingerprint = $3)) AS others
		    FROM envelopes e
		    JOIN recipient_keys k ON k.tenant = e.tenant AND k.fingerprint = e.recipient AND k.status = 'ACTIVE'
		    JOIN identities i ON i.tenant = k.tenant AND i.id = k.principal AND NOT i.disabled
		    JOIN object_versions v ON v.tenant = e.tenant AND v.id = e.version AND v.state = 'LIVE'
		    LEFT JOIN document_versions d ON d.tenant = e.tenant AND d.id = e.document_version
		   WHERE e.tenant = $1 AND e.status = 'ACTIVE' AND (e.document_version IS NULL OR d.state = 'LIVE')
		   GROUP BY e.object, e.version, e.document_version)
		SELECT b.name, count(DISTINCT o.id)
		  FROM readers r
		  LEFT JOIN document_versions d ON d.tenant = $1 AND d.id = r.document_version
		  JOIN objects o ON o.tenant = $1 AND o.id = coalesce(d.document, r.object)
		  JOIN buckets b ON b.tenant = $1 AND b.id = o.bucket
		 WHERE r.given AND NOT r.others
		 GROUP BY b.name ORDER BY b.name`, tenant, principal, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Unreadable
	for rows.Next() {
		var u Unreadable
		if err := rows.Scan(&u.Bucket, &u.Files); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CheckLastReaders is CheckLastReaders within the administration.
func (a *Admin) CheckLastReaders(ctx context.Context, tenant, principal, fingerprint string, confirmed bool) error {
	return CheckLastReaders(ctx, a.tx, tenant, principal, fingerprint, confirmed)
}

// CheckLastReaders refuses with a *LastReaderError a change that would
// leave files without a reader, unless it is confirmed.
func CheckLastReaders(ctx context.Context, q Querier, tenant, principal, fingerprint string, confirmed bool) error {
	if confirmed {
		return nil
	}
	u, err := LastReaders(ctx, q, tenant, principal, fingerprint)
	if err != nil {
		return err
	}
	if len(u) > 0 {
		return &LastReaderError{Unreadable: u}
	}
	return nil
}
