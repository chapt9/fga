package content

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/opplan"
	"fga/internal/registry"
)

// Withdrawal of documents (PUB-005, DOC-002, docs/design/documents.md).

// documentKey resolves a document key to its object, generation and
// current version.
func (s *Service) documentKey(ctx context.Context, tenant, bucketName, key string) (cryptowire.UUID, *cryptowire.UUID, error) {
	b, err := s.bucketByName(ctx, tenant, bucketName)
	if err != nil {
		return cryptowire.UUID{}, nil, err
	}
	var id cryptowire.UUID
	var current *cryptowire.UUID
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id, current_document_version FROM objects WHERE tenant = $1 AND bucket = $2 AND key = $3 AND kind = 'document'`,
		tenant, b.ID, key).Scan(&id, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, nil, ErrNotFound
	}
	return id, current, err
}

// DeleteDocument deletes a document key (PUB-005): it needs delete on the
// document and clears its head, so the key has no current version; its
// versions stay as they are, readable by version with read-units, and a
// new version may be published later. A key without a current version is
// left as it is.
func (s *Service) DeleteDocument(ctx context.Context, c Caller, bucketName, key string) (DeleteOutcome, error) {
	doc, current, err := s.documentKey(ctx, c.Tenant, bucketName, key)
	if err != nil {
		return DeleteOutcome{}, err
	}
	if current == nil {
		return DeleteOutcome{}, ErrNotFound
	}
	rec, err := s.decidePlanned(ctx, c, registry.OpDocDelete,
		[]check{{id: "document", role: registry.RoleDocument, action: "delete", ref: canonical("storage.object", doc.String())}},
		opplan.Summary{Action: "delete", Targets: []opplan.Target{{Role: registry.RoleDocument, Type: "storage.object", ID: doc.String()}},
			Details: details(map[string]string{"bucket": bucketName, "key": key})})
	if err != nil {
		return DeleteOutcome{}, err
	}
	var out DeleteOutcome
	err = s.fenced(ctx, rec, []string{doc.String()}, func(ctx context.Context, tx pgx.Tx) error {
		var head *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_document_version FROM objects WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, doc).Scan(&head); err != nil {
			return err
		}
		var gen uint64
		if err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2 RETURNING generation`,
			c.Tenant, doc.String()).Scan(&gen); err != nil {
			return err
		}
		out = DeleteOutcome{State: "DELETED", Generation: gen}
		if head == nil {
			return nil
		}
		out.Version = head.String()
		if _, err := tx.Exec(ctx, `UPDATE objects SET current_document_version = NULL WHERE tenant = $1 AND id = $2`, c.Tenant, doc); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "DOCUMENT_DELETED",
			audit.Target{Type: "storage.object", ID: doc.String(), Version: head.String(), Generation: gen}))
	})
	return out, err
}

// WithdrawDocumentVersion withdraws one document version (PUB-005,
// DOC-002): it needs delete-version on the document. The version becomes
// WITHDRAWN and its envelopes are retired. Each of its unit versions, and
// its original, that no other LIVE document version references is
// withdrawn as well and scheduled for reclamation; units still referenced
// stay LIVE (V-064). Withdrawing the current version clears the head; it
// never restores an older version.
func (s *Service) WithdrawDocumentVersion(ctx context.Context, c Caller, bucketName, key, versionSel string) (DeleteOutcome, error) {
	doc, _, err := s.documentKey(ctx, c.Tenant, bucketName, key)
	if err != nil {
		return DeleteOutcome{}, err
	}
	dv, err := cryptowire.ParseUUID(versionSel)
	if err != nil {
		return DeleteOutcome{}, ErrNotFound
	}
	var state string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT state FROM document_versions WHERE tenant = $1 AND id = $2 AND document = $3`, c.Tenant, dv, doc).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != "LIVE" {
		return DeleteOutcome{}, ErrNotFound
	}
	if err != nil {
		return DeleteOutcome{}, err
	}
	rec, err := s.decidePlanned(ctx, c, registry.OpDocDeleteVersion,
		[]check{{id: "document", role: registry.RoleDocument, action: "delete-version", ref: canonical("storage.object", doc.String())}},
		opplan.Summary{Action: "delete-version", Targets: []opplan.Target{{Role: registry.RoleDocument, Type: "storage.object", ID: doc.String(), Version: dv.String()}},
			Details: details(map[string]string{"bucket": bucketName, "key": key})})
	if err != nil {
		return DeleteOutcome{}, err
	}
	var out DeleteOutcome
	err = s.fenced(ctx, rec, []string{doc.String()}, func(ctx context.Context, tx pgx.Tx) error {
		var head *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_document_version FROM objects WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, doc).Scan(&head); err != nil {
			return err
		}
		var original *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT state, original_version FROM document_versions WHERE tenant = $1 AND id = $2 FOR UPDATE`,
			c.Tenant, dv).Scan(&state, &original); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE document_versions SET state = 'WITHDRAWN' WHERE tenant = $1 AND id = $2`, c.Tenant, dv); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND type = 'document.version' AND id = $2`,
			c.Tenant, dv.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE envelopes SET status = 'RETIRED' WHERE tenant = $1 AND document_version = $2 AND status = 'ACTIVE'`, c.Tenant, dv); err != nil {
			return err
		}
		// Lock the version's unit versions before looking for other
		// references, so a concurrent publication that reuses one is
		// either seen here or fails on the withdrawn state.
		rows, err := tx.Query(ctx, `SELECT v.id, v.object, v.blob, v.ciphertext_sha256 FROM object_versions v
		                             JOIN document_units u ON u.tenant = v.tenant AND u.unit_version = v.id
		                            WHERE u.tenant = $1 AND u.document_version = $2 AND v.state = 'LIVE' ORDER BY v.id FOR UPDATE OF v`, c.Tenant, dv)
		if err != nil {
			return err
		}
		type unitVersion struct {
			id, object, blob cryptowire.UUID
			sum              string
		}
		var candidates []unitVersion
		for rows.Next() {
			var u unitVersion
			if err := rows.Scan(&u.id, &u.object, &u.blob, &u.sum); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if original != nil {
			var u unitVersion
			if err := tx.QueryRow(ctx, `SELECT id, object, blob, ciphertext_sha256 FROM object_versions WHERE tenant = $1 AND id = $2 FOR UPDATE`,
				c.Tenant, *original).Scan(&u.id, &u.object, &u.blob, &u.sum); err != nil {
				return err
			}
			candidates = append(candidates, u)
		}
		targets := []audit.Target{{Type: "document.version", ID: dv.String()}}
		for _, u := range candidates {
			var referenced bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM document_units x JOIN document_versions d ON d.tenant = x.tenant AND d.id = x.document_version
			                             WHERE x.tenant = $1 AND x.unit_version = $2 AND d.state = 'LIVE')`, c.Tenant, u.id).Scan(&referenced); err != nil {
				return err
			}
			if referenced {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE object_versions SET state = 'WITHDRAWN' WHERE tenant = $1 AND id = $2`, c.Tenant, u.id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE envelopes SET status = 'RETIRED' WHERE tenant = $1 AND version = $2 AND status = 'ACTIVE'`, c.Tenant, u.id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2`, c.Tenant, u.object.String()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO retirements (tenant, version, blob, requested_at) VALUES ($1, $2, $3, $4)`,
				c.Tenant, u.id, u.blob, now); err != nil {
				return err
			}
			targets = append(targets, audit.Target{Type: "storage.object", ID: u.object.String(), Version: u.id.String(), Digest: u.sum})
		}
		var gen uint64
		if err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1 WHERE tenant = $1 AND id = $2 RETURNING generation`,
			c.Tenant, doc.String()).Scan(&gen); err != nil {
			return err
		}
		if head != nil && *head == dv {
			if _, err := tx.Exec(ctx, `UPDATE objects SET current_document_version = NULL WHERE tenant = $1 AND id = $2`, c.Tenant, doc); err != nil {
				return err
			}
		}
		out = DeleteOutcome{Version: dv.String(), State: "WITHDRAWN", Generation: gen}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "DOCUMENT_VERSION_WITHDRAWN", targets...))
	})
	if err != nil {
		return DeleteOutcome{}, err
	}
	return out, nil
}
