package catalog

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"fga/internal/registry"
)

// Encryption modes (specification 2.6, D-12, ENC-001). The attribute
// "encryption" of a bucket and of every resource stored in it is the
// bucket's mode: the mode its new uploads get. Each version records the
// mode it was published under in its own row and keeps it (ENC-002).

// changedEncryption resolves a proposed encryption mode for a bucket: the
// bucket as it is, with new_encryption added.
func (v resourceView) changedEncryption(ctx context.Context, tenant string, alias registry.Alias) (registry.Resource, error) {
	id, mode, ok := strings.Cut(alias.Name, "|")
	if !ok || id == "" || !EncryptionMode(mode) {
		return registry.Resource{}, registry.ErrUnknownAlias
	}
	r, err := v.s.GetResource(ctx, tenant, id)
	if err != nil {
		return registry.Resource{}, err
	}
	if r.Type != "storage.bucket" {
		return registry.Resource{}, registry.ErrUnknownResource
	}
	attrs := make(map[string]any, len(r.Attributes)+1)
	for k, val := range r.Attributes {
		attrs[k] = val
	}
	attrs["new_encryption"] = mode
	r.Attributes = attrs
	return r, nil
}

// BucketEncryption returns a bucket's mode inside tx and locks the bucket
// row: for update when the mode is about to change, otherwise for share,
// so an upload begun under one mode cannot commit after a change to
// another.
func BucketEncryption(ctx context.Context, tx pgx.Tx, tenant, bucket string, forUpdate bool) (string, error) {
	sql := `SELECT encryption FROM buckets WHERE tenant = $1 AND id = $2 FOR SHARE`
	if forUpdate {
		sql = `SELECT encryption FROM buckets WHERE tenant = $1 AND id = $2 FOR UPDATE`
	}
	var mode string
	err := tx.QueryRow(ctx, sql, tenant, bucket).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", registry.ErrUnknownResource
	}
	return mode, err
}

// SetBucketEncryption changes a bucket's mode inside tx, after
// BucketEncryption locked it for update. The bucket and every resource
// stored in it take the new attribute and advance their metadata revision,
// so decisions bound to the old mode fail (DEC-006); open uploads keep the
// mode they began with but plan the new attribute. Versions keep theirs.
// It returns the bucket's new metadata revision.
func SetBucketEncryption(ctx context.Context, tx pgx.Tx, tenant, bucket, mode string) (uint64, error) {
	if !EncryptionMode(mode) {
		return 0, registry.ErrUnknownAlias
	}
	if _, err := tx.Exec(ctx, `UPDATE buckets SET encryption = $3 WHERE tenant = $1 AND id = $2`, tenant, bucket, mode); err != nil {
		return 0, err
	}
	var meta uint64
	err := tx.QueryRow(ctx, `UPDATE resources SET attributes = attributes || jsonb_build_object('encryption', $3::text),
	                                metadata_revision = metadata_revision + 1
	                          WHERE tenant = $1 AND type = 'storage.bucket' AND id = $2 RETURNING metadata_revision`,
		tenant, bucket, mode).Scan(&meta)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, registry.ErrUnknownResource
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE resources r SET attributes = r.attributes || jsonb_build_object('encryption', $3::text),
		                       metadata_revision = r.metadata_revision + 1
		 WHERE r.tenant = $1 AND (r.id IN (SELECT id::text FROM objects WHERE tenant = $1 AND bucket = $2::uuid)
		    OR r.id IN (SELECT d.id::text FROM document_versions d JOIN objects o ON o.tenant = d.tenant AND o.id = d.document
		                 WHERE d.tenant = $1 AND o.bucket = $2::uuid))`, tenant, bucket, mode); err != nil {
		return 0, err
	}
	for _, table := range []string{"upload_intents", "document_intents"} {
		if _, err := tx.Exec(ctx, `UPDATE `+table+` SET planned_attributes = planned_attributes || jsonb_build_object('encryption', $3::text)
		                            WHERE tenant = $1 AND bucket = $2::uuid AND state IN ('RESERVED', 'STAGED')`, tenant, bucket, mode); err != nil {
			return 0, err
		}
	}
	return meta, nil
}
