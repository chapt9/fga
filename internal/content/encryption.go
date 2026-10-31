package content

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/opplan"
	"fga/internal/registry"
)

// Encryption modes (specification 2.6, D-12, ENC-001, ENC-002). A bucket
// is in server mode or client mode. Its mode is copied to each upload it
// admits, and each version keeps the mode it was published under. The
// routes of this package serve client mode; a server-mode bucket or
// version gets ErrEncryptionMode from them, after authorization.

// EncryptionOutcome reports a bucket's encryption mode change.
type EncryptionOutcome struct {
	Bucket           string `json:"bucket_id"`
	Encryption       string `json:"encryption"`
	Previous         string `json:"previous_encryption"`
	MetadataRevision uint64 `json:"metadata_revision"`
}

// SetBucketEncryption changes a bucket's encryption mode (ENC-001). It
// needs manage on the bucket, which a policy may make subject to an
// approval; the decision sees the proposed mode as new_encryption. The
// change applies only to uploads begun after it commits: an upload begun
// earlier keeps its mode, and every version keeps its own. The bucket and
// every resource in it take the new attribute and advance their metadata
// revision, so decisions bound to the old mode fail.
func (s *Service) SetBucketEncryption(ctx context.Context, c Caller, bucketName, mode string) (EncryptionOutcome, error) {
	if !catalog.EncryptionMode(mode) {
		return EncryptionOutcome{}, ErrInvalid
	}
	b, err := s.bucketByName(ctx, c.Tenant, bucketName)
	if err != nil {
		return EncryptionOutcome{}, err
	}
	r, err := s.d.Catalog.GetResource(ctx, c.Tenant, b.ID.String())
	if err != nil {
		return EncryptionOutcome{}, err
	}
	id := b.ID.String()
	rec, err := s.decidePlanned(ctx, c, registry.OpBucketSetEncryption,
		[]check{{id: "bucket", role: registry.RoleBucket, action: "manage", ref: planned(registry.ChangeEncryption, id+"|"+mode)}},
		opplan.Summary{Action: "manage", Targets: []opplan.Target{{Role: registry.RoleBucket, Type: "storage.bucket", ID: id}},
			Changes: map[string]string{"encryption": mode, "previous_encryption": b.Encryption},
			Details: details(map[string]string{"bucket": bucketName})})
	if err != nil {
		return EncryptionOutcome{}, err
	}
	out := EncryptionOutcome{Bucket: id, Encryption: mode, Previous: b.Encryption, MetadataRevision: r.MetadataRevision}
	err = s.fenced(ctx, rec, []string{id}, func(ctx context.Context, tx pgx.Tx) error {
		current, err := catalog.BucketEncryption(ctx, tx, c.Tenant, id, true)
		if err != nil {
			return err
		}
		if current != b.Encryption {
			return fmt.Errorf("%w: the bucket's encryption mode changed", ErrConflict)
		}
		if mode == current {
			return nil
		}
		meta, err := catalog.SetBucketEncryption(ctx, tx, c.Tenant, id, mode)
		if err != nil {
			return err
		}
		out.MetadataRevision = meta
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "ENCRYPTION_MODE_CHANGED",
			audit.Target{Type: "storage.bucket", ID: id, Generation: meta}))
	})
	if err != nil {
		return EncryptionOutcome{}, err
	}
	return out, nil
}
