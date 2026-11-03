package content

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/registry"
)

// The content service's own catalog reads. Visibility decisions use only
// committed state: a head with a LIVE current version (PUB-004).

type bucket struct {
	ID         cryptowire.UUID
	Name       string
	Scope      string
	Project    string
	Label      string
	Encryption string
	// Source names the source of JSON readings that owns the bucket, or
	// is empty (ING-001).
	Source string
}

// sourceBound lets content begin in a source's bucket only through the
// source's routes (ING-002): reading is the begin of a reading, nil for
// any other begin, and attrs the document's attributes, nil for an
// object. Callers check it after authorization, as the mode.
func sourceBound(b bucket, attrs map[string]any, reading *readingSpec) error {
	switch {
	case reading == nil && b.Source != "":
		return ErrSourceBucket
	case reading == nil:
		return nil
	}
	if src, _ := attrs["source"].(string); b.Source != reading.source || src != reading.source {
		return fmt.Errorf("%w: the bucket or the document belongs to another source", ErrConflict)
	}
	return nil
}

type object struct {
	ID         cryptowire.UUID
	Current    *cryptowire.UUID
	Generation uint64
	Meta       uint64
	Scope      string
	Attributes map[string]any
}

type version struct {
	ID            cryptowire.UUID
	Object        cryptowire.UUID
	DeleteMarker  bool
	CryptoVersion cryptowire.UUID
	Blob          cryptowire.UUID
	State         string
	Length        int64
	SHA256        string
	Suite, Format uint16
	Signer        string
	Descriptor    []byte
	DescriptorSig string
	CreatedAt     time.Time
	// Encryption is the mode the version was published under; a delete
	// marker has none (ENC-002). A server-mode version has its plaintext
	// length.
	Encryption      string
	PlaintextLength int64
}

func (s *Service) tenantID(ctx context.Context, tenant string) (cryptowire.UUID, error) {
	var id cryptowire.UUID
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE name = $1`, tenant).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, ErrNotFound
	}
	return id, err
}

// clientMode refuses a target in server mode on a client-mode route
// (ENC-002). Callers check it after authorization.
func clientMode(mode string) error {
	if mode != "client" {
		return ErrEncryptionMode
	}
	return nil
}

// modeHolds runs in the fence of an upload's begin: the bucket is still in
// the mode the upload was decided under, and stays so until the intent
// commits, so a mode change applies only to uploads begun after it
// (ENC-001).
func modeHolds(ctx context.Context, tx pgx.Tx, tenant string, b bucket) error {
	mode, err := catalog.BucketEncryption(ctx, tx, tenant, b.ID.String(), false)
	if err != nil {
		return err
	}
	if mode != b.Encryption {
		return fmt.Errorf("%w: the bucket's encryption mode changed", ErrConflict)
	}
	return nil
}

func (s *Service) bucketByName(ctx context.Context, tenant, name string) (bucket, error) {
	var b bucket
	err := s.d.Catalog.Pool().QueryRow(ctx,
		`SELECT id, name, scope, default_project, default_label, encryption, coalesce(source, '') FROM buckets WHERE tenant = $1 AND name = $2`,
		tenant, name).
		Scan(&b.ID, &b.Name, &b.Scope, &b.Project, &b.Label, &b.Encryption, &b.Source)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrNotFound
	}
	return b, err
}

// objectByKey returns the head of a key and its resource state.
func (s *Service) objectByKey(ctx context.Context, q catalog.Querier, tenant string, b cryptowire.UUID, key string) (object, error) {
	var o object
	err := q.QueryRow(ctx, `
		SELECT o.id, o.current_version, r.generation, r.metadata_revision, r.scope, r.attributes
		  FROM objects o JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
		 WHERE o.tenant = $1 AND o.bucket = $2 AND o.kind = 'object' AND o.key = $3`, tenant, b, key).
		Scan(&o.ID, &o.Current, &o.Generation, &o.Meta, &o.Scope, &o.Attributes)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, err
}

func (s *Service) versionByID(ctx context.Context, q catalog.Querier, tenant string, id cryptowire.UUID, lock bool) (version, error) {
	var v version
	sql := `SELECT id, object, delete_marker, coalesce(crypto_version, '00000000-0000-0000-0000-000000000000'),
	               coalesce(blob, '00000000-0000-0000-0000-000000000000'), state, coalesce(ciphertext_length, 0),
	               coalesce(ciphertext_sha256, ''), coalesce(suite, 0), coalesce(format, 0), coalesce(signer, ''),
	               coalesce(descriptor, ''), coalesce(descriptor_signature, ''), created_at, coalesce(encryption, ''),
	               coalesce(plaintext_length, 0)
	          FROM object_versions WHERE tenant = $1 AND id = $2`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, tenant, id).Scan(&v.ID, &v.Object, &v.DeleteMarker, &v.CryptoVersion, &v.Blob, &v.State,
		&v.Length, &v.SHA256, &v.Suite, &v.Format, &v.Signer, &v.Descriptor, &v.DescriptorSig, &v.CreatedAt, &v.Encryption, &v.PlaintextLength)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

// target resolves a key and an optional version selector to a readable
// version: the current one (never a delete marker), or a named LIVE version
// of this object. Anything else is not found.
func (s *Service) target(ctx context.Context, tenant, bucketName, key, versionSel string) (bucket, object, version, bool, error) {
	b, err := s.bucketByName(ctx, tenant, bucketName)
	if err != nil {
		return b, object{}, version{}, false, err
	}
	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), tenant, b.ID, key)
	if err != nil {
		return b, o, version{}, false, err
	}
	var id cryptowire.UUID
	if versionSel == "" {
		if o.Current == nil {
			return b, o, version{}, false, ErrNotFound
		}
		id = *o.Current
	} else if id, err = cryptowire.ParseUUID(versionSel); err != nil {
		return b, o, version{}, false, ErrNotFound
	}
	v, err := s.versionByID(ctx, s.d.Catalog.Pool(), tenant, id, false)
	if err != nil || v.Object != o.ID || v.State != "LIVE" || v.DeleteMarker {
		return b, o, version{}, false, ErrNotFound
	}
	return b, o, v, o.Current != nil && *o.Current == v.ID, nil
}

// objectAlias is the native alias of a key; bucket IDs never contain "/".
func objectAlias(b cryptowire.UUID, key string) registry.Alias {
	return registry.Alias{Namespace: "native.object", Name: b.String() + "/" + key}
}

// signerActive reports whether fingerprint is an ACTIVE content-signing
// key of principal and returns its public key (RCP-008, RCP-011).
func (s *Service) signerActive(ctx context.Context, tenant, principal, fingerprint string) ([]byte, error) {
	var pub []byte
	var owner, status string
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT public_key, principal, status FROM signing_keys WHERE tenant = $1 AND fingerprint = $2`,
		tenant, fingerprint).Scan(&pub, &owner, &status)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (owner != principal || status != "ACTIVE") {
		return nil, fmt.Errorf("%w: signer is not an active signing key of the uploader", ErrInvalid)
	}
	return pub, err
}

// recipientKey returns an ACTIVE recipient key's version.
func (s *Service) recipientKey(ctx context.Context, tenant, fingerprint string) (uint64, error) {
	var keyVersion uint64
	err := s.d.Catalog.Pool().QueryRow(ctx,
		`SELECT key_version FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2 AND status = 'ACTIVE'`, tenant, fingerprint).Scan(&keyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: recipient is not an active key", ErrInvalid)
	}
	return keyVersion, err
}
