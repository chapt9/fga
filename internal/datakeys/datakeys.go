// Package datakeys is the keys role's part of server mode (specification
// 2.6, D-12, SSE-002 to SSE-004; docs/design/server-keys.md). It seals a
// fresh data key for a server-mode upload and releases a version's data
// key for a read, each against a single-use decision signed for the keys
// role whose checks are exactly those of the operation and bound to the
// exact intent or version. Each is admitted inside the authority fence,
// with the same bindings as an envelope delivery, and audited without key
// material.
//
// Only the keys role links this package, and with it the key-encryption
// keys (MOD-004). It never sees blobs or payload plaintext: the storage
// role encrypts and decrypts with the data key it receives.
package datakeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/kek"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Errors of the service. They carry no protected identifiers.
var (
	ErrDecision    = errors.New("datakeys: decision does not authorize this key")
	ErrNotFound    = errors.New("datakeys: not found")
	ErrConflict    = errors.New("datakeys: conflict")
	ErrUnavailable = errors.New("datakeys: a dependency is unavailable")
)

// Sealer seals and opens data keys under a tenant's KEK versions
// (*kek.File, or *kek.Ring in tests).
type Sealer interface {
	Seal(tenant string, version uint32, dataKey []byte, b kek.Binding) ([]byte, error)
	Open(tenant string, version uint32, sealed []byte, b kek.Binding) ([]byte, error)
}

// Deps are the service's dependencies; all are required.
type Deps struct {
	Catalog *catalog.Store
	Fence   *fence.Fence
	// Verifier verifies decisions for audience fga-keys.
	Verifier *signing.Verifier
	KEKs     Sealer
	Now      func() time.Time
}

// Service seals and releases data keys.
type Service struct {
	d   Deps
	ops *registry.Operations
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	if d.Catalog == nil || d.Fence == nil || d.Verifier == nil || d.KEKs == nil || d.Now == nil {
		return nil, errors.New("datakeys: every dependency is required")
	}
	return &Service{d: d, ops: registry.R1Operations(registry.R1Types())}, nil
}

// DataKey is a data key and its sealed form. The caller owns Key and
// clears it after use (SSE-004).
type DataKey struct {
	Key        []byte
	Sealed     []byte
	KEKVersion uint32
}

// verify checks a decision's signature and that it is single-use, of one
// of ops, and has exactly the operation's checks.
func (s *Service) verify(decision signing.Signed, ops ...string) (signing.Record, error) {
	rec, err := s.d.Verifier.Check(decision)
	if err != nil || !rec.SingleUse {
		return rec, ErrDecision
	}
	op, ok := s.ops.Lookup(rec.Operation)
	if !ok || !contains(ops, rec.Operation) || len(rec.Checks) != len(op.Checks) {
		return rec, ErrDecision
	}
	// Each registered check appears once, as an operation check of the
	// caller (these operations have no optional or recipient checks).
	for i, spec := range op.Checks {
		c := rec.Checks[i]
		if c.ResourceType != spec.ResourceType || c.Action != spec.Action || c.Kind != string(registry.KindOperation) {
			return rec, ErrDecision
		}
	}
	return rec, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Seal gives a server-mode upload intent its data key (SSE-001, SSE-003).
// The decision is for storage.key.seal-create with create-object on the
// intent's bucket, or storage.key.seal-version with new-version on its
// object, made for the intent's own principal. Inside the fence the
// intent must still be RESERVED, unexpired and without a key; the data key
// is sealed under the tenant's ACTIVE KEK version for the intent's exact
// identity and the sealed form is stored on the intent, once. The caller
// receives the data key itself to encrypt with.
func (s *Service) Seal(ctx context.Context, decision signing.Signed, intentID string) (DataKey, error) {
	rec, err := s.verify(decision, registry.OpKeySealCreate, registry.OpKeySealVersion)
	if err != nil {
		return DataKey{}, err
	}
	id, err := cryptowire.ParseUUID(intentID)
	if err != nil {
		return DataKey{}, ErrNotFound
	}
	var in struct {
		binding           kek.Binding
		bucket            cryptowire.UUID
		principal, kind   string
		newObject         bool
		state, encryption string
		expiresAt         time.Time
		sealed            bool
	}
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, i.object, i.version, i.crypto_version, i.blob, i.bucket, i.principal, i.kind, i.new_object, i.state,
		       i.encryption, i.expires_at, i.sealed_key IS NOT NULL
		  FROM upload_intents i JOIN tenants t ON t.name = i.tenant
		 WHERE i.tenant = $1 AND i.id = $2`, rec.Tenant, id).
		Scan(&in.binding.Tenant, &in.binding.Object, &in.binding.Version, &in.binding.CryptoVersion, &in.binding.Blob, &in.bucket,
			&in.principal, &in.kind, &in.newObject, &in.state, &in.encryption, &in.expiresAt, &in.sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return DataKey{}, ErrNotFound
	}
	if err != nil {
		return DataKey{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// The decision is about this intent: its principal, and the bucket of
	// a new key or the object of a new version.
	c := rec.Checks[0]
	bound := in.principal == rec.Actor.ID && in.kind == "object" && in.encryption == "server"
	if rec.Operation == registry.OpKeySealCreate {
		bound = bound && in.newObject && c.ResourceID == in.bucket.String()
	} else {
		bound = bound && !in.newObject && c.ResourceID == in.binding.Object.String()
	}
	if !bound {
		return DataKey{}, ErrDecision
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return DataKey{}, ErrDecision
	}
	var out DataKey
	err = s.d.Fence.RunAll(ctx, []fence.Binding{b}, nil, func(ctx context.Context, tx pgx.Tx) error {
		clear(out.Key)
		out = DataKey{}
		if err := tx.QueryRow(ctx, `SELECT state, sealed_key IS NOT NULL FROM upload_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`,
			rec.Tenant, id).Scan(&in.state, &in.sealed); err != nil {
			return err
		}
		if in.state != "RESERVED" || in.sealed || !s.d.Now().Before(in.expiresAt) {
			return fmt.Errorf("%w: the intent is %s, expired or already has its key", ErrConflict, in.state)
		}
		var version uint32
		err := tx.QueryRow(ctx, `SELECT version FROM kek_versions WHERE tenant = $1 AND state = 'ACTIVE' FOR SHARE`, rec.Tenant).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: the tenant has no active key-encryption key", ErrUnavailable)
		}
		if err != nil {
			return err
		}
		key, err := kek.NewDataKey()
		if err != nil {
			return err
		}
		sealed, err := s.d.KEKs.Seal(rec.Tenant, version, key, in.binding)
		if err != nil {
			clear(key)
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		out = DataKey{Key: key, Sealed: sealed, KEKVersion: version}
		if _, err := tx.Exec(ctx, `UPDATE upload_intents SET sealed_key = $3, kek_version = $4 WHERE tenant = $1 AND id = $2`,
			rec.Tenant, id, sealed, int64(version)); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(rec, "DATA_KEY_SEALED", in.binding, version))
	})
	if err != nil {
		clear(out.Key)
		return DataKey{}, classify(err)
	}
	return out, nil
}

// Release opens the data key of a LIVE server-mode version for a read
// (SSE-003). The decision is for storage.key.release with read on the
// version's object, or storage.key.release-history with read and
// read-history, bound to the exact version. Inside the fence the version
// must be LIVE, and a plain read only releases the current version, so a
// concurrent overwrite cannot turn an old version into a current read
// (review finding 2). Every release is audited; the caller owns the key.
func (s *Service) Release(ctx context.Context, decision signing.Signed, versionID string) ([]byte, error) {
	rec, err := s.verify(decision, registry.OpKeyRelease, registry.OpKeyReleaseHistory)
	if err != nil {
		return nil, err
	}
	id, err := cryptowire.ParseUUID(versionID)
	if err != nil {
		return nil, ErrNotFound
	}
	var bnd kek.Binding
	var mode string
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, v.object, v.id, coalesce(v.crypto_version, '00000000-0000-0000-0000-000000000000'),
		       coalesce(v.blob, '00000000-0000-0000-0000-000000000000'), coalesce(v.encryption, '')
		  FROM object_versions v JOIN tenants t ON t.name = v.tenant
		 WHERE v.tenant = $1 AND v.id = $2`, rec.Tenant, id).
		Scan(&bnd.Tenant, &bnd.Object, &bnd.Version, &bnd.CryptoVersion, &bnd.Blob, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Only a server-mode version has a data key here (ENC-002); every
	// check names its object and exact version.
	if mode != "server" {
		return nil, ErrDecision
	}
	for _, c := range rec.Checks {
		if c.ResourceID != bnd.Object.String() || c.Version != versionID {
			return nil, ErrDecision
		}
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return nil, ErrDecision
	}
	var sealed []byte
	var kekVersion int64
	err = s.d.Fence.RunAll(ctx, []fence.Binding{b}, nil, func(ctx context.Context, tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state, sealed_key, kek_version FROM object_versions WHERE tenant = $1 AND id = $2 FOR SHARE`,
			rec.Tenant, id).Scan(&state, &sealed, &kekVersion); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		if rec.Operation == registry.OpKeyRelease {
			var head *cryptowire.UUID
			if err := tx.QueryRow(ctx, `SELECT current_version FROM objects WHERE tenant = $1 AND id = $2 FOR SHARE`,
				rec.Tenant, bnd.Object).Scan(&head); err != nil {
				return err
			}
			if head == nil || *head != id {
				return ErrNotFound
			}
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(rec, "DATA_KEY_RELEASED", bnd, uint32(kekVersion)))
	})
	if err != nil {
		return nil, classify(err)
	}
	key, err := s.d.KEKs.Open(rec.Tenant, uint32(kekVersion), sealed, bnd)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return key, nil
}

// event is the audit record of a seal or release: identities, decision
// and KEK version, never key material (SSE-003, SSE-004).
func (s *Service) event(rec signing.Record, outcome string, b kek.Binding, kekVersion uint32) audit.Event {
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: audit.KindKeyRelease, Tenant: rec.Tenant, DecisionID: rec.DecisionID,
		OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: outcome, BundleDigest: rec.BundleDigest, PolicyEpoch: rec.PolicyEpoch,
		At: s.d.Now(), Targets: []audit.Target{{Type: "storage.object", ID: b.Object.String(), Version: b.Version.String(),
			KEKVersion: kekVersion}}}
}

// classify keeps the service's own errors and reports anything else from
// the fence as a decision that no longer authorizes the key.
func classify(err error) error {
	for _, e := range []error{ErrNotFound, ErrConflict, ErrUnavailable} {
		if errors.Is(err, e) {
			return err
		}
	}
	return fmt.Errorf("%w: %v", ErrDecision, err)
}
