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
	"fga/internal/keycheck"
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
	// Intent is the unit intent a document seal made the key for.
	Intent string
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
	rec, err := s.verify(decision, registry.OpKeySealCreate, registry.OpKeySealVersion, registry.OpKeySealDerivedVersion)
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
	// An object's or a derived output's upload: the bucket of a new key,
	// new-version on an existing object, or on an existing output.
	c := rec.Checks[0]
	bound := in.principal == rec.Actor.ID && (in.kind == "object" || in.kind == "derived") && in.encryption == "server"
	switch rec.Operation {
	case registry.OpKeySealCreate:
		bound = bound && in.newObject && c.ResourceID == in.bucket.String()
	case registry.OpKeySealVersion:
		bound = bound && in.kind == "object" && !in.newObject && c.ResourceID == in.binding.Object.String()
	default:
		bound = bound && in.kind == "derived" && !in.newObject && c.ResourceID == in.binding.Object.String()
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

// SealDocument gives every new unit of a server-mode document intent, and
// its original file if it reserved one, its
// data key (SSE-001, SSE-003). The decision is for
// storage.key.seal-document-create with create-object on the intent's
// bucket, or storage.key.seal-document-version with new-version on its
// document, made for the intent's own principal. Inside the fence the
// document intent must be RESERVED and unexpired and each unit intent
// RESERVED without a key; each key is sealed for its unit's exact
// identity and stored with the unit intent, once. Reused units get none.
func (s *Service) SealDocument(ctx context.Context, decision signing.Signed, docIntentID string) ([]DataKey, error) {
	rec, err := s.verify(decision, registry.OpKeySealDocCreate, registry.OpKeySealDocVersion)
	if err != nil {
		return nil, err
	}
	id, err := cryptowire.ParseUUID(docIntentID)
	if err != nil {
		return nil, ErrNotFound
	}
	var tenant, bucket, document cryptowire.UUID
	var principal, state, mode, kind string
	var newDocument bool
	var expiresAt time.Time
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, d.bucket, d.document, d.principal, d.new_document, d.state, d.encryption, d.expires_at,
		       coalesce(d.planned_attributes->>'kind', '')
		  FROM document_intents d JOIN tenants t ON t.name = d.tenant
		 WHERE d.tenant = $1 AND d.id = $2`, rec.Tenant, id).
		Scan(&tenant, &bucket, &document, &principal, &newDocument, &state, &mode, &expiresAt, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c := rec.Checks[0]
	bound := principal == rec.Actor.ID && mode == "server"
	if rec.Operation == registry.OpKeySealDocCreate {
		bound = bound && newDocument && c.ResourceID == bucket.String()
	} else {
		bound = bound && !newDocument && c.ResourceID == document.String()
	}
	if !bound {
		return nil, ErrDecision
	}
	unitType := "document.text_unit"
	if kind == "collection" {
		unitType = "text.entry"
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return nil, ErrDecision
	}
	var out []DataKey
	clearAll := func() {
		for _, k := range out {
			clear(k.Key)
		}
		out = nil
	}
	err = s.d.Fence.RunAll(ctx, []fence.Binding{b}, nil, func(ctx context.Context, tx pgx.Tx) error {
		clearAll()
		if err := tx.QueryRow(ctx, `SELECT state FROM document_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`, rec.Tenant, id).Scan(&state); err != nil {
			return err
		}
		if state != "RESERVED" || !s.d.Now().Before(expiresAt) {
			return fmt.Errorf("%w: the document intent is %s or expired", ErrConflict, state)
		}
		var version uint32
		err := tx.QueryRow(ctx, `SELECT version FROM kek_versions WHERE tenant = $1 AND state = 'ACTIVE' FOR SHARE`, rec.Tenant).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: the tenant has no active key-encryption key", ErrUnavailable)
		}
		if err != nil {
			return err
		}
		type unit struct {
			id     cryptowire.UUID
			b      kek.Binding
			state  string
			sealed bool
			mode   string
			kind   string
		}
		rows, err := tx.Query(ctx, `
			SELECT id, object, version, crypto_version, blob, state, sealed_key IS NOT NULL, encryption, kind FROM upload_intents
			 WHERE tenant = $1 AND document_intent = $2 AND kind IN ('unit', 'original') ORDER BY id FOR UPDATE`, rec.Tenant, id)
		if err != nil {
			return err
		}
		var units []unit
		for rows.Next() {
			u := unit{b: kek.Binding{Tenant: tenant}}
			if err := rows.Scan(&u.id, &u.b.Object, &u.b.Version, &u.b.CryptoVersion, &u.b.Blob, &u.state, &u.sealed, &u.mode, &u.kind); err != nil {
				rows.Close()
				return err
			}
			units = append(units, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var targets []audit.Target
		for _, u := range units {
			if u.state != "RESERVED" || u.sealed || u.mode != "server" {
				return fmt.Errorf("%w: a unit intent is %s or already has its key", ErrConflict, u.state)
			}
			key, err := kek.NewDataKey()
			if err != nil {
				return err
			}
			sealed, err := s.d.KEKs.Seal(rec.Tenant, version, key, u.b)
			if err != nil {
				clear(key)
				return fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			out = append(out, DataKey{Key: key, Sealed: sealed, KEKVersion: version, Intent: u.id.String()})
			if _, err := tx.Exec(ctx, `UPDATE upload_intents SET sealed_key = $3, kek_version = $4 WHERE tenant = $1 AND id = $2`,
				rec.Tenant, u.id, sealed, int64(version)); err != nil {
				return err
			}
			typ := unitType
			if u.kind == "original" {
				typ = "document.original"
			}
			targets = append(targets, audit.Target{Type: typ, ID: u.b.Object.String(), Version: u.b.Version.String(), KEKVersion: version})
		}
		ev := s.event(rec, "DATA_KEY_SEALED", kek.Binding{Object: document}, version)
		ev.Targets = append([]audit.Target{{Type: "storage.object", ID: document.String(), KEKVersion: version}}, targets...)
		return s.d.Catalog.AppendTx(ctx, tx, ev)
	})
	if err != nil {
		clearAll()
		return nil, classify(err)
	}
	return out, nil
}

// ReleaseUnit opens the data key of one unit or entry of a LIVE
// server-mode document version for a read (SSE-003, DOC-006). The decision
// is for storage.key.release-unit (or release-entry) with read-units on
// that document version and read on that unit at the exact unit version
// the version holds. Inside the fence both must still be LIVE. Every
// release is audited; the caller owns the key.
func (s *Service) ReleaseUnit(ctx context.Context, decision signing.Signed, documentVersionID, unitID string) ([]byte, error) {
	rec, err := s.verify(decision, registry.OpKeyReleaseUnit, registry.OpKeyReleaseEntry)
	if err != nil {
		return nil, err
	}
	dv, err := cryptowire.ParseUUID(documentVersionID)
	if err != nil {
		return nil, ErrNotFound
	}
	var bnd kek.Binding
	var docMode, unitMode string
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, v.object, v.id, coalesce(v.crypto_version, '00000000-0000-0000-0000-000000000000'),
		       coalesce(v.blob, '00000000-0000-0000-0000-000000000000'), d.encryption, coalesce(v.encryption, '')
		  FROM document_units u JOIN document_versions d ON d.tenant = u.tenant AND d.id = u.document_version
		  JOIN object_versions v ON v.tenant = u.tenant AND v.id = u.unit_version
		  JOIN tenants t ON t.name = u.tenant
		 WHERE u.tenant = $1 AND u.document_version = $2 AND u.unit::text = $3`, rec.Tenant, dv, unitID).
		Scan(&bnd.Tenant, &bnd.Object, &bnd.Version, &bnd.CryptoVersion, &bnd.Blob, &docMode, &unitMode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Server mode only; the checks name this document version, and this
	// unit at the version this document version holds.
	if docMode != "server" || unitMode != "server" ||
		rec.Checks[0].ResourceID != documentVersionID || rec.Checks[1].ResourceID != unitID || rec.Checks[1].Version != bnd.Version.String() {
		return nil, ErrDecision
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return nil, ErrDecision
	}
	var sealed []byte
	var kekVersion int64
	err = s.d.Fence.RunAll(ctx, []fence.Binding{b}, nil, func(ctx context.Context, tx pgx.Tx) error {
		var docState, unitState string
		if err := tx.QueryRow(ctx, `SELECT d.state, v.state, v.sealed_key, v.kek_version FROM document_versions d, object_versions v
		                             WHERE d.tenant = $1 AND d.id = $2 AND v.tenant = $1 AND v.id = $3 FOR SHARE`,
			rec.Tenant, dv, bnd.Version).Scan(&docState, &unitState, &sealed, &kekVersion); err != nil {
			return err
		}
		if docState != "LIVE" || unitState != "LIVE" {
			return ErrNotFound
		}
		ev := s.event(rec, "DATA_KEY_RELEASED", bnd, uint32(kekVersion))
		ev.Targets[0].Type = rec.Checks[1].ResourceType
		ev.Targets = append(ev.Targets, audit.Target{Type: "document.version", ID: documentVersionID})
		return s.d.Catalog.AppendTx(ctx, tx, ev)
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

// ReleaseOriginal opens the data key of a LIVE server-mode document
// version's original file (CNT-003, SSE-003). The decision is for
// storage.key.release-original with raw-read on that document version;
// extra are the complete-content decisions, raw-read on the version and
// read on every unit (internal/keycheck). All are single-use and admitted
// in one fence with the release, so a change to any unit between the
// storage role's checks and the release blocks it (review finding 3,
// V-163). The release is audited; the caller owns the key.
func (s *Service) ReleaseOriginal(ctx context.Context, decision signing.Signed, extra []signing.Signed, documentVersionID string) ([]byte, error) {
	rec, err := s.verify(decision, registry.OpKeyReleaseOriginal)
	if err != nil {
		return nil, err
	}
	dv, err := cryptowire.ParseUUID(documentVersionID)
	if err != nil || rec.Checks[0].ResourceID != documentVersionID {
		return nil, ErrDecision
	}
	var bnd kek.Binding
	var docMode, origMode string
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, v.object, v.id, coalesce(v.crypto_version, '00000000-0000-0000-0000-000000000000'),
		       coalesce(v.blob, '00000000-0000-0000-0000-000000000000'), d.encryption, coalesce(v.encryption, '')
		  FROM document_versions d JOIN object_versions v ON v.tenant = d.tenant AND v.id = d.original_version
		  JOIN tenants t ON t.name = d.tenant
		 WHERE d.tenant = $1 AND d.id = $2`, rec.Tenant, dv).
		Scan(&bnd.Tenant, &bnd.Object, &bnd.Version, &bnd.CryptoVersion, &bnd.Blob, &docMode, &origMode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if docMode != "server" || origMode != "server" {
		return nil, ErrDecision
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return nil, ErrDecision
	}
	more, err := keycheck.CompleteContent(ctx, s.d.Catalog.Pool(), s.d.Verifier, rec, dv, extra)
	if errors.Is(err, keycheck.ErrDecision) {
		return nil, ErrDecision
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var sealed []byte
	var kekVersion int64
	err = s.d.Fence.RunAll(ctx, append([]fence.Binding{b}, more...), nil, func(ctx context.Context, tx pgx.Tx) error {
		var docState, origState string
		if err := tx.QueryRow(ctx, `SELECT d.state, v.state, v.sealed_key, v.kek_version FROM document_versions d, object_versions v
		                             WHERE d.tenant = $1 AND d.id = $2 AND v.tenant = $1 AND v.id = $3 FOR SHARE`,
			rec.Tenant, dv, bnd.Version).Scan(&docState, &origState, &sealed, &kekVersion); err != nil {
			return err
		}
		if docState != "LIVE" || origState != "LIVE" {
			return ErrNotFound
		}
		ev := s.event(rec, "DATA_KEY_RELEASED", bnd, uint32(kekVersion))
		ev.Targets[0].Type = "document.original"
		ev.Targets = append(ev.Targets, audit.Target{Type: "document.version", ID: documentVersionID})
		return s.d.Catalog.AppendTx(ctx, tx, ev)
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

// ReleaseDerived opens the data key of a LIVE server-mode derived output's
// version for its reader, the caller (DRV-002, SSE-003). The decision is
// for storage.key.release-derived with deliver on that output version;
// extra is the reader path (internal/keycheck): the caller's read on every
// source of the transitive lineage, or a declassification for the caller.
// All are admitted in one fence with the release, so a source change in
// between yields no key (DRV-009). The release is audited.
func (s *Service) ReleaseDerived(ctx context.Context, decision signing.Signed, extra []signing.Signed, versionID string) ([]byte, error) {
	rec, err := s.verify(decision, registry.OpKeyReleaseDerived)
	if err != nil {
		return nil, err
	}
	id, err := cryptowire.ParseUUID(versionID)
	if err != nil {
		return nil, ErrNotFound
	}
	var bnd kek.Binding
	var mode, kind string
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT t.id, v.object, v.id, coalesce(v.crypto_version, '00000000-0000-0000-0000-000000000000'),
		       coalesce(v.blob, '00000000-0000-0000-0000-000000000000'), coalesce(v.encryption, ''), o.kind
		  FROM object_versions v JOIN objects o ON o.tenant = v.tenant AND o.id = v.object JOIN tenants t ON t.name = v.tenant
		 WHERE v.tenant = $1 AND v.id = $2`, rec.Tenant, id).
		Scan(&bnd.Tenant, &bnd.Object, &bnd.Version, &bnd.CryptoVersion, &bnd.Blob, &mode, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if mode != "server" || kind != "derived" || rec.Checks[0].ResourceID != bnd.Object.String() || rec.Checks[0].Version != versionID {
		return nil, ErrDecision
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return nil, ErrDecision
	}
	more, err := keycheck.ReaderPath(ctx, s.d.Catalog.Pool(), s.d.Verifier, rec, bnd.Object, id, extra)
	if errors.Is(err, keycheck.ErrDecision) {
		return nil, ErrDecision
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var sealed []byte
	var kekVersion int64
	err = s.d.Fence.RunAll(ctx, append([]fence.Binding{b}, more...), nil, func(ctx context.Context, tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state, sealed_key, kek_version FROM object_versions WHERE tenant = $1 AND id = $2 FOR SHARE`,
			rec.Tenant, id).Scan(&state, &sealed, &kekVersion); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		ev := s.event(rec, "DATA_KEY_RELEASED", bnd, uint32(kekVersion))
		ev.Targets[0].Type = "document.derived"
		return s.d.Catalog.AppendTx(ctx, tx, ev)
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
// the fence as a decision that no longer authorizes the key. When the
// authority it bound moved on in the meantime, that is also a conflict,
// which the caller may begin again after (review v2, finding 3).
func classify(err error) error {
	for _, e := range []error{ErrNotFound, ErrConflict, ErrUnavailable} {
		if errors.Is(err, e) {
			return err
		}
	}
	if errors.Is(err, fence.ErrAdmissionClosed) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, e := range []error{fence.ErrIncarnation, fence.ErrEpoch, fence.ErrIdentity, fence.ErrDelegation, fence.ErrRecipientKey,
		fence.ErrResource, fence.ErrExpired, fence.ErrReplayed, fence.ErrApproval} {
		if errors.Is(err, e) {
			return fmt.Errorf("%w: %w: %v", ErrDecision, ErrConflict, err)
		}
	}
	return fmt.Errorf("%w: %v", ErrDecision, err)
}
