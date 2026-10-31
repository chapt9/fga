package envelope

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fga/internal/audit"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/decisionsvc"
	"fga/internal/enforce"
	"fga/internal/fence"
	"fga/internal/registry"
	"fga/internal/signing"
)

// ChallengeLifetime bounds an enrollment challenge (RCP-002).
const ChallengeLifetime = 5 * time.Minute

// Journal records security-critical changes durably outside the catalog
// before they are committed, so a restore can replay them (AVL-008).
type Journal interface {
	Append(kind, tenant, subject string) error
	// Binding is the journal's identity and entry count, which the
	// catalog records with each journaled change.
	Binding() (id string, entries int, err error)
}

// Challenge is an enrollment challenge for one key.
type Challenge struct {
	ID              string    `json:"challenge_id"`
	Fingerprint     string    `json:"fingerprint"`
	KeyVersion      uint64    `json:"key_version"`
	Nonce           []byte    `json:"nonce"`
	EphemeralPublic []byte    `json:"ephemeral_public_key"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// KeyRecord is a directory entry. It identifies a key; it is not a trust
// anchor for publishing clients (RCP-002).
type KeyRecord struct {
	Fingerprint string `json:"fingerprint"`
	Principal   string `json:"principal"`
	PublicKey   []byte `json:"public_key"`
	KeyVersion  uint64 `json:"key_version,omitempty"`
	Status      string `json:"status"`
	Revision    uint64 `json:"revision"`
}

func (s *Service) authorize(ctx context.Context, c enforce.Caller, op string, checks []enforce.Check) (signing.Record, error) {
	_, rec, err := enforce.Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, op, enforce.KeysAudience, true, checks)
	if errors.Is(err, enforce.ErrNotFound) {
		return rec, ErrNotFound
	}
	if err != nil {
		return rec, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return rec, nil
}

func (s *Service) fenced(ctx context.Context, rec signing.Record, mutate []string, fn func(context.Context, pgx.Tx) error) error {
	b, err := fenceBinding(rec)
	if err != nil {
		return err
	}
	err = s.d.Fence.Run(ctx, b, mutate, fn)
	switch {
	case err == nil, errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound), errors.Is(err, ErrConflict):
		return err
	case errors.Is(err, audit.ErrFull):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
}

func (s *Service) audit(rec signing.Record, outcome string, t audit.Target) audit.Event {
	return audit.Event{ID: cryptowire.NewUUID().String(), Kind: audit.KindEnvelopePublication, Tenant: rec.Tenant, DecisionID: rec.DecisionID,
		OperationID: rec.OperationID, Actor: rec.Actor.ID, Outcome: outcome, BundleDigest: rec.BundleDigest, PolicyEpoch: rec.PolicyEpoch,
		Targets: []audit.Target{t}, At: s.d.Now()}
}

func plannedRecipient(principal, fp string) enforce.Check {
	return enforce.Check{ID: "recipient", Role: registry.RoleRecipient, Action: "", Resource: alias(registry.PlannedRecipient, principal+"|"+fp)}
}

// EnrollRecipient records the caller's new recipient public key as PENDING
// and returns a one-use possession challenge (RCP-002). It needs enroll on
// the planned key.
func (s *Service) EnrollRecipient(ctx context.Context, c enforce.Caller, public []byte) (Challenge, error) {
	if !cryptowire.ValidX25519PublicKey(public) {
		return Challenge{}, ErrInvalid
	}
	fp := cryptowire.RecipientFingerprint(cryptowire.Suite1, public).String()
	check := plannedRecipient(c.Principal, fp)
	check.Action = "enroll"
	rec, err := s.authorize(ctx, c, registry.OpEnrollRecipient, []enforce.Check{check})
	if err != nil {
		return Challenge{}, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Challenge{}, err
	}
	ch := Challenge{ID: cryptowire.NewUUID().String(), Fingerprint: fp, Nonce: make([]byte, 32), EphemeralPublic: eph.PublicKey().Bytes(),
		ExpiresAt: s.d.Now().Add(ChallengeLifetime).UTC()}
	if _, err := rand.Read(ch.Nonce); err != nil {
		return Challenge{}, err
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(key_version), 0) + 1 FROM recipient_keys WHERE tenant = $1 AND principal = $2`,
			c.Tenant, c.Principal).Scan(&ch.KeyVersion); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO recipient_keys (tenant, fingerprint, principal, public_key, suite, key_version, status, revision)
		                        VALUES ($1, $2, $3, $4, 1, $5, 'PENDING', 1)`, c.Tenant, fp, c.Principal, public, ch.KeyVersion)
		if isUnique(err) {
			return fmt.Errorf("%w: the key is already enrolled", ErrConflict)
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO enrollment_challenges VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			c.Tenant, ch.ID, c.Principal, fp, ch.Nonce, eph.Bytes(), ch.ExpiresAt)
		return err
	})
	return ch, err
}

// ActivateRecipient checks the possession proof for a challenge of the
// caller's PENDING key, deletes the challenge and activates the key
// (RCP-002). A wrong, reused or expired proof leaves the key PENDING.
func (s *Service) ActivateRecipient(ctx context.Context, c enforce.Caller, fp, challengeID string, proof []byte) (KeyRecord, error) {
	var principal, chFP string
	var nonce, ephPriv, public []byte
	var expires time.Time
	err := s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT c.principal, c.fingerprint, c.nonce, c.ephemeral_private, c.expires_at, k.public_key
		  FROM enrollment_challenges c JOIN recipient_keys k ON k.tenant = c.tenant AND k.fingerprint = c.fingerprint
		 WHERE c.tenant = $1 AND c.id::text = $2 AND k.status = 'PENDING'`, c.Tenant, challengeID).
		Scan(&principal, &chFP, &nonce, &ephPriv, &expires, &public)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (principal != c.Principal || chFP != fp) {
		return KeyRecord{}, ErrNotFound
	}
	if err != nil {
		return KeyRecord{}, err
	}
	if !s.d.Now().Before(expires) {
		return KeyRecord{}, fmt.Errorf("%w: challenge expired", ErrInvalid)
	}
	eph, err := ecdh.X25519().NewPrivateKey(ephPriv)
	if err != nil {
		return KeyRecord{}, err
	}
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return KeyRecord{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return KeyRecord{}, err
	}
	digest, _ := cryptowire.ParseDigest(fp)
	want, err := cryptowire.RecipientProof(shared, nonce, challengeID, c.Tenant, c.Principal, digest)
	clear(shared)
	if err != nil || !hmac.Equal(want, proof) {
		return KeyRecord{}, fmt.Errorf("%w: possession proof", ErrInvalid)
	}
	check := plannedRecipient(c.Principal, fp)
	check.Action = "activate"
	rec, err := s.authorize(ctx, c, registry.OpActivateRecipient, []enforce.Check{check})
	if err != nil {
		return KeyRecord{}, err
	}
	out := KeyRecord{Fingerprint: fp, Principal: c.Principal, PublicKey: public, Status: "ACTIVE"}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM enrollment_challenges WHERE tenant = $1 AND id::text = $2`, c.Tenant, challengeID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: challenge already used", ErrConflict)
		}
		if err := tx.QueryRow(ctx, `UPDATE recipient_keys SET status = 'ACTIVE', revision = revision + 1
		                             WHERE tenant = $1 AND fingerprint = $2 AND status = 'PENDING' RETURNING key_version, revision`,
			c.Tenant, fp).Scan(&out.KeyVersion, &out.Revision); err != nil {
			return err
		}
		return catalog.InsertRecipientResource(ctx, tx, c.Tenant, fp, c.Principal)
	})
	return out, err
}

// RevokeRecipient revokes one of the caller's keys: future deliveries and
// sharing to it stop at the fence (KEY-008, KEY-010). The change is
// journaled before it is committed.
func (s *Service) RevokeRecipient(ctx context.Context, c enforce.Caller, fp string) error {
	rec, err := s.authorize(ctx, c, registry.OpRevokeRecipient, []enforce.Check{{ID: "recipient", Role: registry.RoleRecipient,
		Action: "revoke", Resource: canonical("crypto.recipient", fp)}})
	if err != nil {
		return err
	}
	var journalID string
	var entries int
	if s.d.Journal != nil {
		if err := s.d.Journal.Append("recipient-revoked", c.Tenant, fp); err != nil {
			return fmt.Errorf("%w: security journal: %v", ErrUnavailable, err)
		}
		if journalID, entries, err = s.d.Journal.Binding(); err != nil {
			return fmt.Errorf("%w: security journal: %v", ErrUnavailable, err)
		}
	}
	return s.fenced(ctx, rec, []string{fp}, func(ctx context.Context, tx pgx.Tx) error {
		// The catalog records the journal it is bound to and its entries
		// (review finding 1).
		if journalID != "" {
			if err := catalog.RecordJournal(ctx, tx, journalID, entries); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE recipient_keys SET status = 'REVOKED', revision = revision + 1 WHERE tenant = $1 AND fingerprint = $2`,
			c.Tenant, fp); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"REVOKED"}'
		                         WHERE tenant = $1 AND type = 'crypto.recipient' AND id = $2`, c.Tenant, fp)
		if err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.audit(rec, "RECIPIENT_REVOKED", audit.Target{Type: "crypto.recipient", ID: fp, Recipient: fp}))
	})
}

// lookup authorizes a directory lookup: default deny applies to reads too
// (ruling 7).
func (s *Service) lookup(ctx context.Context, c enforce.Caller, op string, check enforce.Check) error {
	check.Action = "discover"
	_, rec, err := enforce.Authorize(ctx, s.d.Decider, s.d.Verifier, s.d.Catalog, c, op, enforce.KeysAudience, false, []enforce.Check{check})
	if errors.Is(err, enforce.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	b, err := fenceBinding(rec)
	if err != nil {
		return err
	}
	if err := s.d.Fence.Check(ctx, b); err != nil {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return nil
}

// Recipient looks up a recipient key in the caller's tenant directory. It
// needs discover on the key; a PENDING key is not a resource yet and is
// decided as its planned resource, so the fence also sees an activation.
func (s *Service) Recipient(ctx context.Context, c enforce.Caller, fp string) (KeyRecord, error) {
	k := KeyRecord{Fingerprint: fp}
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT principal, public_key, key_version, status, revision FROM recipient_keys
	                                          WHERE tenant = $1 AND fingerprint = $2`, c.Tenant, fp).
		Scan(&k.Principal, &k.PublicKey, &k.KeyVersion, &k.Status, &k.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return KeyRecord{}, err
	}
	check := enforce.Check{ID: registry.RoleRecipient, Role: registry.RoleRecipient, Resource: canonical("crypto.recipient", fp)}
	if k.Status == "PENDING" {
		check = plannedRecipient(k.Principal, fp)
	}
	if err := s.lookup(ctx, c, registry.OpLookupRecipient, check); err != nil {
		return KeyRecord{}, err
	}
	return k, nil
}

// SigningKey returns a content-signing key's verification record,
// including retired and compromised ones (RCP-011). It needs discover on
// the key.
func (s *Service) SigningKey(ctx context.Context, c enforce.Caller, fp string) (KeyRecord, error) {
	check := enforce.Check{ID: registry.RoleSigner, Role: registry.RoleSigner, Resource: canonical("crypto.signing-key", fp)}
	if err := s.lookup(ctx, c, registry.OpLookupSigner, check); err != nil {
		return KeyRecord{}, err
	}
	k := KeyRecord{Fingerprint: fp}
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT principal, public_key, status, revision FROM signing_keys
	                                          WHERE tenant = $1 AND fingerprint = $2`, c.Tenant, fp).
		Scan(&k.Principal, &k.PublicKey, &k.Status, &k.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// EnvelopeRef reports a published or retired envelope.
type EnvelopeRef struct {
	ID         string `json:"envelope_id"`
	Generation uint64 `json:"generation"`
	Status     string `json:"status"`
}

// Publish is PublishRecipientEnvelope (KEY-012, KEY-016): the caller shares
// one exact LIVE version with a recipient through an envelope its client
// created from a data key it could already decrypt. The service checks the
// origin signature by the caller's active signing key, every binding, the
// next envelope generation, and obtains the share, create, recipient read
// and receive-key checks; the previous active envelope of that recipient
// is retired in the same transaction.
func (s *Service) Publish(ctx context.Context, c enforce.Caller, bucketName, key, versionID string, e EnvelopeIn) (EnvelopeRef, error) {
	ctxv, err := cryptowire.ParseEnvelopeContext(e.Context)
	if err != nil || ctxv.Profile() != 1 || len(e.Ciphertext) == 0 || len(e.Ciphertext) > cryptowire.MaxHPKECiphertext {
		return EnvelopeRef{}, ErrInvalid
	}
	var signerPub []byte
	var owner, status string
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT public_key, principal, status FROM signing_keys WHERE tenant = $1 AND fingerprint = $2`,
		c.Tenant, ctxv.Sharer.String()).Scan(&signerPub, &owner, &status); err != nil || owner != c.Principal || status != "ACTIVE" {
		return EnvelopeRef{}, fmt.Errorf("%w: sharer is not an active signing key of the caller", ErrInvalid)
	}
	if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, e.Signature, cryptowire.EnvelopeSigningInput(e.Context, e.Ciphertext),
		func(kid string) (ed25519.PublicKey, error) {
			if kid != ctxv.Sharer.String() {
				return nil, errors.New("envelope signed by another key")
			}
			return signerPub, nil
		}); err != nil {
		return EnvelopeRef{}, fmt.Errorf("%w: envelope signature", ErrInvalid)
	}
	var objectID, cryptoVersion cryptowire.UUID
	var tenantID cryptowire.UUID
	var vstate, sum, scope string
	var marker bool
	var length int64
	var attrs map[string]any
	err = s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT o.id, v.crypto_version, t.id, v.state, v.delete_marker, coalesce(v.ciphertext_sha256, ''), coalesce(v.ciphertext_length, 0),
		       r.scope, r.attributes
		  FROM objects o JOIN buckets b ON b.tenant = o.tenant AND b.id = o.bucket
		  JOIN object_versions v ON v.tenant = o.tenant AND v.object = o.id
		  JOIN tenants t ON t.name = o.tenant
		  JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text
		 WHERE o.tenant = $1 AND b.name = $2 AND o.kind = 'object' AND o.key = $3 AND v.id::text = $4`, c.Tenant, bucketName, key, versionID).
		Scan(&objectID, &cryptoVersion, &tenantID, &vstate, &marker, &sum, &length, &scope, &attrs)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (vstate != "LIVE" || marker) {
		return EnvelopeRef{}, ErrNotFound
	}
	if err != nil {
		return EnvelopeRef{}, err
	}
	if ctxv.Tenant != tenantID || ctxv.Object != objectID || ctxv.LogicalVersion.String() != versionID || ctxv.CryptoVersion != cryptoVersion ||
		ctxv.CiphertextSHA256.String() != sum || int64(ctxv.CiphertextLength) != length {
		return EnvelopeRef{}, fmt.Errorf("%w: envelope bindings", ErrInvalid)
	}
	fp := ctxv.Recipient.String()
	var keyVersion uint64
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT key_version FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2 AND status = 'ACTIVE'`,
		c.Tenant, fp).Scan(&keyVersion); err != nil || keyVersion != ctxv.RecipientKeyVersion {
		return EnvelopeRef{}, fmt.Errorf("%w: recipient key", ErrInvalid)
	}
	id := cryptowire.NewUUID()
	obj := canonical("storage.object", objectID.String())
	rec, err := s.authorize(ctx, c, registry.OpPublishEnvelope, []enforce.Check{
		{ID: "share", Role: registry.RoleShare, Action: "share", Resource: obj, Version: versionID},
		{ID: "envelope", Role: registry.RoleEnvelope, Action: "create", Resource: alias(registry.PlannedEnvelope, objectID.String()+"|"+fp+"|"+id.String())},
		{ID: "recipient-read", Role: registry.RoleRecipientRead, Action: "read", Resource: obj, Version: versionID, Recipient: fp},
		{ID: "recipient-key", Role: registry.RoleRecipientKey, Action: "receive-key", Resource: canonical("crypto.recipient", fp), Recipient: fp},
	})
	if err != nil {
		return EnvelopeRef{}, err
	}
	digest := cryptowire.EnvelopeDigest(e.Context, e.Ciphertext)
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := catalog.SignerActiveTx(ctx, tx, c.Tenant, c.Principal, ctxv.Sharer.String()); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM object_versions WHERE tenant = $1 AND id::text = $2 FOR SHARE`, c.Tenant, versionID).Scan(&state); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		var last uint64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(generation), 0) FROM envelopes WHERE tenant = $1 AND version::text = $2 AND recipient = $3`,
			c.Tenant, versionID, fp).Scan(&last); err != nil {
			return err
		}
		if ctxv.Generation != last+1 {
			return fmt.Errorf("%w: expected envelope generation %d", ErrConflict, last+1)
		}
		if _, err := tx.Exec(ctx, `UPDATE envelopes SET status = 'RETIRED' WHERE tenant = $1 AND version::text = $2 AND recipient = $3 AND status = 'ACTIVE'`,
			c.Tenant, versionID, fp); err != nil {
			return err
		}
		if err := InsertEnvelope(ctx, tx, c.Tenant, scope, attrs, id, objectID, ctxv.LogicalVersion, ctxv, keyVersion, e, digest, s.d.Now()); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.audit(rec, "ENVELOPE_PUBLISHED", audit.Target{Type: "crypto.envelope", ID: objectID.String(),
			Version: versionID, Recipient: fp, Envelope: id.String(), Generation: ctxv.Generation, Signer: ctxv.Sharer.String(), Digest: digest.String()}))
	})
	if err != nil {
		return EnvelopeRef{}, err
	}
	return EnvelopeRef{ID: id.String(), Generation: ctxv.Generation, Status: "ACTIVE"}, nil
}

// Retire withdraws an envelope from future delivery (RetireEnvelope). It
// does not erase copies a client already holds (KEY-010).
func (s *Service) Retire(ctx context.Context, c enforce.Caller, envelopeID string) (EnvelopeRef, error) {
	id, err := cryptowire.ParseUUID(envelopeID)
	if err != nil {
		return EnvelopeRef{}, ErrInvalid
	}
	rec, err := s.authorize(ctx, c, registry.OpRetireEnvelope, []enforce.Check{{ID: "envelope", Role: registry.RoleEnvelope, Action: "retire",
		Resource: canonical("crypto.envelope", envelopeID)}})
	if err != nil {
		return EnvelopeRef{}, err
	}
	var out EnvelopeRef
	err = s.fenced(ctx, rec, []string{envelopeID}, func(ctx context.Context, tx pgx.Tx) error {
		e, err := s.envelope(ctx, tx, c.Tenant, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE envelopes SET status = 'RETIRED' WHERE tenant = $1 AND id = $2`, c.Tenant, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"RETIRED"}'
		                            WHERE tenant = $1 AND id = $2`, c.Tenant, envelopeID); err != nil {
			return err
		}
		out = EnvelopeRef{ID: envelopeID, Generation: e.Generation, Status: "RETIRED"}
		return s.d.Catalog.AppendTx(ctx, tx, s.audit(rec, "ENVELOPE_RETIRED", audit.Target{Type: "crypto.envelope", ID: e.Object.String(),
			Version: e.Version.String(), Recipient: e.Recipient, Envelope: envelopeID, Generation: e.Generation}))
	})
	return out, err
}

func canonical(typ, id string) decisionsvc.Alias { return decisionsvc.Alias{Type: typ, ID: id} }

func alias(namespace, name string) decisionsvc.Alias {
	return decisionsvc.Alias{Namespace: namespace, Name: name}
}

func fenceBinding(rec signing.Record) (fence.Binding, error) {
	b, err := fence.FromRecord(rec)
	if err != nil {
		return b, fmt.Errorf("%w: %v", ErrDecision, err)
	}
	return b, nil
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
