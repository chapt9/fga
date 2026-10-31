package envelope

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/cryptowire"
	"fga/internal/enforce"
	"fga/internal/registry"
)

// Self-service content-signing keys (RCP-002, RCP-011): a client enrolls
// its own key, which stays PENDING until it answers a one-use challenge
// with a detached JWS over cryptowire.SigningProofInput, and retires it
// to rotate. Compromise stays an administrator's journaled operation.

// EnrollSigningKey records the caller's new content-signing public key as
// PENDING, with its PENDING crypto.signing-key resource, and returns a
// one-use challenge. It needs enroll on the planned key. A small-order or
// non-canonical key is refused: it would prove nothing.
func (s *Service) EnrollSigningKey(ctx context.Context, c enforce.Caller, public []byte) (Challenge, error) {
	if !cryptowire.ValidEd25519PublicKey(public) {
		return Challenge{}, ErrInvalid
	}
	fp := cryptowire.SigningKeyFingerprint(public).String()
	rec, err := s.authorize(ctx, c, registry.OpEnrollSigner, []enforce.Check{{ID: "signer", Role: registry.RoleSigner, Action: "enroll",
		Resource: alias(registry.PlannedSigner, c.Principal+"|"+fp)}})
	if err != nil {
		return Challenge{}, err
	}
	ch := Challenge{ID: cryptowire.NewUUID().String(), Fingerprint: fp, Nonce: make([]byte, 32), ExpiresAt: s.d.Now().Add(ChallengeLifetime).UTC()}
	if _, err := rand.Read(ch.Nonce); err != nil {
		return Challenge{}, err
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		now := s.d.Now()
		_, err := tx.Exec(ctx, `INSERT INTO signing_keys VALUES ($1, $2, $3, $4, 'PENDING', 1, $5, $5)`, c.Tenant, fp, c.Principal, public, now)
		if isUnique(err) {
			return fmt.Errorf("%w: the key is already enrolled", ErrConflict)
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'crypto.signing-key', '', 1, 1, 1,
		                            jsonb_build_object('principal', $3::text, 'status', 'PENDING'))`, c.Tenant, fp, c.Principal); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO signing_challenges VALUES ($1, $2, $3, $4, $5, $6)`,
			c.Tenant, ch.ID, c.Principal, fp, ch.Nonce, ch.ExpiresAt)
		return err
	})
	return ch, err
}

// ActivateSigningKey checks the possession proof, a detached JWS by the
// PENDING key over its challenge, deletes the challenge and activates the
// key. A wrong, reused or expired proof leaves the key PENDING. The
// activation is decided on the key and may be held for an approval.
func (s *Service) ActivateSigningKey(ctx context.Context, c enforce.Caller, fp, challengeID, proof string) (KeyRecord, error) {
	var principal, chFP string
	var nonce, public []byte
	var expires time.Time
	err := s.d.Catalog.Pool().QueryRow(ctx, `
		SELECT c.principal, c.fingerprint, c.nonce, c.expires_at, k.public_key
		  FROM signing_challenges c JOIN signing_keys k ON k.tenant = c.tenant AND k.fingerprint = c.fingerprint
		 WHERE c.tenant = $1 AND c.id::text = $2 AND k.status = 'PENDING'`, c.Tenant, challengeID).
		Scan(&principal, &chFP, &nonce, &expires, &public)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (principal != c.Principal || chFP != fp) {
		return KeyRecord{}, ErrNotFound
	}
	if err != nil {
		return KeyRecord{}, err
	}
	if !s.d.Now().Before(expires) {
		return KeyRecord{}, fmt.Errorf("%w: challenge expired", ErrInvalid)
	}
	digest, err := cryptowire.ParseDigest(fp)
	if err != nil {
		return KeyRecord{}, ErrInvalid
	}
	input := cryptowire.SigningProofInput(challengeID, c.Tenant, c.Principal, digest, nonce)
	if _, err := cryptowire.Verify(cryptowire.TypeSigningProof, proof, input, func(kid string) (ed25519.PublicKey, error) {
		if kid != fp {
			return nil, errors.New("another key")
		}
		return ed25519.PublicKey(public), nil
	}); err != nil {
		return KeyRecord{}, fmt.Errorf("%w: possession proof", ErrInvalid)
	}
	rec, err := s.authorizePlanned(ctx, c, registry.OpActivateSigner, []enforce.Check{{ID: "signer", Role: registry.RoleSigner,
		Action: "activate", Resource: canonical("crypto.signing-key", fp)}}, keyPlan("activate", registry.RoleSigner, "crypto.signing-key", fp))
	if err != nil {
		return KeyRecord{}, err
	}
	out := KeyRecord{Fingerprint: fp, Principal: c.Principal, PublicKey: public, Status: "ACTIVE"}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM signing_challenges WHERE tenant = $1 AND id::text = $2`, c.Tenant, challengeID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: challenge already used", ErrConflict)
		}
		if err := tx.QueryRow(ctx, `UPDATE signing_keys SET status = 'ACTIVE', revision = revision + 1, changed_at = $3
		                             WHERE tenant = $1 AND fingerprint = $2 AND status = 'PENDING' RETURNING revision`,
			c.Tenant, fp, s.d.Now()).Scan(&out.Revision); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"ACTIVE"}'
		                            WHERE tenant = $1 AND type = 'crypto.signing-key' AND id = $2`, c.Tenant, fp); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.audit(rec, "SIGNING_KEY_ACTIVATED", audit.Target{Type: "crypto.signing-key", ID: fp, Signer: fp}))
	})
	return out, err
}

// RetireSigningKey retires one of the caller's content-signing keys, for
// rotation: it signs nothing new, and what it signed stays verifiable
// (RCP-011). It may be held for an approval.
func (s *Service) RetireSigningKey(ctx context.Context, c enforce.Caller, fp string) error {
	rec, err := s.authorizePlanned(ctx, c, registry.OpRetireSigner, []enforce.Check{{ID: "signer", Role: registry.RoleSigner,
		Action: "retire", Resource: canonical("crypto.signing-key", fp)}}, keyPlan("retire", registry.RoleSigner, "crypto.signing-key", fp))
	if err != nil {
		return err
	}
	return s.fenced(ctx, rec, []string{fp}, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'RETIRED', revision = revision + 1, changed_at = $3
		                           WHERE tenant = $1 AND fingerprint = $2 AND status = 'ACTIVE'`, c.Tenant, fp, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: the key is not active", ErrConflict)
		}
		if _, err := tx.Exec(ctx, `UPDATE resources SET generation = generation + 1, attributes = attributes || '{"status":"RETIRED"}'
		                            WHERE tenant = $1 AND type = 'crypto.signing-key' AND id = $2`, c.Tenant, fp); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.audit(rec, "SIGNING_KEY_RETIRED", audit.Target{Type: "crypto.signing-key", ID: fp, Signer: fp}))
	})
}
