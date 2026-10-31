package content

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/registry"
)

// BeginRequest asks to upload a new version of a key.
type BeginRequest struct {
	Bucket         string
	Key            string
	IdempotencyKey string
	// IfMatch is an ETag the current version must have at commit;
	// IfNoneMatch requires no current live version at commit (PUB-007).
	IfMatch     string
	IfNoneMatch bool
}

// Intent is an upload intent's identities (BeginEncryptedUpload, KEY-003).
// The client binds its ciphertext, descriptor and envelopes to them.
type Intent struct {
	IntentID         cryptowire.UUID
	Tenant           cryptowire.UUID
	Object           cryptowire.UUID
	LogicalVersion   cryptowire.UUID
	CryptoVersion    cryptowire.UUID
	Blob             cryptowire.UUID
	Attempt          cryptowire.UUID
	Suite, Format    uint16
	MaxCiphertext    int64
	ExpiresAt        time.Time
	ciphertextLength int64
	ciphertextSHA256 string
	state            string
	newObject        bool
	bucket           cryptowire.UUID
	key              string
	expectedGen      uint64
	ifMatch          string
	ifNoneMatch      bool
	scope            string
	attributes       map[string]any
	principal        string
	result           []byte
}

// ValidKey reports whether key is a valid object key: 1 to 1024 bytes of
// UTF-8 without NUL.
func ValidKey(key string) bool {
	return key != "" && len(key) <= 1024 && utf8.ValidString(key) && !bytes.ContainsRune([]byte(key), 0)
}

func (r BeginRequest) digest() string {
	h := sha256.New()
	fmt.Fprintf(h, "fga.begin/v1\n%q\n%q\n%q\n%t\n", r.Bucket, r.Key, r.IfMatch, r.IfNoneMatch)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Begin reserves an upload intent (PUB-002 step 1): for a new key it
// needs bucket create-object, for an existing key the object's new-version.
// It allocates fresh object (new keys only), version, crypto-version, blob
// and attempt IDs and assigns the protected attributes the version will be
// published with; the client cannot set them. An identical retry under the
// same idempotency key returns the same intent.
func (s *Service) Begin(ctx context.Context, c Caller, r BeginRequest) (Intent, error) {
	if !ValidKey(r.Key) || r.IdempotencyKey == "" || len(r.IdempotencyKey) > 128 || (r.IfMatch != "" && r.IfNoneMatch) {
		return Intent{}, ErrInvalid
	}
	if in, err := s.intentByIdempotency(ctx, c, r.IdempotencyKey); err == nil {
		if in.state == "ABORTED" || in.requestDigest != r.digest() {
			return Intent{}, fmt.Errorf("%w: the idempotency key was used for another request", ErrConflict)
		}
		return in.Intent, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Intent{}, err
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return Intent{}, err
	}
	b, err := s.bucketByName(ctx, c.Tenant, r.Bucket)
	if err != nil {
		return Intent{}, err
	}
	in := Intent{IntentID: cryptowire.NewUUID(), Tenant: tenantID, LogicalVersion: cryptowire.NewUUID(), CryptoVersion: cryptowire.NewUUID(),
		Blob: cryptowire.NewUUID(), Attempt: cryptowire.NewUUID(), Suite: cryptowire.Suite1, Format: cryptowire.Format1,
		MaxCiphertext: s.d.Limits.MaxCiphertext, ExpiresAt: s.d.Now().Add(s.d.Limits.IntentLifetime),
		bucket: b.ID, key: r.Key, ifMatch: r.IfMatch, ifNoneMatch: r.IfNoneMatch, principal: c.Principal}

	o, err := s.objectByKey(ctx, s.d.Catalog.Pool(), c.Tenant, b.ID, r.Key)
	var op string
	var checks []check
	switch {
	case errors.Is(err, ErrNotFound):
		in.Object, in.newObject = cryptowire.NewUUID(), true
		in.scope = b.Scope
		in.attributes = map[string]any{"bucket": b.Name, "owner": c.Principal, "project": b.Project, "label": b.Label}
		op = registry.OpBeginCreate
		checks = []check{{id: "bucket", role: registry.RoleBucket, action: "create-object", ref: canonical("storage.bucket", b.ID.String())}}
	case err != nil:
		return Intent{}, err
	default:
		in.Object, in.expectedGen, in.scope, in.attributes = o.ID, o.Generation, o.Scope, o.Attributes
		op = registry.OpBeginVersion
		checks = []check{{id: "object", role: registry.RoleObject, action: "new-version", ref: canonical("storage.object", o.ID.String())}}
	}
	_, rec, err := s.decide(ctx, c, op, Audience, true, checks)
	if err != nil {
		return Intent{}, err
	}
	attrs, _ := json.Marshal(in.attributes)
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO upload_intents (tenant, id, principal, actor, idempotency_key, request_digest, bucket, key, object, new_object,
			  version, crypto_version, blob, attempt, expected_generation, if_match, if_none_match, planned_scope, planned_attributes,
			  state, expires_at, created_at)
			VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'RESERVED',$19,$20)`,
			c.Tenant, in.IntentID, c.Principal, r.IdempotencyKey, r.digest(), b.ID, r.Key, in.Object, in.newObject,
			in.LogicalVersion, in.CryptoVersion, in.Blob, in.Attempt, in.expectedGen, r.IfMatch, r.IfNoneMatch, in.scope, attrs,
			in.ExpiresAt, s.d.Now())
		if isUnique(err) {
			return fmt.Errorf("%w: the idempotency key is in use", ErrConflict)
		}
		return err
	})
	if err != nil {
		return Intent{}, err
	}
	return in, nil
}

type storedIntent struct {
	Intent
	requestDigest string
}

func (s *Service) intentByIdempotency(ctx context.Context, c Caller, key string) (storedIntent, error) {
	var id cryptowire.UUID
	err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT id FROM upload_intents WHERE tenant = $1 AND principal = $2 AND idempotency_key = $3`,
		c.Tenant, c.Principal, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedIntent{}, ErrNotFound
	}
	if err != nil {
		return storedIntent{}, err
	}
	return s.intent(ctx, s.d.Catalog.Pool(), c, id, false)
}

// intent loads an intent owned by the caller. Another principal's intent is
// not found.
func (s *Service) intent(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, c Caller, id cryptowire.UUID, lock bool) (storedIntent, error) {
	var in storedIntent
	var attrs []byte
	var length *int64
	var sum *string
	sql := `SELECT i.id, t.id, i.object, i.version, i.crypto_version, i.blob, i.attempt, i.expires_at, i.state, i.new_object, i.bucket,
	               i.key, i.expected_generation, i.if_match, i.if_none_match, i.planned_scope, i.planned_attributes, i.principal,
	               i.ciphertext_length, i.ciphertext_sha256, coalesce(i.result::text, ''), i.request_digest
	          FROM upload_intents i JOIN tenants t ON t.name = i.tenant
	         WHERE i.tenant = $1 AND i.id = $2 AND i.principal = $3`
	if lock {
		sql += ` FOR UPDATE OF i`
	}
	var result string
	err := q.QueryRow(ctx, sql, c.Tenant, id, c.Principal).Scan(&in.IntentID, &in.Tenant, &in.Object, &in.LogicalVersion, &in.CryptoVersion,
		&in.Blob, &in.Attempt, &in.ExpiresAt, &in.state, &in.newObject, &in.bucket, &in.key, &in.expectedGen, &in.ifMatch, &in.ifNoneMatch,
		&in.scope, &attrs, &in.principal, &length, &sum, &result, &in.requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, ErrNotFound
	}
	if err != nil {
		return in, err
	}
	in.Suite, in.Format, in.MaxCiphertext = cryptowire.Suite1, cryptowire.Format1, s.d.Limits.MaxCiphertext
	if length != nil {
		in.ciphertextLength = *length
	}
	if sum != nil {
		in.ciphertextSHA256 = *sum
	}
	in.result = []byte(result)
	return in, json.Unmarshal(attrs, &in.attributes)
}

// Receipt reports a staged ciphertext.
type Receipt struct {
	Blob   cryptowire.UUID
	Length int64
	SHA256 cryptowire.Digest
}

// PutCiphertext stages the intent's ciphertext (PUB-002 step 4, BKD-001).
// Only the intent's owner may stage; staging grants no visibility. A retry
// with identical bytes returns the same receipt; other bytes conflict.
func (s *Service) PutCiphertext(ctx context.Context, c Caller, intentID cryptowire.UUID, length int64, sum cryptowire.Digest, body io.Reader) (Receipt, error) {
	if length <= 0 || length > s.d.Limits.MaxCiphertext {
		return Receipt{}, ErrTooLarge
	}
	in, err := s.intent(ctx, s.d.Catalog.Pool(), c, intentID, false)
	if err != nil {
		return Receipt{}, err
	}
	switch {
	case in.state == "STAGED" && in.ciphertextLength == length && in.ciphertextSHA256 == sum.String():
		return Receipt{Blob: in.Blob, Length: length, SHA256: sum}, nil
	case in.state != "RESERVED":
		return Receipt{}, fmt.Errorf("%w: intent is %s", ErrConflict, in.state)
	case !s.d.Now().Before(in.ExpiresAt):
		return Receipt{}, fmt.Errorf("%w: intent expired", ErrConflict)
	}
	w, err := s.d.Blobs.Begin(blob.Ref{Tenant: in.Tenant, Blob: in.Blob}, length)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err := io.Copy(w, body); err != nil {
		w.Abort()
		if errors.Is(err, blob.ErrTooLarge) {
			return Receipt{}, ErrTooLarge
		}
		return Receipt{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := s.d.Blobs.Finalize(w, length, sum); err != nil {
		switch {
		case errors.Is(err, blob.ErrMismatch):
			return Receipt{}, fmt.Errorf("%w: length or digest mismatch", ErrInvalid)
		case errors.Is(err, blob.ErrConflict):
			return Receipt{}, ErrConflict
		}
		return Receipt{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	tag, err := s.d.Catalog.Pool().Exec(ctx, `
		UPDATE upload_intents SET state = 'STAGED', ciphertext_length = $3, ciphertext_sha256 = $4
		 WHERE tenant = $1 AND id = $2 AND state = 'RESERVED'`, c.Tenant, intentID, length, sum.String())
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrConflict
	}
	return Receipt{Blob: in.Blob, Length: length, SHA256: sum}, nil
}

// EnvelopeIn is one initial recipient envelope of an upload.
type EnvelopeIn struct {
	Context    []byte
	Ciphertext []byte
	Signature  string
}

// FinalizeRequest carries the signed descriptor and initial envelopes.
type FinalizeRequest struct {
	Descriptor          []byte
	DescriptorSignature string
	Envelopes           []EnvelopeIn
}

// Published is the result of a commit.
type Published struct {
	Object     string `json:"object_id"`
	Version    string `json:"version_id"`
	ETag       string `json:"etag"`
	Generation uint64 `json:"generation"`
}

// ETag is the opaque ETag of a version: its logical version ID, never a
// hash of plaintext (PUB-007).
func ETag(version cryptowire.UUID) string { return strconv.Quote(version.String()) }

type checkedEnvelope struct {
	EnvelopeIn
	id         cryptowire.UUID
	ctx        cryptowire.EnvelopeContext
	keyVersion uint64
	digest     cryptowire.Digest
}

// Finalize validates the signed descriptor and initial envelopes, obtains a
// fresh decision for the publication and every envelope's sharing and
// target-recipient checks, and commits under the authority fence (PUB-002
// step 4, PUB-003, KEY-012, RES-009). A finalize that already committed
// returns its stored result.
func (s *Service) Finalize(ctx context.Context, c Caller, intentID cryptowire.UUID, r FinalizeRequest) (Published, error) {
	in, err := s.intent(ctx, s.d.Catalog.Pool(), c, intentID, false)
	if err != nil {
		return Published{}, err
	}
	if in.state == "COMMITTED" {
		var p Published
		if err := json.Unmarshal(in.result, &p); err != nil {
			return Published{}, fmt.Errorf("%w: stored result", ErrUnavailable)
		}
		// The original result is returned only to its owner, and only while
		// the owner may still observe the version (PUB-002, write and retry
		// sequence).
		_, rec, err := s.decide(ctx, c, registry.OpStat, Audience, false, []check{{id: "object", role: registry.RoleObject,
			action: "stat", ref: canonical("storage.object", in.Object.String()), version: in.LogicalVersion.String()}})
		if err != nil {
			return Published{}, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return Published{}, err
		}
		return p, nil
	}
	if in.state != "STAGED" {
		return Published{}, fmt.Errorf("%w: intent is %s", ErrConflict, in.state)
	}
	if len(r.Envelopes) == 0 || len(r.Envelopes) > s.d.Limits.MaxEnvelopes {
		return Published{}, ErrInvalid
	}
	desc, signer, err := s.checkDescriptor(ctx, c, in, r)
	if err != nil {
		return Published{}, err
	}
	envs, err := s.checkEnvelopes(ctx, c, in, desc, signer, r.Envelopes)
	if err != nil {
		return Published{}, err
	}

	objectRef := canonical("storage.object", in.Object.String())
	objectName := in.Object.String()
	op := registry.OpPublishVersion
	checks := []check{{id: "object", role: registry.RoleObject, action: "new-version", ref: objectRef}}
	if in.newObject {
		b := in.bucket.String()
		objectRef = planned(registry.PlannedObject, in.IntentID.String())
		objectName = "intent:" + in.IntentID.String()
		op = registry.OpPublishCreate
		checks = []check{{id: "bucket", role: registry.RoleBucket, action: "create-object", ref: canonical("storage.bucket", b)}}
	}
	for i, e := range envs {
		fp := e.ctx.Recipient.String()
		n := strconv.Itoa(i)
		checks = append(checks,
			check{id: "share-" + n, role: registry.RoleShare, action: "share", ref: objectRef},
			check{id: "envelope-" + n, role: registry.RoleEnvelope, action: "create",
				ref: planned(registry.PlannedEnvelope, objectName+"|"+fp+"|"+e.id.String())},
			check{id: "recipient-read-" + n, role: registry.RoleRecipientRead, action: "read", ref: objectRef, recipient: fp},
			check{id: "recipient-key-" + n, role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", fp), recipient: fp})
	}
	_, rec, err := s.decide(ctx, c, op, Audience, true, checks)
	if err != nil {
		return Published{}, err
	}
	var result Published
	mutate := []string{in.Object.String()}
	err = s.fenced(ctx, rec, mutate, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = s.publish(ctx, tx, c, in, desc, r, envs)
		if err != nil {
			return err
		}
		targets := []audit.Target{{Type: "storage.object", ID: result.Object, Version: result.Version, Signer: desc.Signer, Digest: desc.CiphertextSHA256}}
		for _, e := range envs {
			targets = append(targets, audit.Target{Type: "crypto.envelope", ID: result.Object, Version: result.Version,
				Recipient: e.ctx.Recipient.String(), Envelope: e.id.String(), Generation: e.ctx.Generation, Signer: desc.Signer, Digest: e.digest.String()})
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, rec, "PUBLISHED", targets...))
	})
	if err != nil {
		return Published{}, err
	}
	return result, nil
}

// checkDescriptor verifies the descriptor's signature by an active signing
// key of the uploader and every binding against the intent and its staged
// receipt (CRY-004, KEY-003, RCP-008).
func (s *Service) checkDescriptor(ctx context.Context, c Caller, in storedIntent, r FinalizeRequest) (cryptowire.Descriptor, string, error) {
	signer := ""
	_, err := cryptowire.Verify(cryptowire.TypeDescriptor, r.DescriptorSignature, r.Descriptor, func(kid string) (ed25519.PublicKey, error) {
		pub, err := s.signerActive(ctx, c.Tenant, c.Principal, kid)
		signer = kid
		return pub, err
	})
	if err != nil {
		return cryptowire.Descriptor{}, "", fmt.Errorf("%w: descriptor signature", ErrInvalid)
	}
	d, err := cryptowire.ParseDescriptor(r.Descriptor)
	if err != nil || d.Signer != signer || d.TenantID != in.Tenant.String() || d.ObjectID != in.Object.String() ||
		d.LogicalVersionID != in.LogicalVersion.String() || d.CryptoVersionID != in.CryptoVersion.String() || d.BlobID != in.Blob.String() ||
		d.AttemptID != in.Attempt.String() || d.CiphertextSHA256 != in.ciphertextSHA256 || int64(d.CiphertextLength) != in.ciphertextLength {
		return cryptowire.Descriptor{}, "", fmt.Errorf("%w: descriptor does not match the intent", ErrInvalid)
	}
	return d, signer, nil
}

// checkEnvelopes validates each initial envelope's outer format, origin
// signature and bindings (RCP-005, RCP-006). It cannot open them.
func (s *Service) checkEnvelopes(ctx context.Context, c Caller, in storedIntent, d cryptowire.Descriptor, signer string, envs []EnvelopeIn) ([]checkedEnvelope, error) {
	signerPub, err := s.signerActive(ctx, c.Tenant, c.Principal, signer)
	if err != nil {
		return nil, err
	}
	seen := map[cryptowire.Digest]bool{}
	var out []checkedEnvelope
	for _, e := range envs {
		if len(e.Ciphertext) == 0 || len(e.Ciphertext) > cryptowire.MaxHPKECiphertext {
			return nil, ErrInvalid
		}
		ctxv, err := cryptowire.ParseEnvelopeContext(e.Context)
		if err != nil {
			return nil, fmt.Errorf("%w: envelope context", ErrInvalid)
		}
		if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, e.Signature, cryptowire.EnvelopeSigningInput(e.Context, e.Ciphertext),
			func(kid string) (ed25519.PublicKey, error) {
				if kid != signer {
					return nil, errors.New("envelope signed by another key")
				}
				return signerPub, nil
			}); err != nil {
			return nil, fmt.Errorf("%w: envelope signature", ErrInvalid)
		}
		if ctxv.Tenant != in.Tenant || ctxv.Object != in.Object || ctxv.LogicalVersion != in.LogicalVersion ||
			ctxv.CryptoVersion != in.CryptoVersion || ctxv.CiphertextSHA256.String() != d.CiphertextSHA256 ||
			ctxv.CiphertextLength != d.CiphertextLength || ctxv.Sharer.String() != signer || ctxv.Generation != 1 || seen[ctxv.Recipient] {
			return nil, fmt.Errorf("%w: envelope bindings", ErrInvalid)
		}
		seen[ctxv.Recipient] = true
		keyVersion, err := s.recipientKey(ctx, c.Tenant, ctxv.Recipient.String())
		if err != nil {
			return nil, err
		}
		if keyVersion != ctxv.RecipientKeyVersion {
			return nil, fmt.Errorf("%w: recipient key version", ErrInvalid)
		}
		out = append(out, checkedEnvelope{EnvelopeIn: e, id: cryptowire.NewUUID(), ctx: ctxv, keyVersion: keyVersion,
			digest: cryptowire.EnvelopeDigest(e.Context, e.Ciphertext)})
	}
	return out, nil
}

// publish is the publication transaction's own rows (fence step 7): the
// head, the version, the envelopes and the intent.
func (s *Service) publish(ctx context.Context, tx pgx.Tx, c Caller, in storedIntent, d cryptowire.Descriptor, r FinalizeRequest, envs []checkedEnvelope) (Published, error) {
	now := s.d.Now()
	var st string
	err := tx.QueryRow(ctx, `SELECT state FROM upload_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, in.IntentID).Scan(&st)
	if err != nil {
		return Published{}, err
	}
	if st != "STAGED" || !now.Before(in.ExpiresAt) {
		return Published{}, fmt.Errorf("%w: intent is %s or expired", ErrConflict, st)
	}
	var generation uint64
	if in.newObject {
		if in.ifMatch != "" {
			return Published{}, ErrPrecondition
		}
		// A key created by someone else since begin fails here.
		attrs, _ := json.Marshal(in.attributes)
		alias := objectAlias(in.bucket, in.key)
		if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'storage.object', $3, 1, 1, 1, $4)`,
			c.Tenant, in.Object.String(), in.scope, attrs); err != nil {
			return Published{}, err
		}
		_, err := tx.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key) VALUES ($1, $2, $3, $4)`, c.Tenant, in.Object, in.bucket, in.key)
		if isUnique(err) {
			if in.ifNoneMatch {
				return Published{}, ErrPrecondition
			}
			return Published{}, fmt.Errorf("%w: the key was created concurrently", ErrConflict)
		}
		if err != nil {
			return Published{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO aliases VALUES ($1, $2, $3, $4)`, c.Tenant, alias.Namespace, alias.Name, in.Object.String()); err != nil {
			return Published{}, err
		}
		generation = 1
	} else {
		var current *cryptowire.UUID
		if err := tx.QueryRow(ctx, `SELECT current_version FROM objects WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, in.Object).Scan(&current); err != nil {
			return Published{}, err
		}
		if err := s.preconditions(ctx, tx, c.Tenant, current, in.ifMatch, in.ifNoneMatch); err != nil {
			return Published{}, err
		}
		if err := tx.QueryRow(ctx, `UPDATE resources SET generation = generation + 1, version = version + 1
		                             WHERE tenant = $1 AND id = $2 AND generation = $3 RETURNING generation`,
			c.Tenant, in.Object.String(), in.expectedGen).Scan(&generation); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Published{}, fmt.Errorf("%w: the object changed since begin", ErrConflict)
			}
			return Published{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
		                             signer, descriptor, descriptor_signature, created_at, published_at)
		VALUES ($1, $2, $3, $4, $5, 'LIVE', $6, $7, $8, $9, $10, $11, $12, $13, $13)`,
		c.Tenant, in.LogicalVersion, in.Object, in.CryptoVersion, in.Blob, int64(d.CiphertextLength), d.CiphertextSHA256,
		int(d.Suite), int(d.Format), d.Signer, r.Descriptor, r.DescriptorSignature, now); err != nil {
		return Published{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE objects SET current_version = $3 WHERE tenant = $1 AND id = $2`, c.Tenant, in.Object, in.LogicalVersion); err != nil {
		return Published{}, err
	}
	for _, e := range envs {
		if err := insertEnvelope(ctx, tx, c.Tenant, in.scope, in.attributes, e.id, in.Object, in.LogicalVersion, e.ctx, e.keyVersion,
			e.EnvelopeIn, e.digest, now); err != nil {
			return Published{}, err
		}
	}
	result := Published{Object: in.Object.String(), Version: in.LogicalVersion.String(), ETag: ETag(in.LogicalVersion), Generation: generation}
	stored, _ := json.Marshal(result)
	if _, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'COMMITTED', result = $3 WHERE tenant = $1 AND id = $2`,
		c.Tenant, in.IntentID, stored); err != nil {
		return Published{}, err
	}
	return result, nil
}

// insertEnvelope stores an envelope and its crypto.envelope resource.
func insertEnvelope(ctx context.Context, tx pgx.Tx, tenant, scope string, objectAttrs map[string]any, id, object, version cryptowire.UUID,
	ctxv cryptowire.EnvelopeContext, keyVersion uint64, e EnvelopeIn, digest cryptowire.Digest, now time.Time) error {
	var principal string
	if err := tx.QueryRow(ctx, `SELECT principal FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2`, tenant, ctxv.Recipient.String()).Scan(&principal); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO envelopes (tenant, id, object, version, recipient, key_version, generation, context, ciphertext, signature, signer, digest,
		                       status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'ACTIVE', $13)`,
		tenant, id, object, version, ctxv.Recipient.String(), int64(keyVersion), int64(ctxv.Generation), e.Context, e.Ciphertext, e.Signature,
		ctxv.Sharer.String(), digest.String(), now); err != nil {
		if isUnique(err) {
			return fmt.Errorf("%w: an active envelope exists for this recipient", ErrConflict)
		}
		return err
	}
	attrs := map[string]any{"object": object.String(), "version": version.String(), "recipient": ctxv.Recipient.String(),
		"recipient_principal": principal, "status": "ACTIVE"}
	for _, k := range []string{"owner", "project", "label", "bucket"} {
		if v, ok := objectAttrs[k]; ok {
			attrs[k] = v
		}
	}
	b, _ := json.Marshal(attrs)
	_, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'crypto.envelope', $3, 1, 1, 1, $4)`, tenant, id.String(), scope, b)
	return err
}

// preconditions applies If-Match and If-None-Match to the committed head
// (PUB-007): If-None-Match means no current live version; a delete marker
// is not live.
func (s *Service) preconditions(ctx context.Context, tx pgx.Tx, tenant string, current *cryptowire.UUID, ifMatch string, ifNoneMatch bool) error {
	live := false
	if current != nil {
		var marker bool
		if err := tx.QueryRow(ctx, `SELECT delete_marker FROM object_versions WHERE tenant = $1 AND id = $2`, tenant, *current).Scan(&marker); err != nil {
			return err
		}
		live = !marker
	}
	switch {
	case ifNoneMatch && live:
		return ErrPrecondition
	case ifMatch != "" && (!live || ETag(*current) != ifMatch):
		return ErrPrecondition
	}
	return nil
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
