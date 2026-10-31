package content

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"

	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/opplan"
	"fga/internal/payload"
	"fga/internal/registry"
)

// Server-mode objects (specification 2.6, D-12 stretch S3, SSE-001,
// SSE-003, SSE-005; docs/design/server-objects.md). The caller sends and
// receives plaintext over TLS; the storage role encrypts it as it arrives
// under a data key that the keys role sealed for the upload, and decrypts
// it for a read under the data key the keys role released for that read.
// Neither key outlives its stream. Begin, stat, listing, labels, deletion
// and approvals are those of client mode; only the payload path differs.

// StagedApproval is PutObject's error when the staged upload's
// publication needs an approval: once an approver gives it, the caller
// finalizes Intent presenting the approval (APR-001). Nothing is published
// meanwhile.
type StagedApproval struct {
	*ApprovalRequired
	Intent string
}

// Unwrap lets errors.As find the ApprovalRequired.
func (e *StagedApproval) Unwrap() error { return e.ApprovalRequired }

// PutObject uploads length bytes of plaintext from body to a server-mode
// bucket at r.Key: a new key, or a new version of an existing one, with
// the checks, conditions and label rules of Begin and Finalize. The keys
// role seals the upload's data key; the storage role encrypts the body as
// it arrives, so plaintext reaches no staged blob, temporary file or spill
// (SSE-005); the publication is decided and committed like a client
// upload's, without envelopes.
//
// A retry under the same idempotency key returns the outcome of the
// attempt it names: the committed version, or the publication of a staged
// upload (for instance once its approval is given). An attempt whose
// encryption began and did not finish cannot get its data key again; the
// caller begins again under a new idempotency key (CRY-007).
func (s *Service) PutObject(ctx context.Context, c Caller, r BeginRequest, length int64, body io.Reader) (Published, error) {
	if r.Derived || length < 0 {
		return Published{}, ErrInvalid
	}
	if payload.CiphertextSize(length) > s.d.Limits.MaxCiphertext {
		return Published{}, ErrTooLarge
	}
	if s.d.DataKeys == nil {
		return Published{}, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	in, err := s.begin(ctx, c, r, "server")
	if err != nil {
		return Published{}, err
	}
	switch {
	case in.state == "RESERVED" && in.sealed:
		return Published{}, fmt.Errorf("%w: an earlier attempt of this upload did not finish; begin again under a new idempotency key", ErrConflict)
	case in.state == "RESERVED":
		if err := s.stageServer(ctx, c, in, length, body); err != nil {
			return Published{}, err
		}
	}
	p, err := s.Finalize(ctx, c, in.IntentID, FinalizeRequest{})
	var need *ApprovalRequired
	if errors.As(err, &need) {
		return Published{}, &StagedApproval{ApprovalRequired: need, Intent: in.IntentID.String()}
	}
	return p, err
}

// binding is the identity a server-mode payload is bound to (SSE-001).
func binding(tenant, object, version, cryptoVersion, blobID cryptowire.UUID) payload.Binding {
	return payload.Binding{Tenant: tenant, Object: object, Version: version, CryptoVersion: cryptoVersion, Blob: blobID}
}

// keysError keeps the shared not-found and reports any other failure of
// the keys role as unavailable.
func keysError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("%w: keys role: %v", ErrUnavailable, err)
}

// stageServer obtains the upload's data key and encrypts the body into
// the staged blob. Staging is admitted like a client upload's, by a fresh
// single-use decision for the same right as the begin, and runs under a
// lease that fails when that authority changes (ruling 7, DAT-007).
func (s *Service) stageServer(ctx context.Context, c Caller, in storedIntent, length int64, body io.Reader) error {
	if !s.d.Now().Before(in.ExpiresAt) {
		return fmt.Errorf("%w: intent expired", ErrConflict)
	}
	sealOp, sealChecks := s.intentChecks(in, registry.OpKeySealCreate, registry.OpKeySealVersion)
	signed, _, err := s.decide(ctx, c, sealOp, KeysAudience, true, sealChecks)
	if err != nil {
		return err
	}
	dk, err := s.d.DataKeys.SealDataKey(ctx, signed, in.IntentID.String())
	if err != nil {
		return keysError(err)
	}
	defer clear(dk.Key)
	op, checks := s.intentChecks(in, registry.OpStageCreate, registry.OpStageVersion)
	_, rec, err := s.decide(ctx, c, op, Audience, true, checks)
	if err != nil {
		return err
	}
	if err := s.fenced(ctx, rec, nil, func(context.Context, pgx.Tx) error { return nil }); err != nil {
		return err
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	leased := s.upload(io.NopCloser(body), b)
	defer leased.Close()
	return s.encryptStaged(ctx, c, in, dk.Key, length, leased)
}

// encryptStaged encrypts exactly length bytes of src under key into in's
// staged blob, whose size it knows in advance, and marks the intent STAGED
// with its ciphertext digest and length and its plaintext length (SSE-005).
// No plaintext reaches a blob, temporary file or spill.
func (s *Service) encryptStaged(ctx context.Context, c Caller, in storedIntent, key []byte, length int64, src io.Reader) error {
	size := payload.CiphertextSize(length)
	w, err := s.d.Blobs.Begin(blob.Ref{Tenant: in.Tenant, Blob: in.Blob}, size)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	h := sha256.New()
	enc, err := payload.Encrypt(key, binding(in.Tenant, in.Object, in.LogicalVersion, in.CryptoVersion, in.Blob), io.MultiWriter(w, h))
	if err != nil {
		w.Abort()
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	n, err := io.Copy(enc, io.LimitReader(src, length+1))
	if err == nil && n != length {
		err = fmt.Errorf("%w: the body is not %d bytes", ErrInvalid, length)
	}
	if err == nil {
		err = enc.Close()
	}
	if err != nil {
		w.Abort()
		switch {
		case errors.Is(err, ErrLease):
			return fmt.Errorf("%w: %w", ErrConflict, err)
		case errors.Is(err, ErrInvalid):
			return err
		case errors.Is(err, blob.ErrTooLarge):
			return ErrTooLarge
		}
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var sum cryptowire.Digest
	copy(sum[:], h.Sum(nil))
	if _, err := s.d.Blobs.Finalize(w, size, sum); err != nil {
		if errors.Is(err, blob.ErrConflict) {
			return ErrConflict
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	tag, err := s.d.Catalog.Pool().Exec(ctx, `
		UPDATE upload_intents SET state = 'STAGED', ciphertext_length = $3, ciphertext_sha256 = $4, plaintext_length = $5
		 WHERE tenant = $1 AND id = $2 AND state = 'RESERVED'`, c.Tenant, in.IntentID, size, sum.String(), length)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// prepareServer obtains the publication decision of a staged server-mode
// upload: create-object on the bucket for a new key (with label on the
// planned object for an explicit label) or new-version on the object, with
// a plan, so a policy can require an approval (APR-001). There are no
// descriptor, envelopes or recipients.
func (s *Service) prepareServer(ctx context.Context, c Caller, in storedIntent, r FinalizeRequest) (Prepared, error) {
	if len(r.Descriptor) > 0 || r.DescriptorSignature != "" || len(r.Envelopes) > 0 {
		return Prepared{}, fmt.Errorf("%w: a server-mode upload has no descriptor or envelopes", ErrInvalid)
	}
	if in.state != "STAGED" {
		return Prepared{}, fmt.Errorf("%w: intent is %s", ErrConflict, in.state)
	}
	if err := s.stagedBlob(in); err != nil {
		return Prepared{}, err
	}
	op := registry.OpPublishServerVersion
	checks := []check{{id: "object", role: registry.RoleObject, action: "new-version", ref: canonical("storage.object", in.Object.String())}}
	plan := opplan.Summary{Action: "new-version", Targets: []opplan.Target{{Role: registry.RoleObject, Type: "storage.object",
		ID: in.Object.String(), Version: in.LogicalVersion.String()}}, Changes: map[string]string{"encryption": "server"}}
	if in.newObject {
		b := in.bucket.String()
		op = registry.OpPublishServerCreate
		checks = []check{{id: "bucket", role: registry.RoleBucket, action: "create-object", ref: canonical("storage.bucket", b)}}
		plan.Action, plan.Targets = "create-object", []opplan.Target{{Role: registry.RoleBucket, Type: "storage.bucket", ID: b},
			{Role: registry.RoleObject, Type: "storage.object", ID: in.Object.String(), Version: in.LogicalVersion.String()}}
		if in.label != "" {
			op = registry.OpPublishServerCreateLabeled
			checks = append(checks, check{id: "label", role: registry.RoleLabel, action: "label", ref: planned(registry.PlannedObject, in.IntentID.String())})
			plan.Changes["label"] = in.label
		}
	}
	plan.Details = details(map[string]string{"bucket": fmt.Sprint(in.attributes["bucket"]), "key": in.key})
	switch {
	case in.ifMatch != "":
		plan.Preconditions = []string{"if-match " + in.ifMatch}
	case in.ifNoneMatch:
		plan.Preconditions = []string{"if-none-match *"}
	}
	rec, err := s.decidePlanned(ctx, c, op, checks, plan)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{c: c, in: in, req: r, rec: rec}, nil
}

// readCloser reads from one reader and closes another.
type readCloser struct {
	io.Reader
	io.Closer
}

// ReadObject reads a server-mode version's plaintext: the current version,
// or a named one with read-history (CNT-008, SSE-003). The read is
// admitted and recorded like a ciphertext read; the keys role then
// releases the version's data key against its own decision, and the
// stream decrypts under the read's lease. A failed authentication,
// truncation or lease ends the stream with an error, never as a shorter
// plaintext (SSE-005).
func (s *Service) ReadObject(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	_, o, v, current, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	op, checks := readChecks(o, v, current, "read", "read-history", registry.OpRead, registry.OpReadHistory)
	return s.readServer(ctx, c, o, v, current, op, checks)
}

// ExportObjectPlain is the server-mode export: the plaintext of a version
// for a caller with export and read on it (and read-history for an older
// version). It is the server-mode counterpart of ExportObject, which
// exports a client-mode package for a recipient.
func (s *Service) ExportObjectPlain(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	_, o, v, current, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	ref := canonical("storage.object", o.ID.String())
	checks := []check{
		{id: "object", role: registry.RoleObject, action: "export", ref: ref, version: v.ID.String()},
		{id: "object-read", role: registry.RoleObjectRead, action: "read", ref: ref, version: v.ID.String()}}
	if !current {
		checks = append(checks, check{id: "history", role: registry.RoleHistory, action: "read-history", ref: ref, version: v.ID.String()})
	}
	return s.readServer(ctx, c, o, v, current, registry.OpObjectExport, checks)
}

// readServer admits a server-mode read under op and checks, has the keys
// role release the version's data key, and returns the decrypting stream.
func (s *Service) readServer(ctx context.Context, c Caller, o object, v version, current bool, op string, checks []check) (*Stream, error) {
	if s.d.DataKeys == nil {
		return nil, fmt.Errorf("%w: server mode is not configured", ErrUnavailable)
	}
	rec, tenantID, err := s.admitRead(ctx, c, o, v, current, op, checks, "server")
	if err != nil {
		return nil, err
	}
	relOp, relChecks := readChecks(o, v, current, "read", "read-history", registry.OpKeyRelease, registry.OpKeyReleaseHistory)
	signed, _, err := s.decide(ctx, c, relOp, KeysAudience, true, relChecks)
	if err != nil {
		return nil, err
	}
	key, err := s.d.DataKeys.ReleaseDataKey(ctx, signed, v.ID.String())
	if err != nil {
		return nil, keysError(err)
	}
	defer clear(key)
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	plain, err := payload.Decrypt(key, binding(tenantID, o.ID, v.ID, v.CryptoVersion, v.Blob), r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(readCloser{Reader: plain, Closer: r}, b), Version: info(v, current)}, nil
}
