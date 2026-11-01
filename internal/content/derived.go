package content

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/cryptowire"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/labels"
	"fga/internal/opplan"
	"fga/internal/payload"
	"fga/internal/registry"
	"fga/internal/signing"
)

// Derived outputs (docs/design/derived-outputs.md, DRV-001 to DRV-003,
// DRV-007 to DRV-009). A derived output is an encrypted object of kind
// derived with signed lineage. Delivering it needs deliver on it and, for
// the recipient, read on every source in its transitive lineage or an
// explicit declassify; every source binding is part of the decision, so a
// change to any source ends admitted streams.

// ErrLineageChanged ends a derived stream whose own authority holds but a
// lineage source changed (LINEAGE_AUTHORITY_CHANGED, DRV-009, V-145).
var ErrLineageChanged = fmt.Errorf("%w: LINEAGE_AUTHORITY_CHANGED", ErrLease)

// MaxLineageDepth bounds a derived output's transitive lineage.
const MaxLineageDepth = 32

// source is one lineage source as the catalog holds it.
type source struct {
	cryptowire.LineageSource
	label string
	depth int
}

// sourceRole maps a source type to its check role and action.
func sourceRole(typ string) (role, action string) {
	switch typ {
	case cryptowire.SourceObject:
		return registry.RoleSourceObject, "read"
	case cryptowire.SourceUnit:
		return registry.RoleSourceUnit, "read"
	default:
		return registry.RoleSourceDerived, "deliver"
	}
}

// lineageSources resolves direct sources: each must be a LIVE version of
// an object, unit or derived output of the tenant. It returns them with
// their labels and the output's depth.
func (s *Service) lineageSources(ctx context.Context, q catalog.Querier, tenant string, l cryptowire.Lineage) ([]source, int, error) {
	kinds := map[string]string{cryptowire.SourceObject: "object", cryptowire.SourceUnit: "unit", cryptowire.SourceDerived: "derived"}
	depth := 1
	out := make([]source, 0, len(l.Sources))
	for _, src := range l.Sources {
		var label string
		var d *int
		err := q.QueryRow(ctx, `
			SELECT coalesce(r.attributes->>'label', ''), dv.depth FROM objects o
			  JOIN object_versions v ON v.tenant = o.tenant AND v.object = o.id
			  JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text AND r.type = $4
			  LEFT JOIN derived_versions dv ON dv.tenant = v.tenant AND dv.version = v.id
			 WHERE o.tenant = $1 AND o.id::text = $2 AND v.id::text = $3 AND o.kind = $5 AND v.state = 'LIVE' AND NOT v.delete_marker`,
			tenant, src.ID, src.Version, src.Type, kinds[src.Type]).Scan(&label, &d)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		if err != nil {
			return nil, 0, err
		}
		sd := 0
		if d != nil {
			sd = *d
		}
		depth = max(depth, sd+1)
		out = append(out, source{LineageSource: src, label: label, depth: sd})
	}
	if depth > MaxLineageDepth {
		return nil, 0, fmt.Errorf("%w: lineage deeper than %d", ErrInvalid, MaxLineageDepth)
	}
	return out, depth, nil
}

// transitive returns every source in a derived version's transitive
// lineage, each once.
func (s *Service) transitive(ctx context.Context, q catalog.Querier, tenant string, version cryptowire.UUID) ([]cryptowire.LineageSource, error) {
	return catalog.TransitiveLineage(ctx, q, tenant, version, MaxLineageDepth)
}

// sourceGroups are the checks of op on sources, for the caller (recipient
// "") or a recipient key.
func sourceGroups(sources []cryptowire.LineageSource, recipient string) [][]check {
	groups := make([][]check, len(sources))
	for i, src := range sources {
		role, action := sourceRole(src.Type)
		groups[i] = []check{{id: "source-" + strconv.Itoa(i), role: role, action: action, ref: canonical(src.Type, src.ID), version: src.Version,
			recipient: recipient}}
	}
	return groups
}

// decideBatches decides op over groups in batches; any denial is
// ErrNotFound.
func (s *Service) decideBatches(ctx context.Context, c Caller, op, audience string, singleUse bool, groups [][]check) ([]signing.Signed, []signing.Record, error) {
	var signed []signing.Signed
	var recs []signing.Record
	for _, batch := range batches(groups, maxBatch) {
		sg, rec, err := s.decide(ctx, c, op, audience, singleUse, batch)
		if err != nil {
			return nil, nil, err
		}
		signed, recs = append(signed, sg), append(recs, rec)
	}
	return signed, recs, nil
}

// FinalizeDerived publishes a derived output (DRV-001, DRV-007): the
// staged ciphertext and descriptor as for an object, its lineage signed by
// the same key and naming this output and version, and initial envelopes
// for the caller's own keys only. The caller needs create-object on the
// bucket and read (deliver for derived sources) on every direct source;
// the stored label is the maximum of the bucket's floor and the sources'
// labels, raised by an explicit proposal but never lowered by one (V-148).
func (s *Service) FinalizeDerived(ctx context.Context, c Caller, intentID cryptowire.UUID, r FinalizeRequest, lineage []byte, lineageSig string) (Published, error) {
	in, err := s.intent(ctx, s.d.Catalog.Pool(), c, intentID, false)
	if err != nil {
		return Published{}, err
	}
	if in.kind != "derived" {
		return Published{}, ErrNotFound
	}
	if err := clientMode(in.encryption); err != nil {
		return Published{}, err
	}
	if in.state != "STAGED" {
		return Published{}, fmt.Errorf("%w: intent is %s", ErrConflict, in.state)
	}
	if len(r.Envelopes) == 0 || len(r.Envelopes) > s.d.Limits.MaxEnvelopes {
		return Published{}, ErrInvalid
	}
	if err := s.stagedBlob(in); err != nil {
		return Published{}, err
	}
	desc, signer, err := s.checkDescriptor(ctx, c, in, r)
	if err != nil {
		return Published{}, err
	}
	envs, err := s.checkEnvelopes(ctx, c, in, desc, signer, r.Envelopes)
	if err != nil {
		return Published{}, err
	}
	signerPub, err := s.signerActive(ctx, c.Tenant, c.Principal, signer)
	if err != nil {
		return Published{}, err
	}
	if _, err := cryptowire.Verify(cryptowire.TypeLineage, lineageSig, lineage, func(kid string) (ed25519.PublicKey, error) {
		if kid != signer {
			return nil, errors.New("lineage signed by another key")
		}
		return signerPub, nil
	}); err != nil {
		return Published{}, fmt.Errorf("%w: lineage signature", ErrInvalid)
	}
	l, err := cryptowire.ParseLineage(lineage)
	if err != nil || l.TenantID != in.Tenant.String() || l.ObjectID != in.Object.String() || l.VersionID != in.LogicalVersion.String() || l.Signer != signer {
		return Published{}, fmt.Errorf("%w: lineage does not match the intent", ErrInvalid)
	}
	return s.publishDerived(ctx, c, in, derivedPublication{lineage: l, raw: lineage, sig: lineageSig, signer: signer, desc: desc, req: r, envs: envs})
}

// derivedPublication is what a derived version is published with: its
// lineage, as sent and signed in client mode or as recorded by the
// storage role in server mode (no signature or signer), and in client mode
// its descriptor, finalize request and initial envelopes.
type derivedPublication struct {
	lineage cryptowire.Lineage
	raw     []byte
	sig     string
	signer  string
	desc    cryptowire.Descriptor
	req     FinalizeRequest
	envs    []checkedEnvelope
}

// publishDerived decides and commits a derived version (DRV-001, DRV-007),
// in either mode: the label from the bucket's floor, the lineage and any
// proposal; the publication decision with its plan and the caller's read
// on every direct source; and the fenced commit.
func (s *Service) publishDerived(ctx context.Context, c Caller, in storedIntent, p derivedPublication) (Published, error) {
	l, lineage, lineageSig, signer, desc, r, envs := p.lineage, p.raw, p.sig, p.signer, p.desc, p.req, p.envs
	server := in.encryption == "server"
	sources, depth, err := s.lineageSources(ctx, s.d.Catalog.Pool(), c.Tenant, l)
	if err != nil {
		return Published{}, err
	}
	effective, raised, err := s.derivedLabel(ctx, s.d.Catalog.Pool(), c.Tenant, in, sources, false)
	if err != nil {
		return Published{}, err
	}

	// Initial envelopes go to the caller's own keys only; others receive
	// the output through ShareDerived, which checks their lineage.
	op, ref, envelopeObject := registry.OpDerivedPublish, planned(registry.PlannedObject, in.IntentID.String()), "intent:"+in.IntentID.String()
	checks := []check{{id: "bucket", role: registry.RoleBucket, action: "create-object", ref: canonical("storage.bucket", in.bucket.String())}}
	if !in.newObject {
		op, ref, envelopeObject = registry.OpDerivedPublishVersion, planned(registry.ChangeLabel, in.Object.String()+"|"+in.label), in.Object.String()
		checks = []check{{id: "output", role: registry.RoleOutput, action: "new-version", ref: canonical("document.derived", in.Object.String())}}
	}
	if server {
		op = map[string]string{registry.OpDerivedPublish: registry.OpDerivedPublishServer,
			registry.OpDerivedPublishVersion: registry.OpDerivedPublishServerVersion}[op]
	}
	if raised {
		checks = append(checks, check{id: "label", role: registry.RoleLabel, action: "label", ref: ref})
	}
	for i, e := range envs {
		var principal string
		if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT principal FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2`,
			c.Tenant, e.ctx.Recipient.String()).Scan(&principal); err != nil || principal != c.Principal {
			return Published{}, fmt.Errorf("%w: initial envelopes of a derived output are for the caller's own keys", ErrInvalid)
		}
		fp, n := e.ctx.Recipient.String(), strconv.Itoa(i)
		checks = append(checks,
			check{id: "envelope-" + n, role: registry.RoleEnvelope, action: "create",
				ref: planned(registry.PlannedEnvelope, envelopeObject+"|"+fp+"|"+e.id.String())},
			check{id: "recipient-key-" + n, role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", fp), recipient: fp})
	}
	plan := opplan.Summary{Action: checks[0].action, Changes: map[string]string{"lineage": cryptowire.ManifestDigest(lineage).String(), "label": effective},
		Details: details(map[string]string{"key": in.key})}
	if in.newObject {
		plan.Targets = []opplan.Target{{Role: registry.RoleBucket, Type: "storage.bucket", ID: in.bucket.String()},
			{Role: registry.RoleOutput, Type: "document.derived", ID: in.Object.String(), Version: in.LogicalVersion.String()}}
	} else {
		plan.Targets = []opplan.Target{{Role: registry.RoleOutput, Type: "document.derived", ID: in.Object.String(), Version: in.LogicalVersion.String()}}
	}
	base, err := s.decidePlanned(ctx, c, op, checks, plan)
	if err != nil {
		return Published{}, err
	}
	direct := make([]cryptowire.LineageSource, len(sources))
	for i, src := range sources {
		direct[i] = src.LineageSource
	}
	_, srcRecs, err := s.decideBatches(ctx, c, registry.OpDerivedSources, Audience, true, sourceGroups(direct, ""))
	if err != nil {
		return Published{}, err
	}
	recs := append([]signing.Record{base}, srcRecs...)
	bindings := make([]fence.Binding, len(recs))
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return Published{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	var result Published
	// An existing output is locked for update from the start, since the
	// commit updates it (review v3 F13).
	var mutate []string
	if !in.newObject {
		mutate = []string{in.Object.String()}
	}
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, mutate, func(ctx context.Context, tx pgx.Tx) error {
		if !server {
			if err := catalog.SignerActiveTx(ctx, tx, c.Tenant, c.Principal, signer); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalid, err)
			}
		}
		if raised {
			if err := s.labelOrderHolds(ctx, tx, base, in.label, in.bucket); err != nil {
				return err
			}
		}
		current, _, err := s.lineageSources(ctx, tx, c.Tenant, l)
		if err != nil {
			return fmt.Errorf("%w: a lineage source is no longer live", ErrConflict)
		}
		// The label the plan names must still be the one current state
		// gives: the output's label, the sources' labels as the fence sees
		// them and the active order. Otherwise a raise since the plan was
		// read would be lowered by this version; a retry plans again
		// (review v3 F06).
		again, raisedAgain, err := s.derivedLabel(ctx, tx, c.Tenant, in, current, true)
		if err != nil {
			return err
		}
		if again != effective || raisedAgain != raised {
			return fmt.Errorf("%w: a label of the output or its lineage changed since the publication was planned", ErrConflict)
		}
		var st string
		if err := tx.QueryRow(ctx, `SELECT state FROM upload_intents WHERE tenant = $1 AND id = $2 FOR UPDATE`, c.Tenant, in.IntentID).Scan(&st); err != nil {
			return err
		}
		if st != "STAGED" || !s.d.Now().Before(in.ExpiresAt) {
			return fmt.Errorf("%w: intent is %s or expired", ErrConflict, st)
		}
		attrs := map[string]any{"kind": "derived", "label": effective}
		for _, k := range []string{"bucket", "owner", "project", "encryption"} {
			attrs[k] = in.attributes[k]
		}
		ab, _ := json.Marshal(attrs)
		now := s.d.Now()
		generation := uint64(1)
		if in.newObject {
			if _, err := tx.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, 'document.derived', $3, 1, 1, 1, $4)`, c.Tenant, in.Object.String(), in.scope, ab); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO objects (tenant, id, bucket, key, kind) VALUES ($1, $2, $3, $4, 'derived')`, c.Tenant, in.Object, in.bucket, in.key)
			if isUnique(err) {
				return fmt.Errorf("%w: the key was created concurrently", ErrConflict)
			}
			if err != nil {
				return err
			}
		} else {
			// A raised label also advances the metadata revision (LAB-005).
			err := tx.QueryRow(ctx, `
				UPDATE resources SET generation = generation + 1, version = version + 1,
				       metadata_revision = metadata_revision + CASE WHEN attributes->>'label' IS DISTINCT FROM $4 THEN 1 ELSE 0 END,
				       attributes = attributes || jsonb_build_object('label', $4::text)
				 WHERE tenant = $1 AND id = $2 AND generation = $3 RETURNING generation`,
				c.Tenant, in.Object.String(), in.expectedGen, effective).Scan(&generation)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: the derived output changed since begin", ErrConflict)
			}
			if err != nil {
				return err
			}
		}
		if server {
			// The sealed data key moves from the intent to the version
			// (SSE-002); there is no client descriptor.
			if _, err := tx.Exec(ctx, `
				INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
				                             created_at, published_at, encryption, sealed_key, kek_version, plaintext_length)
				SELECT $1, $2, $3, $4, $5, 'LIVE', i.ciphertext_length, i.ciphertext_sha256, $6, $7, $8, $8, 'server', i.sealed_key, i.kek_version,
				       i.plaintext_length
				  FROM upload_intents i WHERE i.tenant = $1 AND i.id = $9 AND i.sealed_key IS NOT NULL AND i.plaintext_length IS NOT NULL`,
				c.Tenant, in.LogicalVersion, in.Object, in.CryptoVersion, in.Blob, int(payload.Suite), int(payload.Format), now, in.IntentID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `
			INSERT INTO object_versions (tenant, id, object, crypto_version, blob, state, ciphertext_length, ciphertext_sha256, suite, format,
			                             signer, descriptor, descriptor_signature, created_at, published_at, encryption)
			VALUES ($1, $2, $3, $4, $5, 'LIVE', $6, $7, $8, $9, $10, $11, $12, $13, $13, $14)`,
			c.Tenant, in.LogicalVersion, in.Object, in.CryptoVersion, in.Blob, int64(desc.CiphertextLength), desc.CiphertextSHA256,
			int(desc.Suite), int(desc.Format), desc.Signer, r.Descriptor, r.DescriptorSignature, now, in.encryption); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE objects SET current_version = $3 WHERE tenant = $1 AND id = $2`, c.Tenant, in.Object, in.LogicalVersion); err != nil {
			return err
		}
		var sigArg any = lineageSig
		if server {
			sigArg = nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO derived_versions VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			c.Tenant, in.LogicalVersion, in.Object, lineage, sigArg, effective, depth); err != nil {
			return err
		}
		for i, src := range l.Sources {
			if _, err := tx.Exec(ctx, `INSERT INTO lineage VALUES ($1, $2, $3, $4, $5, $6)`, c.Tenant, in.LogicalVersion, i, src.Type, src.ID, src.Version); err != nil {
				return err
			}
		}
		for _, e := range envs {
			if err := envelope.InsertEnvelope(ctx, tx, c.Tenant, in.scope, attrs, e.id, in.Object, in.LogicalVersion, e.ctx, e.keyVersion,
				e.EnvelopeIn, e.digest, now); err != nil {
				return err
			}
		}
		result = Published{Object: in.Object.String(), Version: in.LogicalVersion.String(), ETag: ETag(in.LogicalVersion), Generation: generation}
		stored, _ := json.Marshal(result)
		if _, err := tx.Exec(ctx, `UPDATE upload_intents SET state = 'COMMITTED', result = $3 WHERE tenant = $1 AND id = $2`,
			c.Tenant, in.IntentID, stored); err != nil {
			return err
		}
		targets := []audit.Target{{Type: "document.derived", ID: in.Object.String(), Version: in.LogicalVersion.String(), Signer: signer,
			Digest: desc.CiphertextSHA256}}
		if server {
			targets[0].Digest = in.ciphertextSHA256
		}
		for _, src := range l.Sources {
			targets = append(targets, audit.Target{Type: src.Type, ID: src.ID, Version: src.Version})
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindMutation, base, "DERIVED_PUBLISHED", targets...))
	}))
	if err != nil {
		return Published{}, err
	}
	return result, nil
}

// derivedLabel is the label a derived version is published with (DRV-007,
// LAB-004): at least the bucket's floor, the maximum of its direct
// sources' labels and, for a new version, the output's current label, so
// a version never lowers it implicitly (lowering is relabel). An explicit
// proposal can only raise it; raised reports that it did. In the fence
// (lock), the label order is read under a share lock.
func (s *Service) derivedLabel(ctx context.Context, q catalog.Querier, tenant string, in storedIntent, sources []source, lock bool) (string, bool, error) {
	_, order, err := catalog.LabelOrder(ctx, q, lock)
	if err != nil {
		return "", false, fmt.Errorf("%w: no label order is active", ErrInvalid)
	}
	var floor string
	if err := q.QueryRow(ctx, `SELECT default_label FROM buckets WHERE tenant = $1 AND id = $2`, tenant, in.bucket).Scan(&floor); err != nil {
		return "", false, err
	}
	effective, rank := floor, rankOf(order, floor)
	if !in.newObject {
		var current string
		if err := q.QueryRow(ctx, `SELECT coalesce(attributes->>'label', '') FROM resources WHERE tenant = $1 AND id = $2`,
			tenant, in.Object.String()).Scan(&current); err != nil {
			return "", false, err
		}
		if rankOf(order, current) > rank {
			effective, rank = current, rankOf(order, current)
		}
	}
	for _, src := range sources {
		if r := rankOf(order, src.label); r > rank {
			effective, rank = order[r], r
		}
	}
	raised := in.label != "" && rankOf(order, in.label) > rank
	if raised {
		effective = in.label
	}
	return effective, raised, nil
}

func rankOf(order []string, label string) int {
	r, _ := labels.Rank(order, label)
	return r
}

// derivedTarget resolves a derived output key and optional version.
func (s *Service) derivedTarget(ctx context.Context, tenant, bucketName, key, versionSel string) (cryptowire.UUID, version, error) {
	b, err := s.bucketByName(ctx, tenant, bucketName)
	if err != nil {
		return cryptowire.UUID{}, version{}, err
	}
	var id cryptowire.UUID
	var current *cryptowire.UUID
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id, current_version FROM objects WHERE tenant = $1 AND bucket = $2 AND key = $3 AND kind = 'derived'`,
		tenant, b.ID, key).Scan(&id, &current)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current == nil {
		return id, version{}, ErrNotFound
	}
	if err != nil {
		return id, version{}, err
	}
	vid := *current
	if versionSel != "" {
		if vid, err = cryptowire.ParseUUID(versionSel); err != nil {
			return id, version{}, ErrNotFound
		}
	}
	v, err := s.versionByID(ctx, s.d.Catalog.Pool(), tenant, vid, false)
	if err != nil || v.Object != id || v.State != "LIVE" {
		return id, version{}, ErrNotFound
	}
	return id, v, nil
}

// recipientPath decides the recipient's eligibility for a derived version
// (DRV-002): recipient read (deliver for derived outputs) on every
// transitive source, or, failing that, an explicit declassify for this
// output, version and recipient. Every source binding is part of the
// decisions (DRV-009).
func (s *Service) recipientPath(ctx context.Context, c Caller, output cryptowire.UUID, v version, recipient, audience string, singleUse bool) ([]signing.Signed, []signing.Record, error) {
	sources, err := s.transitive(ctx, s.d.Catalog.Pool(), c.Tenant, v.ID)
	if err != nil {
		return nil, nil, err
	}
	signed, recs, err := s.decideBatches(ctx, c, registry.OpDerivedRecipientSources, audience, singleUse, sourceGroups(sources, recipient))
	if !errors.Is(err, ErrNotFound) {
		return signed, recs, err
	}
	ref := canonical("document.derived", output.String())
	sg, rec, err := s.decide(ctx, c, registry.OpDerivedDeclassify, audience, singleUse, []check{
		{id: "output", role: registry.RoleOutput, action: "deliver", ref: ref, version: v.ID.String()},
		{id: "declassify", role: registry.RoleRecipientDeclass, action: "declassify", ref: ref, version: v.ID.String(), recipient: recipient}})
	if err != nil {
		return nil, nil, err
	}
	return []signing.Signed{sg}, []signing.Record{rec}, nil
}

// ownKey checks that recipient is one of the caller's own recipient keys.
func (s *Service) ownKey(ctx context.Context, c Caller, recipient string) error {
	var principal string
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT principal FROM recipient_keys WHERE tenant = $1 AND fingerprint = $2`,
		c.Tenant, recipient).Scan(&principal); err != nil || principal != c.Principal {
		return ErrNotFound
	}
	return nil
}

// DerivedPackage returns a derived version's descriptor and the caller's
// envelope for one of its own keys. The keys role releases it against
// deliver, the envelope's release and receive-key, together with the
// recipient-path decisions, all admitted in its fence.
func (s *Service) DerivedPackage(ctx context.Context, c Caller, bucketName, key, versionSel, recipient string) (Package, error) {
	if _, err := cryptowire.ParseDigest(recipient); err != nil {
		return Package{}, ErrInvalid
	}
	if err := s.ownKey(ctx, c, recipient); err != nil {
		return Package{}, err
	}
	output, v, err := s.derivedTarget(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return Package{}, err
	}
	path, _, err := s.recipientPath(ctx, c, output, v, recipient, KeysAudience, true)
	if err != nil {
		return Package{}, err
	}
	deliver := check{id: "output", role: registry.RoleOutput, action: "deliver", ref: canonical("document.derived", output.String()), version: v.ID.String()}
	if v.Encryption != "client" {
		// A server-mode output has no envelopes; a caller who may deliver
		// it is told its mode rather than that none exists (ENC-002).
		_, rec, err := s.decide(ctx, c, registry.OpDerivedDeliver, Audience, false, []check{deliver})
		if err != nil {
			return Package{}, err
		}
		if err := s.checked(ctx, rec); err != nil {
			return Package{}, err
		}
		return Package{}, ErrEncryptionMode
	}
	var envelopeID string
	err = s.d.Catalog.Pool().QueryRow(ctx, `SELECT id::text FROM envelopes WHERE tenant = $1 AND version = $2 AND recipient = $3
	                                         AND document_version IS NULL AND status = 'ACTIVE'`, c.Tenant, v.ID, recipient).Scan(&envelopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Package{}, ErrNotFound
	}
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	signed, _, err := s.decide(ctx, c, registry.OpDerivedGetEnvelope, KeysAudience, true, []check{
		deliver,
		{id: "envelope", role: registry.RoleEnvelope, action: "release", ref: canonical("crypto.envelope", envelopeID), version: v.ID.String()},
		{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", recipient), recipient: recipient}})
	if err != nil {
		return Package{}, err
	}
	env, err := s.d.Keys.Deliver(ctx, signed, envelopeID, path...)
	if err != nil {
		return Package{}, err
	}
	return Package{Version: info(v, true), Descriptor: v.Descriptor, DescriptorSignature: v.DescriptorSig, Envelope: env}, nil
}

// ReadDerivedCiphertext admits the read of a derived version's ciphertext
// for the caller, as the recipient key recipient: deliver on the output and
// the recipient path, admitted together, under a lease over all of them.
// When a lineage source changes while the output's own authority holds,
// the stream ends with ErrLineageChanged (V-145).
func (s *Service) ReadDerivedCiphertext(ctx context.Context, c Caller, bucketName, key, versionSel, recipient string) (*Stream, error) {
	if err := s.ownKey(ctx, c, recipient); err != nil {
		return nil, err
	}
	output, v, err := s.derivedTarget(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	_, own, err := s.decide(ctx, c, registry.OpDerivedDeliver, Audience, true,
		[]check{{id: "output", role: registry.RoleOutput, action: "deliver", ref: canonical("document.derived", output.String()), version: v.ID.String()}})
	if err != nil {
		return nil, err
	}
	_, path, err := s.recipientPath(ctx, c, output, v, recipient, Audience, true)
	if err != nil {
		return nil, err
	}
	if err := clientMode(v.Encryption); err != nil {
		return nil, err
	}
	merged, own0, tenantID, err := s.admitDerived(ctx, c, output, v, append([]signing.Record{own}, path...), recipient)
	if err != nil {
		return nil, err
	}
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.derivedLease(r, merged, own0), Version: info(v, true)}, nil
}

// admitDerived admits the read of a derived version under the fence over
// recs, the output's own decision first and then its reader's or
// recipient's path, recording the admission. It returns their merged
// binding and the output's own.
func (s *Service) admitDerived(ctx context.Context, c Caller, output cryptowire.UUID, v version, recs []signing.Record,
	recipient string) (fence.Binding, fence.Binding, cryptowire.UUID, error) {
	own := recs[0]
	bindings := make([]fence.Binding, len(recs))
	var err error
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return fence.Binding{}, fence.Binding{}, cryptowire.UUID{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return fence.Binding{}, fence.Binding{}, tenantID, err
	}
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM object_versions WHERE tenant = $1 AND id = $2 FOR SHARE`, c.Tenant, v.ID).Scan(&state); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `INSERT INTO read_admissions VALUES ($1, $2, $3, $4, $5)`, c.Tenant, own.DecisionID, v.ID, s.d.Now(), own.ValidUntil); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindReadAdmission, own, "ADMITTED",
			audit.Target{Type: "document.derived", ID: output.String(), Version: v.ID.String(), Digest: v.SHA256, Recipient: recipient}))
	}))
	if err != nil {
		return fence.Binding{}, fence.Binding{}, tenantID, err
	}
	merged, err := fence.Merge(bindings)
	if err != nil {
		return fence.Binding{}, fence.Binding{}, tenantID, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	ownBinding := bindings[0]
	ownBinding.ValidUntil = merged.ValidUntil
	return merged, ownBinding, tenantID, nil
}

// derivedLease wraps a derived stream in the merged lease; when a recheck
// fails while the output's own authority still holds, a lineage source
// changed and the stream ends with ErrLineageChanged (V-145).
func (s *Service) derivedLease(r io.ReadCloser, merged, own fence.Binding) io.ReadCloser {
	return s.leaseUntil(r, merged, merged.ValidUntil, func(err error) error {
		if s.d.Fence.Check(context.Background(), own) == nil {
			return ErrLineageChanged
		}
		return fmt.Errorf("%w: %v", ErrLease, err)
	})
}

// ShareDerived publishes an envelope of a derived version for another
// recipient (DRV-002): deliver for the caller, the envelope's create and
// the recipient's receive-key, and the recipient path, committed together.
// The envelope is the caller's client's own, made from a key it could
// decrypt; the server never creates one.
func (s *Service) ShareDerived(ctx context.Context, c Caller, bucketName, key, versionSel string, e EnvelopeIn) (envelope.EnvelopeRef, error) {
	output, v, err := s.derivedTarget(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	ctxv, err := cryptowire.ParseEnvelopeContext(e.Context)
	if err != nil || ctxv.Profile() != 1 || len(e.Ciphertext) == 0 || len(e.Ciphertext) > cryptowire.MaxHPKECiphertext {
		return envelope.EnvelopeRef{}, ErrInvalid
	}
	signer := ctxv.Sharer.String()
	signerPub, err := s.signerActive(ctx, c.Tenant, c.Principal, signer)
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	if _, err := cryptowire.Verify(cryptowire.TypeEnvelope, e.Signature, cryptowire.EnvelopeSigningInput(e.Context, e.Ciphertext),
		func(kid string) (ed25519.PublicKey, error) {
			if kid != signer {
				return nil, errors.New("envelope signed by another key")
			}
			return signerPub, nil
		}); err != nil {
		return envelope.EnvelopeRef{}, fmt.Errorf("%w: envelope signature", ErrInvalid)
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	if ctxv.Tenant != tenantID || ctxv.Object != output || ctxv.LogicalVersion != v.ID || ctxv.CryptoVersion != v.CryptoVersion ||
		ctxv.CiphertextSHA256.String() != v.SHA256 || int64(ctxv.CiphertextLength) != v.Length {
		return envelope.EnvelopeRef{}, fmt.Errorf("%w: envelope bindings", ErrInvalid)
	}
	fp := ctxv.Recipient.String()
	keyVersion, err := s.recipientKey(ctx, c.Tenant, fp)
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	if keyVersion != ctxv.RecipientKeyVersion {
		return envelope.EnvelopeRef{}, fmt.Errorf("%w: recipient key version", ErrInvalid)
	}
	id := cryptowire.NewUUID()
	ref := canonical("document.derived", output.String())
	_, share, err := s.decide(ctx, c, registry.OpDerivedShare, Audience, true, []check{
		{id: "output", role: registry.RoleOutput, action: "deliver", ref: ref, version: v.ID.String()},
		{id: "envelope", role: registry.RoleEnvelope, action: "create", ref: planned(registry.PlannedEnvelope, output.String()+"|"+fp+"|"+id.String())},
		{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", fp), recipient: fp}})
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	_, path, err := s.recipientPath(ctx, c, output, v, fp, Audience, true)
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	recs := append([]signing.Record{share}, path...)
	bindings := make([]fence.Binding, len(recs))
	for i, rec := range recs {
		if bindings[i], err = fence.FromRecord(rec); err != nil {
			return envelope.EnvelopeRef{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	var attrs map[string]any
	if err := s.d.Catalog.Pool().QueryRow(ctx, `SELECT attributes FROM resources WHERE tenant = $1 AND id = $2`, c.Tenant, output.String()).Scan(&attrs); err != nil {
		return envelope.EnvelopeRef{}, err
	}
	out := envelope.EnvelopeRef{ID: id.String(), Generation: ctxv.Generation, Status: "ACTIVE"}
	err = mapFence(s.d.Fence.RunAll(ctx, bindings, nil, func(ctx context.Context, tx pgx.Tx) error {
		if err := catalog.SignerActiveTx(ctx, tx, c.Tenant, c.Principal, signer); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		var next uint64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(generation), 0) + 1 FROM envelopes WHERE tenant = $1 AND version = $2 AND recipient = $3
		                             AND document_version IS NULL`, c.Tenant, v.ID, fp).Scan(&next); err != nil {
			return err
		}
		if ctxv.Generation != next {
			return fmt.Errorf("%w: envelope generation %d, want %d", ErrConflict, ctxv.Generation, next)
		}
		if err := envelope.RetireTx(ctx, tx, c.Tenant, `version = $2 AND recipient = $3 AND document_version IS NULL`, v.ID, fp); err != nil {
			return err
		}
		if err := envelope.InsertEnvelope(ctx, tx, c.Tenant, "", attrs, id, output, v.ID, ctxv, keyVersion, e,
			cryptowire.EnvelopeDigest(e.Context, e.Ciphertext), s.d.Now()); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindEnvelopePublication, share, "DERIVED_SHARED",
			audit.Target{Type: "crypto.envelope", ID: output.String(), Version: v.ID.String(), Recipient: fp, Envelope: id.String(),
				Generation: ctxv.Generation, Signer: signer}))
	}))
	if err != nil {
		return envelope.EnvelopeRef{}, err
	}
	return out, nil
}
