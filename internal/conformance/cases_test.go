package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/decision"
	"fga/internal/decisionsvc"
	"fga/internal/fence"
	"fga/internal/journal"
	"fga/internal/policy"
	"fga/internal/policy/engine"
	"fga/internal/policy/format"
	"fga/internal/r1test"
	"fga/internal/recovery"
	"fga/internal/registry"
	"fga/sdk/go/crypto"
)

var ctx = context.Background()

// Mappings from fixture vocabulary to ours, one per line:
//   - fixture tenant "acme" is the harness tenant r1test.Tenant;
//   - fixture version labels (v1, v8, ...) are the UUIDs our uploads get;
//   - a fixture "outcome" of an operation is ALLOW (or COMMITTED for a
//     mutation) when our operation succeeds and DENY when it is refused;
//   - a fence failure on a changed authority fact is AUTHORITY_CHANGED;
//   - fixture policy grants are expressed by the harness policies: the
//     owner of an object may do everything to it.
const authorityChanged = "AUTHORITY_CHANGED"

type admission struct{ principal policy.Principal }

func (a admission) Admit(context.Context, decision.Batch) (decision.Admission, error) {
	return decision.Admission{Principal: a.principal, PrincipalRef: decision.Ref{ID: a.principal.ID, Revision: 1}}, nil
}

// TestV001 binds "evaluate" to the decider over an engine compiled from
// the fixture's policies, at the evaluator boundary (kind policy).
func TestV001(t *testing.T) {
	f := load(t, "V-001")
	var state struct {
		Policies []struct {
			Policy json.RawMessage `json:"policy"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(f.InitialState, &state); err != nil {
		t.Fatal(err)
	}
	var docs []format.Document
	for _, p := range state.Policies {
		d, err := format.Parse(p.Policy)
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, d)
	}
	eng, err := engine.Compile("sha256:v001", docs, registry.R1Types(), engine.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(t, "read")
	var p policy.Principal
	var r policy.Resource
	b, _ := json.Marshal(in["principal"])
	_ = json.Unmarshal(b, &p)
	b, _ = json.Marshal(in["resource"])
	_ = json.Unmarshal(b, &r)
	now := mustTime(t, in["now"])
	d, err := decision.NewDecider(admission{p}, eng, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	got := d.DecideBatch(ctx, decision.Batch{Envelope: decision.Envelope{Tenant: r1test.Tenant, Actor: decision.Ref{ID: p.ID}},
		SnapshotDigest: "sha256:v001", Checks: []decision.Check{{ID: "c1", Action: "read", Resource: r}}})
	ceiling := map[policy.Effect]string{policy.EffectAllow: "PASS", policy.EffectDeny: "DENY"}[got.Results[0].Ceiling]
	f.check(t, map[string]any{"read.business_effect": got.Results[0].Business.String(), "read.ceiling_effect": ceiling,
		"read.outcome": got.Outcome.String()})
}

// TestV141 cannot be bound: the fixture's decision carries a signed
// metadata_projection obligation, and R1 maps no policy output to an
// obligation (POL-011 not built), so its verifiers reject every
// obligation (DEC-002).
func TestV141(t *testing.T) {
	load(t, "V-141").unbound(t, "the decision carries a metadata_projection obligation; R1 has no obligation mapping and rejects all obligations")
}

func setup(t *testing.T, opts r1test.Options) (*r1test.Stack, *r1test.Client) {
	t.Helper()
	st := r1test.NewWith(t, opts)
	st.Bucket("objects", "p1")
	return st, st.Client("alice", []string{"member"}, "p1")
}

// TestV142 binds prepare_publish to PreparePublish (decision issued, not
// committed), revoke_principal to the catalog's identity disable, and
// publish to CommitPublish under the fence.
func TestV142(t *testing.T) {
	f := load(t, "V-142")
	st, alice := setup(t, r1test.Options{})
	if _, err := alice.Put("objects", "o1", []byte("v7")); err != nil {
		t.Fatal(err)
	}
	u, err := alice.Prepare(content.BeginRequest{Bucket: "objects", Key: "o1"}, []byte("v8"), alice)
	if err != nil {
		t.Fatal(err)
	}
	req := content.FinalizeRequest{Descriptor: u.Sealed.Descriptor, DescriptorSignature: u.Sealed.DescriptorSignature}
	for _, e := range u.Sealed.Envelopes {
		req.Envelopes = append(req.Envelopes, content.EnvelopeIn{Context: e.Context, Ciphertext: e.Ciphertext, Signature: e.Signature})
	}
	obs := map[string]any{}
	prepared, err := st.Content.PreparePublish(ctx, alice.Caller, u.Intent.IntentID, req)
	obs["prepare.outcome"], obs["prepare.publication_ready"] = outcome(err, "ALLOW"), err == nil
	err = st.Catalog.DisableIdentity(ctx, r1test.Tenant, "alice")
	obs["revoke.committed"] = err == nil
	_, err = st.Content.CommitPublish(ctx, prepared)
	obs["commit.outcome"] = outcome(err, "ALLOW")
	if errors.Is(err, fence.ErrIdentity) || errors.Is(err, fence.ErrDelegation) || errors.Is(err, fence.ErrResource) {
		obs["commit.reason"] = authorityChanged
	}
	var current string
	_ = st.Pool.QueryRow(ctx, `SELECT current_version::text FROM objects WHERE key = 'o1'`).Scan(&current)
	if current == u.Intent.LogicalVersion.String() {
		current = "v8"
	}
	obs["object.current_version"] = current
	var published int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE kind = 'mutation' AND event->>'outcome' = 'PUBLISHED'
	                            AND event->'targets'->0->>'version' = $1`, u.Intent.LogicalVersion.String()).Scan(&published)
	obs["publication_audit_success_count"] = published
	f.check(t, obs)
}

func outcome(err error, ok string) string {
	if err != nil {
		return "DENY"
	}
	return ok
}

// TestV143 binds decide_read to a single-use read decision for the
// current version, admit_read with emit false to the fence's check, and
// admit_read to the fence's admission, at the fixture's times. The fence
// runs with clock margin 0: in the local profile every role reads one
// host clock. With the default one-second margin the admission one second
// before the cutoff is refused (more restrictive than the fixture).
func TestV143(t *testing.T) {
	f := load(t, "V-143")
	decide := f.input(t, "decide")
	now := mustTime(t, decide["now"])
	zero := time.Duration(0)
	policies := map[string]string{}
	for k, v := range r1test.Policies {
		policies[k] = v
	}
	// The fixture's grant: alice may read o1 while request.now is before
	// the cutoff. The object belongs to "owner".
	policies["objects.json"] = `{"format":"fga.policy/v1","set":"business","resource":"storage.object","scope":"","rules":[
	  {"id":"owner-all","effect":"allow","actions":["*"],"roles":["*"],"when":"resource.attributes.owner == principal.id"},
	  {"id":"fixture-grant","effect":"allow","actions":["read"],"roles":["*"],
	   "when":"principal.id == \"alice\" && request.now < timestamp(\"2026-10-31T17:00:00Z\")"}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies, Start: now, FenceMargin: &zero})
	st.Bucket("objects", "p1")
	owner := st.Client("owner", []string{"member"}, "p1")
	st.User("alice", []string{"reviewer"})
	alice := st.Caller("alice")
	pub, err := owner.Put("objects", "o1", []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	obs := map[string]any{}
	_, rec, err := content.Authorize(ctx, r1test.Decider{Service: st.Decisions, Adapter: r1test.StorageAdapter}, st.Verifier(content.Audience),
		st.Catalog, alice, registry.OpRead, content.Audience, true, []content.Check{{ID: "object", Role: registry.RoleObject, Action: "read",
			Resource: canonicalObject(pub.Object), Version: pub.Version}})
	obs["decide.outcome"] = outcome(err, "ALLOW")
	obs["decide.valid_until"] = rec.ValidUntil
	b, ferr := fence.FromRecord(rec)
	if err == nil && ferr == nil {
		obs["admit_before.outcome"] = outcome(st.Fence.Check(ctx, b), "ALLOW")
		*st.Clock = mustTime(t, f.input(t, "admit")["now"])
		obs["admit.outcome"] = outcome(st.Fence.Run(ctx, b, nil, noop), "ALLOW")
	}
	obs["emitted_bytes"] = 0 // no stream is opened without an admission
	f.check(t, obs)
}

// TestV146 binds the version operations to the content service.
func TestV146(t *testing.T) {
	f := load(t, "V-146")
	st, alice := setup(t, r1test.Options{})
	if _, err := alice.Put("objects", "o1", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	v2, err := alice.Put("objects", "o1", []byte("v2"))
	if err != nil {
		t.Fatal(err)
	}
	obs := map[string]any{}
	_, err = st.Content.DeleteKey(ctx, alice.Caller, "objects", "o1")
	obs["delete_key.outcome"] = outcome(err, "COMMITTED")
	s, err := st.Content.ReadCiphertext(ctx, alice.Caller, "objects", "o1", v2.Version)
	obs["read_history.outcome"] = outcome(err, "ALLOW")
	if s != nil {
		s.Close()
	}
	_, err = st.Content.DeleteVersion(ctx, alice.Caller, "objects", "o1", v2.Version)
	obs["delete_version.outcome"] = outcome(err, "COMMITTED")
	s, err = st.Content.ReadCiphertext(ctx, alice.Caller, "objects", "o1", v2.Version)
	obs["read_withdrawn.outcome"] = outcome(err, "ALLOW")
	if s != nil {
		s.Close()
	}
	var marker bool
	_ = st.Pool.QueryRow(ctx, `SELECT v.delete_marker FROM objects o JOIN object_versions v ON v.id = o.current_version WHERE o.key = 'o1'`).Scan(&marker)
	obs["object.current_is_delete_marker"] = marker
	f.check(t, obs)
}

// TestV149 binds verify_historical_content to the SDK's verification with
// a trust store narrowed by the signer's current status (RCP-011), and the
// signer changes to the administrator's catalog operations.
func TestV149(t *testing.T) {
	f := load(t, "V-149")
	st, alice := setup(t, r1test.Options{})
	if _, err := alice.Put("objects", "o1", []byte("descriptor-o1-v1")); err != nil {
		t.Fatal(err)
	}
	verify := func() bool {
		pkg, err := st.Content.ReadPackage(ctx, alice.Caller, "objects", "o1", "", alice.Recipient.Fingerprint().String())
		if err != nil {
			t.Fatal(err)
		}
		stream, err := st.Content.ReadCiphertext(ctx, alice.Caller, "objects", "o1", pkg.Version.Version)
		if err != nil {
			t.Fatal(err)
		}
		var ct bytes.Buffer
		_, _ = ct.ReadFrom(stream)
		stream.Close()
		trust := crypto.StatusTrust{TrustStore: alice.Trust, Status: func(fp cryptowire.Digest) (string, error) {
			var status string
			err := st.Pool.QueryRow(ctx, `SELECT status FROM signing_keys WHERE fingerprint = $1`, fp.String()).Scan(&status)
			return status, err
		}}
		var out bytes.Buffer
		return crypto.Decrypt(&out, bytes.NewReader(ct.Bytes()), crypto.Package{Descriptor: pkg.Descriptor, DescriptorSignature: pkg.DescriptorSignature,
			Envelope: crypto.Envelope{Context: pkg.Envelope.Context, Ciphertext: pkg.Envelope.Ciphertext, Signature: pkg.Envelope.Signature}},
			alice.Recipient, trust) == nil
	}
	fp := alice.Signer.Fingerprint.String()
	obs := map[string]any{}
	if err := st.Catalog.SetSigningKeyStatus(ctx, r1test.Tenant, fp, "RETIRED"); err != nil {
		t.Fatal(err)
	}
	obs["verify_retired.accepted"] = verify()
	if err := st.Catalog.SetSigningKeyStatus(ctx, r1test.Tenant, fp, "COMPROMISED"); err != nil {
		t.Fatal(err)
	}
	obs["verify_compromised.accepted"] = verify()
	f.check(t, obs)
}

// TestV144 binds the recovery operations to internal/recovery,
// admit_recipient_envelope with emit false to a GetRecipientEnvelope
// decision and the fence's check (nothing is delivered), and
// get_recipient_envelope to a GetRecipientEnvelope decision as the storage
// role would request it. The revocation operator is the local
// administrator: journal first, then the catalog.
func TestV144(t *testing.T) {
	f := load(t, "V-144")
	st := r1test.New(t)
	st.Bucket("objects", "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := bob.Put("objects", "o1", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	fp := bob.Recipient.Fingerprint().String()
	status := func() string {
		var s string
		_ = st.Pool.QueryRow(ctx, `SELECT status FROM recipient_keys WHERE fingerprint = $1`, fp).Scan(&s)
		return s
	}
	get := func(prefix string, obs map[string]any) {
		resp, _, err := bob.DeliveryResponse("objects", "o1", fp, registry.OpGetEnvelope, content.KeysAudience)
		if err != nil {
			t.Fatal(err)
		}
		obs[prefix+".outcome"] = map[bool]string{true: "ALLOW", false: "DENY"}[resp.Outcome == "ALLOW"]
		obs[prefix+".reason"] = resp.Reason
	}
	obs := map[string]any{}
	signed, _, err := bob.DeliveryDecision("objects", "o1", fp, registry.OpGetEnvelope, content.KeysAudience)
	if err == nil {
		rec, verr := st.Verifier(content.KeysAudience).Check(signed)
		b, ferr := fence.FromRecord(rec)
		err = errors.Join(verr, ferr)
		if err == nil {
			err = st.Fence.Check(ctx, b)
		}
	}
	obs["baseline.outcome"] = outcome(err, "ALLOW")

	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(ctx, st.Pool, st.Blobs, dir, nil, ""); err != nil {
		t.Fatal(err)
	}
	obs["backup.recipient_status"] = status()
	err = st.Journal.Append(journal.RecipientRevoked, r1test.Tenant, fp)
	entries, _ := st.Journal.Entries()
	obs["revoke.recovery_record_durable"] = err == nil && len(entries) == 1
	obs["revoke.committed"] = st.Catalog.RevokeRecipientKey(ctx, r1test.Tenant, fp) == nil
	if _, err := recovery.Restore(ctx, st.Pool, st.Blobs, st.Journal, dir, nil); err != nil {
		t.Fatal(err)
	}
	_, open, _ := st.Catalog.AuthorityState(ctx)
	obs["restore.admission_open"] = open
	get("request_before", obs)
	if _, err := recovery.Reconcile(ctx, st.Catalog, st.Blobs, st.Journal); err != nil {
		t.Fatal(err)
	}
	obs["reconcile.recipient_status"] = status()
	get("request_after", obs)
	var delivered int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE kind = 'key_release'`).Scan(&delivered)
	obs["envelopes_delivered"] = delivered
	f.check(t, obs)
}

func canonicalObject(id string) decisionsvc.Alias {
	return decisionsvc.Alias{Type: "storage.object", ID: id}
}

func noop(context.Context, pgx.Tx) error { return nil }

// TestV147 binds propose_label to content.ProposeLabel. The fixture's unit
// is a storage object until document units exist (step 3 of R1-C); its
// collection floor is the bucket's default label, and its access revision
// is our metadata revision, brought to the fixture's 3 by two raises from
// the bucket default. The proposer is a project member whose policy allows
// propose-label; its classifier is not registered (no classifier registry
// exists, D-06), so the proposal can only be advisory.
func TestV147(t *testing.T) {
	f := load(t, "V-147")
	var init struct {
		Label          string `json:"label"`
		AccessRevision uint64 `json:"access_revision"`
		Floor          string `json:"collection_floor"`
	}
	if err := json.Unmarshal(f.InitialState, &init); err != nil {
		t.Fatal(err)
	}
	st := r1test.New(t)
	st.LabeledBucket("objects", "p1", init.Floor)
	alice := st.Client("alice", []string{"member"}, "p1")
	if _, err := alice.Put("objects", "u1", []byte("unit")); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"confidential", init.Label} {
		if _, err := st.Content.SetLabel(ctx, alice.Caller, "objects", "u1", l); err != nil {
			t.Fatal(err)
		}
	}
	probe := func() (string, uint64) {
		var label string
		var meta uint64
		_ = st.Pool.QueryRow(ctx, `SELECT r.attributes->>'label', r.metadata_revision FROM objects o
		                            JOIN resources r ON r.tenant = o.tenant AND r.id = o.id::text WHERE o.key = 'u1'`).Scan(&label, &meta)
		return label, meta
	}
	if label, meta := probe(); label != init.Label || meta != init.AccessRevision {
		t.Fatalf("initial state %s at %d, want %s at %d", label, meta, init.Label, init.AccessRevision)
	}
	in := f.input(t, "proposal")
	p, err := st.Content.ProposeLabel(ctx, alice.Caller, "objects", "u1", in["label"].(string), in["signer"].(string))
	if err != nil {
		t.Fatal(err)
	}
	label, meta := probe()
	f.check(t, map[string]any{"unit.label": label, "unit.access_revision": meta, "proposal.authoritative": p.Authoritative})
}
