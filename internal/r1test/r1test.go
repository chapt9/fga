// Package r1test builds a complete R1 storage stack for tests: a migrated
// catalog in a throwaway PostgreSQL schema, a signed storage policy
// release, the decision service in process, the authority fence, a blob
// store and the content service. Tests skip without FGA_TEST_DATABASE_URL.
package r1test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/approval"
	"fga/internal/authn"
	"fga/internal/blob"
	"fga/internal/catalog"
	"fga/internal/content"
	"fga/internal/decision"
	"fga/internal/decisionsvc"
	"fga/internal/envelope"
	"fga/internal/fence"
	"fga/internal/gate"
	"fga/internal/journal"
	"fga/internal/pgtest"
	"fga/internal/policy/engine"
	"fga/internal/registry"
	"fga/internal/release"
	"fga/internal/signing"
)

// Tenant is the tenant of every fixture.
const Tenant = "t-acme"

// StorageAdapter is the workload name of the storage role.
const StorageAdapter = "storage-1"

// LabelOrder is the fixture release's label order (D-06), generation 1.
var LabelOrder = []string{"public", "internal", "confidential", "restricted"}

// Policies is the storage policy release of the fixture.
//
//   - Members of a bucket's project may create objects in it and list it.
//   - An object's owner may use every listed object action on it; project
//     members may read, stat and discover it; auditors may see history.
//   - A recipient may receive its own active key's envelopes, and anyone
//     with share on the object may create envelopes for eligible
//     recipients.
//   - Members cannot see others' objects labelled secret.
//   - Members may look up recipient keys (to share) and signing keys (to
//     verify); a principal may use its own keys. Every action is listed:
//     nothing is allowed without a rule (ruling 7).
//   - An owner may set or raise its object's label, and lower it only with
//     an approval; members may propose labels; project leads approve.
//   - A document's owner may use its versions and units; members may read
//     units of their projects below restricted and the versions' units.
//   - The ceiling forbids receive-key for a key that is not active.
var Policies = map[string]string{
	"buckets.json": `{"format":"fga.policy/v1","set":"business","resource":"storage.bucket","scope":"","rules":[
	  {"id":"members-use-bucket","effect":"allow","actions":["create-object","list"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"leads-approve-buckets","effect":"allow","actions":["approve"],"roles":["lead"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`,
	"objects.json": `{"format":"fga.policy/v1","set":"business","resource":"storage.object","scope":"","rules":[
	  {"id":"owner-all","effect":"allow","actions":["read","stat","discover","read-history","discover-history","new-version","delete","delete-version","share","label"],"roles":["*"],"when":"resource.attributes.owner == principal.id"},
	  {"id":"owner-lowers-with-approval","effect":"allow","actions":["relabel"],"roles":["*"],"requires":["approval"],
	   "when":"resource.attributes.owner == principal.id"},
	  {"id":"members-propose-labels","effect":"allow","actions":["propose-label"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"leads-approve-objects","effect":"allow","actions":["approve"],"roles":["lead"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"members-read","effect":"allow","actions":["read","stat","discover"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"auditors-history","effect":"allow","actions":["read-history","discover-history"],"roles":["auditor"]},
	  {"id":"contractors-never-read","effect":"deny","actions":["read"],"roles":["contractor"]},
	  {"id":"secret-hidden","effect":"deny","actions":["read","stat","discover"],"roles":["member"],
	   "when":"resource.attributes.label == \"secret\" && resource.attributes.owner != principal.id"}]}`,
	"envelopes.json": `{"format":"fga.policy/v1","set":"business","resource":"crypto.envelope","scope":"","rules":[
	  {"id":"create-for-sharers","effect":"allow","actions":["create"],"roles":["*"]},
	  {"id":"release-to-recipient","effect":"allow","actions":["release"],"roles":["*"],
	   "when":"resource.attributes.recipient_principal == principal.id"},
	  {"id":"owner-retires","effect":"allow","actions":["retire"],"roles":["*"],"when":"resource.attributes.owner == principal.id"}]}`,
	"recipients.json": `{"format":"fga.policy/v1","set":"business","resource":"crypto.recipient","scope":"","rules":[
	  {"id":"own-key","effect":"allow","actions":["enroll","activate","receive-key","revoke","discover"],"roles":["*"],"when":"resource.attributes.principal == principal.id"},
  {"id":"members-find-keys","effect":"allow","actions":["discover"],"roles":["member"]}]}`,
	"signing-keys.json": `{"format":"fga.policy/v1","set":"business","resource":"crypto.signing-key","scope":"","rules":[
  {"id":"members-verify-signers","effect":"allow","actions":["discover"],"roles":["member"]},
  {"id":"own-signing-key","effect":"allow","actions":["discover"],"roles":["*"],"when":"resource.attributes.principal == principal.id"}]}`,
	"documents.json": `{"format":"fga.policy/v1","set":"business","resource":"document.version","scope":"","rules":[
	  {"id":"owner-versions","effect":"allow","actions":["read-units","raw-read","discover","share","export"],"roles":["*"],
	   "when":"resource.attributes.owner == principal.id"},
	  {"id":"members-read-versions","effect":"allow","actions":["read-units","discover"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`,
	"units.json": `{"format":"fga.policy/v1","set":"business","resource":"document.text_unit","scope":"","rules":[
	  {"id":"owner-units","effect":"allow","actions":["read","share","label","export-key"],"roles":["*"],
	   "when":"resource.attributes.owner == principal.id"},
	  {"id":"members-read-units-below-restricted","effect":"allow","actions":["read"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects && resource.attributes.label_rank < 3"}]}`,
	"ceiling.json": `{"format":"fga.policy/v1","set":"ceiling","resource":"crypto.recipient","scope":"","rules":[
	  {"id":"only-active-keys-receive","effect":"deny","actions":["receive-key"],"roles":["*"],
	   "when":"resource.attributes.status != \"ACTIVE\""}]}`,
}

// UserActions are the capabilities every fixture user gets (DLG-004).
var UserActions = map[string][]string{
	"storage.bucket": {"create-object", "list", "manage", "approve"},
	"storage.object": {"read", "stat", "discover", "read-history", "discover-history", "new-version", "delete", "delete-version", "share",
		"label", "relabel", "propose-label", "approve"},
	"crypto.envelope":    {"create", "release", "retire"},
	"document.version":   {"read-units", "raw-read", "discover", "share", "export"},
	"document.text_unit": {"read", "share", "label", "relabel", "propose-label", "export-key"},
	"crypto.recipient":   {"enroll", "activate", "receive-key", "revoke", "discover"},
	"crypto.signing-key": {"discover"},
}

// Stack is a running fixture.
type Stack struct {
	T          testing.TB
	Pool       *pgxpool.Pool
	Catalog    *catalog.Store
	Decisions  *decisionsvc.Service
	Fence      *fence.Fence
	Blobs      *blob.Store
	Content    *content.Service
	Issuer     *authn.Issuer
	Tokens     *authn.Verifier
	DecisionPK ed25519.PublicKey
	Clock      *time.Time
	// Envelopes is the keys role. Keys is the envelope delivery the content
	// service calls; it is Envelopes unless a test replaces it.
	Envelopes  *envelope.Service
	Keys       content.EnvelopeDelivery
	ReceiptKey ed25519.PublicKey
	// BeforeDecide, if set, runs before each decision the storage and keys
	// roles request (see Decider.Before).
	BeforeDecide func(decisionsvc.Request)
	// Journal is the security journal; BlobDir and JournalDir are the
	// directories of the blob store and the journal.
	Journal    *journal.Journal
	BlobDir    string
	JournalDir string
}

// Now is the fixture clock's start.
var Now = time.Now().UTC().Truncate(time.Second)

// Decider adapts the in-process decision service to content.Decider for
// one adapter.
type Decider struct {
	Service *decisionsvc.Service
	Adapter string
	// Before, if set, runs before each request is decided; tests use it to
	// interleave a concurrent change with an operation.
	Before *func(decisionsvc.Request)
}

// Decide implements content.Decider.
func (d Decider) Decide(ctx context.Context, req decisionsvc.Request) (decisionsvc.Response, error) {
	if d.Before != nil && *d.Before != nil {
		(*d.Before)(req)
	}
	return d.Service.Decide(ctx, d.Adapter, req), nil
}

type deliveryFunc func(ctx context.Context, decision signing.Signed, envelopeID string) (content.Delivered, error)

func (f deliveryFunc) Deliver(ctx context.Context, d signing.Signed, id string) (content.Delivered, error) {
	return f(ctx, d, id)
}

// Options change the fixture.
type Options struct {
	// Policies replaces the policy release; nil keeps Policies. A document
	// named ceiling*.json is in the ceiling set.
	Policies map[string]string
	// Start is the fixture clock's start; zero means Now.
	Start time.Time
	// FenceMargin is the fence's clock margin; nil means one second.
	FenceMargin *time.Duration
}

// New builds the stack.
func New(t testing.TB) *Stack { return NewWith(t, Options{}) }

// NewWith builds the stack with options.
func NewWith(t testing.TB, opts Options) *Stack {
	t.Helper()
	pool := pgtest.Pool(t, catalog.Migrate)
	ctx := context.Background()
	clock := Now
	if !opts.Start.IsZero() {
		clock = opts.Start
	}
	policies := Policies
	if opts.Policies != nil {
		policies = opts.Policies
	}
	margin := time.Second
	if opts.FenceMargin != nil {
		margin = *opts.FenceMargin
	}
	st := &Stack{T: t, Pool: pool, Catalog: catalog.New(pool, 10_000), Clock: &clock}
	now := func() time.Time { return *st.Clock }

	types := registry.R1Types()
	env := release.R1Environment()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	releases := release.NewManager(map[string]ed25519.PublicKey{"pub-1": pub}, env, st.Catalog, now)
	info := release.Info{Audience: release.AudienceDecision, CostLimit: engine.DefaultOptions.CostLimit, TestEvidence: "r1test",
		LabelOrder: LabelOrder, LabelGeneration: 1}
	env.Stamp(&info)
	b := release.Bundle{Epoch: 1, Info: info, Documents: map[string][]byte{}, CeilingDeclared: true, KeyID: "pub-1"}
	for name, doc := range policies {
		b.Documents[name] = []byte(doc)
		if strings.HasPrefix(name, "ceiling") {
			b.Ceiling = append(b.Ceiling, name)
		} else {
			b.Info.Business = append(b.Info.Business, name)
		}
	}
	digest, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = ed25519.Sign(priv, release.SigningBytes(1, digest))
	if err := releases.Activate(ctx, b); err != nil {
		t.Fatal(err)
	}
	pgtest.Exec(t, pool, `INSERT INTO tenant_epochs VALUES ('`+Tenant+`', 1)`)
	if err := st.Catalog.SetLabelOrder(ctx, 1, LabelOrder); err != nil {
		t.Fatal(err)
	}

	resolver := registry.NewResolver(st.Catalog.Resources(), types)
	g, err := gate.New(gate.Deps{Identities: st.Catalog.Identities(), Delegations: st.Catalog.Delegations(), Capabilities: st.Catalog,
		Resources: resolver, Epochs: st.Catalog, Recipients: st.Catalog, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	decider, err := decision.NewDecider(g, releases, now)
	if err != nil {
		t.Fatal(err)
	}
	decPub, decPriv, _ := ed25519.GenerateKey(rand.Reader)
	st.DecisionPK = decPub
	signer, err := signing.NewSigner("dec-1", decPriv)
	if err != nil {
		t.Fatal(err)
	}
	tokPub, tokPriv, _ := ed25519.GenerateKey(rand.Reader)
	if st.Issuer, err = authn.NewIssuer("fga-dev", "tok-1", tokPriv, now); err != nil {
		t.Fatal(err)
	}
	tokens := authn.NewVerifier("fga-dev", map[string]ed25519.PublicKey{"tok-1": tokPub}, now)
	st.Tokens = tokens
	st.Decisions, err = decisionsvc.New(decisionsvc.Deps{Decider: decider, Gate: g, Releases: releases, Resolver: resolver, Types: types,
		Operations: registry.R1Operations(types), Authority: st.Catalog, Signer: signer, Outbox: st.Catalog,
		Approvals: approval.New(pool, now),
		Audiences: []string{content.Audience, content.KeysAudience}, MaxAge: 30 * time.Second, Limits: decisionsvc.Limits{MaxChecks: 50, Deadline: 5 * time.Second},
		Now: now, Authn: tokens, AdapterAudiences: map[string][]string{StorageAdapter: {content.Audience}, "keys-1": {content.KeysAudience}}})
	if err != nil {
		t.Fatal(err)
	}
	st.Fence = fence.New(pool, margin, now)
	st.BlobDir, st.JournalDir = t.TempDir(), t.TempDir()
	if st.Blobs, err = blob.Open(st.BlobDir); err != nil {
		t.Fatal(err)
	}
	if st.Journal, err = journal.Open(st.JournalDir, now); err != nil {
		t.Fatal(err)
	}
	tokenKey := make([]byte, 32)
	_, _ = rand.Read(tokenKey)
	st.Content, err = content.New(content.Deps{Catalog: st.Catalog, Blobs: st.Blobs, Fence: st.Fence,
		Decider: Decider{Service: st.Decisions, Adapter: StorageAdapter, Before: &st.BeforeDecide}, Verifier: st.Verifier(content.Audience),
		Keys: deliveryFunc(func(ctx context.Context, d signing.Signed, id string) (content.Delivered, error) {
			return st.Keys.Deliver(ctx, d, id)
		}), TokenKey: tokenKey, Limits: limits(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	receiptPub, receiptPriv, _ := ed25519.GenerateKey(rand.Reader)
	st.ReceiptKey = receiptPub
	st.Envelopes, err = envelope.New(envelope.Deps{Catalog: st.Catalog, Fence: st.Fence, Decider: Decider{Service: st.Decisions, Adapter: "keys-1", Before: &st.BeforeDecide},
		Verifier: st.Verifier(content.KeysAudience), ReceiptKeyID: "receipt-1", ReceiptKey: receiptPriv, Journal: st.Journal, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	st.Keys = st.Envelopes
	return st
}

// Verifier returns a decision verifier for audience.
func (st *Stack) Verifier(audience string) *signing.Verifier {
	keys := func() map[string]signing.Key {
		return map[string]signing.Key{"dec-1": {Public: st.DecisionPK, NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}}
	}
	return signing.NewVerifier(audience, keys, signing.NewMemoryConsumption(), func() time.Time { return *st.Clock })
}

// User creates an identity with the fixture capabilities and returns its
// caller with a fresh token for the storage audience.
func (st *Stack) User(id string, roles []string, projects ...string) content.Caller {
	st.T.Helper()
	ctx := context.Background()
	if projects == nil {
		projects = []string{}
	}
	if err := st.Catalog.PutIdentity(ctx, Tenant, id, roles, map[string]any{"projects": projects}, nil); err != nil {
		st.T.Fatal(err)
	}
	if err := st.Catalog.GrantCapabilities(ctx, Tenant, id, UserActions); err != nil {
		st.T.Fatal(err)
	}
	return st.Caller(id)
}

// Caller returns a caller for an existing identity with a fresh token for
// the storage role.
func (st *Stack) Caller(id string) content.Caller { return st.CallerFor(id, content.Audience) }

// KeysCaller returns a caller with a fresh token for the keys role.
func (st *Stack) KeysCaller(id string) content.Caller { return st.CallerFor(id, content.KeysAudience) }

// CallerFor returns a caller with a fresh token for audience.
func (st *Stack) CallerFor(id, audience string) content.Caller {
	st.T.Helper()
	tok, err := st.Issuer.Issue(id, Tenant, audience, 30*time.Minute)
	if err != nil {
		st.T.Fatal(err)
	}
	return content.Caller{Tenant: Tenant, Principal: id, Token: tok}
}

// Bucket creates a bucket of project with label "internal".
func (st *Stack) Bucket(name, project string) { st.LabeledBucket(name, project, "internal") }

// LabeledBucket creates a bucket of project whose objects get label.
func (st *Stack) LabeledBucket(name, project, label string) {
	st.T.Helper()
	if _, err := st.Catalog.CreateBucket(context.Background(), Tenant, catalog.Bucket{Name: name, Project: project, Label: label}); err != nil {
		st.T.Fatal(err)
	}
}

// LeaseCheckEvery is the stream-lease recheck interval of the fixture,
// shorter than production's so tests run quickly.
var LeaseCheckEvery = 200 * time.Millisecond

func limits() content.Limits {
	l := content.DefaultLimits
	l.LeaseCheckEvery = LeaseCheckEvery
	return l
}
