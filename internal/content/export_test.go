package content_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/enforce"
	"fga/internal/r1test"
	"fga/internal/registry"
	"fga/sdk/go/crypto"
)

// exportFixture publishes alice's three-unit document (unit 1 labelled
// confidential) to alice and bob under policies.
func exportFixture(t *testing.T, policies map[string]string) (*r1test.Stack, *r1test.Client, *r1test.Client, []string) {
	t.Helper()
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "q3.md", paragraphs(3),
		[]content.DocumentUnitSpec{{}, {Label: "confidential"}, {}}, nil, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	var units []string
	for _, u := range up.Intent.Units {
		units = append(units, u.Unit)
	}
	return st, alice, bob, units
}

func edited(edits map[string][2]string) map[string]string {
	p := map[string]string{}
	for k, v := range r1test.Policies {
		p[k] = v
	}
	for doc, e := range edits {
		p[doc] = strings.Replace(p[doc], e[0], e[1], 1)
	}
	return p
}

// TestExport covers the encrypted remote export: the package carries the
// units' exact ciphertext and the target's existing envelopes, which the
// target opens with its own key.
func TestExport(t *testing.T) {
	st, alice, bob, units := exportFixture(t, nil)
	x, err := st.Content.ExportUnits(ctx, alice.Caller, "reports", "q3.md", "", []string{units[2], units[0]}, bob.Recipient.Fingerprint().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Units) != 2 || x.Units[0].Unit.Unit != units[0] {
		t.Fatalf("export = %+v", x)
	}
	for i, u := range x.Units {
		var out bytes.Buffer
		_, err := crypto.DecryptUnit(&out, bytes.NewReader(u.Ciphertext), crypto.UnitPackage{Descriptor: u.Unit.Descriptor,
			DescriptorSignature: u.Unit.DescriptorSignature,
			Envelope:            crypto.Envelope{Context: u.Envelope.Context, Ciphertext: u.Envelope.Ciphertext, Signature: u.Envelope.Signature}},
			bob.Recipient, bob.Trust)
		if err != nil || !strings.HasPrefix(out.String(), "Paragraph") {
			t.Fatalf("bob opens exported unit %d: %q, %v", i, out.String(), err)
		}
	}
	carol := st.Client("carol", []string{"member"}, "p1")
	if _, err := st.Content.ExportUnits(ctx, alice.Caller, "reports", "q3.md", "", units[:1], carol.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("export to a target without an envelope: %v", err)
	}
}

// TestExportNeedsEveryCheck covers V-132 to V-135: with any one required
// check denied, and all others allowed, the export is denied.
func TestExportNeedsEveryCheck(t *testing.T) {
	cases := map[string]struct {
		edits  map[string][2]string
		revoke bool
	}{
		"V-132 parent export": {edits: map[string][2]string{"documents.json": {`"share","export"]`, `"share"]`}}},
		"V-133 export-key on a unit": {edits: map[string][2]string{"units.json": {`"rules":[`, `"rules":[
		  {"id":"no-confidential-export","effect":"deny","actions":["export-key"],"roles":["*"],"when":"resource.attributes.label == \"confidential\""},`}}},
		"V-134 receive-key": {revoke: true},
		"V-135 release of an envelope": {edits: map[string][2]string{"envelopes.json": {
			`"id":"owner-releases-for-export","effect":"allow","actions":["release"]`, `"id":"owner-releases-for-export","effect":"allow","actions":["retire"]`}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st, alice, bob, units := exportFixture(t, edited(tc.edits))
			if tc.revoke {
				if err := st.Catalog.RevokeRecipientKey(ctx, r1test.Tenant, bob.Recipient.Fingerprint().String()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.Content.ExportUnits(ctx, alice.Caller, "reports", "q3.md", "", units, bob.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
				t.Fatalf("export: %v, want a denial", err)
			}
		})
	}
}

// TestExportDecisionMustBeComplete covers V-136: a request for the export
// envelope operation without the receive-key check is refused by the
// decision role, and a validly signed decision of another operation is
// refused by the keys role.
func TestExportDecisionMustBeComplete(t *testing.T) {
	st, alice, bob, units := exportFixture(t, nil)
	d := r1test.Decider{Service: st.Decisions, Adapter: r1test.StorageAdapter}
	fp := bob.Recipient.Fingerprint().String()
	version := enforce.Check{ID: "version", Role: registry.RoleVersion, Action: "export"}
	var dv string
	if err := st.Pool.QueryRow(ctx, `SELECT current_document_version::text FROM objects WHERE key = 'q3.md'`).Scan(&dv); err != nil {
		t.Fatal(err)
	}
	version.Resource.Type, version.Resource.ID = "document.version", dv
	partial := []enforce.Check{version}
	if _, _, err := enforce.Authorize(ctx, d, st.Verifier(content.KeysAudience), st.Catalog, alice.Caller, registry.OpDocExportEnvelope,
		content.KeysAudience, true, partial); !errors.Is(err, enforce.ErrNotFound) {
		t.Fatalf("an incomplete export decision was issued: %v", err)
	}
	unitRead := enforce.Check{ID: "unit-0", Role: registry.RoleUnit, Action: "read"}
	unitRead.Resource.Type, unitRead.Resource.ID = "document.text_unit", units[0]
	var unitVersion, envelopeID string
	if err := st.Pool.QueryRow(ctx, `SELECT unit_version::text FROM document_units WHERE unit::text = $1`, units[0]).Scan(&unitVersion); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT id::text FROM envelopes WHERE version::text = $1 AND recipient = $2`, unitVersion, fp).Scan(&envelopeID); err != nil {
		t.Fatal(err)
	}
	unitRead.Version = unitVersion
	readUnits := enforce.Check{ID: "version", Role: registry.RoleVersion, Action: "read-units"}
	readUnits.Resource.Type, readUnits.Resource.ID = "document.version", dv
	signed, _, err := enforce.Authorize(ctx, d, st.Verifier(content.KeysAudience), st.Catalog, alice.Caller, registry.OpDocSelectUnits,
		content.KeysAudience, true, []enforce.Check{readUnits, unitRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Envelopes.Deliver(ctx, signed, envelopeID); err == nil {
		t.Fatalf("the keys role released an envelope on a %s decision", registry.OpDocSelectUnits)
	}
}

// TestSearchDocuments covers SRH-001, SRH-004 and V-070: of 20 candidate
// documents, 5 are not discoverable for bob; his results are the other 15
// in key order, across pages, with no total, and the continuation is
// bound to him. Filters use catalog metadata only.
func TestSearchDocuments(t *testing.T) {
	st := r1test.NewWith(t, r1test.Options{Policies: edited(map[string][2]string{"documents.json": {
		`"actions":["read-units","discover"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"`,
		`"actions":["read-units","discover"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects && resource.attributes.owner != \"zed\""`}})})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	zed := st.Client("zed", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	var want []string
	for i := 0; i < 20; i++ {
		owner, key := alice, fmt.Sprintf("notes/%02d.md", i)
		if i%4 == 3 {
			owner = zed
		} else {
			want = append(want, key)
		}
		up, err := owner.PrepareDocument("reports", key, []string{"x"}, nil, owner)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.FinalizeDocument(up); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	cont := ""
	for {
		page, err := st.Content.SearchDocuments(ctx, bob.Caller, "reports", content.SearchQuery{Prefix: "notes/"}, 6, cont)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Results {
			got = append(got, r.Key)
		}
		if page.Continuation == "" {
			break
		}
		if _, err := st.Content.SearchDocuments(ctx, alice.Caller, "reports", content.SearchQuery{Prefix: "notes/"}, 6, page.Continuation); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("another caller used the continuation: %v", err)
		}
		cont = page.Continuation
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("results = %v, want %v", got, want)
	}
	for q, n := range map[content.SearchQuery]int{
		{Prefix: "notes/0"}:      8,
		{Project: "p2"}:          0,
		{MaxLabel: "public"}:     0,
		{MaxLabel: "restricted"}: 15,
	} {
		page, err := st.Content.SearchDocuments(ctx, bob.Caller, "reports", q, 100, "")
		if err != nil || len(page.Results) != n {
			t.Errorf("search %+v = %d results, %v; want %d", q, len(page.Results), err, n)
		}
	}
	if _, err := st.Content.SearchDocuments(ctx, bob.Caller, "reports", content.SearchQuery{MaxLabel: "secret"}, 10, ""); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("search with an unknown label: %v", err)
	}
}

// TestObjectExport covers export of a whole object version: export and
// read for the caller (read-history for an older version), and the
// target's existing envelope released only against the full check set.
func TestObjectExport(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	carol := st.Client("carol", []string{"member"}, "p1")
	alice.Pin(bob)
	bob.Pin(alice)
	v1, err := alice.Put("reports", "doc", []byte("version one"), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Put("reports", "doc", []byte("version two"), alice, bob); err != nil {
		t.Fatal(err)
	}
	open := func(x content.ObjectExport) string {
		var out bytes.Buffer
		err := crypto.Decrypt(&out, bytes.NewReader(x.Ciphertext), crypto.Package{Descriptor: x.Descriptor, DescriptorSignature: x.DescriptorSignature,
			Envelope: crypto.Envelope{Context: x.Envelope.Context, Ciphertext: x.Envelope.Ciphertext, Signature: x.Envelope.Signature}},
			bob.Recipient, bob.Trust)
		if err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	fp := bob.Recipient.Fingerprint().String()
	x, err := st.Content.ExportObject(ctx, alice.Caller, "reports", "doc", "", fp)
	if err != nil || open(x) != "version two" || !x.Version.Current {
		t.Fatalf("export of the current version: %v", err)
	}
	if x, err := st.Content.ExportObject(ctx, alice.Caller, "reports", "doc", v1.Version, fp); err != nil || open(x) != "version one" {
		t.Fatalf("export of a historical version: %v", err)
	}
	if _, err := st.Content.ExportObject(ctx, bob.Caller, "reports", "doc", "", fp); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("export by a member without export: %v", err)
	}
	if _, err := st.Content.ExportObject(ctx, alice.Caller, "reports", "doc", "", carol.Recipient.Fingerprint().String()); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("export to a target without an envelope: %v", err)
	}
}

// TestExportSizeAfterAuthorization covers review v5 F07: an export larger
// than one package is refused as too large only to a caller allowed to
// export it. To anyone else it is not found, as a key that does not exist
// is, so its size class tells nothing.
func TestExportSizeAfterAuthorization(t *testing.T) {
	st := r1test.New(t)
	st.Bucket("reports", "p1")
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	if _, err := alice.Put("reports", "doc", []byte("large"), alice); err != nil {
		t.Fatal(err)
	}
	up, err := alice.PrepareDocument("reports", "q3.md", paragraphs(2), nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.PutDocumentText(ctx, alice.Caller, content.TextRequest{Bucket: "vault", Key: "report.md", IdempotencyKey: "t1"},
		[]byte("Summary.\n\nDetails.\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE object_versions SET ciphertext_length = $1`, content.MaxExportBytes+1); err != nil {
		t.Fatal(err)
	}
	fp := alice.Recipient.Fingerprint().String()
	docUnits := st.UnitIDs(alice.Caller, "reports", "q3.md", "")
	vaultUnits := st.UnitIDs(alice.Caller, "vault", "report.md", "")
	for name, export := range map[string]func(c content.Caller, key string) error{
		"object": func(c content.Caller, key string) error {
			_, err := st.Content.ExportObject(ctx, c, "reports", key, "", fp)
			return err
		},
		"units": func(c content.Caller, key string) error {
			_, err := st.Content.ExportUnits(ctx, c, "reports", key, "", docUnits, fp)
			return err
		},
		"plain units": func(c content.Caller, key string) error {
			_, err := st.Content.ExportUnitsPlain(ctx, c, "vault", key, "", vaultUnits)
			return err
		},
	} {
		key := map[string]string{"object": "doc", "units": "q3.md", "plain units": "report.md"}[name]
		if err := export(bob.Caller, key); !errors.Is(err, content.ErrNotFound) {
			t.Errorf("%s: a caller without export: %v, want not found", name, err)
		}
		if err := export(bob.Caller, "missing"); !errors.Is(err, content.ErrNotFound) {
			t.Errorf("%s: a missing key: %v", name, err)
		}
		if err := export(alice.Caller, key); !errors.Is(err, content.ErrTooLarge) {
			t.Errorf("%s: the owner: %v, want too large", name, err)
		}
	}
}
