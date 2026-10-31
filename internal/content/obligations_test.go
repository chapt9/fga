package content_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/r1test"
	"fga/internal/release"
	"fga/internal/signing"
)

// TestMetadataProjection covers POL-011 and APR-007 at the storage role:
// with a release that maps a projection output, a stat shows only the
// fields the policy's projection names, and an obligation the role cannot
// apply (a projection on a read) makes the operation fail closed. Without
// the mapping, the same outputs are data and change nothing.
func TestMetadataProjection(t *testing.T) {
	projected := func(rule string) map[string]string {
		policies := maps.Clone(r1test.Policies)
		policies["objects.json"] = strings.Replace(policies["objects.json"], `"rules":[`, `"rules":[`+rule+`,`, 1)
		return policies
	}
	mapping := &release.ObligationMapping{Version: signing.ObligationsV1, Outputs: map[string]string{"projection": signing.MetadataProjection}}
	statRule := `{"id":"members-stat-projected","effect":"allow","actions":["stat"],"roles":["member"],
	  "when":"resource.attributes.project in principal.attributes.projects","outputs":{"projection":["version_id","etag"]}}`
	setup := func(t *testing.T, opts r1test.Options) (*r1test.Stack, content.Caller) {
		st := r1test.NewWith(t, opts)
		st.ModeBucket("vault", "p1", "internal", "server")
		alice := st.Client("alice", []string{"member"}, "p1")
		bob := st.Client("bob", []string{"member"}, "p1")
		if _, err := putPlain(st, alice.Caller, "vault", "a.txt", "a", []byte("hello")); err != nil {
			t.Fatal(err)
		}
		return st, bob.Caller
	}

	t.Run("projected", func(t *testing.T) {
		st, bob := setup(t, r1test.Options{Policies: projected(statRule), ObligationMapping: mapping})
		info, err := st.Content.Stat(ctx, bob, "vault", "a.txt", "")
		if err != nil || !slices.Equal(info.Projection, []string{"etag", "version_id"}) {
			t.Fatalf("stat: %+v %v", info, err)
		}
		wire, ok := info.Wire().(map[string]any)
		if !ok || len(wire) != 2 || wire["version_id"] != info.Version || wire["etag"] != info.ETag {
			t.Fatalf("the response shows %v", info.Wire())
		}
	})
	t.Run("unmapped outputs are data", func(t *testing.T) {
		st, bob := setup(t, r1test.Options{Policies: projected(statRule)})
		if info, err := st.Content.Stat(ctx, bob, "vault", "a.txt", ""); err != nil || info.Projection != nil {
			t.Fatalf("stat without a mapping: %+v %v", info, err)
		}
	})
	t.Run("an obligation the role cannot apply", func(t *testing.T) {
		readRule := `{"id":"members-read-projected","effect":"allow","actions":["read"],"roles":["member"],
		  "when":"resource.attributes.project in principal.attributes.projects","outputs":{"projection":["version_id"]}}`
		st, bob := setup(t, r1test.Options{Policies: projected(readRule), ObligationMapping: mapping})
		if _, _, err := readPlain(st, bob, "vault", "a.txt", ""); err == nil {
			t.Fatal("a read carrying a projection the storage role cannot apply succeeded")
		}
	})
}
