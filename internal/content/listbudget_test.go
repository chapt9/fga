package content_test

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"fga/internal/content"
	"fga/internal/decisionsvc"
	"fga/internal/r1test"
)

// TestListingBoundsSingleChecks is the regression test of the security
// review of 4 November 2026, finding 2: after a denied batch, a listing
// decides at most ListSingleChecks checks one by one per request, then
// ends the page with a continuation, so one request cannot cost the
// decision role thousands of decisions. Members here discover nothing of
// others' objects and read no restricted unit.
func TestListingBoundsSingleChecks(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["objects.json"] = strings.Replace(policies["objects.json"],
		`{"id":"members-read","effect":"allow","actions":["read","stat","discover"],"roles":["member"],`,
		`{"id":"members-read","effect":"allow","actions":["read","stat"],"roles":["member"],`, 1)
	if !strings.Contains(policies["objects.json"], `"actions":["read","stat"],"roles":["member"]`) {
		t.Fatal("the fixture policy changed; members still discover others' objects")
	}
	limits := content.DefaultLimits
	limits.ListSingleChecks, limits.LeaseCheckEvery = 3, r1test.LeaseCheckEvery
	st := r1test.NewWith(t, r1test.Options{Policies: policies, Limits: &limits})
	st.Bucket("reports", "p1")
	alice := st.Client("alice", []string{"member"}, "p1")
	bob := st.Client("bob", []string{"member"}, "p1")
	for i := range 7 {
		if _, err := alice.Put("reports", fmt.Sprintf("a-%d", i), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bob.Put("reports", "z-bob", []byte("y")); err != nil {
		t.Fatal(err)
	}
	specs := make([]content.DocumentUnitSpec, 5)
	for i := range specs {
		specs[i].Label = "restricted"
	}
	up, err := alice.PrepareDocumentSpecs(ctx, "reports", "q3.md", []string{"a", "b", "c", "d", "e"}, specs, nil, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.FinalizeDocument(up); err != nil {
		t.Fatal(err)
	}
	decisions := 0
	st.BeforeDecide = func(decisionsvc.Request) { decisions++ }

	// Objects: the first page decides the bucket's list, one denied batch
	// of eight and three single checks, then ends with a continuation;
	// following the continuations ends with bob's own object.
	page, err := st.Content.List(ctx, bob.Caller, "reports", "", 10, "")
	if err != nil || len(page.Entries) != 0 || page.Continuation == "" {
		t.Fatalf("first page = %+v, %v", page, err)
	}
	if decisions > 5 {
		t.Fatalf("%d decisions for the first page, want at most 5", decisions)
	}
	var keys []string
	for cont, pages := page.Continuation, 1; cont != ""; pages++ {
		if pages > 10 {
			t.Fatal("the listing does not end")
		}
		next, err := st.Content.List(ctx, bob.Caller, "reports", "", 10, cont)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range next.Entries {
			keys = append(keys, e.Key)
		}
		cont = next.Continuation
	}
	if len(keys) != 1 || keys[0] != "z-bob" {
		t.Fatalf("listed %v, want only bob's object", keys)
	}

	// Units: the same bound, the page ending before the fourth single check.
	decisions = 0
	units, err := st.Content.ListUnits(ctx, bob.Caller, "reports", "q3.md", "", 10, "")
	if err != nil || len(units.Units) != 0 || units.Continuation == "" {
		t.Fatalf("first unit page = %+v, %v", units, err)
	}
	if decisions > 5 {
		t.Fatalf("%d decisions for the first unit page, want at most 5", decisions)
	}
	for cont, pages := units.Continuation, 1; cont != ""; pages++ {
		if pages > 10 {
			t.Fatal("the unit listing does not end")
		}
		next, err := st.Content.ListUnits(ctx, bob.Caller, "reports", "q3.md", "", 10, cont)
		if err != nil || len(next.Units) != 0 {
			t.Fatalf("unit page %d = %+v, %v", pages, next, err)
		}
		cont = next.Continuation
	}
}
