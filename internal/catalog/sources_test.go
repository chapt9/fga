package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func (j *recordingJournal) sourceJournal() Journal {
	jj := j.journal()
	jj.SourceSetKind, jj.SourceDisabledKind = "source-set", "source-disabled"
	return jj
}

func (j *recordingJournal) sourceState(t *testing.T, i int) SourceState {
	t.Helper()
	var st SourceState
	if err := json.Unmarshal([]byte(j.subjects[i]), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

var climateBucket = Bucket{Name: "climate", Project: "p1", Label: "internal", Encryption: "server"}

// definition stands for a stored record, which the catalog does not read.
func definition(n int) ([]byte, string) {
	raw, _ := json.Marshal(map[string]any{"format": "fga.source/v1", "n": n})
	return raw, "digest-" + string(rune('0'+n))
}

func createSource(t *testing.T, s *Store, j Journal) {
	t.Helper()
	ctx := context.Background()
	raw, digest := definition(1)
	if err := s.Administer(ctx, adminEvent(), j, func(a *Admin) error {
		_, err := a.CreateSource(ctx, "t-acme", climateBucket, "greenhouse", raw, digest, "root", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSourceLifecycle covers ING-001 and ING-008: a source is created
// with its bucket, which names it; a new version supersedes an unreviewed
// draft; only the draft with the digest its reviewer saw is reviewed, and
// not by its author; a review and a disable are journaled first, an
// unknown source or a second disable not at all, and a disabled source
// takes no change.
func TestSourceLifecycle(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	var j recordingJournal
	admin := func(change func(a *Admin) error) error {
		return s.Administer(ctx, adminEvent(), j.sourceJournal(), change)
	}
	createSource(t, s, j.sourceJournal())

	var attrs map[string]any
	if err := s.pool.QueryRow(ctx, `SELECT r.attributes FROM buckets b JOIN resources r ON r.tenant = b.tenant AND r.id = b.id::text
	                                 WHERE b.tenant = 't-acme' AND b.name = 'climate' AND b.source = 'greenhouse'`).Scan(&attrs); err != nil {
		t.Fatal(err)
	}
	if attrs["source"] != "greenhouse" || attrs["project"] != "p1" {
		t.Fatalf("bucket attributes %v", attrs)
	}
	if bs, err := s.ListBuckets(ctx, "t-acme", "", 10); err != nil || len(bs) != 1 || bs[0].Source != "greenhouse" {
		t.Fatalf("buckets %+v %v", bs, err)
	}
	src, err := s.Source(ctx, "t-acme", "greenhouse")
	if err != nil || src.Bucket != "climate" || src.Encryption != "server" || src.Active != nil || src.Draft == nil || src.Draft.Version != 1 {
		t.Fatalf("source %+v %v", src, err)
	}

	raw2, digest2 := definition(2)
	var version int
	if err := admin(func(a *Admin) error {
		version, err = a.PutSourceDraft(ctx, "t-acme", "greenhouse", raw2, digest2, "root", now)
		return err
	}); err != nil || version != 2 {
		t.Fatalf("put = %d, %v", version, err)
	}
	if v1, err := s.SourceVersion(ctx, "t-acme", "greenhouse", 1); err != nil || v1.State != "SUPERSEDED" {
		t.Fatalf("version 1 %+v %v", v1, err)
	}
	review := func(version int, digest, reviewer string, allowSelf bool) error {
		return admin(func(a *Admin) error {
			_, err := a.ReviewSource(ctx, "t-acme", "greenhouse", version, digest, reviewer, allowSelf, now)
			return err
		})
	}
	_, digest1 := definition(1)
	for name, c := range map[string]struct {
		version  int
		digest   string
		reviewer string
		want     error
	}{
		"a superseded draft":   {1, digest1, "rita", ErrSourceConflict},
		"another digest":       {2, digest1, "rita", ErrSourceConflict},
		"an unknown version":   {7, digest2, "rita", ErrSourceConflict},
		"the draft's author":   {2, digest2, "root", ErrSelfReview},
		"an unknown source ID": {2, digest2, "rita", nil},
	} {
		if name == "an unknown source ID" {
			if err := admin(func(a *Admin) error {
				_, err := a.ReviewSource(ctx, "t-acme", "orchard", 2, digest2, "rita", false, now)
				return err
			}); !errors.Is(err, ErrNoRow) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err := review(c.version, c.digest, c.reviewer, false); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if len(j.kinds) != 0 {
		t.Fatalf("a refused review journaled %v", j.kinds)
	}
	if err := review(2, digest2, "rita", false); err != nil {
		t.Fatal(err)
	}
	want := SourceState{Source: "greenhouse", Version: 2, Digest: digest2, Definition: raw2, Author: "root", Reviewer: "rita"}
	if len(j.kinds) != 1 || j.kinds[0] != "source-set" || !reflect.DeepEqual(j.sourceState(t, 0), want) {
		t.Fatalf("journal %v %v", j.kinds, j.subjects)
	}
	// The local administrator may review its own draft.
	raw3, digest3 := definition(3)
	if err := admin(func(a *Admin) error {
		_, err := a.PutSourceDraft(ctx, "t-acme", "greenhouse", raw3, digest3, "operator", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := review(3, digest3, "operator", true); err != nil {
		t.Fatal(err)
	}
	src, err = s.Source(ctx, "t-acme", "greenhouse")
	if err != nil || src.Active == nil || src.Active.Version != 3 || src.Active.Reviewer != "operator" || src.Draft != nil {
		t.Fatalf("after the reviews %+v %v", src, err)
	}
	if v2, _ := s.SourceVersion(ctx, "t-acme", "greenhouse", 2); v2.State != "SUPERSEDED" {
		t.Fatalf("version 2 is %s", v2.State)
	}

	for range 2 {
		if err := admin(func(a *Admin) error { return a.DisableSource(ctx, "t-acme", "greenhouse") }); err != nil {
			t.Fatal(err)
		}
	}
	if err := admin(func(a *Admin) error { return a.DisableSource(ctx, "t-acme", "orchard") }); !errors.Is(err, ErrNoRow) {
		t.Fatalf("disable an unknown source: %v", err)
	}
	if len(j.kinds) != 3 || j.kinds[2] != "source-disabled" || j.subjects[2] != "greenhouse" {
		t.Fatalf("journal %v %v", j.kinds, j.subjects)
	}
	if err := admin(func(a *Admin) error {
		_, err := a.PutSourceDraft(ctx, "t-acme", "greenhouse", raw3, digest3, "root", now)
		return err
	}); !errors.Is(err, ErrSourceDisabled) {
		t.Fatalf("a draft for a disabled source: %v", err)
	}
	if list, err := s.ListSources(ctx, "t-acme", "", 10); err != nil || len(list) != 1 || !list[0].Disabled || list[0].Active.Version != 3 {
		t.Fatalf("sources %+v %v", list, err)
	}
}

// TestFailedReviewRestatesSource: a review that journaled a version and
// then does not commit journals the source's committed state after it, so
// a restore does not activate a version no review made active.
func TestFailedReviewRestatesSource(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	var j recordingJournal
	createSource(t, s, j.sourceJournal())
	raw1, digest1 := definition(1)
	failed := errors.New("a later step failed")
	review := func(version int, digest string, fail bool) error {
		return s.Administer(ctx, adminEvent(), j.sourceJournal(), func(a *Admin) error {
			if _, err := a.ReviewSource(ctx, "t-acme", "greenhouse", version, digest, "rita", false, now); err != nil || !fail {
				return err
			}
			return failed
		})
	}
	if err := review(1, digest1, true); !errors.Is(err, failed) {
		t.Fatalf("a failed review: %v", err)
	}
	if err := review(1, digest1, false); err != nil {
		t.Fatal(err)
	}
	raw2, digest2 := definition(2)
	if err := s.Administer(ctx, adminEvent(), j.sourceJournal(), func(a *Admin) error {
		_, err := a.PutSourceDraft(ctx, "t-acme", "greenhouse", raw2, digest2, "root", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := review(2, digest2, true); !errors.Is(err, failed) {
		t.Fatalf("a failed review: %v", err)
	}
	v1 := SourceState{Source: "greenhouse", Version: 1, Digest: digest1, Definition: raw1, Author: "root", Reviewer: "rita"}
	want := []SourceState{
		v1, {Source: "greenhouse"}, // the failed review, then no version active
		v1, // the review that committed
		{Source: "greenhouse", Version: 2, Digest: digest2, Definition: raw2, Author: "root", Reviewer: "rita"}, v1,
	}
	if len(j.subjects) != len(want) {
		t.Fatalf("journal %v %v", j.kinds, j.subjects)
	}
	for i, w := range want {
		if got := j.sourceState(t, i); j.kinds[i] != "source-set" || !reflect.DeepEqual(got, w) {
			t.Fatalf("entry %d = %s %+v, want %+v", i, j.kinds[i], got, w)
		}
	}
	if src, err := s.Source(ctx, "t-acme", "greenhouse"); err != nil || src.Active.Version != 1 || src.Draft.Version != 2 {
		t.Fatalf("source %+v %v", src, err)
	}
}

// TestApplySourceState: reconcile makes a journaled version active,
// writing it from the entry when the catalog lacks it or holds other
// bytes, clears the active version for version 0, and leaves a source the
// catalog does not hold unknown.
func TestApplySourceState(t *testing.T) {
	s, ctx := adminStore(t), context.Background()
	var j recordingJournal
	createSource(t, s, j.sourceJournal())
	raw1, digest1 := definition(1)
	raw2, digest2 := definition(2)
	apply := func(st SourceState) {
		t.Helper()
		if err := s.ApplySourceState(ctx, "t-acme", st); err != nil {
			t.Fatal(err)
		}
	}
	active := func() *SourceVersion {
		t.Helper()
		src, err := s.Source(ctx, "t-acme", "greenhouse")
		if err != nil {
			t.Fatal(err)
		}
		return src.Active
	}
	// The draft the entry reviewed becomes active.
	apply(SourceState{Source: "greenhouse", Version: 1, Digest: digest1, Definition: raw1, Author: "root", Reviewer: "rita"})
	if v := active(); v == nil || v.Version != 1 || v.Reviewer != "rita" {
		t.Fatalf("active %+v", v)
	}
	// A version reviewed after the backup is written from the entry.
	apply(SourceState{Source: "greenhouse", Version: 2, Digest: digest2, Definition: raw2, Author: "root", Reviewer: "rita"})
	if v := active(); v == nil || v.Version != 2 || v.Digest != digest2 || string(v.Definition) != string(raw2) {
		t.Fatalf("active %+v", v)
	}
	if v1, _ := s.SourceVersion(ctx, "t-acme", "greenhouse", 1); v1.State != "SUPERSEDED" {
		t.Fatalf("version 1 is %s", v1.State)
	}
	// Version 1 with other bytes than the catalog holds takes the entry's.
	apply(SourceState{Source: "greenhouse", Version: 1, Digest: digest2, Definition: raw2, Author: "root", Reviewer: "rita"})
	if v := active(); v == nil || v.Version != 1 || v.Digest != digest2 {
		t.Fatalf("active %+v", v)
	}
	apply(SourceState{Source: "greenhouse"})
	if v := active(); v != nil {
		t.Fatalf("active after version 0: %+v", v)
	}
	apply(SourceState{Source: "orchard", Version: 1, Digest: digest1, Definition: raw1})
	if _, err := s.Source(ctx, "t-acme", "orchard"); !errors.Is(err, ErrNoRow) {
		t.Fatalf("a source created after the backup: %v", err)
	}
}
