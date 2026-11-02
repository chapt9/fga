package content_test

import (
	"errors"
	"maps"
	"testing"

	"fga/internal/content"
	"fga/internal/cryptowire"
	"fga/internal/r1test"
)

// TestServerPublishNeedsSealedKey covers audit note M-3: a staged
// server-mode upload whose intent holds no sealed data key is refused as a
// conflict at publication, with no version published and no head moved,
// rather than failing later on a constraint.
func TestServerPublishNeedsSealedKey(t *testing.T) {
	policies := maps.Clone(r1test.Policies)
	policies["buckets.json"] = `{"format":"fga.policy/v1","set":"business","resource":"storage.bucket","scope":"","rules":[
	  {"id":"members-use-bucket","effect":"allow","actions":["list"],"roles":["member"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"members-create-with-approval","effect":"allow","actions":["create-object"],"roles":["member"],"requires":["approval"],
	   "when":"resource.attributes.project in principal.attributes.projects"},
	  {"id":"leads-approve-buckets","effect":"allow","actions":["approve"],"roles":["lead"],
	   "when":"resource.attributes.project in principal.attributes.projects"}]}`
	st := r1test.NewWith(t, r1test.Options{Policies: policies})
	st.ModeBucket("vault", "p1", "internal", "server")
	alice := st.Client("alice", []string{"member"}, "p1")
	lena := st.User("lena", []string{"lead"}, "p1")
	_, err := putPlain(st, alice.Caller, "vault", "a.txt", "a", []byte("a"))
	var staged *content.StagedApproval
	if !errors.As(err, &staged) {
		t.Fatalf("publication without approval: %v", err)
	}
	if _, err := st.Content.DecideApproval(ctx, lena, staged.ID, true); err != nil {
		t.Fatal(err)
	}
	intent, err := cryptowire.ParseUUID(staged.Intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE upload_intents SET sealed_key = NULL, kek_version = NULL WHERE tenant = $1 AND id = $2`,
		r1test.Tenant, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Content.Finalize(ctx, withApproval(alice.Caller, staged.ID), intent, content.FinalizeRequest{}); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("publication without a sealed key: %v", err)
	}
	if n := st.Count(`SELECT count(*) FROM object_versions`); n != 0 {
		t.Fatalf("%d versions published without a sealed key", n)
	}
	if n := st.Count(`SELECT count(*) FROM objects WHERE current_version IS NOT NULL`); n != 0 {
		t.Fatal("a head moved to a version that does not exist")
	}
}
