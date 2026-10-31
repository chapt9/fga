//go:build unix

package kek

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestLockSerializesRotations is the regression test of review v3 F07:
// rotations read, changed and replaced the shared ring file without a
// lock, so two rotations of one tenant could write different keys for the
// same version, and rotations of different tenants could lose each other's
// versions. Under Lock, concurrent read-modify-write rounds of several
// tenants lose nothing.
func TestLockSerializesRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keks")
	if err := WriteRing(path, NewRing(), nil); err != nil {
		t.Fatal(err)
	}
	const writers, rounds = 6, 5
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tenant := []string{"t-a", "t-b"}[w%2]
			for range rounds {
				unlock, err := Lock(path)
				if err != nil {
					t.Error(err)
					return
				}
				r, err := ReadRing(path, nil)
				if err == nil {
					_, err = r.Add(tenant, time.Now())
				}
				if err == nil {
					err = WriteRing(path, r, nil)
				}
				unlock()
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	r, err := ReadRing(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"t-a", "t-b"} {
		if got, want := len(r.Versions(tenant)), writers/2*rounds; got != want {
			t.Errorf("%s has %d KEK versions, want %d: a rotation was lost", tenant, got, want)
		}
	}
}
