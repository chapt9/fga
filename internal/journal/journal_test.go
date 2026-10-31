package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newJournal(t *testing.T) *Journal {
	t.Helper()
	j, err := Init(t.TempDir(), func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func appendAll(t *testing.T, j *Journal, subjects ...string) {
	t.Helper()
	for _, s := range subjects {
		if err := j.Append(RecipientRevoked, "t-acme", s); err != nil {
			t.Fatal(err)
		}
	}
}

// TestChain covers review v2 finding 1: the entries form a chain from the
// journal's identity, and a deleted, altered or swapped entry breaks it.
func TestChain(t *testing.T) {
	j := newJournal(t)
	appendAll(t, j, "a", "b", "c")
	st, err := j.State()
	if err != nil || st.Entries != 3 || len(st.Chains) != 3 || st.Head() != st.Chains[2] {
		t.Fatalf("state %+v, %v", st, err)
	}
	other := newJournal(t)
	appendAll(t, other, "a", "b", "c")
	if os, _ := other.State(); os.Chains[0] == st.Chains[0] {
		t.Fatal("two journals share a chain")
	}

	for name, damage := range map[string]func(dir string){
		"a deleted entry": func(dir string) { os.Remove(filepath.Join(dir, chainedName(2))) },
		"an altered entry": func(dir string) {
			p := filepath.Join(dir, chainedName(2))
			b, _ := os.ReadFile(p)
			os.WriteFile(p, []byte(strings.Replace(string(b), `"subject":"b"`, `"subject":"x"`, 1)), 0o600)
		},
		"swapped entries": func(dir string) {
			a, _ := os.ReadFile(filepath.Join(dir, chainedName(1)))
			b, _ := os.ReadFile(filepath.Join(dir, chainedName(2)))
			os.WriteFile(filepath.Join(dir, chainedName(1)), b, 0o600)
			os.WriteFile(filepath.Join(dir, chainedName(2)), a, 0o600)
		},
	} {
		dir := filepath.Join(t.TempDir(), "copy")
		copyJournal(t, j.dir, dir)
		damage(dir)
		c, err := Open(dir, j.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Entries(); !errors.Is(err, ErrBroken) {
			t.Errorf("%s: %v", name, err)
		}
		if err := c.Append(RecipientRevoked, "t-acme", "d"); !errors.Is(err, ErrBroken) {
			t.Errorf("appending after %s: %v", name, err)
		}
	}

	// A lost last entry leaves a shorter valid chain: only the catalog's
	// recorded head tells it apart, and a new entry takes another value.
	os.Remove(filepath.Join(j.dir, chainedName(3)))
	appendAll(t, j, "d")
	again, err := j.State()
	if err != nil || again.Entries != 3 || again.Chains[2] == st.Chains[2] || again.Chains[1] != st.Chains[1] {
		t.Fatalf("after a lost last entry: %+v, %v", again, err)
	}
}

// TestLegacyPrefix covers journals written before the chain: their entries
// are accepted only before every chained entry, and the chain covers them.
func TestLegacyPrefix(t *testing.T) {
	j := newJournal(t)
	legacy := `{"kind":"recipient-revoked","tenant":"t-acme","subject":"old","at":"2026-10-30T12:00:00Z"}`
	if err := writeDurably(j.dir, "01793000000000000000-00aa.json", []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	appendAll(t, j, "new")
	es, err := j.Entries()
	if err != nil || len(es) != 2 || es[0].Subject != "old" || es[1].Seq != 2 {
		t.Fatalf("entries %+v, %v", es, err)
	}
	// Losing the legacy entry breaks the chain that covers it.
	if err := os.Remove(filepath.Join(j.dir, "01793000000000000000-00aa.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Entries(); !errors.Is(err, ErrBroken) {
		t.Fatalf("after losing the legacy entry: %v", err)
	}
	// A legacy entry after a chained one is refused.
	k := newJournal(t)
	appendAll(t, k, "new")
	if err := writeDurably(k.dir, "z-late.json", []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Entries(); !errors.Is(err, ErrBroken) {
		t.Fatalf("a legacy entry after the chain: %v", err)
	}
}

// TestConcurrentAppends covers several writers (the keys role, the storage
// role, fga-admin): every entry gets its own position in one chain.
func TestConcurrentAppends(t *testing.T) {
	j := newJournal(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := Open(j.dir, j.now)
			if err != nil {
				t.Error(err)
				return
			}
			for k := range 5 {
				if err := o.Append(GrantRemoved, "t-acme", string(rune('a'+i))+string(rune('0'+k))); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	es, err := j.Entries()
	if err != nil || len(es) != 40 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
}

func copyJournal(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	des, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		b, err := os.ReadFile(filepath.Join(from, d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, d.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
