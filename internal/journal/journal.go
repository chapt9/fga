// Package journal is the security journal of docs/design/storage-r1b.md
// (specification 2.5, AVL-008, KEY-017): a separately stored, append-only
// record of security-critical changes (revocations, removed share grants,
// compromised signers, raised epochs, recovery incarnations). Each change is written here
// durably before it is committed to the catalog, so a restore from an older
// backup can replay it. Every entry but IdentitySet is restrictive, so
// replaying one whose catalog change never committed only removes access;
// an IdentitySet whose change fails is followed by the identity's
// committed state (catalog.Store.Administer).
//
// The entries form a hash chain (review v2 finding 1): each names its
// position and the chain value of the entry before it, and is published
// atomically under its position, so a lost, altered or reordered entry
// breaks the chain. The catalog records the chain value of the last entry
// it saw, so a loss followed by new entries is not mistaken for the
// recorded history either. Entries written before the chain (named by
// time) are accepted only as a prefix, and the chain covers them.
package journal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fga/internal/strictjson"
)

// Entry kinds.
const (
	IdentityDisabled  = "identity-disabled"
	DelegationRevoked = "delegation-revoked"
	RecipientRevoked  = "recipient-revoked"
	SignerCompromised = "signer-compromised"
	EpochRaised       = "epoch-raised"
	Incarnation       = "incarnation"
	// GrantRemoved names a share grant that was removed or replaced
	// (SHR-002); its subject is the grant ID.
	GrantRemoved = "grant-removed"
	// AccessRemoved records capabilities an administrative change took
	// from an identity (and, in entries written before IdentitySet, roles
	// and attribute values); its subject is the catalog.Removal as JSON.
	// Reconcile re-applies the removal only.
	AccessRemoved = "access-removed"
	// IdentitySet records the roles and attributes an administrative
	// change left an identity with; its subject is the
	// catalog.IdentityState as JSON. Reconcile sets them, so a restore
	// keeps the last recorded state (review v5 F01).
	IdentitySet = "identity-set"
	// SourceSet records the version a review made a source's active one;
	// its subject is the catalog.SourceState as JSON. Reconcile makes it
	// active again, so a restore does not bring an older one back
	// (ING-008).
	SourceSet = "source-set"
	// SourceDisabled names a disabled source of JSON readings.
	SourceDisabled = "source-disabled"
	// SignInKeyRemoved names a removed sign-in key by its fingerprint;
	// reconcile removes it again, so a restore cannot bring it back.
	SignInKeyRemoved = "sign-in-key-removed"
)

var kinds = []string{IdentityDisabled, DelegationRevoked, RecipientRevoked, SignerCompromised, EpochRaised, Incarnation, GrantRemoved, AccessRemoved,
	IdentitySet, SourceSet, SourceDisabled, SignInKeyRemoved}

// Entry is one journaled change. Subject names what changed: an identity,
// delegation or key, an epoch or an incarnation number. Seq is its
// position from 1 and Prev the chain value of the entry before it (the
// journal's genesis for the first); an entry from before the chain has
// neither.
type Entry struct {
	Seq     int       `json:"seq,omitempty"`
	Prev    string    `json:"prev,omitempty"`
	Kind    string    `json:"kind"`
	Tenant  string    `json:"tenant"`
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
	// Chain is the entry's chain value, computed on reading: the hash of
	// the previous chain value and the entry's bytes.
	Chain string `json:"-"`
}

// ErrBroken means the journal's chain does not verify: an entry is
// missing, altered or out of order. Recovery refuses it.
var ErrBroken = errors.New("journal: the chain of entries is broken")

// genesis is the chain value before a journal's first entry.
func genesis(id string) string {
	h := sha256.Sum256([]byte("fga.journal/chain\x00" + id))
	return hex.EncodeToString(h[:])
}

func link(prev string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// chainedName is the file name of the entry at seq. It sorts after every
// name of an entry from before the chain, which starts with a digit.
func chainedName(seq int) string { return fmt.Sprintf("s%020d.json", seq) }

// Journal is a directory with one file per entry and an identity file.
type Journal struct {
	dir string
	id  string
	now func() time.Time
}

// ErrMissing means dir holds no initialized journal. A missing journal is
// never created implicitly: an empty one would hide the revocations a
// restore must replay (review finding 1).
var ErrMissing = errors.New("journal: no initialized security journal; run fga-admin journal init once at setup")

// idFile names the journal's identity file.
const idFile = "JOURNAL"

type identity struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// Init creates a new journal at dir (mode 0700) with a fresh random
// identity. It refuses a directory that already holds one.
func Init(dir string, now func() time.Time) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	id := identity{ID: hex.EncodeToString(random), CreatedAt: now().UTC()}
	b, _ := json.Marshal(id)
	if err := writeDurably(dir, idFile, b); err != nil {
		return nil, fmt.Errorf("journal: init: %w", err)
	}
	return &Journal{dir: dir, id: id.ID, now: now}, nil
}

// Open opens the initialized journal at dir.
func Open(dir string, now func() time.Time) (*Journal, error) {
	b, err := os.ReadFile(filepath.Join(dir, idFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	var id identity
	if err := strictjson.Decode(b, &id); err != nil || len(id.ID) != 32 {
		return nil, fmt.Errorf("journal: malformed identity file")
	}
	return &Journal{dir: dir, id: id.ID, now: now}, nil
}

// ID is the journal's identity.
func (j *Journal) ID() string { return j.id }

// State is a journal's identity and the chain values of its entries, in
// order, which the catalog records so that recovery can tell a complete
// journal from a lost or older one.
type State struct {
	ID      string
	Entries int
	Chains  []string
}

// Head is the chain value of the last entry, or "" for an empty journal.
func (s State) Head() string {
	if len(s.Chains) == 0 {
		return ""
	}
	return s.Chains[len(s.Chains)-1]
}

// StateOf is the state of entries read from the journal id.
func StateOf(id string, entries []Entry) State {
	st := State{ID: id, Entries: len(entries), Chains: make([]string, len(entries))}
	for i, e := range entries {
		st.Chains[i] = e.Chain
	}
	return st
}

// State returns the journal's current state.
func (j *Journal) State() (State, error) {
	es, err := j.Entries()
	return StateOf(j.id, es), err
}

// Binding is State as plain values, for callers that must not link this
// package (the storage role reaches the envelope service).
func (j *Journal) Binding() (string, []string, error) {
	st, err := j.State()
	return st.ID, st.Chains, err
}

// writeDurably creates name in dir exclusively, flushes it and then the
// directory.
func writeDurably(dir, name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Append writes one entry durably: an exclusive new file, flushed, then the
// directory flushed.
func (j *Journal) Append(kind, tenant, subject string) error {
	if !slices.Contains(kinds, kind) || subject == "" {
		return fmt.Errorf("journal: invalid entry %q", kind)
	}
	// Another writer (the keys role, the storage role or fga-admin) may
	// take the next position first; then the entry is chained again.
	for range 100 {
		es, err := j.Entries()
		if err != nil {
			return err
		}
		prev := genesis(j.id)
		if len(es) > 0 {
			prev = es[len(es)-1].Chain
		}
		e := Entry{Seq: len(es) + 1, Prev: prev, Kind: kind, Tenant: tenant, Subject: subject, At: j.now().UTC()}
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		err = publish(j.dir, chainedName(e.Seq), b)
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return errors.New("journal: too many concurrent appends")
}

// Entries returns every entry in the order written. A malformed entry is an
// error: the journal is not trusted partially.
func (j *Journal) Entries() ([]Entry, error) {
	des, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range des {
		if strings.HasSuffix(d.Name(), ".json") && d.Type().IsRegular() {
			names = append(names, d.Name())
		}
	}
	slices.Sort(names)
	out := make([]Entry, 0, len(names))
	chain, chained := genesis(j.id), false
	for i, n := range names {
		b, err := os.ReadFile(filepath.Join(j.dir, n))
		if err != nil {
			return nil, err
		}
		var e Entry
		if err := strictjson.Decode(b, &e); err != nil || !slices.Contains(kinds, e.Kind) {
			return nil, errors.Join(fmt.Errorf("journal: malformed entry %s", n), err)
		}
		switch {
		case e.Seq == 0 && e.Prev == "" && !chained:
			// An entry from before the chain.
		case e.Seq == i+1 && e.Prev == chain && n == chainedName(e.Seq):
			chained = true
		default:
			return nil, fmt.Errorf("%w at %s (position %d)", ErrBroken, n, i+1)
		}
		chain = link(chain, b)
		e.Chain = chain
		out = append(out, e)
	}
	return out, nil
}

// publish writes name in dir atomically: it is complete and durable before
// it appears, and it is never replaced (os.ErrExist when it exists).
func publish(dir, name string, b []byte) error {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmp := "tmp-" + hex.EncodeToString(random)
	if err := writeDurably(dir, tmp, b); err != nil {
		return err
	}
	defer os.Remove(filepath.Join(dir, tmp))
	if err := os.Link(filepath.Join(dir, tmp), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
