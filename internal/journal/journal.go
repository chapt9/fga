// Package journal is the security journal of docs/design/storage-r1b.md
// (specification 2.5, AVL-008, KEY-017): a separately stored, append-only
// record of security-critical changes (revocations, compromised signers,
// raised epochs, recovery incarnations). Each change is written here
// durably before it is committed to the catalog, so a restore from an older
// backup can replay it. Every entry is restrictive, so replaying an entry
// whose catalog change never committed only removes access.
package journal

import (
	"crypto/rand"
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
)

var kinds = []string{IdentityDisabled, DelegationRevoked, RecipientRevoked, SignerCompromised, EpochRaised, Incarnation}

// Entry is one journaled change. Subject names what changed: an identity,
// delegation or key, an epoch or an incarnation number.
type Entry struct {
	Kind    string    `json:"kind"`
	Tenant  string    `json:"tenant"`
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
}

// Journal is a directory with one file per entry.
type Journal struct {
	dir string
	now func() time.Time
}

// Open opens (and creates, mode 0700) the journal directory.
func Open(dir string, now func() time.Time) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Journal{dir: dir, now: now}, nil
}

// Append writes one entry durably: an exclusive new file, flushed, then the
// directory flushed.
func (j *Journal) Append(kind, tenant, subject string) error {
	if !slices.Contains(kinds, kind) || subject == "" {
		return fmt.Errorf("journal: invalid entry %q", kind)
	}
	e := Entry{Kind: kind, Tenant: tenant, Subject: subject, At: j.now().UTC()}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	name := filepath.Join(j.dir, fmt.Sprintf("%020d-%s.json", e.At.UnixNano(), hex.EncodeToString(random)))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
	d, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(j.dir, n))
		if err != nil {
			return nil, err
		}
		var e Entry
		if err := strictjson.Decode(b, &e); err != nil || !slices.Contains(kinds, e.Kind) {
			return nil, errors.Join(fmt.Errorf("journal: malformed entry %s", n), err)
		}
		out = append(out, e)
	}
	return out, nil
}
