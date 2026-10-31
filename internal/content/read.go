package content

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"fga/internal/audit"
	"fga/internal/blob"
	"fga/internal/cryptowire"
	"fga/internal/fence"
	"fga/internal/registry"
)

// VersionInfo is the metadata of one version that stat discloses.
type VersionInfo struct {
	Version          string    `json:"version_id"`
	ETag             string    `json:"etag"`
	Current          bool      `json:"current"`
	CiphertextLength int64     `json:"ciphertext_length"`
	CiphertextSHA256 string    `json:"ciphertext_sha256"`
	Suite            uint16    `json:"suite"`
	Format           uint16    `json:"format"`
	CreatedAt        time.Time `json:"created_at"`
}

func info(v version, current bool) VersionInfo {
	return VersionInfo{Version: v.ID.String(), ETag: ETag(v.ID), Current: current, CiphertextLength: v.Length,
		CiphertextSHA256: v.SHA256, Suite: v.Suite, Format: v.Format, CreatedAt: v.CreatedAt.UTC()}
}

// readChecks are the checks of a read-like operation on one exact version:
// the action, plus its history action for a non-current version.
func readChecks(o object, v version, current bool, action, history string, plain, old string) (string, []check) {
	ref := canonical("storage.object", o.ID.String())
	checks := []check{{id: "object", role: registry.RoleObject, action: action, ref: ref, version: v.ID.String()}}
	if current {
		return plain, checks
	}
	return old, append(checks, check{id: "history", role: registry.RoleHistory, action: history, ref: ref, version: v.ID.String()})
}

// Stat returns a version's metadata (CNT-004): the current version, or a
// named one with discover-history. Absent and undiscoverable targets are
// the same ErrNotFound.
func (s *Service) Stat(ctx context.Context, c Caller, bucketName, key, versionSel string) (VersionInfo, error) {
	_, o, v, current, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return VersionInfo{}, err
	}
	op, checks := readChecks(o, v, current, "stat", "discover-history", registry.OpStat, registry.OpStatHistory)
	_, rec, err := s.decide(ctx, c, op, Audience, false, checks)
	if err != nil {
		return VersionInfo{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return VersionInfo{}, err
	}
	return info(v, current), nil
}

// Package is the encrypted package of one version for one recipient
// (CNT-001): the signed descriptor and the existing envelope for that
// recipient with its delivery receipt. The ciphertext itself is read with
// ReadCiphertext.
type Package struct {
	Version             VersionInfo
	Descriptor          []byte
	DescriptorSignature string
	Envelope            Delivered
}

// ReadPackage authorizes the ciphertext read for the descriptor and asks
// the keys role to release the recipient's envelope under the separate
// GetRecipientEnvelope checks (Table "Compound operations", TRU-005). It
// never creates an envelope: a recipient without one gets ErrNotFound.
func (s *Service) ReadPackage(ctx context.Context, c Caller, bucketName, key, versionSel, recipient string) (Package, error) {
	if _, err := cryptowire.ParseDigest(recipient); err != nil {
		return Package{}, ErrInvalid
	}
	_, o, v, current, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return Package{}, err
	}
	op, checks := readChecks(o, v, current, "read", "read-history", registry.OpRead, registry.OpReadHistory)
	_, rec, err := s.decide(ctx, c, op, Audience, false, checks)
	if err != nil {
		return Package{}, err
	}
	if err := s.checked(ctx, rec); err != nil {
		return Package{}, err
	}

	var envelopeID string
	err = s.d.Catalog.Pool().QueryRow(ctx,
		`SELECT id::text FROM envelopes WHERE tenant = $1 AND version = $2 AND recipient = $3 AND status = 'ACTIVE'`,
		c.Tenant, v.ID, recipient).Scan(&envelopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Package{}, ErrNotFound
	}
	if err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	ref := canonical("storage.object", o.ID.String())
	envOp := registry.OpGetEnvelope
	envChecks := []check{{id: "object", role: registry.RoleObject, action: "read", ref: ref, version: v.ID.String()}}
	if !current {
		envOp = registry.OpGetEnvelopeOld
		envChecks = append(envChecks, check{id: "history", role: registry.RoleHistory, action: "read-history", ref: ref, version: v.ID.String()})
	}
	envChecks = append(envChecks,
		check{id: "envelope", role: registry.RoleEnvelope, action: "release", ref: canonical("crypto.envelope", envelopeID), version: v.ID.String()},
		check{id: "recipient-read", role: registry.RoleRecipientRead, action: "read", ref: ref, version: v.ID.String(), recipient: recipient},
		check{id: "recipient-key", role: registry.RoleRecipientKey, action: "receive-key", ref: canonical("crypto.recipient", recipient), recipient: recipient})
	signed, _, err := s.decide(ctx, c, envOp, KeysAudience, true, envChecks)
	if err != nil {
		return Package{}, err
	}
	env, err := s.d.Keys.Deliver(ctx, signed, envelopeID)
	if err != nil {
		return Package{}, err
	}
	return Package{Version: info(v, current), Descriptor: v.Descriptor, DescriptorSignature: v.DescriptorSig, Envelope: env}, nil
}

// Stream is an admitted ciphertext read. It stops emitting at the
// decision's valid_until and aborts when a periodic recheck of the bound
// authority fails or is overdue (CNT-008).
type Stream struct {
	io.ReadCloser
	Version VersionInfo
}

// ReadCiphertext admits the read of one version's exact ciphertext under
// the fence, recording the admission, and returns its stream (CNT-008,
// DEC-006). It never falls back to another version or a raw path.
func (s *Service) ReadCiphertext(ctx context.Context, c Caller, bucketName, key, versionSel string) (*Stream, error) {
	_, o, v, current, err := s.target(ctx, c.Tenant, bucketName, key, versionSel)
	if err != nil {
		return nil, err
	}
	op, checks := readChecks(o, v, current, "read", "read-history", registry.OpRead, registry.OpReadHistory)
	_, rec, err := s.decide(ctx, c, op, Audience, true, checks)
	if err != nil {
		return nil, err
	}
	tenantID, err := s.tenantID(ctx, c.Tenant)
	if err != nil {
		return nil, err
	}
	err = s.fenced(ctx, rec, nil, func(ctx context.Context, tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM object_versions WHERE tenant = $1 AND id = $2 FOR SHARE`, c.Tenant, v.ID).Scan(&state); err != nil {
			return err
		}
		if state != "LIVE" {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `INSERT INTO read_admissions VALUES ($1, $2, $3, $4, $5)`,
			c.Tenant, rec.DecisionID, v.ID, s.d.Now(), rec.ValidUntil); err != nil {
			return err
		}
		return s.d.Catalog.AppendTx(ctx, tx, s.event(audit.KindReadAdmission, rec, "ADMITTED",
			audit.Target{Type: "storage.object", ID: o.ID.String(), Version: v.ID.String(), Digest: v.SHA256}))
	})
	if err != nil {
		return nil, err
	}
	digest, err := cryptowire.ParseDigest(v.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: stored digest", ErrUnavailable)
	}
	r, err := s.d.Blobs.Open(blob.Receipt{Ref: blob.Ref{Tenant: tenantID, Blob: v.Blob}, Length: v.Length, SHA256: digest})
	if err != nil {
		return nil, fmt.Errorf("%w: backend: %v", ErrUnavailable, err)
	}
	b, err := fence.FromRecord(rec)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Stream{ReadCloser: s.lease(r, b), Version: info(v, current)}, nil
}

// ErrLease aborts a stream whose authority changed, whose recheck is
// overdue, or whose decision expired (CNT-008).
var ErrLease = errors.New("content: read lease ended")

// lease wraps r so that reads fail once the binding no longer holds or the
// decision expires (CNT-008).
func (s *Service) lease(r io.ReadCloser, b fence.Binding) io.ReadCloser {
	return s.leaseUntil(r, b, b.ValidUntil)
}

// upload wraps an admitted upload body: it fails once the bound authority
// changes, but an upload admitted in time may outlast the decision. The
// staged bytes stay invisible until a commit, which needs its own
// decision.
func (s *Service) upload(r io.ReadCloser, b fence.Binding) io.ReadCloser {
	b.ValidUntil = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	return s.leaseUntil(r, b, b.ValidUntil)
}

func (s *Service) leaseUntil(r io.ReadCloser, b fence.Binding, until time.Time) io.ReadCloser {
	l := &leased{r: r, validUntil: until, now: s.d.Now, every: s.d.Limits.LeaseCheckEvery, done: make(chan struct{})}
	l.lastOK = s.d.Now()
	go func() {
		t := time.NewTicker(l.every)
		defer t.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), l.every)
				err := s.d.Fence.Check(ctx, b)
				cancel()
				l.mu.Lock()
				if err != nil {
					l.err = fmt.Errorf("%w: %v", ErrLease, err)
				} else {
					l.lastOK = s.d.Now()
				}
				l.mu.Unlock()
			}
		}
	}()
	return l
}

type leased struct {
	r          io.ReadCloser
	validUntil time.Time
	now        func() time.Time
	every      time.Duration
	done       chan struct{}
	once       sync.Once

	mu     sync.Mutex
	err    error
	lastOK time.Time
}

func (l *leased) Read(p []byte) (int, error) {
	l.mu.Lock()
	err, lastOK := l.err, l.lastOK
	l.mu.Unlock()
	now := l.now()
	switch {
	case err != nil:
		return 0, err
	case !now.Before(l.validUntil):
		return 0, fmt.Errorf("%w: decision expired", ErrLease)
	case now.Sub(lastOK) > 2*l.every:
		return 0, fmt.Errorf("%w: authority recheck overdue", ErrLease)
	}
	return l.r.Read(p)
}

func (l *leased) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.r.Close()
}
