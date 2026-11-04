// Package auditexport drains the audit outbox into durable files outside
// the catalog (specification 2.5, AUD-002, AUD-003;
// docs/design/audit-export.md). An event is marked delivered only after its
// export file and directory are flushed; a crash in between exports it
// again, and readers deduplicate by event ID.
//
// Every export file has a link: a record of its digest and of the
// previous link's digest, signed with the audit export key. The catalog
// keeps the chain's head, so a deleted, changed, reordered or truncated
// export is evident, and Verify checks a directory with the public key
// alone. A collector, if configured, receives each file with its link.
package auditexport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fga/internal/cryptowire"
	"fga/internal/roleconfig"
)

// lockKey is the advisory lock that keeps one exporter active.
const lockKey = 7317

// Errors.
var (
	// ErrBusy is returned when another exporter holds the lock.
	ErrBusy = errors.New("auditexport: another exporter is running")
	// ErrChain is returned when the export directory does not hold one
	// unbroken chain through the catalog's head: files were deleted,
	// changed or replaced.
	ErrChain = errors.New("auditexport: the export chain is broken")
)

// LinkFormat names a link record, and LinkType its signature's JWS type.
const (
	LinkFormat = "fga.audit-chain/v1"
	LinkType   = "fga-audit-link+jws"
)

// Suffixes of a link, its signature, a shipped marker, and the leftovers
// of an export a crash interrupted.
const (
	linkSuffix       = ".link"
	sigSuffix        = ".link.jws"
	shippedSuffix    = ".shipped"
	incompleteSuffix = ".incomplete"
)

// Link is the chain record of one export file.
type Link struct {
	Format   string `json:"format"`
	File     string `json:"file"`
	Events   int    `json:"events"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
	SHA256   string `json:"sha256"`
	// Previous is the previous link's digest, empty for the first link.
	// Reset marks a link an operator started after a head the directory
	// no longer holds.
	Previous  string    `json:"previous"`
	Reset     bool      `json:"reset,omitempty"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
}

func linkDigest(l Link) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%t", LinkFormat, l.Previous, l.File, l.SHA256, l.Events, l.FirstSeq, l.LastSeq, l.Reset)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Collector receives export files: a POST of the file's JSON lines with
// the link and its signature in headers. Any 2xx acknowledges the file; a
// collector deduplicates by link digest or event ID.
type Collector struct {
	// URL is https, or http to a loopback address.
	URL string
	// Token, if set, is sent as a bearer token.
	Token string
	HTTP  *http.Client
}

// Options configure an exporter.
type Options struct {
	Batch int
	// Key signs the links. Trusted are earlier export keys whose links
	// the directory still holds.
	Key       ed25519.PrivateKey
	Trusted   []ed25519.PublicKey
	Collector *Collector
	// Reset continues although the directory no longer holds the
	// catalog's head (it was truncated, or replaced by an empty one): an
	// operator's decision, which the next link records.
	Reset bool
}

// Exporter exports one catalog's outbox into a directory.
type Exporter struct {
	pool *pgxpool.Pool
	dir  string
	o    Options
	kid  string
	keys map[string]ed25519.PublicKey
	// last is the link this exporter continued or wrote last; while the
	// catalog still records it and it verifies, the directory is not
	// scanned again.
	last Link
}

// New returns an exporter.
func New(pool *pgxpool.Pool, dir string, o Options) (*Exporter, error) {
	if o.Batch <= 0 {
		return nil, errors.New("auditexport: batch must be positive")
	}
	if len(o.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("auditexport: an Ed25519 export key is required")
	}
	if c := o.Collector; c != nil {
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && roleconfig.Loopback(hostPort(u))) {
			return nil, errors.New("auditexport: the collector URL must be https, or http to a loopback address")
		}
		if c.HTTP == nil {
			c.HTTP = &http.Client{Timeout: 30 * time.Second}
		}
		if c.HTTP.CheckRedirect == nil {
			c.HTTP.CheckRedirect = refuseRedirect
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	pub := o.Key.Public().(ed25519.PublicKey)
	return &Exporter{pool: pool, dir: dir, o: o, kid: KeyID(pub), keys: keyring(append([]ed25519.PublicKey{pub}, o.Trusted...))}, nil
}

func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return u.Host + ":80"
}

// KeyID identifies an export key in its links' signatures.
func KeyID(pub ed25519.PublicKey) string {
	return cryptowire.SigningKeyFingerprint(pub).String()
}

func keyring(pubs []ed25519.PublicKey) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, p := range pubs {
		m[KeyID(p)] = p
	}
	return m
}

// State is the chain head the catalog records.
type State struct {
	Head      string
	File      string
	UpdatedAt time.Time
}

// Head returns the catalog's chain head; a zero State before the first
// export.
func Head(ctx context.Context, pool *pgxpool.Pool) (State, error) {
	var s State
	err := pool.QueryRow(ctx, `SELECT head, file, updated_at FROM audit_export_state WHERE id = 1`).Scan(&s.Head, &s.File, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, nil
	}
	return s, err
}

// Once exports at most one batch and returns how many events it exported.
func (e *Exporter) Once(ctx context.Context) (int, error) {
	last := e.last
	e.last = Link{}
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&locked); err != nil {
		return 0, err
	}
	if !locked {
		return 0, ErrBusy
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey) //nolint:errcheck // released with the session too

	prev, reset, err := e.head(ctx, conn.Conn(), last)
	if err != nil {
		return 0, err
	}
	rows, err := conn.Query(ctx, `SELECT seq, id, event FROM audit_outbox WHERE delivered_at IS NULL ORDER BY seq LIMIT $1`, e.o.Batch)
	if err != nil {
		return 0, err
	}
	var ids []string
	var lines []byte
	var first, end int64
	for rows.Next() {
		var seq int64
		var id string
		var event json.RawMessage
		if err := rows.Scan(&seq, &id, &event); err != nil {
			rows.Close()
			return 0, err
		}
		if len(ids) == 0 {
			first = seq
		}
		end = seq
		ids = append(ids, id)
		lines = append(append(lines, event...), '\n')
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		if !reset {
			e.last = prev
		}
		return 0, nil
	}
	name := fmt.Sprintf("%020d-%020d-%d.jsonl", first, end, time.Now().UnixNano())
	sum := sha256.Sum256(lines)
	l := Link{Format: LinkFormat, File: name, Events: len(ids), FirstSeq: first, LastSeq: end, SHA256: "sha256:" + hex.EncodeToString(sum[:]),
		Previous: prev.Digest, Reset: reset, CreatedAt: time.Now().UTC()}
	l.Digest = linkDigest(l)
	link, err := json.Marshal(l)
	if err != nil {
		return 0, err
	}
	sig, err := cryptowire.Sign(LinkType, e.kid, e.o.Key, link)
	if err != nil {
		return 0, err
	}
	// The file, its link, then the signature, each flushed: a signed link
	// never names a file that is not durable, and an export without its
	// signature is the leftover of an interrupted one.
	if err := e.write(name, lines); err != nil {
		return 0, err
	}
	if err := e.write(name+linkSuffix, link); err != nil {
		return 0, err
	}
	if err := e.write(name+sigSuffix, []byte(sig)); err != nil {
		return 0, err
	}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE audit_outbox SET delivered_at = now() WHERE id = ANY($1) AND delivered_at IS NULL`, ids); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_export_state (id, head, file, updated_at) VALUES (1, $1, $2, now())
		                        ON CONFLICT (id) DO UPDATE SET head = excluded.head, file = excluded.file, updated_at = excluded.updated_at`,
			l.Digest, l.File)
		return err
	})
	if err != nil {
		return 0, err
	}
	e.last = l
	return len(ids), nil
}

// head returns the link the next one continues (zero for the first) and
// whether the next link is a reset. The directory must hold one unbroken
// chain through the catalog's head; the next link continues the end of
// that head's segment, which after a restore lies past the restored head.
// A head the directory does not hold stops the exporter unless
// Options.Reset, and the reset link continues after its digest; a broken
// chain always stops it, and the operator keeps that directory as evidence
// and exports into a new one with Reset.
func (e *Exporter) head(ctx context.Context, conn *pgx.Conn, last Link) (Link, bool, error) {
	var recorded string
	err := conn.QueryRow(ctx, `SELECT head FROM audit_export_state WHERE id = 1`).Scan(&recorded)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Link{}, false, err
	}
	if recorded != "" && recorded == last.Digest {
		if _, err := readLink(e.dir, last.File, e.keys); err == nil {
			return last, false, nil
		}
	}
	if err := e.setAsideIncomplete(); err != nil {
		return Link{}, false, err
	}
	ls, err := readLinks(e.dir, e.keys)
	if err != nil {
		return Link{}, false, err
	}
	segs, err := ls.segments()
	if err != nil {
		return Link{}, false, err
	}
	if _, held := ls.byDigest[recorded]; recorded != "" && !held {
		if e.o.Reset {
			return Link{Digest: recorded}, true, nil
		}
		return Link{}, false, fmt.Errorf("%w: the catalog's head %s is not in the directory", ErrChain, recorded)
	}
	for _, s := range segs {
		for _, l := range s {
			if recorded == "" || l.Digest == recorded {
				return s[len(s)-1], false, nil
			}
		}
	}
	return Link{}, false, nil
}

// setAsideIncomplete renames the leftovers of an export a crash
// interrupted (a file, perhaps its link, without the signature) so they
// stay for inspection but outside the chain. Their events were never
// marked delivered and are exported again.
func (e *Exporter) setAsideIncomplete() error {
	files, err := filepath.Glob(filepath.Join(e.dir, "*.jsonl"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if _, err := os.Stat(f + sigSuffix); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, p := range []string{f + linkSuffix, f} {
			if err := os.Rename(p, p+incompleteSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// links are the verified links of a directory.
type links struct {
	byDigest map[string]Link
	next     map[string][]Link
}

// readLinks reads every link of dir and verifies its signature, digest
// and export file.
func readLinks(dir string, keys map[string]ed25519.PublicKey) (links, error) {
	out := links{byDigest: map[string]Link{}, next: map[string][]Link{}}
	names, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return out, err
	}
	for _, path := range names {
		l, err := readLink(dir, filepath.Base(path), keys)
		if err != nil {
			return out, err
		}
		out.byDigest[l.Digest] = l
		out.next[l.Previous] = append(out.next[l.Previous], l)
	}
	if sigs, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"+sigSuffix)); len(sigs) != len(names) {
		return out, fmt.Errorf("%w: a signed link without its export file", ErrChain)
	}
	return out, nil
}

func readLink(dir, name string, keys map[string]ed25519.PublicKey) (Link, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name+linkSuffix))
	if err != nil {
		return Link{}, fmt.Errorf("%w: %s has no link", ErrChain, name)
	}
	sig, err := os.ReadFile(filepath.Join(dir, name+sigSuffix))
	if err != nil {
		return Link{}, fmt.Errorf("%w: %s has no signed link", ErrChain, name)
	}
	if _, err := cryptowire.Verify(LinkType, strings.TrimSpace(string(sig)), raw, func(id string) (ed25519.PublicKey, error) {
		if k, ok := keys[id]; ok {
			return k, nil
		}
		return nil, errors.New("not a trusted export key")
	}); err != nil {
		return Link{}, fmt.Errorf("%w: %s: %v", ErrChain, name, err)
	}
	var l Link
	if err := json.Unmarshal(raw, &l); err != nil || l.Format != LinkFormat || l.Digest != linkDigest(l) || l.File != name {
		return Link{}, fmt.Errorf("%w: the link of %s is malformed", ErrChain, name)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return Link{}, err
	}
	sum := sha256.Sum256(data)
	if l.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		return Link{}, fmt.Errorf("%w: %s was changed", ErrChain, name)
	}
	return l, nil
}

// segments returns the chain's segments in order: the one from the first
// link, then each an operator reset, by time. A link outside every
// segment (a file before it is missing), or two links after the same one,
// breaks the chain.
func (ls links) segments() ([][]Link, error) {
	var resets []Link
	for prev, succ := range ls.next {
		if _, held := ls.byDigest[prev]; prev != "" && !held && len(succ) == 1 && succ[0].Reset {
			resets = append(resets, succ[0])
		}
	}
	sort.Slice(resets, func(i, j int) bool { return resets[i].CreatedAt.Before(resets[j].CreatedAt) })
	starts := []string{""}
	for _, r := range resets {
		starts = append(starts, r.Previous)
	}
	var segs [][]Link
	walked := 0
	for _, s := range starts {
		var seg []Link
		for cur := s; ; {
			succ := ls.next[cur]
			if len(succ) > 1 {
				return nil, fmt.Errorf("%w: two links follow %q", ErrChain, cur)
			}
			if len(succ) == 0 {
				break
			}
			seg = append(seg, succ[0])
			cur = succ[0].Digest
		}
		walked += len(seg)
		if len(seg) > 0 {
			segs = append(segs, seg)
		}
	}
	if walked != len(ls.byDigest) {
		return nil, fmt.Errorf("%w: %d export files are outside the chain; a file before them is missing", ErrChain, len(ls.byDigest)-walked)
	}
	return segs, nil
}

// Report is the result of verifying an export directory.
type Report struct {
	Files  int
	Events int
	// Head is the digest of the chain's last link.
	Head string
	// Resets are the files whose links an operator started after a head
	// the directory no longer held.
	Resets []string
}

// Verify checks an export directory with the export public keys alone:
// every export file has a link signed by one of keys that matches it, the
// links form one chain from its first link (and from each recorded reset),
// and, if head is given (the catalog's), the directory holds it, so it was
// not truncated. Resets are reported, not failed.
func Verify(dir, head string, keys ...ed25519.PublicKey) (Report, error) {
	ls, err := readLinks(dir, keyring(keys))
	if err != nil {
		return Report{}, err
	}
	segs, err := ls.segments()
	if err != nil {
		return Report{}, err
	}
	if _, held := ls.byDigest[head]; head != "" && !held {
		return Report{}, fmt.Errorf("%w: the catalog's head %s is not in the directory", ErrChain, head)
	}
	var rep Report
	for _, s := range segs {
		for _, l := range s {
			rep.Files++
			rep.Events += l.Events
			if l.Reset {
				rep.Resets = append(rep.Resets, l.File)
			}
		}
		rep.Head = s[len(s)-1].Digest
	}
	return rep, nil
}

// Ship sends the collector, in chain order, every export file it has not
// acknowledged, and returns how many it sent. A file is marked shipped
// (FILE.shipped) only after a 2xx; a failure ends the pass, and the next
// one sends the rest. Exporting never waits for shipping.
func (e *Exporter) Ship(ctx context.Context) (int, error) {
	c := e.o.Collector
	if c == nil {
		return 0, nil
	}
	ls, err := readLinks(e.dir, e.keys)
	if err != nil {
		return 0, err
	}
	segs, err := ls.segments()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range segs {
		for _, l := range s {
			sent, err := e.ship(ctx, c, l)
			if err != nil {
				return n, err
			}
			if sent {
				n++
			}
		}
	}
	return n, nil
}

func (e *Exporter) ship(ctx context.Context, c *Collector, l Link) (bool, error) {
	if _, err := os.Stat(filepath.Join(e.dir, l.File+shippedSuffix)); err == nil {
		return false, nil
	}
	var body [3][]byte
	for i, suffix := range []string{"", linkSuffix, sigSuffix} {
		b, err := os.ReadFile(filepath.Join(e.dir, l.File+suffix))
		if err != nil {
			return false, err
		}
		body[i] = b
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body[0]))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Fga-Audit-Link", base64.StdEncoding.EncodeToString(body[1]))
	req.Header.Set("Fga-Audit-Link-Signature", strings.TrimSpace(string(body[2])))
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("auditexport: collector: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, fmt.Errorf("auditexport: the collector answered %d for %s", resp.StatusCode, l.File)
	}
	return true, e.write(l.File+shippedSuffix, nil)
}

// write creates the file exclusively, flushes it and its directory.
func (e *Exporter) write(name string, data []byte) error {
	path := filepath.Join(e.dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
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
	d, err := os.Open(e.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Drain exports batches until the outbox is empty and returns the total.
func (e *Exporter) Drain(ctx context.Context) (int, error) {
	total := 0
	for {
		n, err := e.Once(ctx)
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
}

// Backlog returns how many events wait in the outbox, for an alarm before
// the roles must refuse operations because it is full (AUD-002).
func Backlog(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE delivered_at IS NULL`).Scan(&n)
	return n, err
}

// refuseRedirect makes a redirect the collector's answer, not a step: Go
// would repeat the POST as a GET without the file and forward the token
// (security review of 4 November 2026, finding 9).
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
