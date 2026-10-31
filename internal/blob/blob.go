// Package blob is the R1 single-node blob store (specification 2.5,
// BKD-001 to BKD-003, decision D-02; docs/design/storage-r1b.md). It holds
// client ciphertext only, under one service-owned directory, and never
// decides visibility: the catalog does.
//
// Every path is built from generated UUIDs and opened through an os.Root,
// so no name can leave the directory or follow a symlink out of it. A blob
// becomes durable through an exclusively created temporary file that is
// fully written, checked against its expected length and SHA-256, flushed,
// linked to its final name without replacing anything, and followed by a
// flush of the directory. Only then is a receipt returned.
package blob

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"

	"fga/internal/cryptowire"
)

// Errors of the store.
var (
	ErrMismatch = errors.New("blob: length or digest does not match")
	ErrConflict = errors.New("blob: the blob ID already holds other bytes")
	ErrNotFound = errors.New("blob: no such blob")
	ErrTooLarge = errors.New("blob: larger than the declared length")
)

// Ref names a blob: its tenant and its generated ID.
type Ref struct {
	Tenant cryptowire.UUID
	Blob   cryptowire.UUID
}

// Receipt is the durable-completion evidence of one finalized blob
// (BKD-001), bound to its identity and verified content.
type Receipt struct {
	Ref
	Length int64
	SHA256 cryptowire.Digest
}

// Store is a blob directory.
type Store struct {
	root *os.Root
}

const (
	tmpDir  = "tmp"
	blobDir = "blobs"
)

// Open opens (and creates, mode 0700) the store directory dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{tmpDir, blobDir} {
		if err := root.MkdirAll(d, 0o700); err != nil {
			root.Close()
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

// Close releases the directory.
func (s *Store) Close() error { return s.root.Close() }

func (r Ref) dir() string  { return path.Join(blobDir, r.Tenant.String(), r.Blob.String()[:2]) }
func (r Ref) name() string { return path.Join(r.dir(), r.Blob.String()) }

// Writer receives one blob's bytes into an exclusive temporary file.
type Writer struct {
	s     *Store
	ref   Ref
	tmp   string
	f     *os.File
	h     hash.Hash
	n     int64
	limit int64
}

// Begin starts a blob of at most limit bytes (BKD-001).
func (s *Store) Begin(ref Ref, limit int64) (*Writer, error) {
	if ref.Tenant.IsZero() || ref.Blob.IsZero() || limit <= 0 {
		return nil, errors.New("blob: tenant, blob ID and a positive limit are required")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	tmp := path.Join(tmpDir, ref.Blob.String()+"."+hex.EncodeToString(random))
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{s: s, ref: ref, tmp: tmp, f: f, h: sha256.New(), limit: limit}, nil
}

// Write implements io.Writer. Bytes beyond the limit fail the blob.
func (w *Writer) Write(p []byte) (int, error) {
	if w.n+int64(len(p)) > w.limit {
		return 0, ErrTooLarge
	}
	n, err := w.f.Write(p)
	w.h.Write(p[:n])
	w.n += int64(n)
	return n, err
}

// Abort discards the temporary file.
func (w *Writer) Abort() {
	w.f.Close()
	_ = w.s.root.Remove(w.tmp)
}

// Finalize checks the exact length and digest, makes the blob durable and
// returns its receipt. If the blob ID already holds the same bytes the call
// is idempotent; other bytes conflict. The temporary file is gone either
// way.
func (s *Store) Finalize(w *Writer, length int64, sum cryptowire.Digest) (Receipt, error) {
	defer w.Abort()
	var got cryptowire.Digest
	copy(got[:], w.h.Sum(nil))
	if w.n != length || got != sum {
		return Receipt{}, ErrMismatch
	}
	if err := w.f.Sync(); err != nil {
		return Receipt{}, err
	}
	rec := Receipt{Ref: w.ref, Length: length, SHA256: sum}
	if err := s.mkdirs(w.ref.dir()); err != nil {
		return Receipt{}, err
	}
	err := s.root.Link(w.tmp, w.ref.name())
	switch {
	case errors.Is(err, fs.ErrExist):
		if err := s.Verify(rec); err != nil {
			return Receipt{}, ErrConflict
		}
		return rec, nil
	case err != nil:
		return Receipt{}, err
	}
	if err := s.syncDir(w.ref.dir()); err != nil {
		return Receipt{}, err
	}
	return rec, nil
}

// mkdirs creates dir and its parents below the root, flushing each parent
// whose entries changed.
func (s *Store) mkdirs(dir string) error {
	if _, err := s.root.Stat(dir); err == nil {
		return nil
	}
	parent := path.Dir(dir)
	if err := s.mkdirs(parent); err != nil {
		return err
	}
	if err := s.root.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return s.syncDir(parent)
}

func (s *Store) syncDir(dir string) error {
	d, err := s.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Open returns the exact bytes of a finalized blob. A file whose size
// differs from the receipt is not served.
func (s *Store) Open(r Receipt) (io.ReadCloser, error) {
	f, err := s.root.Open(r.name())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || info.Size() != r.Length || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: stored size differs", ErrMismatch)
	}
	return f, nil
}

// Verify rehashes a finalized blob and compares it with its receipt.
func (s *Store) Verify(r Receipt) error {
	f, err := s.Open(r)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	var got cryptowire.Digest
	copy(got[:], h.Sum(nil))
	if n != r.Length || got != r.SHA256 {
		return ErrMismatch
	}
	return nil
}

// Remove deletes a finalized blob for a catalog-authorized retirement
// (BKD-001, PUB-005). Removing an absent blob succeeds, so retries are
// idempotent.
func (s *Store) Remove(r Ref) error {
	err := s.root.Remove(r.name())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.syncDir(r.dir())
}

// Put writes a complete blob from src, for restore. It is Begin, copy and
// Finalize.
func (s *Store) Put(ref Ref, src io.Reader, length int64, sum cryptowire.Digest) (Receipt, error) {
	w, err := s.Begin(ref, length)
	if err != nil {
		return Receipt{}, err
	}
	if _, err := io.Copy(w, src); err != nil {
		w.Abort()
		return Receipt{}, err
	}
	return s.Finalize(w, length, sum)
}
