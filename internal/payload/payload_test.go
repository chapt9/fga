package payload

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"fga/internal/cryptowire"
)

func binding() Binding {
	return Binding{Tenant: cryptowire.NewUUID(), Object: cryptowire.NewUUID(), Version: cryptowire.NewUUID(),
		CryptoVersion: cryptowire.NewUUID(), Blob: cryptowire.NewUUID()}
}

func encrypt(t *testing.T, key []byte, b Binding, plain []byte) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := Encrypt(key, b, &ct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

func decrypt(key []byte, b Binding, ct []byte) ([]byte, error) {
	r, err := Decrypt(key, b, bytes.NewReader(ct))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// TestRoundTripAndSize: CiphertextSize is exact, across segment
// boundaries, and the plaintext comes back.
func TestRoundTripAndSize(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	b := binding()
	first := segmentSize - headerSize - tagSize
	for _, n := range []int{0, 1, first - 1, first, first + 1, first + segmentSize - tagSize, first + segmentSize - tagSize + 1, 3 << 20} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		ct := encrypt(t, key, b, plain)
		if int64(len(ct)) != CiphertextSize(int64(n)) {
			t.Errorf("%d bytes: ciphertext %d, CiphertextSize %d", n, len(ct), CiphertextSize(int64(n)))
		}
		got, err := decrypt(key, b, ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%d bytes: round trip: %v", n, err)
		}
	}
}

// TestBindingAndIntegrity covers SSE-001 and SSE-005 (V-164, V-165): a
// payload decrypts only with its key and exact identity; corruption and
// truncation fail instead of ending short.
func TestBindingAndIntegrity(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	b := binding()
	plain := make([]byte, 2<<20+5)
	_, _ = rand.Read(plain)
	ct := encrypt(t, key, b, plain)
	moved := b
	moved.Object = cryptowire.NewUUID()
	if _, err := decrypt(key, moved, ct); err == nil {
		t.Error("a payload copied to another object decrypted")
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if _, err := decrypt(other, b, ct); err == nil {
		t.Error("another data key decrypted the payload")
	}
	corrupt := bytes.Clone(ct)
	corrupt[len(corrupt)-3] ^= 1
	if got, err := decrypt(key, b, corrupt); err == nil {
		t.Errorf("a corrupted last segment decrypted to %d bytes", len(got))
	}
	if got, err := decrypt(key, b, ct[:len(ct)-tagSize-100]); err == nil {
		t.Errorf("a truncated payload decrypted to %d bytes", len(got))
	}
	if got, err := decrypt(key, b, ct[:segmentSize]); err == nil {
		t.Errorf("a payload cut at a segment boundary decrypted to %d bytes", len(got))
	}
	if _, err := Encrypt(key[:16], b, io.Discard); err != ErrKey {
		t.Errorf("a short key: %v", err)
	}
}
