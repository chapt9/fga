package recovery

import (
	"errors"
	"testing"

	"fga/internal/blob"
	"fga/internal/cryptowire"
)

// cutRows yields n rows, then ends with err, as a scan does whose query is
// cancelled or loses its connection midway.
type cutRows struct {
	n   int
	err error
}

func (r *cutRows) Next() bool {
	if r.n == 0 {
		return false
	}
	r.n--
	return true
}

func (r *cutRows) Scan(dest ...any) error {
	*dest[0].(*string) = "t-acme"
	*dest[1].(*cryptowire.UUID) = cryptowire.NewUUID()
	*dest[2].(*cryptowire.UUID) = cryptowire.NewUUID()
	*dest[3].(*cryptowire.UUID) = cryptowire.NewUUID()
	*dest[4].(*int64) = 1
	*dest[5].(*string) = "not a digest" // so every row counts as unverified
	return nil
}

func (r *cutRows) Err() error { return r.err }
func (r *cutRows) Close()     {}

type verifies struct{}

func (verifies) Verify(blob.Receipt) error { return nil }

// TestScanCutShort covers review v4 F10: a blob-verification scan that ends
// with an error fails reconciliation instead of reporting the blobs it
// reached, so admission is not reopened over blobs nobody checked.
func TestScanCutShort(t *testing.T) {
	cut := errors.New("connection lost")
	if _, err := unverified(&cutRows{n: 2, err: cut}, verifies{}); !errors.Is(err, cut) {
		t.Fatalf("a scan cut short: %v", err)
	}
	if bad, err := unverified(&cutRows{n: 2}, verifies{}); err != nil || len(bad) != 2 {
		t.Fatalf("a complete scan: %v %v", bad, err)
	}
}
