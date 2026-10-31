package backupcrypt

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestSealOpen(t *testing.T) {
	raw, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	k, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("catalog row\n"), 300_000)
	var ct bytes.Buffer
	w, _ := k.Seal(&ct, []byte("catalog/identities.copy"))
	_, _ = w.Write(plain)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	open := func(b, aad []byte) ([]byte, error) {
		r, err := k.Open(bytes.NewReader(b), aad)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}
	if got, err := open(ct.Bytes(), []byte("catalog/identities.copy")); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	if _, err := open(ct.Bytes(), []byte("catalog/delegations.copy")); err == nil {
		t.Error("a file opened under another name")
	}
	if _, err := open(ct.Bytes()[:ct.Len()-1], []byte("catalog/identities.copy")); err == nil {
		t.Error("a truncated file opened")
	}
	other, _ := Generate()
	k2, _ := Load(other)
	if r, err := k2.Open(bytes.NewReader(ct.Bytes()), []byte("catalog/identities.copy")); err == nil {
		if _, err := io.ReadAll(r); err == nil {
			t.Error("another key opened the file")
		}
	}
	if _, err := Load([]byte("not a keyset")); !errors.Is(err, ErrKey) {
		t.Errorf("load garbage: %v", err)
	}
}
