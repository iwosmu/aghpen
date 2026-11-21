package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, _ := GenerateKey()
	kr, _, err := LoadKeyring(k, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestBackupRoundTripAndTamper(t *testing.T) {
	kr := testKeyring(t)
	data := make([]byte, 3*backupChunk+12345)
	_, _ = rand.Read(data)
	var arch bytes.Buffer
	w, err := kr.BackupWriter(&arch, map[string]string{"version": "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data); i += 70000 {
		_, _ = w.Write(data[i:min(i+70000, len(data))])
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(arch.Bytes(), data[:64]) {
		t.Fatal("the archive holds clear text")
	}
	r, h, err := kr.BackupReader(bytes.NewReader(arch.Bytes()))
	if err != nil || h.KeyID != kr.CurrentID() || h.Meta["version"] != "test" {
		t.Fatalf("open: %+v %v", h, err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %d bytes, %v", len(got), err)
	}

	read := func(b []byte) error {
		r, _, err := kr.BackupReader(bytes.NewReader(b))
		if err != nil {
			return err
		}
		_, err = io.ReadAll(r)
		return err
	}
	raw := arch.Bytes()
	cut := raw[:len(raw)-backupChunk/2]
	if err := read(cut); err == nil {
		t.Error("a cut archive must fail")
	}
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)/2] ^= 1
	if err := read(flipped); err == nil {
		t.Error("a changed byte must fail")
	}
	if err := read(append(append([]byte(nil), raw...), 0, 0, 0, 1)); err == nil {
		t.Error("data after the last chunk must fail")
	}
	// Dropping the last chunk: the stream ends without the final marker.
	w2buf := bytes.Buffer{}
	w2, _ := kr.BackupWriter(&w2buf, nil)
	_, _ = w2.Write(bytes.Repeat([]byte("x"), backupChunk)) // one full chunk sealed, not last
	if err := read(w2buf.Bytes()); err == nil {
		t.Error("an archive without its last chunk must fail")
	}
	// Another master key does not open it; an old key in the keyring does.
	other := testKeyring(t)
	if _, _, err := other.BackupReader(bytes.NewReader(raw)); !errors.Is(err, ErrBackupKey) {
		t.Errorf("another key: %v", err)
	}
	nk, _ := GenerateKey()
	cur, _ := ParseKey(nk)
	rotated, _ := NewKeyring(cur, kr.raw[kr.CurrentID()])
	if err := read2(rotated, raw, data); err != nil {
		t.Errorf("after a rotation the old key in the keyring opens old archives: %v", err)
	}
}

func read2(kr *Keyring, raw, want []byte) error {
	r, _, err := kr.BackupReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	got, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("content differs")
	}
	return nil
}
