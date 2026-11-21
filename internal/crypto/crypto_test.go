package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestRoundTripAndBinding(t *testing.T) {
	kr, err := NewKeyring(key(1))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := kr.EncryptString("sekret-analityka", "hosts|note|7")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tok, "sekret") || !IsToken(tok) || TokenKeyID(tok) != kr.CurrentID() {
		t.Fatalf("bad token %q", tok)
	}
	got, err := kr.DecryptString(tok, "hosts|note|7")
	if err != nil || got != "sekret-analityka" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := kr.DecryptString(tok, "hosts|note|8"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a token moved to another row must not decrypt, got %v", err)
	}
	tok2, _ := kr.EncryptString("sekret-analityka", "hosts|note|7")
	if tok == tok2 {
		t.Fatal("two encryptions of the same text must differ (fresh data key and nonce)")
	}
	if e, _ := kr.EncryptString("", "x"); e != "" {
		t.Fatal("empty string must stay empty")
	}
}

func TestTamperDetection(t *testing.T) {
	kr, _ := NewKeyring(key(1))
	tok, _ := kr.EncryptString("abc", "ad")
	p := strings.Split(tok, ".")
	raw, _ := b64.DecodeString(p[3])
	raw[len(raw)-1] ^= 1
	p[3] = b64.EncodeToString(raw)
	if _, err := kr.DecryptString(strings.Join(p, "."), "ad"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext must fail, got %v", err)
	}
	if _, err := kr.DecryptString("not-a-token", "ad"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("garbage must fail, got %v", err)
	}
}

func TestRotation(t *testing.T) {
	oldKR, _ := NewKeyring(key(1))
	tok, _ := oldKR.EncryptString("klucz-api-defectdojo", "settings|defectdojo")

	newOnly, _ := NewKeyring(key(2))
	if _, err := newOnly.DecryptString(tok, "settings|defectdojo"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}

	rot, _ := NewKeyring(key(2), key(1))
	if got, err := rot.DecryptString(tok, "settings|defectdojo"); err != nil || got != "klucz-api-defectdojo" {
		t.Fatalf("old key must still decrypt: %q %v", got, err)
	}
	re, changed, err := rot.Rewrap(tok, "settings|defectdojo")
	if err != nil || !changed || TokenKeyID(re) != KeyID(key(2)) {
		t.Fatalf("rewrap: changed=%v err=%v id=%s", changed, err, TokenKeyID(re))
	}
	if strings.Split(re, ".")[3] != strings.Split(tok, ".")[3] {
		t.Fatal("rewrap must not touch the data ciphertext")
	}
	if got, err := newOnly.DecryptString(re, "settings|defectdojo"); err != nil || got != "klucz-api-defectdojo" {
		t.Fatalf("new key alone must decrypt after rewrap: %q %v", got, err)
	}
	if _, changed, _ := rot.Rewrap(re, "settings|defectdojo"); changed {
		t.Fatal("second rewrap must be a no-op")
	}
	if _, _, err := rot.Rewrap(tok, "settings|other"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("rewrap with wrong associated data must fail, got %v", err)
	}
}

func TestParseKeyAndKeyFile(t *testing.T) {
	g, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k, err := ParseKey(g); err != nil || len(k) != KeySize {
		t.Fatalf("generated key must parse: %v", err)
	}
	if _, err := ParseKey(strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("hex key must parse: %v", err)
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("short key must be rejected")
	}
	if _, _, err := LoadKeyring("", "", nil); err == nil {
		t.Fatal("missing key must be an error")
	}
	path := filepath.Join(t.TempDir(), "keys", "master.key")
	kr1, created, err := LoadKeyring("", path, nil)
	if err != nil || !created {
		t.Fatalf("key file must be created: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", st.Mode().Perm())
	}
	kr2, created, err := LoadKeyring("", path, nil)
	if err != nil || created || kr1.CurrentID() != kr2.CurrentID() {
		t.Fatalf("key file must be reused: %v", err)
	}
}
