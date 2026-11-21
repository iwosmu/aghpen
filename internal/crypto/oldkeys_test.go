package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOldKeyFileKeepsRetiredKeysReadable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "master.key")
	kr1, created, err := LoadKeyring("", file, nil)
	if err != nil || !created {
		t.Fatalf("first load: %v %v", created, err)
	}
	tok, err := kr1.EncryptString("tajne", "ad")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	oldKey := string(b)
	// What rotate-key does: retire the old key, write a new one.
	if err := AppendOldKey(file, oldKey); err != nil {
		t.Fatal(err)
	}
	if err := AppendOldKey(file, oldKey); err != nil { // no duplicate
		t.Fatal(err)
	}
	newKey, _ := GenerateKey()
	if err := os.WriteFile(file, []byte(newKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kr2, created, err := LoadKeyring("", file, nil)
	if err != nil || created {
		t.Fatalf("second load: %v %v", created, err)
	}
	if kr2.CurrentID() == kr1.CurrentID() || len(kr2.IDs()) != 2 {
		t.Fatalf("keyring after rotation: current %s ids %v", kr2.CurrentID(), kr2.IDs())
	}
	if got, err := kr2.DecryptString(tok, "ad"); err != nil || got != "tajne" {
		t.Fatalf("a value under the retired key: %q %v", got, err)
	}
	old, _ := readOldKeys(file)
	if len(old) != 1 {
		t.Fatalf("old key file: %v", old)
	}
	if st, _ := os.Stat(OldKeyFile(file)); st.Mode().Perm() != 0o600 {
		t.Fatalf("old key file mode %v", st.Mode().Perm())
	}
	if err := AppendOldKey(file, "nie-klucz"); err == nil {
		t.Fatal("a bad key must be refused")
	}
}
