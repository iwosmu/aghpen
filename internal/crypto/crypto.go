// Package crypto implements the field-level encryption of Czujka (layer 2 of
// docs/ARCHITECTURE.md §5): AES-256-GCM envelope encryption.
//
// Every record gets its own random 256-bit data key. The data key encrypts the
// plaintext and is itself wrapped by a master key. The token that is stored in
// the database carries the id of the master key, the wrapped data key and the
// ciphertext. Associated data binds a token to its row, so a ciphertext copied
// to another row or column does not decrypt.
//
// Key rotation re-wraps the data keys with a new master key. The data
// ciphertext does not change, so rotation is cheap.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// KeySize is the size of master keys and data keys in bytes.
	KeySize = 32
	prefix  = "czk1"
)

var (
	// ErrUnknownKey means the token was wrapped by a master key that is not in the keyring.
	ErrUnknownKey = errors.New("crypto: master key of this ciphertext is not in the keyring")
	// ErrDecrypt means the token is damaged, or the associated data does not match its row.
	ErrDecrypt = errors.New("crypto: decryption failed")
	b64        = base64.RawURLEncoding
)

// Keyring holds the current master key and older keys that can still decrypt.
type Keyring struct {
	current string
	keys    map[string]cipher.AEAD
}

// ParseKey decodes a master key given as base64 (any alphabet, with or without
// padding) or as 64 hex characters. The key must be exactly 32 bytes.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 2*KeySize {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == KeySize {
			return k, nil
		}
	}
	return nil, fmt.Errorf("crypto: master key must be 32 random bytes as base64 or hex (make one with: openssl rand -base64 32)")
}

// GenerateKey returns a new random master key as base64.
func GenerateKey() (string, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

// KeyID is the public identifier of a master key. It is stored with every ciphertext.
func KeyID(key []byte) string {
	h := sha256.Sum256(append([]byte("czujka-master-key-id:"), key...))
	return hex.EncodeToString(h[:6])
}

// NewKeyring builds a keyring. New data is encrypted with current; old keys only decrypt.
func NewKeyring(current []byte, old ...[]byte) (*Keyring, error) {
	kr := &Keyring{keys: map[string]cipher.AEAD{}}
	for i, k := range append([][]byte{current}, old...) {
		if len(k) != KeySize {
			return nil, fmt.Errorf("crypto: master key %d has %d bytes, want %d", i, len(k), KeySize)
		}
		a, err := newGCM(k)
		if err != nil {
			return nil, err
		}
		id := KeyID(k)
		kr.keys[id] = a
		if i == 0 {
			kr.current = id
		}
	}
	return kr, nil
}

// LoadKeyring builds the keyring from configuration values. key wins over
// keyFile. When only keyFile is given and the file does not exist, a new key is
// generated and written there with mode 0600; created reports that.
func LoadKeyring(key, keyFile string, oldKeys []string) (kr *Keyring, created bool, err error) {
	if key == "" && keyFile != "" {
		b, rerr := os.ReadFile(keyFile)
		switch {
		case rerr == nil:
			key = strings.TrimSpace(string(b))
		case errors.Is(rerr, os.ErrNotExist):
			if key, err = GenerateKey(); err != nil {
				return nil, false, err
			}
			if err = os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
				return nil, false, fmt.Errorf("crypto: create key directory: %w", err)
			}
			if err = os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
				return nil, false, fmt.Errorf("crypto: write key file: %w", err)
			}
			created = true
		default:
			return nil, false, fmt.Errorf("crypto: read key file: %w", rerr)
		}
	}
	if key == "" {
		return nil, false, errors.New("crypto: no master key: set CZUJKA_MASTER_KEY or CZUJKA_MASTER_KEY_FILE")
	}
	cur, err := ParseKey(key)
	if err != nil {
		return nil, false, err
	}
	var old [][]byte
	for _, o := range oldKeys {
		k, err := ParseKey(o)
		if err != nil {
			return nil, false, fmt.Errorf("old master key: %w", err)
		}
		old = append(old, k)
	}
	kr, err = NewKeyring(cur, old...)
	return kr, created, err
}

// CurrentID returns the id of the key that encrypts new data.
func (k *Keyring) CurrentID() string { return k.current }

// IDs returns the ids of every key in the keyring.
func (k *Keyring) IDs() []string {
	out := make([]string, 0, len(k.keys))
	for id := range k.keys {
		out = append(out, id)
	}
	return out
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func wrapAD(keyID, ad string) []byte { return []byte("czujka-dek|" + keyID + "|" + ad) }

// Encrypt seals plaintext under a fresh data key. ad is the associated data
// that names the row and column, for example "findings|note|42".
func (k *Keyring) Encrypt(plaintext []byte, ad string) (string, error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	data, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, data.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := data.Seal(nonce, nonce, plaintext, []byte(ad))
	wrapped, err := k.wrap(k.current, dek, ad)
	if err != nil {
		return "", err
	}
	return prefix + "." + k.current + "." + b64.EncodeToString(wrapped) + "." + b64.EncodeToString(ct), nil
}

func (k *Keyring) wrap(keyID string, dek []byte, ad string) ([]byte, error) {
	master := k.keys[keyID]
	nonce := make([]byte, master.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return master.Seal(nonce, nonce, dek, wrapAD(keyID, ad)), nil
}

type token struct {
	keyID   string
	wrapped []byte
	ct      []byte
}

func parse(tok string) (token, error) {
	p := strings.Split(tok, ".")
	if len(p) != 4 || p[0] != prefix {
		return token{}, ErrDecrypt
	}
	w, err1 := b64.DecodeString(p[2])
	c, err2 := b64.DecodeString(p[3])
	if err1 != nil || err2 != nil {
		return token{}, ErrDecrypt
	}
	return token{keyID: p[1], wrapped: w, ct: c}, nil
}

func (k *Keyring) unwrap(t token, ad string) ([]byte, error) {
	master, ok := k.keys[t.keyID]
	if !ok {
		return nil, fmt.Errorf("%w (key id %s)", ErrUnknownKey, t.keyID)
	}
	ns := master.NonceSize()
	if len(t.wrapped) < ns {
		return nil, ErrDecrypt
	}
	dek, err := master.Open(nil, t.wrapped[:ns], t.wrapped[ns:], wrapAD(t.keyID, ad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Decrypt opens a token made by Encrypt. ad must equal the value given to Encrypt.
func (k *Keyring) Decrypt(tok, ad string) ([]byte, error) {
	t, err := parse(tok)
	if err != nil {
		return nil, err
	}
	dek, err := k.unwrap(t, ad)
	if err != nil {
		return nil, err
	}
	data, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	ns := data.NonceSize()
	if len(t.ct) < ns {
		return nil, ErrDecrypt
	}
	pt, err := data.Open(nil, t.ct[:ns], t.ct[ns:], []byte(ad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// EncryptString encrypts s. The empty string stays empty, so empty fields cost nothing.
func (k *Keyring) EncryptString(s, ad string) (string, error) {
	if s == "" {
		return "", nil
	}
	return k.Encrypt([]byte(s), ad)
}

// DecryptString is the inverse of EncryptString.
func (k *Keyring) DecryptString(tok, ad string) (string, error) {
	if tok == "" {
		return "", nil
	}
	b, err := k.Decrypt(tok, ad)
	return string(b), err
}

// Rewrap moves the data key of a token under the current master key. It
// returns changed = false when the token already uses the current key.
func (k *Keyring) Rewrap(tok, ad string) (out string, changed bool, err error) {
	if tok == "" {
		return "", false, nil
	}
	t, err := parse(tok)
	if err != nil {
		return "", false, err
	}
	if t.keyID == k.current {
		return tok, false, nil
	}
	dek, err := k.unwrap(t, ad)
	if err != nil {
		return "", false, err
	}
	wrapped, err := k.wrap(k.current, dek, ad)
	if err != nil {
		return "", false, err
	}
	return prefix + "." + k.current + "." + b64.EncodeToString(wrapped) + "." + b64.EncodeToString(t.ct), true, nil
}

// TokenKeyID returns the master key id of a token, or "" when s is not a token.
func TokenKeyID(s string) string {
	t, err := parse(s)
	if err != nil {
		return ""
	}
	return t.keyID
}

// IsToken reports whether s looks like a ciphertext token of this package.
func IsToken(s string) bool { return strings.HasPrefix(s, prefix+".") && TokenKeyID(s) != "" }
