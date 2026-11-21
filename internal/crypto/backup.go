package crypto

import (
	"bufio"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Encrypted archive (czujka backup): a magic line, one JSON header line, then
// chunks. Each chunk is a 4-byte big-endian length of the sealed bytes, then
// AES-256-GCM output. The key is HKDF-SHA256 of the master key with a random
// salt per archive, so every archive has its own key and the chunk counter
// is a safe nonce. The additional data binds every chunk to the header, its
// position and whether it is the last one: reordering, cutting or appending
// chunks is detected.

// BackupMagic is the first line of an archive.
const BackupMagic = "CZUJKA-BACKUP v1"

const backupChunk = 1 << 20

// BackupHeader is the clear-text header of an archive. It holds no secret.
type BackupHeader struct {
	Format    string            `json:"format"` // "czujka-backup"
	Version   int               `json:"version"`
	KeyID     string            `json:"key_id"` // master key the archive key is derived from
	Salt      []byte            `json:"salt"`
	CreatedAt time.Time         `json:"created_at"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// ErrBackupKey means that no key of the keyring opens the archive.
var ErrBackupKey = errors.New("crypto: the archive was made with another master key")

// DeriveKey returns a 32-byte key for one purpose, derived (HKDF-SHA256) from
// the master key keyID (empty: the current key).
func (k *Keyring) DeriveKey(keyID string, salt []byte, purpose string) ([]byte, error) {
	if keyID == "" {
		keyID = k.current
	}
	master, ok := k.raw[keyID]
	if !ok {
		return nil, ErrBackupKey
	}
	return hkdf.Key(sha256.New, master, salt, "czujka|"+purpose, KeySize)
}

type backupWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	hdrSum [32]byte
	buf    []byte
	n      uint64
	closed bool
}

// BackupWriter returns a writer that encrypts everything written to it into
// an archive on w under the current master key. Close writes the last chunk;
// an archive without it does not open.
func (k *Keyring) BackupWriter(w io.Writer, meta map[string]string) (io.WriteCloser, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h := BackupHeader{Format: "czujka-backup", Version: 1, KeyID: k.current, Salt: salt, CreatedAt: time.Now().UTC(), Meta: meta}
	line, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	key, err := k.DeriveKey(k.current, salt, "backup")
	if err != nil {
		return nil, err
	}
	a, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(w, "%s\n%s\n", BackupMagic, line); err != nil {
		return nil, err
	}
	return &backupWriter{w: w, aead: a, hdrSum: sha256.Sum256(line), buf: make([]byte, 0, backupChunk)}, nil
}

func chunkAD(sum [32]byte, n uint64, last bool) []byte {
	ad := make([]byte, 0, 41)
	ad = append(ad, sum[:]...)
	ad = binary.BigEndian.AppendUint64(ad, n)
	if last {
		return append(ad, 1)
	}
	return append(ad, 0)
}

func chunkNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

func (b *backupWriter) seal(last bool) error {
	out := b.aead.Seal(nil, chunkNonce(b.n), b.buf, chunkAD(b.hdrSum, b.n, last))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(out)))
	if _, err := b.w.Write(l[:]); err != nil {
		return err
	}
	if _, err := b.w.Write(out); err != nil {
		return err
	}
	b.n++
	b.buf = b.buf[:0]
	return nil
}

func (b *backupWriter) Write(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("crypto: write after close")
	}
	n := 0
	for len(p) > 0 {
		room := backupChunk - len(b.buf)
		take := min(room, len(p))
		b.buf = append(b.buf, p[:take]...)
		p, n = p[take:], n+take
		if len(b.buf) == backupChunk {
			if err := b.seal(false); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (b *backupWriter) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.seal(true)
}

type backupReader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	hdrSum [32]byte
	n      uint64
	plain  []byte
	done   bool
}

// ReadBackupHeader reads the magic line and the header of an archive.
func ReadBackupHeader(br *bufio.Reader) (BackupHeader, []byte, error) {
	var h BackupHeader
	magic, err := br.ReadString('\n')
	if err != nil || strings.TrimSpace(magic) != BackupMagic {
		return h, nil, errors.New("crypto: not a Czujka backup archive")
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		return h, nil, errors.New("crypto: the archive header is cut")
	}
	line = line[:len(line)-1]
	if err := json.Unmarshal(line, &h); err != nil || h.Format != "czujka-backup" || h.Version != 1 || len(h.Salt) < 16 {
		return h, nil, errors.New("crypto: the archive header is damaged")
	}
	return h, line, nil
}

// BackupReader opens an archive with the master key it names (current or an
// old key of the keyring) and returns the decrypted stream. A damaged, cut or
// extended archive fails while reading.
func (k *Keyring) BackupReader(r io.Reader) (io.Reader, BackupHeader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	h, line, err := ReadBackupHeader(br)
	if err != nil {
		return nil, h, err
	}
	key, err := k.DeriveKey(h.KeyID, h.Salt, "backup")
	if err != nil {
		return nil, h, fmt.Errorf("%w (key %s; have %s)", ErrBackupKey, h.KeyID, strings.Join(k.IDs(), ", "))
	}
	a, err := newGCM(key)
	if err != nil {
		return nil, h, err
	}
	return &backupReader{r: br, aead: a, hdrSum: sha256.Sum256(line)}, h, nil
}

func (b *backupReader) Read(p []byte) (int, error) {
	for len(b.plain) == 0 {
		if b.done {
			return 0, io.EOF
		}
		var l [4]byte
		if _, err := io.ReadFull(b.r, l[:]); err != nil {
			return 0, errors.New("crypto: the archive is cut (no last chunk)")
		}
		size := binary.BigEndian.Uint32(l[:])
		if size < uint32(b.aead.Overhead()) || size > backupChunk+uint32(b.aead.Overhead()) {
			return 0, errors.New("crypto: the archive is damaged (chunk size)")
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(b.r, sealed); err != nil {
			return 0, errors.New("crypto: the archive is cut")
		}
		plain, err := b.aead.Open(nil, chunkNonce(b.n), sealed, chunkAD(b.hdrSum, b.n, false))
		if err != nil {
			plain, err = b.aead.Open(nil, chunkNonce(b.n), sealed, chunkAD(b.hdrSum, b.n, true))
			if err != nil {
				return 0, errors.New("crypto: the archive is damaged or was changed")
			}
			b.done = true
			if _, err := b.r.ReadByte(); err != io.EOF {
				return 0, errors.New("crypto: data after the last chunk")
			}
		}
		b.n++
		b.plain = plain
	}
	n := copy(p, b.plain)
	b.plain = b.plain[n:]
	return n, nil
}
