package labcfg

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

// Favicon builds a deterministic 16x16 32-bit ICO file from a seed. The lab
// cannot ship vendor favicons, so every imitation gets its own stable icon
// and the ground truth records its hashes.
func Favicon(seed string) []byte {
	h := sha256.Sum256([]byte("czujka-lab-favicon|" + seed))
	fg := [4]byte{h[0], h[1], h[2], 0xff} // BGRA
	bg := [4]byte{0xf4, 0xf4, 0xf4, 0xff}
	const n = 16
	var buf bytes.Buffer
	// ICONDIR
	binary.Write(&buf, binary.LittleEndian, []uint16{0, 1, 1})
	// ICONDIRENTRY
	xorSize := n * n * 4
	andSize := n * 4 // 16 rows, each padded to 4 bytes
	buf.Write([]byte{n, n, 0, 0})
	binary.Write(&buf, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&buf, binary.LittleEndian, []uint32{uint32(40 + xorSize + andSize), 22})
	// BITMAPINFOHEADER (height is doubled: XOR + AND bitmap)
	binary.Write(&buf, binary.LittleEndian, []uint32{40, n, 2 * n})
	binary.Write(&buf, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&buf, binary.LittleEndian, []uint32{0, uint32(xorSize + andSize), 0, 0, 0, 0})
	// Pixels: an 8x8 mirrored pattern scaled by 2 (identicon style).
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			cx, cy := x/2, y/2
			if cx > 3 {
				cx = 7 - cx
			}
			bit := h[4+cy] >> (uint(cx)) & 1
			if bit == 1 {
				buf.Write(fg[:])
			} else {
				buf.Write(bg[:])
			}
		}
	}
	buf.Write(make([]byte, andSize))
	return buf.Bytes()
}

// FaviconSHA256 is the hex SHA-256 of the icon bytes.
func FaviconSHA256(icon []byte) string {
	s := sha256.Sum256(icon)
	return hex.EncodeToString(s[:])
}

// FaviconMMH3 is the Shodan-style favicon hash: MurmurHash3 (x86, 32 bit,
// seed 0) of the base64 text with a newline after every 76 characters, as a
// signed integer.
func FaviconMMH3(icon []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(icon)
	var b bytes.Buffer
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return int32(Murmur3(b.Bytes(), 0))
}

// Murmur3 is MurmurHash3_x86_32.
func Murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	tail := data[n*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
