package httpfp

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/bits"
	"strings"
	"unicode"
)

// FaviconMMH3 is the favicon hash that Shodan, Censys and FOFA use: the
// 32-bit MurmurHash3 (seed 0, signed) of the base64 text of the icon, where
// the base64 text has a newline after every 76 characters and at the end
// (Python's base64.encodebytes).
func FaviconMMH3(icon []byte) int32 {
	return int32(Murmur3(pythonBase64(icon), 0))
}

func pythonBase64(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/76 + 2)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	if len(enc) > 0 {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Murmur3 is MurmurHash3_x86_32.
func Murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data)
	for len(data) >= 4 {
		k := binary.LittleEndian.Uint32(data)
		data = data[4:]
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	switch len(data) {
	case 3:
		k ^= uint32(data[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(data[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(data[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// Simhash computes a 64-bit similarity hash of a text body. Two pages that
// differ in a few words (a CSRF token, a date) get hashes that differ in a
// few bits, so the Hamming distance groups near-duplicates.
func Simhash(text string) uint64 {
	var counts [64]int
	var prev string
	features := 0
	add := func(feature string) {
		h := fnv.New64a()
		h.Write([]byte(feature))
		v := h.Sum64()
		for i := 0; i < 64; i++ {
			if v&(1<<uint(i)) != 0 {
				counts[i]++
			} else {
				counts[i]--
			}
		}
		features++
	}
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		w := strings.ToLower(text[start:end])
		start = -1
		// Long tokens are nonces, hashes or inline data: they would only add noise.
		if len(w) < 2 || len(w) > 24 {
			return
		}
		if prev != "" {
			add(prev + " " + w)
		}
		prev = w
	}
	for i, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(text))
	if features == 0 {
		if prev == "" {
			return 0
		}
		add(prev)
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if counts[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// SimhashHex returns the simhash as 16 hex digits, or "" for an empty body.
func SimhashHex(text string) string {
	if text == "" {
		return ""
	}
	return fmt.Sprintf("%016x", Simhash(text))
}

// SimhashDistance is the Hamming distance of two hex simhashes, or -1 when
// one of them is not a simhash.
func SimhashDistance(a, b string) int {
	var x, y uint64
	if _, err := fmt.Sscanf(a, "%016x", &x); err != nil || len(a) != 16 {
		return -1
	}
	if _, err := fmt.Sscanf(b, "%016x", &y); err != nil || len(b) != 16 {
		return -1
	}
	return bits.OnesCount64(x ^ y)
}
