// Package targets parses scan targets (IP, CIDR, range, domain), counts and
// expands them without materialising every address, subtracts exclusions and
// resolves domain names.
package targets

import (
	"fmt"
	"net/netip"
	"sort"
)

// Range is an inclusive range of IPv4 addresses in host byte order.
type Range struct {
	Lo, Hi uint32
}

// Size is the number of addresses in the range.
func (r Range) Size() int64 { return int64(r.Hi) - int64(r.Lo) + 1 }

// Set is a normalised set of IPv4 addresses: sorted, merged, non-adjacent
// ranges. The zero value is the empty set. A /8 costs one Range.
type Set struct {
	r []Range
}

// NewSet builds a set from any ranges (overlaps and duplicates are merged).
func NewSet(rs ...Range) Set {
	if len(rs) == 0 {
		return Set{}
	}
	cp := make([]Range, 0, len(rs))
	for _, r := range rs {
		if r.Lo > r.Hi {
			r.Lo, r.Hi = r.Hi, r.Lo
		}
		cp = append(cp, r)
	}
	sort.Slice(cp, func(i, j int) bool { return cp[i].Lo < cp[j].Lo })
	out := cp[:1]
	for _, r := range cp[1:] {
		last := &out[len(out)-1]
		// merge when overlapping or adjacent (careful with overflow at 255.255.255.255)
		if r.Lo <= last.Hi || (last.Hi != ^uint32(0) && r.Lo == last.Hi+1) {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return Set{r: out}
}

// Ranges returns the merged ranges in address order. Do not modify the result.
func (s Set) Ranges() []Range { return s.r }

// IsEmpty reports whether the set has no address.
func (s Set) IsEmpty() bool { return len(s.r) == 0 }

// Count returns the number of addresses without expanding them.
func (s Set) Count() int64 {
	var n int64
	for _, r := range s.r {
		n += r.Size()
	}
	return n
}

// Contains reports whether ip is in the set.
func (s Set) Contains(ip uint32) bool {
	i := sort.Search(len(s.r), func(i int) bool { return s.r[i].Hi >= ip })
	return i < len(s.r) && s.r[i].Lo <= ip
}

// Union returns s ∪ o.
func (s Set) Union(o Set) Set {
	all := make([]Range, 0, len(s.r)+len(o.r))
	all = append(all, s.r...)
	all = append(all, o.r...)
	return NewSet(all...)
}

// Subtract returns s minus o.
func (s Set) Subtract(o Set) Set {
	if len(o.r) == 0 || len(s.r) == 0 {
		return s
	}
	var out []Range
	j := 0
	for _, r := range s.r {
		lo := uint64(r.Lo)
		hi := uint64(r.Hi)
		for j < len(o.r) && uint64(o.r[j].Hi) < lo {
			j++
		}
		k := j
		for k < len(o.r) && uint64(o.r[k].Lo) <= hi {
			ex := o.r[k]
			if uint64(ex.Lo) > lo {
				out = append(out, Range{uint32(lo), ex.Lo - 1})
			}
			lo = uint64(ex.Hi) + 1
			if lo > hi {
				break
			}
			k++
		}
		if lo <= hi {
			out = append(out, Range{uint32(lo), uint32(hi)})
		}
	}
	return Set{r: out}
}

// Blocks calls yield for every /24-aligned block of the set, in address
// order. A block never crosses a /24 boundary; it is a whole /24 or a part of
// one. Iteration stops when yield returns false.
func (s Set) Blocks(yield func(Range) bool) {
	for _, r := range s.r {
		lo := uint64(r.Lo)
		hi := uint64(r.Hi)
		for lo <= hi {
			end := lo | 0xff
			if end > hi {
				end = hi
			}
			if !yield(Range{uint32(lo), uint32(end)}) {
				return
			}
			lo = end + 1
		}
	}
}

// BlockCount returns the number of /24-aligned blocks without iterating addresses.
func (s Set) BlockCount() int64 {
	var n int64
	for _, r := range s.r {
		n += int64(r.Hi>>8) - int64(r.Lo>>8) + 1
	}
	return n
}

// Each calls yield for every address. Use it only on small sets.
func (s Set) Each(yield func(uint32) bool) {
	for _, r := range s.r {
		for ip := uint64(r.Lo); ip <= uint64(r.Hi); ip++ {
			if !yield(uint32(ip)) {
				return
			}
		}
	}
}

// U32 converts an IPv4 address to its numeric value.
func U32(a netip.Addr) uint32 {
	b := a.Unmap().As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Addr converts a numeric value to an IPv4 address.
func Addr(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// IPString formats a numeric IPv4 address.
func IPString(u uint32) string { return Addr(u).String() }

// PrefixRange returns the address range of an IPv4 prefix.
func PrefixRange(p netip.Prefix) Range {
	p = p.Masked()
	lo := U32(p.Addr())
	bits := p.Bits()
	if bits == 0 {
		return Range{0, ^uint32(0)}
	}
	hi := lo | (^uint32(0) >> uint(bits))
	return Range{lo, hi}
}

// CIDRs returns the minimal list of prefixes that covers the range exactly.
func (r Range) CIDRs() []netip.Prefix {
	var out []netip.Prefix
	lo := uint64(r.Lo)
	hi := uint64(r.Hi)
	for lo <= hi {
		// largest block aligned at lo that does not pass hi
		size := uint64(1) << 32
		if lo != 0 {
			size = lo & -lo
		}
		for size > hi-lo+1 {
			size >>= 1
		}
		bits := 32
		for s := size; s > 1; s >>= 1 {
			bits--
		}
		out = append(out, netip.PrefixFrom(Addr(uint32(lo)), bits))
		lo += size
	}
	return out
}

// Spec formats ranges as strings that both nmap and ParseValue accept:
// a single address, a CIDR, or "a.b.c.d-N" for a part of one /24.
func Spec(rs []Range) []string {
	var out []string
	for _, r := range rs {
		switch {
		case r.Lo == r.Hi:
			out = append(out, IPString(r.Lo))
		case r.Lo>>8 == r.Hi>>8 && len(r.CIDRs()) > 1:
			out = append(out, fmt.Sprintf("%s-%d", IPString(r.Lo), r.Hi&0xff))
		default:
			for _, p := range r.CIDRs() {
				if p.Bits() == 32 {
					out = append(out, p.Addr().String())
				} else {
					out = append(out, p.String())
				}
			}
		}
	}
	return out
}
