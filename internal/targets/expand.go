package targets

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func invalid(line int, value, reason string) model.InvalidLine {
	return model.InvalidLine{Line: line, Value: value, Reason: reason}
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 120 {
		b = append(b[:117], '.', '.', '.')
	}
	return string(b)
}

// Resolver resolves a host name. *net.Resolver implements it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Static is the part of a target list that needs no DNS.
type Static struct {
	V4      Set
	V6      []netip.Addr
	Domains []string
	Invalid []model.InvalidLine // values that do not parse (index in the input as Line)
}

// Build turns target values into an address set. Overlapping targets are merged.
func Build(values []string) Static {
	var st Static
	var rs []Range
	seen6 := map[netip.Addr]bool{}
	seenD := map[string]bool{}
	for i, v := range values {
		p, err := ParseValue(v)
		if err != nil {
			st.Invalid = append(st.Invalid, invalid(i+1, v, err.Error()))
			continue
		}
		switch {
		case p.Kind == model.TargetDomain:
			if !seenD[p.Domain] {
				seenD[p.Domain] = true
				st.Domains = append(st.Domains, p.Domain)
			}
		case p.V6.IsValid():
			if !seen6[p.V6] {
				seen6[p.V6] = true
				st.V6 = append(st.V6, p.V6)
			}
		default:
			rs = append(rs, p.Range)
		}
	}
	st.V4 = NewSet(rs...)
	return st
}

func values(ts []model.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Value
	}
	return out
}

// Count returns the number of distinct addresses of the targets and how many
// of them the exclusions remove. It sends nothing: a domain counts as one
// address. A /8 is counted in constant time.
func Count(ts []model.Target, exclusions []string) (total, excluded int64) {
	st := Build(values(ts))
	ex := Build(exclusions)
	total = st.V4.Count() + int64(len(st.V6)) + int64(len(st.Domains))
	left := st.V4.Subtract(ex.V4).Count()
	excluded = st.V4.Count() - left
	exd := map[string]bool{}
	for _, d := range ex.Domains {
		exd[d] = true
	}
	for _, d := range st.Domains {
		if exd[d] {
			excluded++
		}
	}
	ex6 := map[netip.Addr]bool{}
	for _, a := range ex.V6 {
		ex6[a] = true
	}
	for _, a := range st.V6 {
		if ex6[a] {
			excluded++
		}
	}
	return total, excluded
}

// Preview parses free text and counts addresses against the exclusions.
func Preview(text string, exclusions []string) model.TargetPreview {
	return PreviewOf(ParseText(text), exclusions)
}

// PreviewOf builds the API preview from a parse result.
func PreviewOf(res ParseResult, exclusions []string) model.TargetPreview {
	total, excluded := Count(res.Targets, exclusions)
	return model.TargetPreview{
		Valid:        res.Targets,
		Invalid:      res.Invalid,
		Duplicates:   res.Duplicates,
		Excluded:     excluded,
		AddressCount: total - excluded,
	}
}

// Expanded is the resolved scan scope of a run.
type Expanded struct {
	V4         Set                 // IPv4 addresses to scan, exclusions removed
	V6         []netip.Addr        // single IPv6 addresses to scan
	Hostnames  map[string][]string // IP → names of the domain targets that resolve to it
	Unresolved map[string]string   // domain → error text
	Exclusions Set                 // the IPv4 exclusion set (resolved exclusion domains included)
	Total      int64               // addresses before exclusions
	Excluded   int64               // addresses removed by exclusions
}

// Count is the number of addresses to scan.
func (e Expanded) Count() int64 { return e.V4.Count() + int64(len(e.V6)) }

// Expand builds the scan scope: it merges the targets, resolves domains
// (A records, also AAAA when wantV6 is set) with a timeout per name, and
// subtracts the exclusions (IPs, CIDRs, ranges and domains).
func Expand(ctx context.Context, ts []model.Target, exclusions []string, res Resolver, timeout time.Duration) Expanded {
	if res == nil {
		res = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	st := Build(values(ts))
	ex := Build(exclusions)
	out := Expanded{Hostnames: map[string][]string{}, Unresolved: map[string]string{}}

	exDomain := map[string]bool{}
	for _, d := range ex.Domains {
		exDomain[d] = true
	}
	var domains []string
	for _, d := range st.Domains {
		if exDomain[d] {
			out.Total++
			out.Excluded++
			continue
		}
		domains = append(domains, d)
	}

	// Resolve target domains and exclusion domains together.
	type answer struct {
		ips []net.IP
		err error
	}
	names := append(append([]string{}, domains...), ex.Domains...)
	answers := make([]answer, len(names))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ips, err := res.LookupIP(c, "ip4", name)
			answers[i] = answer{ips, err}
		}()
	}
	wg.Wait()

	exRanges := append([]Range{}, ex.V4.Ranges()...)
	for i := len(domains); i < len(names); i++ {
		for _, ip := range answers[i].ips {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
				u := U32(a)
				exRanges = append(exRanges, Range{u, u})
			}
		}
	}
	exSet := NewSet(exRanges...)

	rs := append([]Range{}, st.V4.Ranges()...)
	for i, d := range domains {
		a := answers[i]
		if a.err != nil || len(a.ips) == 0 {
			msg := "brak rekordu A"
			if a.err != nil {
				msg = a.err.Error()
			}
			out.Unresolved[d] = msg
			continue
		}
		for _, ip := range a.ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok || !addr.Unmap().Is4() {
				continue
			}
			u := U32(addr)
			rs = append(rs, Range{u, u})
			key := addr.Unmap().String()
			if !contains(out.Hostnames[key], d) {
				out.Hostnames[key] = append(out.Hostnames[key], d)
			}
		}
	}
	for k := range out.Hostnames {
		sort.Strings(out.Hostnames[k])
	}
	all := NewSet(rs...)
	out.Exclusions = exSet
	out.V4 = all.Subtract(exSet)
	out.Total += all.Count() + int64(len(st.V6)) + int64(len(out.Unresolved))
	out.Excluded += all.Count() - out.V4.Count()

	ex6 := map[netip.Addr]bool{}
	for _, a := range ex.V6 {
		ex6[a] = true
	}
	for _, a := range st.V6 {
		if ex6[a] {
			out.Excluded++
			continue
		}
		out.V6 = append(out.V6, a)
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
