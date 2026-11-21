package analyze

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// MergeHostResults joins the results of one run that name the same address.
// The engine can report an address twice when a chunk is scanned again after
// a resume. The caller (the result sink) uses it before it records
// observations, so one run gives one observation per host.
//
// Rules: the host is up when any result is up; services are joined by
// port/proto, an open service wins over a closed one, and the later result
// wins between two equal states; hostnames are joined; Attempts is the
// largest value; ObservedAt and the other host fields come from the latest
// result that answered. The order of first appearance is kept.
func MergeHostResults(results []model.HostResult) []model.HostResult {
	idx := make(map[string]int, len(results))
	out := make([]model.HostResult, 0, len(results))
	for _, r := range results {
		key := normIP(r.IP)
		k, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, r)
			continue
		}
		out[k] = mergeHost(out[k], r)
	}
	return out
}

func normIP(s string) string {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

func mergeHost(a, b model.HostResult) model.HostResult {
	base, other := a, b
	switch {
	case b.Up && !a.Up:
		base, other = b, a
	case a.Up == b.Up && b.ObservedAt.After(a.ObservedAt):
		base, other = b, a
	}
	out := base
	out.IP = a.IP // the address as first reported
	out.Up = a.Up || b.Up
	out.Attempts = max(a.Attempts, b.Attempts)
	out.Hostnames = joinStrings(base.Hostnames, other.Hostnames)
	svc := make(map[string]int, len(base.Services)+len(other.Services))
	out.Services = make([]model.ServiceResult, 0, len(base.Services)+len(other.Services))
	add := func(s model.ServiceResult, preferNew bool) {
		k := svcKey(&s)
		i, ok := svc[k]
		if !ok {
			svc[k] = len(out.Services)
			out.Services = append(out.Services, s)
			return
		}
		cur := &out.Services[i]
		switch {
		case isOpen(&s) && !isOpen(cur):
			*cur = s
		case isOpen(&s) == isOpen(cur) && preferNew:
			*cur = s
		}
	}
	// The older result first, so the newer one wins between equal states.
	first, second := a, b
	if a.ObservedAt.After(b.ObservedAt) {
		first, second = b, a
	}
	for _, s := range first.Services {
		add(s, false)
	}
	for _, s := range second.Services {
		add(s, true)
	}
	return out
}

func joinStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ObservationKey is the key under which one run records one host: the
// sink records an observation only once per key.
func ObservationKey(runID int64, ip string) string {
	return strconv.FormatInt(runID, 10) + "|" + normIP(ip)
}
