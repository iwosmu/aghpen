package runner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

// LookupFunc resolves a host name to its addresses.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultLookup resolves with the system resolver.
func DefaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ParseAllowed parses the allowed networks of the safety policy (CIDRs or
// single addresses). An empty list means "no restriction".
func ParseAllowed(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "/") {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("%q nie jest siecią CIDR ani adresem IP", v)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("%q nie jest siecią CIDR", v)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func addrAllowed(a netip.Addr, nets []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// TargetAllowed reports whether every address of a target lies inside the
// allowed networks. A domain is resolved and each of its addresses must be
// allowed; a name that does not resolve is not allowed. reason is Polish.
// An empty nets list allows everything.
func TargetAllowed(ctx context.Context, t model.Target, nets []netip.Prefix, lookup LookupFunc) (ok bool, reason string) {
	if len(nets) == 0 {
		return true, ""
	}
	if m := targets.MapsTo(t.Value); m != "" {
		// A loopback target is scanned as the docker host: check that address.
		t = model.Target{Kind: model.TargetIP, Value: m}
	}
	outside := "poza dozwolonymi sieciami polityki bezpieczeństwa"
	switch t.Kind {
	case model.TargetIP:
		a, err := netip.ParseAddr(t.Value)
		if err == nil && addrAllowed(a, nets) {
			return true, ""
		}
		return false, outside
	case model.TargetCIDR:
		tp, err := netip.ParsePrefix(t.Value)
		if err != nil {
			return false, outside
		}
		tp = tp.Masked()
		for _, p := range nets {
			if p.Addr().BitLen() == tp.Addr().BitLen() && p.Bits() <= tp.Bits() && p.Contains(tp.Addr()) {
				return true, ""
			}
		}
		return false, outside + " (sieć musi leżeć w całości w jednej z dozwolonych sieci)"
	case model.TargetRange:
		a, b, _ := strings.Cut(t.Value, "-")
		from, err1 := netip.ParseAddr(strings.TrimSpace(a))
		to, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil {
			return false, outside
		}
		for _, p := range nets {
			if p.Contains(from.Unmap()) && p.Contains(to.Unmap()) {
				return true, ""
			}
		}
		return false, outside + " (zakres musi leżeć w całości w jednej z dozwolonych sieci)"
	case model.TargetDomain:
		if lookup == nil {
			lookup = DefaultLookup
		}
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addrs, err := lookup(lctx, t.Value)
		if err != nil || len(addrs) == 0 {
			return false, "nazwa się nie rozwiązuje, więc nie można sprawdzić dozwolonych sieci polityki bezpieczeństwa"
		}
		// The engine scans a name on its IPv4 addresses (A records): those
		// must be allowed. An AAAA answer is not scanned, so it is not
		// checked (Docker Desktop answers host.docker.internal with IPv6 first).
		v4 := IPv4Of(addrs)
		if len(v4) == 0 {
			return false, "nazwa nie ma adresu IPv4 (rekordu A); Czujka skanuje nazwy po adresach IPv4"
		}
		for _, a := range v4 {
			if !addrAllowed(a, nets) {
				return false, fmt.Sprintf("%s (nazwa wskazuje na %s)", outside, a)
			}
		}
		return true, ""
	}
	return false, outside
}

// FilterAllowed keeps the targets that lie inside the allowed networks of the
// policy and returns the dropped ones with their reasons.
//
// The operator lock (policy.OperatorNetworks, from CZUJKA_ALLOWED_NETWORKS)
// is checked first and in addition: a target must lie inside both lists.
func FilterAllowed(ctx context.Context, targets []model.Target, policy model.SafetyPolicy, lookup LookupFunc) (kept []model.Target, dropped []model.InvalidLine, err error) {
	op, err := ParseAllowed(policy.OperatorNetworks)
	if err != nil {
		return nil, nil, err
	}
	nets, err := ParseAllowed(policy.AllowedNetworks)
	if err != nil {
		return nil, nil, err
	}
	if len(op) == 0 && len(nets) == 0 {
		return targets, nil, nil
	}
	for i, t := range targets {
		ok, why := TargetAllowed(ctx, t, op, lookup)
		if !ok {
			why = OperatorReason(why)
		} else {
			ok, why = TargetAllowed(ctx, t, nets, lookup)
		}
		if ok {
			kept = append(kept, t)
		} else {
			dropped = append(dropped, model.InvalidLine{Line: i + 1, Value: t.Value, Reason: why})
		}
	}
	return kept, dropped, nil
}

// OperatorReason turns a refusal of TargetAllowed into the Polish text for the operator lock.
func OperatorReason(why string) string {
	const policy = "dozwolonymi sieciami polityki bezpieczeństwa"
	if strings.Contains(why, policy) {
		return strings.ReplaceAll(why, policy, "blokadą operatora")
	}
	return why + " (blokada operatora)"
}

// PrefixInside reports whether p lies wholly inside one of nets.
func PrefixInside(p netip.Prefix, nets []netip.Prefix) bool {
	p = p.Masked()
	for _, q := range nets {
		if q.Addr().BitLen() == p.Addr().BitLen() && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// IPv4Of returns the IPv4 addresses of a lookup answer, unmapped, in order,
// without duplicates.
func IPv4Of(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
