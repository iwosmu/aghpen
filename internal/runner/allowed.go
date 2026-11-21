package runner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
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
		for _, a := range addrs {
			if !addrAllowed(a, nets) {
				return false, fmt.Sprintf("%s (nazwa wskazuje na %s)", outside, a.Unmap())
			}
		}
		return true, ""
	}
	return false, outside
}

// FilterAllowed keeps the targets that lie inside the allowed networks of the
// policy and returns the dropped ones with their reasons.
func FilterAllowed(ctx context.Context, targets []model.Target, policy model.SafetyPolicy, lookup LookupFunc) (kept []model.Target, dropped []model.InvalidLine, err error) {
	nets, err := ParseAllowed(policy.AllowedNetworks)
	if err != nil {
		return nil, nil, err
	}
	if len(nets) == 0 {
		return targets, nil, nil
	}
	for i, t := range targets {
		if ok, why := TargetAllowed(ctx, t, nets, lookup); ok {
			kept = append(kept, t)
		} else {
			dropped = append(dropped, model.InvalidLine{Line: i + 1, Value: t.Value, Reason: why})
		}
	}
	return kept, dropped, nil
}
