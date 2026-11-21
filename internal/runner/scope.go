package runner

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

// Ad-hoc runs (POST /runs/adhoc, the re-probe executor, czujka reprobe) take
// addresses from the caller, not from a scope. A caller with scans:run only
// must not reach an address that no user with targets:create put into an
// enabled target, so every ad-hoc address is checked against the enabled
// targets of all scopes. Addresses are compared as they are scanned: a
// loopback value counts as the docker host address (targets.MapsTo) and a
// domain target counts as its IPv4 addresses.

// maxScopeLookups bounds the DNS lookups of one check.
const maxScopeLookups = 64

// span is the inclusive address range a target is scanned as.
type span struct{ from, to netip.Addr }

func (s span) inside(o span) bool {
	return s.from.BitLen() == o.from.BitLen() && s.from.Compare(o.from) >= 0 && s.to.Compare(o.to) <= 0
}

// spanOf returns the range a target is scanned as; ok is false for a domain
// (resolved separately) or an unparsable value.
func spanOf(t model.Target) (span, bool) {
	if m := targets.MapsTo(t.Value); m != "" {
		if a, err := netip.ParseAddr(m); err == nil {
			return span{a, a}, true
		}
	}
	switch t.Kind {
	case model.TargetIP:
		if a, err := netip.ParseAddr(strings.TrimSpace(t.Value)); err == nil {
			return span{a.Unmap(), a.Unmap()}, true
		}
	case model.TargetCIDR:
		if p, err := netip.ParsePrefix(strings.TrimSpace(t.Value)); err == nil {
			p = p.Masked()
			return span{p.Addr().Unmap(), lastOf(p)}, true
		}
	case model.TargetRange:
		x, y, _ := strings.Cut(t.Value, "-")
		from, e1 := netip.ParseAddr(strings.TrimSpace(x))
		to, e2 := netip.ParseAddr(strings.TrimSpace(y))
		if e1 == nil && e2 == nil {
			return span{from.Unmap(), to.Unmap()}, true
		}
	}
	return span{}, false
}

func lastOf(p netip.Prefix) netip.Addr {
	b := p.Addr().Unmap().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// outsideTargets returns the ad-hoc targets that do not lie wholly inside
// one enabled target. Domains of enabled targets are resolved only when an
// address is not covered otherwise.
func (m *Manager) outsideTargets(ctx context.Context, adhoc []model.Target) ([]model.InvalidLine, error) {
	enabled, err := m.st.EnabledTargets(ctx, nil)
	if err != nil {
		return nil, err
	}
	var spans []span
	var domains []string
	for _, t := range enabled {
		if s, ok := spanOf(t); ok {
			spans = append(spans, s)
		} else if t.Kind == model.TargetDomain {
			domains = append(domains, t.Value)
		}
	}
	covered := func(s span) bool {
		for _, o := range spans {
			if s.inside(o) {
				return true
			}
		}
		return false
	}
	resolved := false
	var out []model.InvalidLine
	for i, t := range adhoc {
		s, ok := spanOf(t)
		if ok && covered(s) {
			continue
		}
		if ok && !resolved && len(domains) > 0 {
			resolved = true
			lookup := m.opt.Lookup
			if lookup == nil {
				lookup = DefaultLookup
			}
			for j, d := range domains {
				if j == maxScopeLookups {
					break
				}
				lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				addrs, err := lookup(lctx, d)
				cancel()
				if err != nil {
					continue
				}
				for _, a := range IPv4Of(addrs) {
					spans = append(spans, span{a, a})
				}
			}
			if covered(s) {
				continue
			}
		}
		out = append(out, model.InvalidLine{Line: i + 1, Value: t.Value,
			Reason: "Adres nie leży w żadnym włączonym celu."})
	}
	return out, nil
}

// checkAdHocScope fails with ErrInvalid when an ad-hoc target lies outside
// the enabled targets.
func (m *Manager) checkAdHocScope(ctx context.Context, adhoc []model.Target) error {
	out, err := m.outsideTargets(ctx, adhoc)
	if err != nil {
		return err
	}
	if len(out) > 0 {
		msg := out[0].Value + ": " + out[0].Reason
		if len(out) > 1 {
			msg += fmt.Sprintf(" (i %d innych)", len(out)-1)
		}
		return fmt.Errorf("%w: %s", ErrInvalid, msg)
	}
	return nil
}

// KeepInTargets returns the single addresses of addrs that lie inside an
// enabled target, in order (the re-probe executor drops the others, such as
// hosts that only an import or a manual entry knows).
func (m *Manager) KeepInTargets(ctx context.Context, addrs []string) ([]string, error) {
	var ts []model.Target
	for _, v := range addrs {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		ts = append(ts, model.Target{Kind: model.TargetIP, Value: a.Unmap().String(), Addresses: 1})
	}
	out, err := m.outsideTargets(ctx, ts)
	if err != nil {
		return nil, err
	}
	drop := map[int]bool{}
	for _, d := range out {
		drop[d.Line-1] = true
	}
	kept := make([]string, 0, len(ts))
	for i, t := range ts {
		if !drop[i] {
			kept = append(kept, t.Value)
		}
	}
	return kept, nil
}
