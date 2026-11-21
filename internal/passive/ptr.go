package passive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Defaults of the reverse DNS source.
const (
	DefaultPTRRate    = 5.0 // lookups per second
	DefaultPTRTimeout = 3 * time.Second
	DefaultPTRMax     = 4096 // addresses per call
)

// Resolver is the part of net.Resolver that the PTR source uses.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// PTRSource asks the system resolver for the PTR records of the known live
// addresses of the scope. The queries go to the resolver that the operating
// system is set to use (normally the organisation's own DNS server), never to
// the scanned hosts.
type PTRSource struct {
	Resolver Resolver      // nil means net.DefaultResolver
	Rate     float64       // lookups per second; 0 means DefaultPTRRate
	Timeout  time.Duration // per lookup; 0 means DefaultPTRTimeout
	Max      int           // most addresses per call; 0 means DefaultPTRMax
	// Now is the clock of LastSeen. Nil means time.Now.
	Now func() time.Time

	// Stats of the last Collect.
	Asked, Answered, Failed int
}

func (p *PTRSource) Name() string   { return "ptr" }
func (p *PTRSource) External() bool { return false }

// Collect looks up scope.KnownIPs that lie inside the scope, in address
// order, at most Rate lookups per second. An address without a PTR record is
// not an error.
func (p *PTRSource) Collect(ctx context.Context, scope Scope) ([]Fact, error) {
	res := p.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	rate, timeout, max := p.Rate, p.Timeout, p.Max
	if rate <= 0 {
		rate = DefaultPTRRate
	}
	if timeout <= 0 {
		timeout = DefaultPTRTimeout
	}
	if max <= 0 {
		max = DefaultPTRMax
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	seen := map[netip.Addr]bool{}
	var ips []netip.Addr
	for _, a := range scope.KnownIPs {
		a = a.Unmap()
		if !seen[a] && scope.ContainsIP(a) {
			seen[a] = true
			ips = append(ips, a)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	var truncated error
	if len(ips) > max {
		truncated = fmt.Errorf("zapytano o pierwsze %d z %d adresów", max, len(ips))
		ips = ips[:max]
	}

	p.Asked, p.Answered, p.Failed = 0, 0, 0
	interval := time.Duration(float64(time.Second) / rate)
	var facts []Fact
	var lastErr error
	var next time.Time
	for _, a := range ips {
		// Rate limit: one lookup per interval.
		if wait := time.Until(next); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return facts, ctx.Err()
			case <-t.C:
			}
		}
		next = time.Now().Add(interval)
		if err := ctx.Err(); err != nil {
			return facts, err
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		names, err := res.LookupAddr(lctx, a.String())
		cancel()
		p.Asked++
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				continue // no PTR record
			}
			p.Failed++
			lastErr = err
			continue
		}
		got := false
		for _, n := range names {
			h, _, ok := cleanHost(n)
			if !ok {
				continue
			}
			got = true
			facts = append(facts, Fact{Kind: KindPTR, IP: a.String(), Hostname: h, Source: p.Name(), LastSeen: now().UTC()})
		}
		if got {
			p.Answered++
		}
	}
	if p.Failed > 0 {
		return facts, fmt.Errorf("odwrotny DNS: %d z %d zapytań nieudanych, ostatni błąd: %w", p.Failed, p.Asked, lastErr)
	}
	return facts, truncated
}
