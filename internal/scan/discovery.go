package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

// liveBlockGuess is the share of /24 blocks expected to hold a live host
// when the inventory knows nothing about the scope (estimates only).
const liveBlockGuess = 0.25

// discoveryMode normalises DiscoveryOpts.Mode. Empty and unknown values mean balanced.
func discoveryMode(m string) string {
	switch m {
	case model.DiscoveryFast, model.DiscoveryThorough:
		return m
	}
	return model.DiscoveryBalanced
}

// probeCount is the number of discovery probes one address gets per round.
// Without raw sockets only the TCP SYN ports are used (connect ping).
func probeCount(d model.DiscoveryOpts, privileged bool) int {
	n := len(d.TCPSynPorts)
	if privileged {
		n += len(d.TCPAckPorts)
		if d.ICMPEcho {
			n++
		}
		if d.ICMPTimestamp {
			n++
		}
	}
	return n
}

// splitDiscovery cuts the full probe set in two: a cheap first pass (ICMP
// echo and TCP SYN to the web ports, which most reachable hosts answer) and
// the rest. ok is false when one half would be empty: then one pass with
// the full set is the only sensible plan.
func splitDiscovery(d model.DiscoveryOpts, privileged bool) (first, rest model.DiscoveryOpts, ok bool) {
	first = model.DiscoveryOpts{ARP: d.ARP, Mode: d.Mode, ICMPEcho: d.ICMPEcho}
	rest = model.DiscoveryOpts{ARP: d.ARP, Mode: d.Mode, ICMPTimestamp: d.ICMPTimestamp, TCPAckPorts: d.TCPAckPorts}
	for _, p := range d.TCPSynPorts {
		if (p == 80 || p == 443) && len(first.TCPSynPorts) < 2 {
			first.TCPSynPorts = append(first.TCPSynPorts, p)
		} else {
			rest.TCPSynPorts = append(rest.TCPSynPorts, p)
		}
	}
	if len(first.TCPSynPorts) == 0 && len(rest.TCPSynPorts) > 0 {
		// the profile has no web port among its SYN probes: take its first port
		first.TCPSynPorts, rest.TCPSynPorts = rest.TCPSynPorts[:1:1], rest.TCPSynPorts[1:]
	}
	return first, rest, probeCount(first, privileged) > 0 && probeCount(rest, privileged) > 0
}

// deadCost is the expected number of discovery packets for one address
// that does not answer. liveBlocks is the share of /24 blocks that get the
// second pass in balanced mode.
func deadCost(d model.DiscoveryOpts, privileged bool, mode string, liveBlocks float64) float64 {
	if d.SkipDiscovery {
		return 0
	}
	full := float64(max(1, probeCount(d, privileged)))
	first, rest, ok := splitDiscovery(d, privileged)
	if !ok || mode == model.DiscoveryThorough {
		return full * 2 // one retry
	}
	p1, p2 := float64(probeCount(first, privileged)), float64(probeCount(rest, privileged))
	if mode == model.DiscoveryFast {
		return p1 * 2 // one retry, no second pass
	}
	return p1*2 + liveBlocks*p2*2
}

// localNets returns the IPv4 networks this machine has an address in,
// loopback excluded. nmap finds hosts there by ARP, whatever probes are set.
func localNets() []targets.Range {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []targets.Range
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() {
			continue
		}
		ip4 := ipn.IP.To4()
		ones, bits := ipn.Mask.Size()
		if ip4 == nil || bits != 32 || ones < 1 || ones > 31 {
			continue
		}
		mask := ^uint32(0) << (32 - uint(ones))
		lo := binary.BigEndian.Uint32(ip4) & mask
		out = append(out, targets.Range{Lo: lo, Hi: lo | ^mask})
	}
	return out
}

// localNetsFn lists the directly connected IPv4 networks; tests replace it.
var localNetsFn = localNets

// onLink reports whether every address of the group is in a directly
// connected network.
func (r *run) onLink(g *group) bool {
	if g.v6 || len(r.local) == 0 {
		return false
	}
	for _, rg := range g.ranges() {
		in := false
		for _, n := range r.local {
			if rg.Lo >= n.Lo && rg.Hi <= n.Hi {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return true
}

// discover finds the live hosts of one group. In thorough mode every
// address gets the full probe set. In the other modes a cheap first pass
// goes to every address and the rest of the probe set only where it is
// likely to find something more: in balanced mode the silent addresses of
// each /24 block where a host answered or a hint exists, in fast mode only
// the hinted hosts.
func (r *run) discover(ctx context.Context, g *group, tgts []string, rate int, gs *groupStats) ([]probe.Host, error) {
	arpOnly := r.disc.ARP && r.prober.Privileged() && r.onLink(g) // ARP answers for the whole segment in one pass
	pass := func(tg []string, o model.DiscoveryOpts, retries int) ([]probe.Host, error) {
		t0 := r.e.now()
		end := r.stats.begin(rate)
		res, err := r.prober.Discover(ctx, probe.DiscoverRequest{
			Targets: tg, Opts: o, MaxRate: rate, MaxRetries: retries, HostTimeout: discoveryHostTimeout, IPv6: g.v6, ARPOnly: arpOnly,
		})
		end()
		r.account(gs, res, t0)
		if err != nil {
			return nil, fmt.Errorf("host discovery: %w", err)
		}
		return res.Hosts, nil
	}
	first, rest, ok := splitDiscovery(r.disc, r.prober.Privileged())
	if arpOnly {
		// Two retries: an ARP request costs one small frame per address.
		live, err := pass(tgts, r.disc, 2)
		if err != nil {
			return nil, err
		}
		// A second ARP sweep over the silent addresses of each /24 block where
		// a host answered. Measured on the lab /16 (4 groups in parallel): a
		// single sweep lost 1 of 3 hosts in 10.66.40.0/24 and 1 of 6 in
		// 10.66.50.0/24, and nmap alone on the same ranges lost none. Live
		// hosts cluster, so this costs about 254 frames per active block.
		second := r.silentInLiveBlocks(g, live)
		if second.Count() == 0 {
			return live, nil
		}
		r.log.Debug("discovery ARP confirmation pass", "group", g.id, "addresses", second.Count(), "first_pass_hosts", len(live))
		more, err := pass(targets.Spec(second.Ranges()), r.disc, 2)
		if err != nil {
			return nil, err
		}
		live = mergeHosts(live, more)
		sort.SliceStable(live, func(i, j int) bool { return ipLess(live[i].IP, live[j].IP) })
		return live, nil
	}
	if r.mode == model.DiscoveryThorough || !ok || g.v6 {
		return pass(tgts, r.disc, 1)
	}

	// One retry in every mode. nmap with --max-retries 0 sends only the first
	// ping probe type to each host (measured in the lab: the TCP probes never
	// left), so a host that drops ICMP would be lost.
	live, err := pass(tgts, first, 1)
	if err != nil {
		return nil, err
	}
	found := make([]targets.Range, 0, len(live))
	blocks := map[uint32]bool{}
	for _, h := range live {
		if p, err := targets.ParseValue(h.IP); err == nil {
			found = append(found, p.Range)
			blocks[p.Range.Lo>>8] = true
		}
	}
	var again []targets.Range
	for _, h := range r.hintsIn(g) {
		if p, err := targets.ParseValue(h.IP); err == nil {
			blocks[p.Range.Lo>>8] = true
			if r.mode == model.DiscoveryFast {
				again = append(again, p.Range)
			}
		}
	}
	if r.mode == model.DiscoveryBalanced {
		for _, rg := range g.ranges() {
			for b := rg.Lo >> 8; b <= rg.Hi>>8; b++ {
				if blocks[b] {
					again = append(again, targets.Range{Lo: max(rg.Lo, b<<8), Hi: min(rg.Hi, b<<8|255)})
				}
				if b == 1<<24-1 {
					break
				}
			}
		}
	}
	second := targets.NewSet(again...).Subtract(targets.NewSet(found...))
	if second.Count() == 0 {
		return live, nil
	}
	r.log.Debug("discovery second pass", "group", g.id, "mode", r.mode, "addresses", second.Count(), "first_pass_hosts", len(live))
	more, err := pass(targets.Spec(second.Ranges()), rest, 1)
	if err != nil {
		return nil, err
	}
	live = mergeHosts(live, more)
	sort.SliceStable(live, func(i, j int) bool { return ipLess(live[i].IP, live[j].IP) })
	return live, nil
}

// silentInLiveBlocks returns the addresses of the group that did not answer
// and lie in a /24 block where a host answered or a hint exists.
func (r *run) silentInLiveBlocks(g *group, live []probe.Host) targets.Set {
	found := make([]targets.Range, 0, len(live))
	blocks := map[uint32]bool{}
	for _, h := range live {
		if p, err := targets.ParseValue(h.IP); err == nil {
			found = append(found, p.Range)
			blocks[p.Range.Lo>>8] = true
		}
	}
	for _, h := range r.hintsIn(g) {
		if p, err := targets.ParseValue(h.IP); err == nil {
			blocks[p.Range.Lo>>8] = true
		}
	}
	var again []targets.Range
	for _, rg := range g.ranges() {
		for b := rg.Lo >> 8; b <= rg.Hi>>8; b++ {
			if blocks[b] {
				again = append(again, targets.Range{Lo: max(rg.Lo, b<<8), Hi: min(rg.Hi, b<<8|255)})
			}
			if b == 1<<24-1 {
				break
			}
		}
	}
	return targets.NewSet(again...).Subtract(targets.NewSet(found...))
}

// mergeHosts adds the hosts of a later discovery pass that an earlier pass
// did not report. A prober may answer for an address twice (overlapping
// specs, a host that answers both probe sets); a duplicate would count the
// host twice and scan its ports twice.
func mergeHosts(live, more []probe.Host) []probe.Host {
	seen := make(map[string]bool, len(live)+len(more))
	out := live[:0:0]
	for _, h := range append(live, more...) {
		if seen[h.IP] {
			continue
		}
		seen[h.IP] = true
		out = append(out, h)
	}
	return out
}

func ipLess(a, b string) bool {
	pa, ea := targets.ParseValue(a)
	pb, eb := targets.ParseValue(b)
	if ea != nil || eb != nil || pa.V6.IsValid() || pb.V6.IsValid() {
		return a < b
	}
	return pa.Range.Lo < pb.Range.Lo
}
