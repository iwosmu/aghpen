package scan

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
)

// The rotating deep pass. A larger scope (more than fullRangeMaxAddresses
// addresses, no full-range pass) with a ranked port list (top-N) scans only
// the profile's ports. After that general pass, the deep pass gives the rest
// of 1-65535 to at most deepPassHosts live hosts of the run, one host at a
// time with the run's whole share of the packet budget (inside the global
// budget), and sends each host's updated result as soon as it is done.
// Priority: hosts never fully scanned first (HostHint.DeepAt nil), then
// hosts with more open TCP ports outside nmap's top 1000 (a service moved to
// an unusual port suggests more of them), then the hosts fully scanned
// longest ago, then the address. Each run so reaches other hosts, and every
// live host is covered in turn.
const deepPassHosts = 16

// deepFor reports whether a run gets the deep pass.
func deepFor(spec string, ports *probe.PortSet, addresses int64) bool {
	if ports == nil || addresses <= fullRangeMaxAddresses || ports.Count() >= 65535 {
		return false
	}
	return strings.Contains(strings.ToLower(spec), "top-")
}

// keepFinal records the final result of a live host for the deep pass.
func (r *run) keepFinal(h model.HostResult) {
	if !r.deepPlanned || !h.Up || h.Interim || h.PortsUnknown {
		return
	}
	r.finalMu.Lock()
	r.finals[h.IP] = h
	r.finalMu.Unlock()
}

type deepCand struct {
	res     model.HostResult
	addr    netip.Addr
	before  bool      // fully scanned in an earlier run
	at      time.Time // when (zero when never)
	unusual int       // open TCP ports outside the top 1000
}

// deepOrder sorts the candidates by priority.
func deepOrder(cs []deepCand) {
	slices.SortFunc(cs, func(a, b deepCand) int {
		if a.before != b.before {
			if !a.before {
				return -1
			}
			return 1
		}
		if a.unusual != b.unusual {
			return b.unusual - a.unusual
		}
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		return a.addr.Compare(b.addr)
	})
}

// deepCandidates lists the live hosts of the run that the deep pass may
// take, in priority order.
func (r *run) deepCandidates() []deepCand {
	r.finalMu.Lock()
	finals := make([]model.HostResult, 0, len(r.finals))
	for _, h := range r.finals {
		finals = append(finals, h)
	}
	r.finalMu.Unlock()
	top, _ := probe.EffectivePorts("top-1000", "", "")
	var cs []deepCand
	for _, h := range finals {
		a, err := netip.ParseAddr(h.IP)
		if err != nil || h.FullPorts {
			continue
		}
		c := deepCand{res: h, addr: a}
		if hint, ok := r.hints[h.IP]; ok && hint.DeepAt != nil {
			c.before, c.at = true, *hint.DeepAt
		}
		for _, s := range h.Services {
			if s.Proto != "udp" && s.State == "open" && (top == nil || !top.Has(s.Port)) {
				c.unusual++
			}
		}
		cs = append(cs, c)
	}
	deepOrder(cs)
	return cs
}

// deepPass runs after the general pass of the run (every chunk done).
func (r *run) deepPass(ctx context.Context) {
	cs := r.deepCandidates()
	rest, err := probe.EffectivePorts("1-65535", r.plan.Policy.AllowedPorts, r.plan.Policy.DeniedPorts)
	if err == nil {
		rest.Remove(r.ports)
	}
	if len(cs) == 0 || err != nil || rest.Count() == 0 {
		r.stats.passState(model.PassDeep, model.PassSkipped)
		return
	}
	n := min(len(cs), deepPassHosts)
	pick, waiting := cs[:n], len(cs)-n
	r.stats.passSkipHosts(model.PassDeep, waiting)
	r.log.Info("deep pass", "hosts", n, "waiting", waiting, "ports", rest.Count())

	// the run's whole share, inside what all runs together may send
	rate, err := r.budget.Acquire(ctx, r.lim.ProbePPS())
	if err != nil {
		return
	}
	got, err := r.global.Acquire(ctx, rate)
	if err != nil {
		r.budget.Release(rate)
		return
	}
	if got < rate {
		r.budget.Release(rate - got)
		rate = got
	}
	defer r.budget.Release(rate)
	defer r.global.Release(rate)

	t0 := r.e.now()
	gs := &groupStats{}
	done, found := 0, 0
	for _, c := range pick {
		if ctx.Err() != nil {
			break
		}
		k, ok := r.deepHost(ctx, c.res, rest, rate, gs)
		if ok {
			done++
			found += k
		}
	}
	if ctx.Err() == nil {
		r.stats.passState(model.PassDeep, model.PassDone)
	}
	r.log.Info("deep pass finished", "hosts", done, "of", n, "waiting", waiting, "new_open", found, "ms", r.e.now().Sub(t0).Milliseconds())
}

// deepHost scans the rest of the ports on one host, describes what it
// finds and sends the host's updated result. It returns the new services.
func (r *run) deepHost(ctx context.Context, h model.HostResult, all *probe.PortSet, rate int, gs *groupStats) (int, bool) {
	a, _ := netip.ParseAddr(h.IP)
	g := &group{v6: a.Is6()}
	// the ports this run already scanned on the host (the wide pass for
	// dense hosts) are not scanned, described or counted a second time
	todo := *all
	if v, ok := r.covered.Load(h.IP); ok {
		todo.Remove(v.(*probe.PortSet))
	}
	rest := &todo
	t0 := r.e.now()
	end := r.stats.begin(rate)
	endPass := r.stats.passBegin(model.PassDeep, 1, int64(rest.Count()), rate)
	ps, err := &probe.Result{Hosts: []probe.Host{{IP: h.IP, Up: true}}}, error(nil) // nothing left to scan
	if rest.Count() > 0 {
		ps, err = r.prober.PortScan(ctx, probe.PortScanRequest{
			Hosts: []string{h.IP}, Ports: rest, MaxRate: rate, MaxRetries: 1, HostTimeout: portScanTimeout(1, rest.Count(), rate), IPv6: g.v6,
		})
	}
	endPass()
	end()
	r.account(gs, ps, t0)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("deep pass scan failed", "ip", h.IP, "error", err.Error())
		}
		return 0, false
	}
	if !slices.Contains(finished(ps), h.IP) {
		r.log.Info("deep pass did not finish the host; its coverage stays", "ip", h.IP)
		return 0, false
	}
	var ports []probe.Port
	for _, ph := range ps.Hosts {
		if ph.IP == h.IP {
			ports = ph.Ports
		}
	}
	res := h
	res.Services = slices.Clone(h.Services)
	added, web := 0, 0
	if len(ports) > 0 {
		add, err := r.describeHosts(ctx, g, []probe.Host{{IP: h.IP, Up: true, Responded: true, Ports: ports}}, 1, rate, gs, false, false)
		if err != nil {
			return 0, false
		}
		have := map[int]bool{}
		for _, s := range h.Services {
			if s.Proto != "udp" {
				have[s.Port] = true
			}
		}
		for _, x := range add {
			for _, s := range x.Services {
				if s.Proto != "udp" && have[s.Port] {
					continue // the host already has this port
				}
				s.DeepPass = true
				res.Services = append(res.Services, s)
				if s.State == "open" {
					added++
					if s.HTTP != nil {
						web++
					}
				}
			}
		}
		sort.SliceStable(res.Services, func(x, y int) bool {
			sx, sy := res.Services[x], res.Services[y]
			if sx.Proto != sy.Proto {
				return sx.Proto < sy.Proto
			}
			return sx.Port < sy.Port
		})
	}
	if ctx.Err() != nil {
		return 0, false
	}
	r.cover(h.IP, rest)
	res.Coverage = r.coverage(h.IP)
	res.FullPorts = true
	// the store keeps the latest observation of a run: later than the general pass's
	res.ObservedAt = r.e.now().UTC()
	if !res.ObservedAt.After(h.ObservedAt) {
		res.ObservedAt = h.ObservedAt.Add(time.Millisecond)
	}
	if err := r.sink.OnHost(r.sinkCtx, res); err != nil {
		r.log.Warn("sink OnHost failed", "ip", h.IP, "error", err.Error())
		r.stats.update(func(s *model.RunStats) { s.Errors++ })
		return 0, false
	}
	r.stats.update(func(s *model.RunStats) {
		s.ServicesOpen += added
		s.HTTPServices += web
	})
	r.log.Info("deep pass host", "ip", h.IP, "new_open", added, "ms", r.e.now().Sub(t0).Milliseconds())
	return added, true
}

// deepNote is the run note of the deep pass.
func deepNote(covered, waiting int) string {
	return fmt.Sprintf("głębszy przebieg: reszta portów 1-65535 objęła %d hostów; czeka jeszcze %d (następne przebiegi biorą najpierw hosty nigdy nie skanowane w pełni, potem najdawniej skanowane)", covered, waiting)
}
