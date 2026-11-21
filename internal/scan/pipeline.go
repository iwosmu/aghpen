package scan

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

const (
	discoveryHostTimeout = 30 * time.Second
	portScanHostTimeout  = 5 * time.Minute
	serviceHostTimeout   = 3 * time.Minute
	udpHostTimeout       = time.Minute
	defaultBackoff       = 1500 * time.Millisecond
	maxBackoff           = 30 * time.Second
)

// account adds the packets of one finished probe stage to the counters.
func (r *run) account(gs *groupStats, res *probe.Result, start time.Time) {
	if res == nil || res.Packets <= 0 {
		return
	}
	gs.mu.Lock()
	gs.packets += res.Packets
	gs.mu.Unlock()
	r.stats.addStage(res.Packets, start, r.e.now())
}

// nmapTargets returns what the group scans. IPv4 units use their ranges,
// which already have the current exclusions removed.
func (g *group) nmapTargets() []string {
	if g.v6 {
		return g.specs()
	}
	return targets.Spec(targets.NewSet(g.ranges()...).Ranges())
}

// hintsIn returns the hinted hosts inside the group.
func (r *run) hintsIn(g *group) []model.HostHint {
	var out []model.HostHint
	if g.v6 {
		for _, u := range g.units {
			for _, ip := range u.v6 {
				if h, ok := r.hints[ip]; ok {
					out = append(out, h)
				}
			}
		}
		return out
	}
	for _, rg := range g.ranges() {
		lo := sort.Search(len(r.hintIPs), func(i int) bool { return r.hintIPs[i] >= rg.Lo })
		for i := lo; i < len(r.hintIPs) && r.hintIPs[i] <= rg.Hi; i++ {
			if h, ok := r.hints[targets.IPString(r.hintIPs[i])]; ok {
				out = append(out, h)
			}
		}
	}
	return out
}

// scanGroup runs the stages of one group: discovery, port scan, service
// detection, HTTP/TLS and signatures, then the retries for hinted hosts
// that did not answer.
func (r *run) scanGroup(ctx context.Context, g *group, rate int, gs *groupStats) error {
	tgts := g.nmapTargets()
	if len(tgts) == 0 {
		return nil // everything in this group is excluded now
	}
	found := map[string]bool{}
	var live []probe.Host
	if r.disc.SkipDiscovery {
		// -Pn mode: every address goes to the port scan
		if g.v6 {
			for _, ip := range tgts {
				live = append(live, probe.Host{IP: ip})
			}
		} else {
			targets.NewSet(g.ranges()...).Each(func(u uint32) bool {
				live = append(live, probe.Host{IP: targets.IPString(u)})
				return true
			})
		}
	} else {
		var err error
		if live, err = r.discover(ctx, g, tgts, rate, gs); err != nil {
			return err
		}
	}
	if err := r.deepScan(ctx, g, live, 1, rate, gs, found); err != nil {
		return err
	}

	// Unstable hosts: the inventory says they exist, but they did not answer.
	var missing []model.HostHint
	for _, h := range r.hintsIn(g) {
		if !found[h.IP] {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	rounds := r.plan.Profile.Retry.UnstableRetries
	backoff := time.Duration(r.plan.Profile.Retry.BackoffMs) * time.Millisecond
	if backoff <= 0 {
		backoff = defaultBackoff
	}
	attempts := 1
	if rounds > 0 {
		r.stats.update(func(s *model.RunStats) { s.Retried += len(missing) })
	}
	for round := 1; round <= rounds && len(missing) > 0; round++ {
		wait := backoff << uint(round-1)
		if wait > maxBackoff || wait <= 0 {
			wait = maxBackoff
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		attempts = 1 + round
		back, err := r.retryRound(ctx, g, missing, round == rounds, rate, gs)
		if err != nil {
			return err
		}
		if len(back) > 0 {
			r.log.Info("unstable host answered on retry", "hosts", len(back), "round", round)
			if err := r.deepScan(ctx, g, back, attempts, rate, gs, found); err != nil {
				return err
			}
		}
		var still []model.HostHint
		for _, h := range missing {
			if !found[h.IP] {
				still = append(still, h)
			}
		}
		missing = still
	}
	for _, h := range missing {
		r.emitHost(g, gs, model.HostResult{
			RunID: r.plan.RunID, IP: h.IP, Hostnames: r.names(h.IP), Up: false, Reason: "no-response",
			Attempts: attempts, ObservedAt: r.e.now().UTC(), Services: []model.ServiceResult{},
		})
	}
	return nil
}

// udpStage probes the allow-listed UDP services of the hosts that are up
// and adds the ports that answered to them. It runs after the TCP stages of
// the group and inside the same packet share.
func (r *run) udpStage(ctx context.Context, g *group, up []probe.Host, rate int, gs *groupStats) error {
	scanner, ok := r.prober.(probe.UDPScanner)
	if !ok {
		return nil
	}
	ips := make([]string, len(up))
	for i, h := range up {
		ips[i] = h.IP
	}
	t0 := r.e.now()
	end := r.stats.begin(rate)
	res, err := scanner.UDPScan(ctx, probe.UDPScanRequest{Hosts: ips, Ports: r.udpPorts, MaxRate: rate, HostTimeout: udpHostTimeout, IPv6: g.v6})
	end()
	r.account(gs, res, t0)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		r.log.Warn("UDP scan failed, keeping the TCP data", "error", err.Error())
		r.stats.update(func(s *model.RunStats) { s.Errors++ })
		return nil
	}
	byIP := map[string][]probe.Port{}
	for _, h := range res.Hosts {
		byIP[h.IP] = h.Ports
	}
	for i := range up {
		up[i].Ports = append(up[i].Ports, byIP[up[i].IP]...)
	}
	return nil
}

// retryRound probes the missing hosts again. The last round uses a second
// method: a direct TCP connect to the ports the host had open before.
func (r *run) retryRound(ctx context.Context, g *group, missing []model.HostHint, last bool, rate int, gs *groupStats) ([]probe.Host, error) {
	var back []probe.Host
	var rediscover []string
	if last {
		lim := probe.NewLimiter(float64(rate), 1)
		t0 := r.e.now()
		var sent int64
		for _, h := range missing {
			ports, _ := probe.FilterPorts(h.OpenPorts, r.plan.Policy.AllowedPorts, r.plan.Policy.DeniedPorts)
			if len(ports) == 0 {
				rediscover = append(rediscover, h.IP)
				continue
			}
			if len(ports) > 5 {
				ports = ports[:5]
			}
			ph, n := r.e.direct(ctx, h.IP, ports, 2*time.Second, lim)
			sent += n
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
			if ph.Up {
				back = append(back, ph)
			}
		}
		r.account(gs, &probe.Result{Packets: sent}, t0)
	} else {
		for _, h := range missing {
			rediscover = append(rediscover, h.IP)
		}
	}
	if len(rediscover) > 0 {
		t0 := r.e.now()
		res, err := r.prober.Discover(ctx, probe.DiscoverRequest{
			Targets: rediscover, Opts: r.disc, MaxRate: rate, MaxRetries: 2, HostTimeout: discoveryHostTimeout, IPv6: g.v6,
		})
		r.account(gs, res, t0)
		if err != nil {
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
			r.log.Warn("retry discovery failed", "error", err.Error())
			r.stats.update(func(s *model.RunStats) { s.Errors++ })
		} else {
			back = append(back, res.Hosts...)
		}
	}
	return back, nil
}

// deepScan runs the port scan, the service detection and the HTTP stage for
// hosts that answered, and reports each of them to the sink.
func (r *run) deepScan(ctx context.Context, g *group, hosts []probe.Host, attempts, rate int, gs *groupStats, found map[string]bool) error {
	if len(hosts) == 0 {
		return nil
	}
	ips := make([]string, len(hosts))
	for i, h := range hosts {
		ips[i] = h.IP
	}
	t0 := r.e.now()
	end := r.stats.begin(rate)
	ps, err := r.prober.PortScan(ctx, probe.PortScanRequest{
		Hosts: ips, Ports: r.ports, MaxRate: rate, MaxRetries: 2, HostTimeout: portScanHostTimeout, IPv6: g.v6,
	})
	end()
	r.account(gs, ps, t0)
	if err != nil {
		return fmt.Errorf("port scan: %w", err)
	}
	scanned := map[string]*probe.Host{}
	for i := range ps.Hosts {
		scanned[ps.Hosts[i].IP] = &ps.Hosts[i]
	}
	var up []probe.Host
	for _, h := range hosts {
		p := scanned[h.IP]
		if !h.Up {
			// discovery was skipped: only an answer to the port scan proves the host
			if p == nil || !p.Responded {
				continue
			}
			h.Up, h.Reason = true, "reset"
			if len(p.Ports) > 0 {
				h.Reason = "syn-ack"
			}
		}
		if p != nil {
			h.Ports = p.Ports
			if h.MAC == "" {
				h.MAC, h.Vendor = p.MAC, p.Vendor
			}
			if h.RTTMs == 0 {
				h.RTTMs = p.RTTMs
			}
		}
		up = append(up, h)
	}

	if r.plan.Profile.ServiceDetection {
		var hp []probe.HostPorts
		for _, h := range up {
			if len(h.Ports) == 0 {
				continue
			}
			x := probe.HostPorts{IP: h.IP}
			for _, p := range h.Ports {
				x.Ports = append(x.Ports, p.Port)
			}
			hp = append(hp, x)
		}
		if len(hp) > 0 {
			t0 := r.e.now()
			sv, err := r.prober.ServiceScan(ctx, probe.ServiceRequest{
				Hosts: hp, Intensity: r.plan.Profile.VersionIntensity, MaxRate: rate, HostTimeout: serviceHostTimeout, IPv6: g.v6,
			})
			r.account(gs, sv, t0)
			if err != nil {
				if ctx.Err() != nil {
					return context.Cause(ctx)
				}
				// keep the port-scan result; the services stay named by port number
				r.log.Warn("service detection failed, keeping port-scan data", "error", err.Error())
				r.stats.update(func(s *model.RunStats) { s.Errors++ })
			}
			if sv != nil {
				detected := map[string]map[int]probe.Port{}
				for _, h := range sv.Hosts {
					m := map[int]probe.Port{}
					for _, p := range h.Ports {
						m[p.Port] = p
					}
					detected[h.IP] = m
				}
				for i := range up {
					for j, p := range up[i].Ports {
						if d, ok := detected[up[i].IP][p.Port]; ok {
							up[i].Ports[j] = d
						}
					}
				}
			}
		}
	}

	if len(r.udpPorts) > 0 && len(up) > 0 {
		if err := r.udpStage(ctx, g, up, rate, gs); err != nil {
			return err
		}
	}

	for _, h := range up {
		found[h.IP] = true
	}
	var wg sync.WaitGroup
	for _, h := range up {
		select {
		case r.hostSem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return context.Cause(ctx)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-r.hostSem }()
			res := r.buildHost(ctx, h, attempts)
			if ctx.Err() != nil {
				return // half-collected: the chunk is deferred and scanned again
			}
			r.emitHost(g, gs, res)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (r *run) names(ip string) []string {
	if n := r.hostnames[ip]; len(n) > 0 {
		return append([]string{}, n...)
	}
	return []string{}
}

func toService(p probe.Port) model.ServiceResult {
	s := model.ServiceResult{
		Port: p.Port, Proto: p.Proto, State: p.State, Name: p.Name, Product: p.Product, Version: p.Version,
		ExtraInfo: p.ExtraInfo, CPE: p.CPE, Banner: p.Banner, Tunnel: p.Tunnel, Confidence: p.Confidence,
		Matches: []model.SigMatch{}, Technologies: []model.Technology{}, Classes: []string{},
	}
	if s.Proto == "" {
		s.Proto = "tcp"
	}
	if s.CPE == nil {
		s.CPE = []string{}
	}
	return s
}

// buildHost turns a probed host into a HostResult. For every open TCP port
// it calls the fingerprinter (HTTP and TLS) and then the signature engine.
func (r *run) buildHost(ctx context.Context, h probe.Host, attempts int) model.HostResult {
	res := model.HostResult{
		RunID: r.plan.RunID, IP: h.IP, Hostnames: r.names(h.IP), Up: true, Reason: h.Reason, RTTMs: h.RTTMs,
		Attempts: attempts, MAC: h.MAC, Vendor: h.Vendor, ObservedAt: r.e.now().UTC(),
		Services: make([]model.ServiceResult, len(h.Ports)),
	}
	for _, n := range h.Hostnames {
		if !containsStr(res.Hostnames, n) {
			res.Hostnames = append(res.Hostnames, n)
		}
	}
	for i, p := range h.Ports {
		res.Services[i] = toService(p)
	}

	if r.e.deps.Fingerprinter != nil && r.plan.Profile.HTTP.Enabled && len(res.Services) > 0 {
		// One limiter per host: every request to this address takes a token,
		// whichever service it goes to.
		perHost := r.lim.PerHostRPS
		if d := r.lim.PerHostDelay; d > 0 && 1/d.Seconds() < perHost {
			perHost = 1 / d.Seconds()
		}
		hostLim := probe.NewLimiter(perHost, 1)
		sem := make(chan struct{}, r.lim.PerHostConc)
		hostname := ""
		if len(res.Hostnames) > 0 {
			hostname = res.Hostnames[0]
		}
		var wg sync.WaitGroup
		for i := range res.Services {
			svc := &res.Services[i]
			if svc.Proto != "tcp" || svc.State != "open" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				r.httpStage(ctx, hostLim, &res, svc, hostname)
			}()
		}
		wg.Wait()
	}

	for i := range res.Services {
		r.match(&res.Services[i], res.Hostnames)
	}
	return res
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// emitHost counts one host and keeps it until its group ends. A host goes
// to the sink only when its chunk is final: a group that is cut (pause,
// window end) is scanned again, and its hosts must not be reported twice.
func (r *run) emitHost(g *group, gs *groupStats, res model.HostResult) {
	gs.mu.Lock()
	gs.hosts = append(gs.hosts, res)
	gs.mu.Unlock()
	if !res.Up {
		return
	}
	open, web := 0, 0
	for _, s := range res.Services {
		if s.State == "open" {
			open++
		}
		if s.HTTP != nil {
			web++
		}
	}
	gs.mu.Lock()
	gs.hostsUp++
	gs.services += open
	gs.http += web
	if u := g.unitOf(res.IP); u != nil {
		u.hostUp++
	}
	gs.mu.Unlock()
	r.stats.update(func(s *model.RunStats) {
		s.HostsUp++
		s.ServicesOpen += open
		s.HTTPServices += web
	})
}
