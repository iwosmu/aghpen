package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

const (
	discoveryHostTimeout = 30 * time.Second
	portScanHostTimeout  = 5 * time.Minute // the floor; see portScanTimeout
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
	r.stats.addStage(res.Packets, res.PacketsExact, start, r.e.now())
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
			ARPOnly: r.prober.Privileged() && r.onLink(g),
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
	nports := 0
	if r.ports != nil {
		nports = int(r.ports.Count())
	}
	endPass := r.stats.passBegin(model.PassTopPorts, len(ips), int64(len(ips)*nports), rate)
	ps, err := r.prober.PortScan(ctx, probe.PortScanRequest{
		Hosts: ips, Ports: r.ports, MaxRate: rate, MaxRetries: 2, HostTimeout: portScanTimeout(len(ips), nports, rate), IPv6: g.v6,
	})
	endPass()
	end()
	r.account(gs, ps, t0)
	if err != nil {
		return fmt.Errorf("port scan: %w", err)
	}
	scanned := map[string]*probe.Host{}
	for i := range ps.Hosts {
		scanned[ps.Hosts[i].IP] = &ps.Hosts[i]
	}
	// A host that discovery found but that gave the port scan no answer at
	// all (not even a closed port) lost its probes, usually its neighbour
	// resolution under load: nmap then marks it down and reports no port.
	// A host whose scan hit --host-timeout has no port either. Scan those
	// hosts once more before their ports are recorded as none.
	var silent []string
	for _, h := range hosts {
		if p := scanned[h.IP]; h.Up && (p == nil || !p.Responded) {
			silent = append(silent, h.IP)
		}
	}
	timedOut := func() []string {
		var out []string
		for _, h := range hosts {
			if p := scanned[h.IP]; p != nil && p.TimedOut {
				out = append(out, h.IP)
			}
		}
		return out
	}
	if t := timedOut(); len(t) > 0 {
		r.log.Warn("port scan timed out for hosts", "group", g.id, "hosts", len(t), "of", len(hosts), "rate", rate, "ports", nports)
	}
	if len(silent) > 0 && ctx.Err() == nil {
		t1 := r.e.now()
		end := r.stats.begin(rate)
		again, err := r.prober.PortScan(ctx, probe.PortScanRequest{
			Hosts: silent, Ports: r.ports, MaxRate: rate, MaxRetries: 3, HostTimeout: portScanTimeout(len(silent), nports, rate), IPv6: g.v6,
		})
		end()
		r.account(gs, again, t1)
		if err == nil {
			n := 0
			for i := range again.Hosts {
				if again.Hosts[i].Responded {
					scanned[again.Hosts[i].IP] = &again.Hosts[i]
					n++
				} else if again.Hosts[i].TimedOut {
					scanned[again.Hosts[i].IP] = &again.Hosts[i]
				}
			}
			r.stats.update(func(s *model.RunStats) { s.Retried += len(silent) })
			r.log.Info("port scan retried for silent hosts", "group", g.id, "hosts", len(silent), "answered", n)
		} else if ctx.Err() != nil {
			return context.Cause(ctx)
		}
	}
	full := r.claimFullRange(hosts, scanned)
	if full {
		r.stats.passState(model.PassTopPorts, model.PassDone)
	} else if err := r.densePass(ctx, g, scanned, rate, gs); err != nil {
		return err
	}
	unknown := map[string]bool{}
	if t := timedOut(); len(t) > 0 {
		for _, ip := range t {
			unknown[ip] = true
		}
		r.stats.update(func(s *model.RunStats) { s.PortsUnknown += len(t) })
		r.stats.warn("Skan portów nie skończył się dla części hostów (limit czasu nmap). Ich usługi w tym przebiegu są nieznane, nie zniknęły.")
	}
	var answered int64
	for _, h := range hosts {
		if p := scanned[h.IP]; p != nil && (p.Responded || len(p.Ports) > 0) {
			answered++
		}
	}
	r.portAnswered.Add(answered)
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

	for _, h := range up {
		found[h.IP] = true
	}
	describeRate := rate
	var wide chan fullScan
	if full {
		// The rest of the range starts now, beside the description of the
		// top ports: the port scan gets 90 % of the rate, version detection
		// (a few connects per port) and its 1-port SYN scans the rest.
		wide = make(chan fullScan, 1)
		go func() { wide <- r.fullRangeScan(ctx, g, up, rate*9/10, gs) }()
		describeRate = max(1, rate/10)
	}
	results, err := r.describeHosts(ctx, g, up, attempts, describeRate, gs, true, true)
	if full {
		fs := <-wide
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		// the top ports are known: store them now, then describe the rest
		for _, res := range results {
			r.interimHost(gs, res)
		}
		if err := r.fullRangeFinish(ctx, g, up, results, fs, attempts, rate, gs); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for _, res := range results {
		if unknown[res.IP] {
			res.PortsUnknown, res.Reason = true, model.ReasonPortsUnknown
		}
		r.emitHost(g, gs, res)
	}
	return nil
}

// describeHosts runs version detection, the UDP stage (withUDP) and the
// HTTP stage on hosts whose open ports are known, and returns their
// results in the order of up. interim lets the quick path store a partial
// result while a slow version detection runs.
func (r *run) describeHosts(ctx context.Context, g *group, up []probe.Host, attempts, rate int, gs *groupStats, withUDP, interim bool) ([]model.HostResult, error) {
	if r.quickEligible(up) {
		return r.quickResults(ctx, g, up, attempts, rate, gs, withUDP, interim)
	}
	up = append([]probe.Host(nil), up...)
	for i := range up {
		up[i].Ports = append([]probe.Port(nil), up[i].Ports...)
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
					return nil, context.Cause(ctx)
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
							if d.Name == "" {
								d.Name = p.Name // version detection named nothing: keep the port table's name
							}
							up[i].Ports[j] = d
						}
					}
				}
			}
		}
	}

	if withUDP && len(r.udpPorts) > 0 && len(up) > 0 {
		if err := r.udpStage(ctx, g, up, rate, gs); err != nil {
			return nil, err
		}
	}

	results := make([]model.HostResult, len(up))
	var wg sync.WaitGroup
	for i, h := range up {
		select {
		case r.hostSem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return nil, context.Cause(ctx)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-r.hostSem }()
			results[i] = r.buildHost(ctx, h, attempts)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, context.Cause(ctx) // half-collected: the chunk is deferred and scanned again
	}
	return results, nil
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
	res := r.newHostResult(h, attempts)
	r.httpHost(ctx, &res, nil)
	r.finishHost(&res)
	return res
}

// newHostResult is the host as the port scan (and version detection, when
// it ran before) saw it, without the HTTP stage.
func (r *run) newHostResult(h probe.Host, attempts int) model.HostResult {
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
	return res
}

// httpHost runs the HTTP stage on the open TCP services of one host. done,
// when set, is called after each service's stage.
func (r *run) httpHost(ctx context.Context, res *model.HostResult, done func(*model.ServiceResult)) {
	if r.e.deps.Fingerprinter == nil || !r.plan.Profile.HTTP.Enabled || len(res.Services) == 0 {
		return
	}
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
			r.httpStage(ctx, hostLim, res, svc, hostname)
			if done != nil {
				done(svc)
			}
		}()
	}
	wg.Wait()
}

// finishHost names every service and runs the signature engine.
func (r *run) finishHost(res *model.HostResult) {
	for i := range res.Services {
		nameService(&res.Services[i])
		r.match(&res.Services[i], res.Hostnames)
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// nameService gives every service a name: nmap's name, else "http" or
// "https" when the HTTP stage got an answer, else "unknown" (the UI shows it
// as "nierozpoznana"). An empty name looked like a broken scan in the list.
func nameService(s *model.ServiceResult) {
	// "tcpwrapped" means nmap's probes got the connection closed on them;
	// when our GET got a page, the service is HTTP (the template's httpbin
	// on 8888 behind Gunicorn showed as tcpwrapped).
	if s.Name != "" && s.Name != "unknown" && !(s.Name == "tcpwrapped" && s.HTTP != nil) {
		return
	}
	switch {
	case s.HTTP != nil && (s.TLS != nil || s.Tunnel == "ssl"):
		s.Name = "https"
	case s.HTTP != nil:
		s.Name = "http"
	default:
		s.Name = "unknown"
	}
}

// emitHost counts one host and keeps it until its group ends. A host goes
// to the sink only when its chunk is final: a group that is cut (pause,
// window end) is scanned again, and its hosts must not be reported twice.
func (r *run) emitHost(g *group, gs *groupStats, res model.HostResult) {
	gs.mu.Lock()
	prev, hadInterim := gs.interim[res.IP]
	delete(gs.interim, res.IP)
	if hadInterim {
		// the store keeps the latest observation of a run (by time): the
		// final result must be later than every partial one
		if now := r.e.now().UTC(); now.After(res.ObservedAt) {
			res.ObservedAt = now
		}
		if !res.ObservedAt.After(prev.at) {
			res.ObservedAt = prev.at.Add(time.Millisecond)
		}
	}
	gs.hosts = append(gs.hosts, res)
	gs.mu.Unlock()
	if hadInterim { // the final result replaces the stored partial one in the counters
		r.stats.update(func(s *model.RunStats) {
			s.HostsUp -= prev.hosts
			s.ServicesOpen -= prev.open
			s.HTTPServices -= prev.web
		})
	}
	if !res.Up {
		return
	}
	open, web := serviceCounts(res)
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

func serviceCounts(res model.HostResult) (open, web int) {
	for _, s := range res.Services {
		if s.State == "open" {
			open++
		}
		if s.HTTP != nil {
			web++
		}
	}
	return open, web
}

// interimCount is what a stored partial result added to the run counters.
type interimCount struct {
	hosts, open, web int
	at               time.Time // ObservedAt of the latest partial result
}

// interimHost stores a partial result of a host before its group ends, so
// GET /services shows it while the run goes on. It is marked PortsUnknown:
// the store then marks none of the host's other services gone (the final
// result does that). The counters grow now; emitHost replaces the partial
// numbers with the final ones, and a deferred group takes them back.
func (r *run) interimHost(gs *groupStats, res model.HostResult) {
	if !res.Up {
		return
	}
	res.PortsUnknown = true
	open, web := serviceCounts(res)
	gs.mu.Lock()
	if gs.interim == nil {
		gs.interim = map[string]interimCount{}
	}
	prev := gs.interim[res.IP]
	at := res.ObservedAt
	if prev.at.After(at) {
		at = prev.at
	}
	gs.interim[res.IP] = interimCount{hosts: 1, open: open, web: web, at: at}
	gs.mu.Unlock()
	r.stats.update(func(s *model.RunStats) {
		s.HostsUp += 1 - prev.hosts
		s.ServicesOpen += open - prev.open
		s.HTTPServices += web - prev.web
	})
	if err := r.sink.OnHost(r.sinkCtx, res); err != nil {
		r.log.Warn("sink OnHost (partial) failed", "ip", res.IP, "error", err.Error())
	}
}

// portScanTimeout is nmap's --host-timeout for one port-scan process. nmap
// scans the hosts of one process side by side at the process's packet rate,
// so one host may need the whole process's time: hosts x ports / rate, and
// up to three times that when ports are filtered (two retransmissions).
// Measured on the public instance (8 parallel groups at 105 pps each): a
// group with about 35 live hosts and 1000 ports needs over 330 s, and a fixed
// 5 minutes dropped every host of that group without a single port.
func portScanTimeout(hosts, ports, rate int) time.Duration {
	if rate < 1 {
		rate = 1
	}
	need := time.Duration(float64(hosts) * float64(ports) * 3 / float64(rate) * float64(time.Second))
	return max(portScanHostTimeout, need)
}

// A host that already shows denseOpenPorts open ports in the profile's list
// gets one more port scan over the rest of ports 1-10000 (at most
// maxDensePerGroup hosts per group). A host that exposes many services
// usually listens on unusual ports too (application servers, proxies, test
// instances). Measured on the lab: the 64-port host showed 33 ports from the
// default list and hid 31 ports ranked 1045 to 7379 in nmap's frequency
// table or not ranked at all, all below 10000; no other lab host has 10
// open ports. The full range 1-65535 found the same 31 ports but took the
// group's share of the cap (210 pps) for 307 s and made the /16 run 1060 s
// instead of 559 s; 1-10000 is about 9 000 ports, 43 s at that share.
const (
	denseOpenPorts   = 10
	maxDensePerGroup = 4
	densePorts       = "1-10000"
)

func (r *run) densePass(ctx context.Context, g *group, scanned map[string]*probe.Host, rate int, gs *groupStats) error {
	if r.ports == nil || ctx.Err() != nil {
		return nil
	}
	// the policy's allowed and denied ports hold here too
	rest, err := probe.EffectivePorts(densePorts, r.plan.Policy.AllowedPorts, r.plan.Policy.DeniedPorts)
	if err != nil {
		return nil
	}
	rest.Remove(r.ports)
	if rest.Count() == 0 {
		return nil
	}
	var dense []string
	for ip, p := range scanned {
		if p != nil && !p.TimedOut && len(p.Ports) >= denseOpenPorts {
			dense = append(dense, ip)
		}
	}
	if len(dense) == 0 {
		return nil
	}
	sort.Strings(dense)
	dense = dense[:min(len(dense), maxDensePerGroup)]
	t0 := r.e.now()
	end := r.stats.begin(rate)
	endPass := r.stats.passBegin(model.PassDense, len(dense), int64(len(dense)*rest.Count()), rate)
	res, err := r.prober.PortScan(ctx, probe.PortScanRequest{
		Hosts: dense, Ports: rest, MaxRate: rate, MaxRetries: 1, HostTimeout: portScanTimeout(len(dense), rest.Count(), rate), IPv6: g.v6,
	})
	endPass()
	end()
	r.account(gs, res, t0)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		r.log.Warn("wide port pass for dense hosts failed", "group", g.id, "error", err.Error())
		return nil
	}
	added := 0
	for _, h := range res.Hosts {
		p := scanned[h.IP]
		if p == nil || len(h.Ports) == 0 {
			continue
		}
		merged := append(append([]probe.Port{}, p.Ports...), h.Ports...)
		sort.SliceStable(merged, func(i, j int) bool { return merged[i].Port < merged[j].Port })
		cp := *p
		cp.Ports = merged
		scanned[h.IP] = &cp
		added += len(h.Ports)
	}
	r.log.Info("wide port pass for dense hosts", "group", g.id, "hosts", len(dense), "ports", rest.Count(), "new_open", added)
	return nil
}

// A small run (few open TCP ports in the group) takes the quick path:
// version detection runs per port, in parallel with the HTTP stage, and a
// port that answered HTTP stops its version detection. nmap's -sV is slow on
// HTTP servers that ignore its non-HTTP probes: Gitea on port 3000 took 42 s
// for one port (probes listing port 3000 first, 5 s wait each), while the
// HTTP collector reads it in under a second. Measured on one host with 7
// ports: 68 s before, mostly -sV (43 s) and then the HTTP stage (24 s).
const (
	quickMaxPairs       = 32               // open TCP ports in a group, all hosts together
	quickServiceTimeout = 30 * time.Second // bound for one port's version detection
	quickMaxProcs       = 8                // nmap processes at one time on the quick path
)

// quickStoreEvery is the pace of partial results of a host being described
// (a variable for tests).
var quickStoreEvery = 2 * time.Second

func (r *run) quickEligible(up []probe.Host) bool {
	if !r.plan.Profile.ServiceDetection || r.e.deps.Fingerprinter == nil || !r.plan.Profile.HTTP.Enabled {
		return false
	}
	n := 0
	for _, h := range up {
		for _, p := range h.Ports {
			if p.Proto == "" || p.Proto == "tcp" {
				n++
			}
		}
	}
	return n > 0 && n <= quickMaxPairs
}

func (r *run) quickResults(ctx context.Context, g *group, up []probe.Host, attempts, rate int, gs *groupStats, withUDP, interim bool) ([]model.HostResult, error) {
	// UDP runs beside the TCP work on its own copy of the hosts.
	udpUp := make([]probe.Host, len(up))
	for i, h := range up {
		udpUp[i] = probe.Host{IP: h.IP}
	}
	udpDone := make(chan error, 1)
	if withUDP && len(r.udpPorts) > 0 {
		go func() { udpDone <- r.udpStage(ctx, g, udpUp, rate, gs) }()
	} else {
		udpDone <- nil
	}
	procs := make(chan struct{}, quickMaxProcs)
	share := max(1, rate/quickMaxProcs)
	results := make([]model.HostResult, len(up))
	var wg sync.WaitGroup
	for i, h := range up {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var store func(model.HostResult)
			if interim {
				store = func(part model.HostResult) { r.interimHost(gs, part) }
			}
			results[i] = r.quickHost(ctx, h, attempts, share, procs, gs, g.v6, store)
		}()
	}
	wg.Wait()
	if err := <-udpDone; err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	for i := range results {
		for _, p := range udpUp[i].Ports {
			s := toService(p)
			nameService(&s)
			r.match(&s, results[i].Hostnames)
			results[i].Services = append(results[i].Services, s)
		}
	}
	return results, nil
}

// quickHost runs version detection per open TCP port and the HTTP stage at
// the same time. A port whose HTTP stage got a page cancels its version
// detection (the page names it); the others keep nmap's answer, bounded by
// quickServiceTimeout.
func (r *run) quickHost(ctx context.Context, h probe.Host, attempts, rate int, procs chan struct{}, gs *groupStats, v6 bool, store func(model.HostResult)) model.HostResult {
	res := r.newHostResult(h, attempts)
	cancels := map[int]context.CancelFunc{}
	var mu sync.Mutex
	detected := map[int]probe.Port{}           // version detection answers
	described := map[int]model.ServiceResult{} // services whose HTTP stage ended
	changed := false
	var svwg sync.WaitGroup
	for _, p := range h.Ports {
		if (p.Proto != "" && p.Proto != "tcp") || p.State != "open" {
			continue
		}
		port := p.Port
		pctx, cancel := context.WithTimeout(ctx, quickServiceTimeout)
		cancels[port] = cancel
		svwg.Add(1)
		go func() {
			defer svwg.Done()
			defer cancel()
			select {
			case procs <- struct{}{}:
			case <-pctx.Done():
				return
			}
			defer func() { <-procs }()
			t0 := r.e.now()
			sv, err := r.prober.ServiceScan(pctx, probe.ServiceRequest{
				Hosts: []probe.HostPorts{{IP: h.IP, Ports: []int{port}}}, Intensity: r.plan.Profile.VersionIntensity,
				MaxRate: rate, HostTimeout: quickServiceTimeout, IPv6: v6,
			})
			r.account(gs, sv, t0)
			if err != nil || sv == nil || pctx.Err() != nil {
				return
			}
			for _, sh := range sv.Hosts {
				for _, d := range sh.Ports {
					if d.Port == port {
						mu.Lock()
						detected[port], changed = d, true
						mu.Unlock()
					}
				}
			}
		}()
	}

	// Partial results go to the store every quickStoreEvery while ports are
	// described, so the first services show within seconds. A partial result
	// lists only the described services and is marked PortsUnknown.
	stop := make(chan struct{})
	var pwg sync.WaitGroup
	if store != nil {
		pwg.Add(1)
		go func() {
			defer pwg.Done()
			t := time.NewTicker(quickStoreEvery)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ctx.Done():
					return
				case <-t.C:
				}
				mu.Lock()
				if !changed {
					mu.Unlock()
					continue
				}
				changed = false
				part := r.newHostResult(probe.Host{IP: h.IP, Reason: h.Reason, RTTMs: h.RTTMs, MAC: h.MAC, Vendor: h.Vendor, Hostnames: h.Hostnames}, attempts)
				for _, p := range h.Ports {
					s, ok := described[p.Port]
					if !ok {
						if _, svOK := detected[p.Port]; !svOK || p.Proto == "udp" {
							continue
						}
						s = toService(p)
					}
					part.Services = append(part.Services, s)
				}
				part = quickMerge(part, detected)
				mu.Unlock()
				r.finishHost(&part)
				if ctx.Err() == nil && len(part.Services) > 0 {
					store(part)
				}
			}
		}()
	}

	r.httpHost(ctx, &res, func(svc *model.ServiceResult) {
		mu.Lock()
		described[svc.Port], changed = *svc, true
		mu.Unlock()
		if svc.HTTP != nil {
			if c := cancels[svc.Port]; c != nil {
				c()
			}
		}
	})
	svwg.Wait()
	close(stop)
	pwg.Wait()
	res = quickMerge(res, detected)
	r.finishHost(&res)
	return res
}

// quickMerge returns a copy of res with the version-detection answers in
// detected, and the HTTP-named ports renamed by their page (see quickHost).
func quickMerge(res model.HostResult, detected map[int]probe.Port) model.HostResult {
	res.Services = append([]model.ServiceResult(nil), res.Services...)
	for i := range res.Services {
		s := &res.Services[i]
		d, ok := detected[s.Port]
		if !ok && s.Proto == "tcp" && s.HTTP != nil {
			// version detection was stopped by the HTTP answer: the name so
			// far is the port table's guess (3000 is "ppp"), the page is a fact
			s.Name = ""
		}
		if !ok || s.Proto != "tcp" {
			continue
		}
		if d.Name != "" {
			s.Name = d.Name
		}
		s.Product, s.Version, s.ExtraInfo, s.Banner, s.Confidence = d.Product, d.Version, d.ExtraInfo, d.Banner, d.Confidence
		if d.CPE != nil {
			s.CPE = d.CPE
		}
		if d.Tunnel != "" {
			s.Tunnel = d.Tunnel
		}
	}
	return res
}

// A small scope gets every TCP port: after the profile's top ports (stored
// at once, so their services show within seconds), a second pass scans the
// rest of 1-65535 on the live hosts. It applies to profiles with a ranked
// port list (top-N), to scopes of at most fullRangeMaxAddresses addresses,
// and to at most fullRangeMaxHosts live hosts in the whole run. An explicit
// port list ("80,443,8080") is scanned as written. One host at cap 1000
// (840 for nmap after the HTTP reserve): about 64 500 ports in ~80 s.
const (
	fullRangeMaxAddresses = 256
	fullRangeMaxHosts     = 16
)

// fullRangePlanned tells whether the run may get the full-range pass.
func (r *run) fullRangePlanned(addresses int64) bool {
	return fullRangeFor(r.plan.Profile.Ports, r.ports, addresses)
}

func fullRangeFor(spec string, ports *probe.PortSet, addresses int64) bool {
	if ports == nil || addresses > fullRangeMaxAddresses {
		return false
	}
	// "1-65535" itself is split the same way: top ports first, then the rest
	return ports.Count() >= 65535 || strings.Contains(strings.ToLower(spec), "top-")
}

// claimFullRange decides the full-range pass for one group: every live host
// of the group must fit into what is left of the run's host budget.
func (r *run) claimFullRange(hosts []probe.Host, scanned map[string]*probe.Host) bool {
	if !r.fullPlanned {
		return false
	}
	n := int64(0)
	for _, h := range hosts {
		if p := scanned[h.IP]; p != nil && !p.TimedOut && (h.Up || p.Responded) {
			n++
		}
	}
	if n == 0 {
		return false
	}
	for {
		left := r.fullLeft.Load()
		if left < n {
			r.log.Info("full port range skipped: too many live hosts", "hosts", n, "budget_left", left)
			return false
		}
		if r.fullLeft.CompareAndSwap(left, left-n) {
			return true
		}
	}
}

// fullScan is the outcome of the full-range port scan.
type fullScan struct {
	res   *probe.Result
	err   error
	ports int
	start time.Time
}

// fullRangeScan scans the ports outside the profile's list on the live hosts.
func (r *run) fullRangeScan(ctx context.Context, g *group, up []probe.Host, rate int, gs *groupStats) fullScan {
	// the policy's allowed and denied ports hold here too
	rest, err := probe.EffectivePorts("1-65535", r.plan.Policy.AllowedPorts, r.plan.Policy.DeniedPorts)
	if err != nil {
		return fullScan{err: err}
	}
	rest.Remove(r.ports)
	ips := make([]string, len(up))
	for i, h := range up {
		ips[i] = h.IP
	}
	t0 := r.e.now()
	if len(ips) == 0 || rest.Count() == 0 {
		return fullScan{start: t0}
	}
	end := r.stats.begin(rate)
	endPass := r.stats.passBegin(model.PassFullRange, len(ips), int64(len(ips)*rest.Count()), rate)
	ps, err := r.prober.PortScan(ctx, probe.PortScanRequest{
		Hosts: ips, Ports: rest, MaxRate: rate, MaxRetries: 1, HostTimeout: portScanTimeout(len(ips), rest.Count(), rate), IPv6: g.v6,
	})
	endPass()
	end()
	r.account(gs, ps, t0)
	return fullScan{res: ps, err: err, ports: rest.Count(), start: t0}
}

// fullRangeFinish describes the new open ports of the full-range scan and
// adds them to results.
func (r *run) fullRangeFinish(ctx context.Context, g *group, up []probe.Host, results []model.HostResult, fs fullScan, attempts, rate int, gs *groupStats) error {
	var ips []string
	byIP := map[string]int{}
	for i, res := range results {
		if res.Up {
			ips = append(ips, res.IP)
			byIP[res.IP] = i
		}
	}
	if fs.res == nil && fs.err == nil {
		r.stats.passState(model.PassFullRange, model.PassSkipped)
		return nil
	}
	ps, err, t0 := fs.res, fs.err, fs.start
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		r.log.Warn("full port range failed, keeping the top ports", "group", g.id, "error", err.Error())
		for _, ip := range ips {
			results[byIP[ip]].PortsUnknown = true // the other ports were not seen: nothing there is gone
		}
		r.stats.warn("Pełny zakres portów nie został przeskanowany (błąd nmap). Usługi spoza listy portów profilu są w tym przebiegu nieznane.")
		return nil
	}
	var more []probe.Host
	for _, h := range ps.Hosts {
		i, ok := byIP[h.IP]
		if !ok {
			continue
		}
		if h.TimedOut {
			results[i].PortsUnknown = true
			r.stats.warn("Pełny zakres portów nie skończył się dla części hostów (limit czasu nmap). Usługi spoza listy portów profilu są w tym przebiegu nieznane.")
			continue
		}
		if len(h.Ports) == 0 {
			continue
		}
		for _, u := range up {
			if u.IP == h.IP {
				u.Ports = h.Ports
				more = append(more, u)
				break
			}
		}
	}
	newOpen := 0
	if len(more) > 0 {
		add, err := r.describeHosts(ctx, g, more, attempts, rate, gs, false, false)
		if err != nil {
			return err
		}
		for _, a := range add {
			i := byIP[a.IP]
			results[i].Services = append(results[i].Services, a.Services...)
			sort.SliceStable(results[i].Services, func(x, y int) bool {
				sx, sy := results[i].Services[x], results[i].Services[y]
				if sx.Proto != sy.Proto {
					return sx.Proto < sy.Proto
				}
				return sx.Port < sy.Port
			})
			newOpen += len(a.Services)
		}
	}
	r.stats.passState(model.PassFullRange, model.PassDone)
	r.log.Info("full port range pass", "group", g.id, "hosts", len(ips), "ports", fs.ports, "new_open", newOpen, "ms", r.e.now().Sub(t0).Milliseconds())
	return nil
}
