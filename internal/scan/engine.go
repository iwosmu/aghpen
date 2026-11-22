package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

// Deps are the collaborators of the engine. Fingerprinter and Signatures may
// be nil: the HTTP stage and the signature stage are skipped then.
type Deps struct {
	Fingerprinter model.Fingerprinter
	Signatures    model.SignatureEngine
	Logger        *slog.Logger
	NmapPath      string // empty: "nmap" from PATH; when nmap is missing the native prober runs

	// Optional settings.
	Prober      probe.Prober     // replaces the nmap/native choice (tests)
	ForceNative bool             // use the native Go prober even when nmap is installed
	Resolver    targets.Resolver // DNS resolver for domain targets; default net.DefaultResolver
	Now         func() time.Time // clock; default time.Now
	OnGroup     func(GroupEvent) // called when a work group ends (dev CLI, diagnostics)
}

// GroupEvent describes one finished work group: the consecutive chunks that
// one nmap process per stage scanned together. Its size is the adaptive
// chunk size.
type GroupEvent struct {
	ID         int       `json:"id"`
	FirstSeq   int       `json:"first_seq"`
	LastSeq    int       `json:"last_seq"`
	Chunks     int       `json:"chunks"`
	Size       int       `json:"size"` // addresses
	Spec       []string  `json:"spec"`
	RatePPS    int       `json:"rate_pps"` // --max-rate share of this group
	Status     string    `json:"status"`
	DurationMs int64     `json:"duration_ms"`
	HostsUp    int       `json:"hosts_up"`
	Packets    int64     `json:"packets"`
	PPS        float64   `json:"pps"`
	NextSize   int       `json:"next_size"` // group size the planner wants next
	StartedAt  time.Time `json:"started_at"`
	Error      string    `json:"error,omitempty"`
}

// Engine implements model.Engine.
type Engine struct {
	// deepHosts: the hosts the deep pass may take per run (CZUJKA_DEEP_PASS_HOSTS, 0 = off)
	deepHosts int
	deps      Deps
	log       *slog.Logger
	now       func() time.Time
	once      sync.Once
	prober    probe.Prober
	// direct is the "second method" of the last retry round: a TCP connect
	// to the ports a host had open before. Tests replace it.
	direct func(ctx context.Context, ip string, ports []int, timeout time.Duration, lim *probe.Limiter) (probe.Host, int64)

	// One budget for every run of the engine: the safety policy's caps hold
	// for all concurrent runs together (a scheduled scan, a re-probe and an
	// ad-hoc run at the same time), the profile's caps are lower limits
	// inside them. See shared.
	sharedMu   sync.Mutex
	global     *Budget                   // nmap packets per second, all runs
	globalHTTP *probe.Limiter            // HTTP requests per second, all runs
	hostLims   map[string]*probe.Limiter // HTTP requests per second to one address, all runs
}

// allowedScope turns the policy's allowed networks (the operator lock
// CZUJKA_ALLOWED_NETWORKS and the policy's own list; an address must lie in
// both when both are set) into the IPv4 addresses outside them and a test
// for IPv6. outside is nil when neither list is set (everything allowed).
func allowedScope(pol model.SafetyPolicy) (outside *targets.Set, v6 func(netip.Addr) bool, err error) {
	lists := [][]string{pol.OperatorNetworks, pol.AllowedNetworks}
	var sets []targets.Set
	var v6s [][]netip.Prefix
	for _, list := range lists {
		var rs []targets.Range
		var p6 []netip.Prefix
		n := 0
		for _, v := range list {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			n++
			var p netip.Prefix
			if strings.Contains(v, "/") {
				if p, err = netip.ParsePrefix(v); err != nil {
					return nil, nil, fmt.Errorf("%q is not a CIDR network", v)
				}
				p = p.Masked()
			} else {
				a, perr := netip.ParseAddr(v)
				if perr != nil {
					return nil, nil, fmt.Errorf("%q is not a CIDR network or an IP address", v)
				}
				a = a.Unmap()
				p = netip.PrefixFrom(a, a.BitLen())
			}
			if p.Addr().Is4() {
				rs = append(rs, targets.PrefixRange(p))
			} else {
				p6 = append(p6, p)
			}
		}
		if n == 0 {
			continue // this list is not set
		}
		sets = append(sets, targets.NewSet(rs...))
		v6s = append(v6s, p6)
	}
	if len(sets) == 0 {
		return nil, func(netip.Addr) bool { return true }, nil
	}
	all := targets.NewSet(targets.Range{Lo: 0, Hi: 0xFFFFFFFF})
	out := targets.NewSet()
	for _, s := range sets {
		out = out.Union(all.Subtract(s)) // outside any one list is outside
	}
	v6 = func(a netip.Addr) bool {
		for _, ps := range v6s {
			in := false
			for _, p := range ps {
				if p.Contains(a) {
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
	return &out, v6, nil
}

// shared returns the engine-wide limits for the policy, made on first use
// and resized when the policy changed (a limiter is replaced, not resized:
// a run that started before keeps the old one until it ends).
func (e *Engine) shared(pol model.SafetyPolicy) (*Budget, *probe.Limiter) {
	l := EffectiveLimits(model.ScanProfile{}, pol)
	e.sharedMu.Lock()
	defer e.sharedMu.Unlock()
	if e.global == nil {
		e.global = NewBudget(l.ProbePPS())
	} else if e.global.Total() != l.ProbePPS() {
		e.global.SetTotal(l.ProbePPS())
	}
	if e.globalHTTP == nil || e.globalHTTP.Rate() != l.HTTPRPS {
		e.globalHTTP = probe.NewLimiter(l.HTTPRPS, 1)
	}
	return e.global, e.globalHTTP
}

// hostLimiter is the engine-wide request limiter of one address.
func (e *Engine) hostLimiter(ip string, perSecond float64) *probe.Limiter {
	e.sharedMu.Lock()
	defer e.sharedMu.Unlock()
	if e.hostLims == nil {
		e.hostLims = map[string]*probe.Limiter{}
	}
	l := e.hostLims[ip]
	if l == nil || l.Rate() != perSecond {
		l = probe.NewLimiter(perSecond, 1)
		e.hostLims[ip] = l
	}
	return l
}

var _ model.Engine = (*Engine)(nil)

// New builds an engine. The prober (nmap or native) is chosen on first use.
func New(d Deps) *Engine {
	e := &Engine{deps: d, log: d.Logger, now: d.Now, direct: probe.ConnectProbe, deepHosts: deepHostsSetting(os.Getenv("CZUJKA_DEEP_PASS_HOSTS"))}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e
}

// Prober returns the prober in use (nmap or native).
func (e *Engine) Prober() probe.Prober {
	e.once.Do(func() {
		if e.deps.Prober != nil {
			e.prober = e.deps.Prober
			return
		}
		e.prober = probe.New(probe.Options{NmapPath: e.deps.NmapPath, ForceNative: e.deps.ForceNative, Logger: e.log})
	})
	return e.prober
}

// run is the state of one Run call.
type run struct {
	// active maps the groupStats of each running group to its group, for
	// the progress inside a group (groupProgress).
	active sync.Map
	// portAnswered counts live hosts that answered the port scan (an open
	// or a closed port); the end-of-run sanity check compares it with the
	// hosts discovery found.
	portAnswered atomic.Int64
	// fullLeft is the host budget of the full-range pass (fullRangePlanned).
	fullLeft atomic.Int64
	// full-range claims go in group order (claimFullRange): fullNext is the
	// highest group id allowed to claim, fullPassed the groups done with it
	fullMu      sync.Mutex
	fullNext    int
	fullPassed  map[int]bool
	fullWake    chan struct{}
	fullPlanned bool
	// the rotating deep pass (deeppass.go): the final results of live hosts
	deepPlanned bool
	finalMu     sync.Mutex
	finals      map[string]model.HostResult
	// fullDone holds the IPs whose full-range pass finished in this run
	fullDone sync.Map

	e       *Engine
	log     *slog.Logger
	plan    model.ScanPlan
	sink    model.ResultSink
	sinkCtx context.Context // survives cancellation, so the final state reaches the store
	prober  probe.Prober
	ports   *probe.PortSet
	disc    model.DiscoveryOpts
	mode    string          // discovery mode: fast, balanced or thorough
	local   []targets.Range // directly connected IPv4 networks
	lim     Limits
	sizer   *sizer
	budget  *Budget
	stats   *statsKeeper
	httpLim *probe.Limiter
	// the engine-wide limits (Engine.shared) the run takes from as well
	global     *Budget
	globalHTTP *probe.Limiter
	polPerHost float64 // the policy's per-host request rate (engine-wide limiter)
	hostSem    chan struct{}
	paths      []string
	udpPorts   []int // allow-listed UDP ports to probe; empty: no UDP stage
	// covered holds, per host IP, the extra TCP ports a finished dense or
	// full-range pass scanned (*probe.PortSet); see coverage.
	covered sync.Map
	// udpCovered holds the IPs whose UDP stage finished (the UDP ports count
	// as covered only there; a failed or skipped stage covers nothing).
	udpCovered sync.Map

	hostnames map[string][]string
	hints     map[string]model.HostHint
	hintIPs   []uint32

	mu         sync.Mutex
	all        []*unit
	pending    []*unit
	running    int
	groupSeq   int
	windowStop bool
	firstErr   error
}

// Run executes one scan plan. See model.Engine.
func (e *Engine) Run(ctx context.Context, plan model.ScanPlan, sink model.ResultSink) model.RunOutcome {
	prev := model.RunStats{}
	if plan.PrevStats != nil {
		prev = *plan.PrevStats
	}
	log := e.log.With("run", plan.RunID)
	fail := func(err error) model.RunOutcome {
		log.Error("run refused", "error", err.Error())
		return model.RunOutcome{Status: model.RunFailed, Stats: prev, Err: err}
	}

	// 1. Safety gate.
	if plan.Policy.EmergencyStop {
		if len(plan.Chunks) > 0 {
			// a paused run stays paused, its remaining chunks are kept
			log.Warn("emergency stop is active: the paused run is not resumed")
			return model.RunOutcome{Status: model.RunPaused, PauseReason: model.PauseEmergency, Stats: prev, Err: ErrEmergencyStop}
		}
		return fail(ErrEmergencyStop)
	}
	if sink == nil {
		return fail(errors.New("scan: no result sink"))
	}

	// 2. Effective limits and ports: the stricter of profile and policy.
	ports, err := probe.EffectivePorts(plan.Profile.Ports, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts)
	if err != nil {
		return fail(fmt.Errorf("scan: ports: %w", err))
	}
	if ports.Count() == 0 {
		return fail(errors.New("scan: the safety policy leaves no port to scan"))
	}
	disc := probe.NormalizeDiscovery(plan.Profile.Discovery)
	if disc.TCPSynPorts, err = probe.FilterPorts(disc.TCPSynPorts, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts); err != nil {
		return fail(err)
	}
	disc.TCPAckPorts, _ = probe.FilterPorts(disc.TCPAckPorts, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts)
	if len(disc.TCPSynPorts) == 0 && !disc.ICMPEcho && !disc.ICMPTimestamp && !disc.SkipDiscovery {
		// the policy removed every TCP probe port: probe the first ports of the allowed set
		list := ports.List()
		disc.TCPSynPorts = list[:min(3, len(list))]
	}
	lim := EffectiveLimits(plan.Profile, plan.Policy)

	// 3. Scope: merge targets, resolve domains, subtract exclusions.
	exp := targets.Expand(ctx, plan.Targets, plan.Policy.Exclusions, e.deps.Resolver, 3*time.Second)
	for d, why := range exp.Unresolved {
		log.Warn("domain target does not resolve, skipped", "domain", d, "reason", why)
	}
	if ctx.Err() != nil {
		return model.RunOutcome{Status: model.RunCancelled, Stats: prev, Err: context.Cause(ctx)}
	}
	// The allowed networks hold inside the engine too: the runner checked
	// the targets, but a domain is resolved again here (its answer may have
	// changed) and a resumed run brings stored chunks (the lock may have
	// been narrowed during the pause). Addresses outside are dropped.
	outside, v6Allowed, err := allowedScope(plan.Policy)
	if err != nil {
		return fail(fmt.Errorf("scan: allowed networks: %w", err))
	}
	if outside != nil {
		before := exp.Count()
		exp.V4 = exp.V4.Subtract(*outside)
		kept := exp.V6[:0:0]
		for _, a := range exp.V6 {
			if v6Allowed(a) {
				kept = append(kept, a)
			}
		}
		exp.V6 = kept
		if n := before - exp.Count(); n > 0 {
			log.Warn("addresses outside the allowed networks dropped by the engine", "addresses", n)
		}
	}

	r := &run{
		e: e, log: log, plan: plan, sink: sink, sinkCtx: context.WithoutCancel(ctx),
		prober: e.Prober(), ports: ports, disc: disc, lim: lim,
		mode: discoveryMode(plan.Profile.Discovery.Mode), local: localNetsFn(),
		budget:    NewBudget(lim.ProbePPS()),
		httpLim:   probe.NewLimiter(lim.HTTPRPS, 1), // no burst: the cap holds in every second
		hostSem:   make(chan struct{}, lim.ParallelHosts),
		hostnames: exp.Hostnames,
		hints:     map[string]model.HostHint{},
		finals:    map[string]model.HostResult{},
	}
	r.global, r.globalHTTP = e.shared(plan.Policy)
	r.polPerHost = EffectiveLimits(model.ScanProfile{}, plan.Policy).PerHostRPS
	for _, h := range plan.Hints {
		p, err := targets.ParseValue(h.IP)
		if err != nil || p.Count != 1 {
			continue
		}
		r.hints[p.Value] = h
		if !p.V6.IsValid() {
			r.hintIPs = append(r.hintIPs, p.Range.Lo)
		}
	}
	sort.Slice(r.hintIPs, func(i, j int) bool { return r.hintIPs[i] < r.hintIPs[j] })
	if e.deps.Signatures != nil && plan.Profile.HTTP.SignaturePaths && lim.MaxPaths > 0 {
		r.paths = e.deps.Signatures.ExtraPaths()
		if len(r.paths) > lim.MaxPaths {
			r.paths = r.paths[:lim.MaxPaths]
		}
	}

	if plan.Profile.UDP.Enabled {
		udp, err := probe.UDPPorts(plan.Profile.UDP.Ports, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts)
		_, can := r.prober.(probe.UDPScanner)
		switch {
		case err != nil:
			return fail(fmt.Errorf("scan: UDP ports: %w", err))
		case len(udp) == 0:
			log.Warn("UDP scan skipped: the profile and the safety policy leave no allow-listed UDP port")
		case !can || !r.prober.Privileged():
			log.Warn("UDP scan skipped: it needs nmap with raw sockets (root or CAP_NET_RAW)", "prober", r.prober.Name(), "privileged", r.prober.Privileged())
		default:
			r.udpPorts = udp
			log.Info("UDP scan is on", "ports", fmt.Sprint(udp))
		}
	}

	// 4. Plan: fresh, or the remaining chunks of a paused run.
	chunking := normalizeChunking(plan.Profile.Chunking)
	resumed := len(plan.Chunks) > 0
	var units []*unit
	if resumed {
		excl := exp.Exclusions
		if outside != nil {
			excl = excl.Union(*outside)
		}
		units, err = unitsFromChunks(plan.Chunks, excl, v6Allowed)
	} else {
		units, err = buildUnits(plan.RunID, exp.V4, exp.V6, r.hintIPs, unitSizeFor(chunking, exp.Count()))
	}
	if err != nil {
		return fail(fmt.Errorf("scan: plan: %w", err))
	}
	unitSize := blockSize
	var total int64
	for _, u := range units {
		total += int64(u.c.Size)
		unitSize = max(unitSize, min(u.c.Size, chunking.MaxSize))
	}
	if !resumed {
		unitSize = unitSizeFor(chunking, exp.Count())
	}
	r.all, r.pending = units, append([]*unit{}, units...)
	r.sizer = newSizer(chunking, unitSize)
	if plan.MeasuredPPS > 0 && chunking.Adaptive && !resumed {
		// history: start near the size that should take target_seconds
		perAddr := r.packetsPerAddress()
		guess := plan.MeasuredPPS / perAddr * float64(chunking.TargetSeconds)
		r.sizer.cur = clampF(guess, r.sizer.min, r.sizer.max)
	}

	r.stats = newStatsKeeper(plan.PrevStats, e.now)
	r.stats.partial = r.groupProgress
	r.stats.update(func(s *model.RunStats) {
		s.AddressesTotal = s.AddressesDone + total
		s.ChunksTotal = s.ChunksDone + len(units)
	})
	if !r.fullRangePlanned(int64(total)) && e.deepHosts > 0 && deepFor(plan.Profile.Ports, r.ports, int64(total)) {
		r.deepPlanned = true
		r.stats.addPass(model.PassTopPorts)
		r.stats.addPass(model.PassDeep)
	}
	if r.fullPlanned = r.fullRangePlanned(int64(total)); r.fullPlanned {
		if r.ports.Count() >= 65535 {
			// every port asked for: the top ports go first, so their services
			// show within seconds, and the second pass scans the rest
			if top, err := probe.EffectivePorts("top-1000", plan.Policy.AllowedPorts, plan.Policy.DeniedPorts); err == nil && top.Count() > 0 {
				r.ports = top
			}
		}
		r.fullLeft.Store(fullRangeMaxHosts)
		r.stats.addPass(model.PassTopPorts)
		r.stats.addPass(model.PassFullRange)
	}

	chunks := make([]model.Chunk, len(units))
	for i, u := range units {
		chunks[i] = u.c
	}
	if err := sink.OnPlan(ctx, plan.RunID, chunks); err != nil {
		return fail(fmt.Errorf("scan: sink rejected the plan: %w", err))
	}
	log.Info("scan plan ready",
		"addresses", total, "excluded", exp.Excluded, "chunks", len(units), "unit_size", unitSize,
		"resumed", resumed, "prober", r.prober.Name(), "privileged", r.prober.Privileged(),
		"ports", ports.Count(), "pps", lim.PPS, "parallel_chunks", lim.ParallelChunks,
		"http_rps", lim.HTTPRPS, "hints", len(r.hints), "first_group", r.sizer.Next(), "discovery", r.mode)
	return r.execute(ctx)
}

// packetsPerAddress estimates the discovery packets for one dead address.
func (r *run) packetsPerAddress() float64 {
	return deadCost(r.disc, r.prober.Privileged(), r.mode, liveBlockGuess)
}

func discoveryProbes(d model.DiscoveryOpts, privileged bool) float64 {
	if d.SkipDiscovery {
		return 0
	}
	return float64(max(1, probeCount(d, privileged)))
}

func (r *run) execute(ctx context.Context) model.RunOutcome {
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if we := r.plan.WindowEnd; we != nil {
		if d := we.Sub(r.e.now()); d <= 0 {
			cancel(ErrPauseWindow)
		} else {
			t := time.AfterFunc(d, func() { cancel(ErrPauseWindow) })
			defer t.Stop()
		}
	}

	// progress about once per second
	progStop := make(chan struct{})
	var progWG sync.WaitGroup
	progWG.Add(1)
	go func() {
		defer progWG.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if err := r.sink.OnProgress(r.sinkCtx, r.plan.RunID, r.stats.snapshot()); err != nil {
					r.log.Debug("sink OnProgress failed", "error", err.Error())
				}
			case <-progStop:
				return
			}
		}
	}()

	sem := make(chan struct{}, r.lim.ParallelChunks)
	var wg sync.WaitGroup
loop:
	for {
		select {
		case sem <- struct{}{}:
		case <-workCtx.Done():
			break loop
		}
		g, rate := r.claim()
		if g == nil {
			<-sem
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.runGroup(workCtx, g, rate)
		}()
	}
	wg.Wait()
	if r.deepPlanned && workCtx.Err() == nil && r.allChunksDone() {
		// the speed the planner learns from is the general pass's: the deep
		// pass sends at the run's whole share, one host at a time, and would
		// make the next run's first group too large (one group, every live
		// host, a small share)
		gen := r.stats.snapshot().AvgPPS
		r.stats.update(func(s *model.RunStats) { s.GeneralPPS = gen })
		r.deepPass(workCtx)
	}
	close(progStop)
	progWG.Wait()
	return r.finish(ctx, workCtx)
}

// allChunksDone reports whether every chunk of the run is done (the
// general pass ended without a pause, a failure or a deferred chunk).
func (r *run) allChunksDone() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.all {
		if u.c.Status != model.ChunkDone {
			return false
		}
	}
	return true
}

// claim takes the next work group, or nil when nothing may start: no chunk
// is left, or the next one would not fit before the window ends.
func (r *run) claim() (*group, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 || r.windowStop {
		return nil, 0
	}
	g, rest := takeGroup(r.pending, r.sizer.Next())
	// equal share of the packet budget; the last lone group may use all of it
	rate := r.budget.Share(r.lim.ParallelChunks)
	if len(rest) == 0 && r.running == 0 {
		rate = r.lim.ProbePPS()
	}
	if we := r.plan.WindowEnd; we != nil {
		left := we.Sub(r.e.now())
		for r.estimate(g.size, rate) > left {
			if len(g.units) == 1 {
				r.windowStop = true
				r.log.Info("window guard: the next chunk does not fit before the window ends, no new chunk starts",
					"chunk", g.units[0].c.Seq, "size", g.size, "estimate_ms", r.estimate(g.size, rate).Milliseconds(), "left_ms", left.Milliseconds())
				return nil, 0
			}
			last := g.units[len(g.units)-1]
			g.units = g.units[:len(g.units)-1]
			g.size -= last.c.Size
		}
		rest = r.pending[len(g.units):]
	}
	r.pending = rest
	r.groupSeq++
	g.id = r.groupSeq
	r.running++
	r.sizer.record(g.size)
	return g, rate
}

// estimate predicts the wall time of a group: from the measured speed when
// there is one, else from the packet count and the rate.
func (r *run) estimate(size, rate int) time.Duration {
	if d, ok := r.sizer.Estimate(size); ok {
		return d
	}
	sec := float64(size) * r.packetsPerAddress() / float64(max(1, rate))
	return time.Duration(sec * float64(time.Second))
}

func (r *run) emitChunk(u *unit) {
	if err := r.sink.OnChunk(r.sinkCtx, u.c); err != nil {
		r.log.Warn("sink OnChunk failed", "chunk", u.c.Seq, "error", err.Error())
		r.stats.update(func(s *model.RunStats) { s.Errors++ })
	}
}

// groupStats are the counters of one group. They are taken back when the
// group is deferred, because its chunks will be scanned again.
type groupStats struct {
	mu       sync.Mutex
	hostsUp  int
	services int
	http     int
	packets  int64
	hosts    []model.HostResult      // reported to the sink when the group is final
	interim  map[string]interimCount // partial results already stored, not yet final
	// discovery ended and found live hosts (progress inside the group)
	discovered bool
	live       int
}

func (r *run) runGroup(ctx context.Context, g *group, want int) {
	defer r.fullPass(g.id) // a group that never claims must not hold the later ones
	defer func() {
		r.mu.Lock()
		r.running--
		r.mu.Unlock()
	}()
	start := r.e.now()
	for _, u := range g.units {
		t := start
		u.c.Status, u.c.StartedAt, u.c.FinishedAt, u.c.Error, u.hostUp = model.ChunkRunning, &t, nil, "", 0
		u.c.Group = g.units[0].c.Seq
		r.emitChunk(u)
	}
	gs := &groupStats{}
	r.active.Store(gs, g)
	defer r.active.Delete(gs) // a deferred or failed group's partial progress goes away
	rate, err := r.budget.Acquire(ctx, want)
	if err == nil {
		// the group's share must also fit into what all runs together may send
		var got int
		if got, err = r.global.Acquire(ctx, rate); err == nil {
			if got < rate {
				r.budget.Release(rate - got)
				rate = got
			}
			sh := &share{r: r, rate: rate}
			err = r.scanGroup(ctx, g, sh, gs)
			r.global.Release(sh.rate)
			rate = sh.rate // what the group held at the end, given back below
		}
		r.budget.Release(rate)
	}
	end := r.e.now()
	dur := end.Sub(start)
	pps := 0.0
	if dur > 0 {
		pps = round1(float64(gs.packets) / dur.Seconds())
	}

	status := model.ChunkDone
	errText := ""
	switch {
	case ctx.Err() != nil:
		status = model.ChunkDeferred
		var pi interimCount
		for _, c := range gs.interim {
			pi.hosts, pi.open, pi.web = pi.hosts+c.hosts, pi.open+c.open, pi.web+c.web
		}
		r.stats.update(func(s *model.RunStats) {
			s.HostsUp -= gs.hostsUp + pi.hosts
			s.ServicesOpen -= gs.services + pi.open
			s.HTTPServices -= gs.http + pi.web
		})
	case err != nil:
		status = model.ChunkFailed
		errText = err.Error()
		r.log.Error("chunk group failed", "group", g.id, "chunks", g.label(), "error", errText)
		r.mu.Lock()
		if r.firstErr == nil {
			r.firstErr = err
		}
		r.mu.Unlock()
		r.stats.update(func(s *model.RunStats) { s.Errors++ })
	default:
		r.sizer.Observe(g.size, dur)
		r.stats.update(func(s *model.RunStats) {
			s.AddressesDone += int64(g.size)
			s.ChunksDone += len(g.units)
			r.active.Delete(gs) // under the keeper's lock: a snapshot never counts the group twice
		})
	}
	if status != model.ChunkDeferred {
		// hosts first, then the chunk state: a chunk marked done has its results stored
		for _, h := range gs.hosts {
			if h.Up && !h.PortsUnknown && !h.Interim {
				h.Coverage = r.coverage(h.IP)
				_, h.FullPorts = r.fullDone.Load(h.IP)
				r.keepFinal(h)
			}
			if err := r.sink.OnHost(r.sinkCtx, h); err != nil {
				r.log.Warn("sink OnHost failed", "ip", h.IP, "error", err.Error())
				r.stats.update(func(s *model.RunStats) { s.Errors++ })
			}
		}
	}
	gs.hosts = nil
	for _, u := range g.units {
		u.c.Status, u.c.Error, u.c.PPS, u.c.HostsUp = status, errText, pps, u.hostUp
		// the group ran as one process: each chunk gets its share of the time
		u.c.DurationMs = dur.Milliseconds() * int64(u.c.Size) / int64(max(1, g.size))
		if status != model.ChunkDeferred {
			t := end
			u.c.FinishedAt = &t
		} else {
			u.c.HostsUp = 0
		}
		r.emitChunk(u)
	}
	ev := GroupEvent{
		ID: g.id, FirstSeq: g.units[0].c.Seq, LastSeq: g.units[len(g.units)-1].c.Seq, Chunks: len(g.units),
		Size: g.size, Spec: g.specs(), RatePPS: rate, Status: string(status), DurationMs: dur.Milliseconds(),
		HostsUp: gs.hostsUp, Packets: gs.packets, PPS: pps, NextSize: r.sizer.Next(), StartedAt: start, Error: errText,
	}
	r.log.Info("chunk group finished", "group", g.id, "chunks", g.label(), "size", g.size, "status", ev.Status,
		"ms", ev.DurationMs, "hosts_up", ev.HostsUp, "packets", ev.Packets, "pps", ev.PPS, "rate_cap", rate, "next_size", ev.NextSize)
	if r.e.deps.OnGroup != nil {
		r.e.deps.OnGroup(ev)
	}
}

// finish computes the outcome and marks unfinished chunks as deferred.
func (r *run) finish(parent, work context.Context) model.RunOutcome {
	open, done, failed := 0, 0, 0
	for _, u := range r.all {
		switch u.c.Status {
		case model.ChunkDone:
			done++
		case model.ChunkFailed:
			failed++
		default:
			open++
		}
	}
	out := model.RunOutcome{Status: model.RunCompleted}
	switch {
	case parent.Err() != nil:
		cause := context.Cause(parent)
		if reason, ok := pauseReason(cause); ok {
			out.Status, out.PauseReason = model.RunPaused, reason
		} else {
			out.Status, out.Err = model.RunCancelled, cause
		}
	case open > 0:
		// the window closed, or the guard refused to start the next chunk
		out.Status, out.PauseReason = model.RunPaused, model.PauseWindowClosed
	case failed > 0 && done == 0:
		out.Status, out.Err = model.RunFailed, r.firstErr
	}
	if out.Status != model.RunCompleted && out.Status != model.RunFailed {
		for _, u := range r.all {
			if u.c.Status == model.ChunkPending || u.c.Status == model.ChunkRunning {
				u.c.Status = model.ChunkDeferred
				r.emitChunk(u)
			}
		}
	}
	r.sanityCheck()
	r.stats.finishPasses(out.Status == model.RunCompleted)
	out.Stats = r.stats.snapshot()
	if out.Status == model.RunCompleted {
		out.Stats.ETASec = 0
	}
	if err := r.sink.OnProgress(r.sinkCtx, r.plan.RunID, out.Stats); err != nil {
		r.log.Debug("sink OnProgress failed", "error", err.Error())
	}
	r.log.Info("run finished", "status", out.Status, "pause_reason", out.PauseReason,
		"addresses_done", out.Stats.AddressesDone, "addresses_total", out.Stats.AddressesTotal,
		"chunks_done", out.Stats.ChunksDone, "chunks_total", out.Stats.ChunksTotal, "deferred", open,
		"hosts_up", out.Stats.HostsUp, "services", out.Stats.ServicesOpen, "packets", out.Stats.PacketsSent,
		"avg_pps", out.Stats.AvgPPS, "elapsed_sec", out.Stats.ElapsedSec, "group_sizes", fmt.Sprint(r.sizer.History()))
	return out
}

// DefaultLiveRate is the share of live addresses the estimate assumes for a
// scope the inventory does not know (the high end of the range);
// LowLiveRate is the low end.
const (
	DefaultLiveRate = 0.05
	LowLiveRate     = 0.01
)

// scopeOnLink reports whether every IPv4 target of the plan lies in a
// directly connected network, so discovery would be ARP-only.
func (e *Engine) scopeOnLink(plan model.ScanPlan) bool {
	local := localNetsFn()
	if len(local) == 0 {
		return false
	}
	vals := make([]string, len(plan.Targets))
	for i, t := range plan.Targets {
		vals[i] = t.Value
	}
	st := targets.Build(vals)
	if len(st.V6) > 0 || len(st.Domains) > 0 || st.V4.Count() == 0 {
		return false
	}
	for _, rg := range st.V4.Ranges() {
		in := false
		for _, n := range local {
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

// Estimate computes the traffic budget of a plan. It sends nothing: domains
// are not resolved and count as one address each.
func (e *Engine) Estimate(plan model.ScanPlan) model.ScanEstimate {
	lim := EffectiveLimits(plan.Profile, plan.Policy)
	chunking := normalizeChunking(plan.Profile.Chunking)
	est := model.ScanEstimate{EffectivePPS: lim.PPS, FitsWindow: true, DiscoveryMode: discoveryMode(plan.Profile.Discovery.Mode)}

	if len(plan.Chunks) > 0 {
		for _, c := range plan.Chunks {
			if c.Status != model.ChunkDone {
				est.Addresses += int64(c.Size)
				est.Chunks++
			}
		}
	} else {
		total, excluded := targets.Count(plan.Targets, plan.Policy.Exclusions)
		est.Addresses = total - excluded
		us := int64(unitSizeFor(chunking, est.Addresses))
		est.Chunks = int((est.Addresses + us - 1) / us)
		vals := make([]string, len(plan.Targets))
		for i, t := range plan.Targets {
			vals[i] = t.Value
		}
		st := targets.Build(vals)
		set := st.V4.Subtract(targets.Build(plan.Policy.Exclusions).V4)
		if set.BlockCount() <= 1<<16 { // exact count for scopes up to a /8
			if units, err := buildUnits(0, set, st.V6, nil, int(us)); err == nil {
				est.Chunks = len(units) + (len(st.Domains)+blockSize-1)/blockSize
			}
		}
	}
	if est.Addresses <= 0 {
		return est
	}

	// Expected share of live addresses: from the inventory when it knows
	// hosts in this scope. A new scope has no such number: the estimate is
	// then a range, from LowLiveRate (est_packets_low) to the cautious
	// default (est_packets). Measured on the lab /16: 67 of 65 487 addresses
	// live (0.1 %), which the second run's estimate learns from the inventory.
	est.ExpectedLiveRate = DefaultLiveRate
	if len(plan.Hints) > 0 {
		est.ExpectedLiveRate = math.Min(1, float64(len(plan.Hints))/float64(est.Addresses))
	}

	nPorts := 100.0
	fullRange, deep := false, false
	if ports, err := probe.EffectivePorts(plan.Profile.Ports, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts); err == nil {
		nPorts = float64(ports.Count())
		fullRange = fullRangeFor(plan.Profile.Ports, ports, est.Addresses)
		deep = !fullRange && e.deepHosts > 0 && deepFor(plan.Profile.Ports, ports, est.Addresses)
	}
	if deep {
		// the rotating deep pass: up to deepHosts live hosts get the rest of
		// 1-65535; the known live hosts beyond that wait for later runs
		est.DeepMaxHosts = e.deepHosts
		est.DeepWaitingHosts = max(0, len(plan.Hints)-e.deepHosts)
	}
	if fullRange {
		est.FullRangeMaxHosts = fullRangeMaxHosts
		est.FullRangeMaxAddresses = fullRangeMaxAddresses
		if all, err := probe.EffectivePorts("1-65535", plan.Policy.AllowedPorts, plan.Policy.DeniedPorts); err == nil {
			first, _ := probe.EffectivePorts(plan.Profile.Ports, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts)
			if first != nil && first.Count() >= 65535 { // 1-65535: the top ports go first
				first, _ = probe.EffectivePorts("top-1000", plan.Policy.AllowedPorts, plan.Policy.DeniedPorts)
			}
			if first != nil {
				all.Remove(first)
			}
			est.FullRangePorts = all.Count()
			est.EstFullRangeSecPerHost = math.Round(float64(est.FullRangePorts)/(float64(lim.ProbePPS())*0.9)*10) / 10
		}
	}
	disc := probe.NormalizeDiscovery(plan.Profile.Discovery)
	privileged := e.Prober().Privileged()
	probes := discoveryProbes(disc, privileged)
	// ARP-only discovery (see discover): one frame per address and two
	// retries for the silent ones, plus the confirmation sweep of live blocks.
	arpOnly := privileged && !disc.SkipDiscovery && e.scopeOnLink(plan)
	// Share of /24 blocks that get the second pass: the blocks the inventory
	// knows hosts in, or a guess for a new scope.
	liveBlocks := liveBlockGuess
	if len(plan.Hints) > 0 {
		seen := map[string]bool{}
		for _, h := range plan.Hints {
			if p, err := targets.ParseValue(h.IP); err == nil && !p.V6.IsValid() {
				seen[fmt.Sprint(p.Range.Lo>>8)] = true
			}
		}
		liveBlocks = math.Min(1, float64(len(seen))*256/float64(est.Addresses))
	}
	calc := func(rate float64) (packets, sec float64) {
		live := float64(est.Addresses) * rate
		dead := float64(est.Addresses) - live
		switch {
		case disc.SkipDiscovery:
			packets = float64(est.Addresses) * nPorts * 2 // every address gets a port scan, silent ports are retried
		case arpOnly:
			packets = dead*3*(1+liveBlocks) + live
			packets += live * nPorts * 1.05
		default:
			packets = dead*deadCost(disc, privileged, est.DiscoveryMode, liveBlocks) + live*probes
			packets += live * nPorts * 1.05
		}
		if fullRange {
			// the second pass: the rest of 1-65535 on up to fullRangeMaxHosts live hosts
			// (a new scope: every address may be live, the cautious figure)
			fh := live
			if len(plan.Hints) == 0 && rate == est.ExpectedLiveRate {
				fh = float64(est.Addresses)
			}
			packets += math.Min(fh, fullRangeMaxHosts) * (65535 - nPorts) * 1.02
		}
		if deep {
			packets += math.Min(live, float64(e.deepHosts)) * (65535 - nPorts) * 1.02
		}
		if plan.Profile.ServiceDetection {
			packets += live * 3 * 14 // about 3 open ports per host, about 14 packets per version probe
		}
		if plan.Profile.UDP.Enabled {
			if udp, err := probe.UDPPorts(plan.Profile.UDP.Ports, plan.Policy.AllowedPorts, plan.Policy.DeniedPorts); err == nil {
				packets += live * float64(len(udp)) * 2 // one retry for silent ports
				if plan.Profile.ServiceDetection {
					packets += live * 0.1 * float64(len(udp)) * 3 // version probes of the open ones (about 1 in 10 answers)
				}
			}
		}
		if plan.Profile.Retry.UnstableRetries > 0 {
			packets += float64(len(plan.Hints)) * 0.1 * probes * float64(plan.Profile.Retry.UnstableRetries)
		}
		if plan.MeasuredPPS > 0 {
			return packets, packets / plan.MeasuredPPS
		}
		// nmap seldom holds the cap exactly; process start and the service
		// stage add fixed time per group
		groups := math.Ceil(float64(est.Addresses) / float64(chunking.MaxSize))
		sec = packets/(float64(lim.PPS)*0.85) + groups*2/float64(lim.ParallelChunks)
		if plan.Profile.ServiceDetection {
			sec += live * 3 * 1.5 / float64(lim.ParallelHosts)
		}
		return packets, sec
	}
	packets, sec := calc(est.ExpectedLiveRate)
	est.BasedOnHistory = plan.MeasuredPPS > 0
	est.EstPackets = int64(packets)
	est.EstPacketsLow, est.EstDurationLowSec = est.EstPackets, int64(math.Ceil(sec))
	if len(plan.Hints) == 0 && LowLiveRate < est.ExpectedLiveRate {
		lowP, lowS := calc(LowLiveRate)
		est.EstPacketsLow, est.EstDurationLowSec = int64(lowP), int64(math.Ceil(lowS))
	}
	est.EstDurationSec = int64(math.Ceil(sec))
	if plan.WindowEnd != nil {
		est.WindowSec = int64(plan.WindowEnd.Sub(e.now()).Seconds())
		if est.WindowSec < 0 {
			est.WindowSec = 0
		}
		est.FitsWindow = est.EstDurationSec <= est.WindowSec
	}
	return est
}

// sanityCheck warns when the run found hosts but lost their ports: a run like
// that must not look like a clean success. Measured on the public instance:
// 71 hosts up, 8 open services instead of 107, no error, and the diff then
// reported 100 services gone. Live hosts on a network answer a SYN to a
// closed port with a reset, so most of them answer the port scan.
func (r *run) sanityCheck() {
	s := r.stats.snapshot()
	if r.disc.SkipDiscovery || s.HostsUp < minHostsForSanity {
		return
	}
	answered := r.portAnswered.Load()
	if answered*2 < int64(s.HostsUp) {
		r.log.Warn("sanity check: most live hosts gave the port scan no answer", "hosts_up", s.HostsUp, "answered", answered)
		r.stats.warn(fmt.Sprintf("Wykrywanie znalazło %d hostów, a na skan portów odpowiedziało tylko %d. Wynik portów jest niepełny: sprawdź limit pakietów, limit czasu i obciążenie sieci.", s.HostsUp, answered))
	}
}

// share is the packet rate a running group holds in the run budget and in
// the global budget. It is fixed for each nmap process; between the
// group's stages grow adds the budget that other groups gave back.
type share struct {
	r    *run
	rate int
}

// grow adds free packet budget to the group's share between its nmap
// stages, only when no group waits to start (the tail of the run): a long
// group that started with a small share does not run on at it while the
// rest of the budget is idle. It never waits, never takes more than the
// run's probe rate, and stays inside both budgets.
func (s *share) grow() int {
	r := s.r
	r.mu.Lock()
	waiting := len(r.pending) > 0 && !r.windowStop
	r.mu.Unlock()
	if want := r.lim.ProbePPS() - s.rate; !waiting && want > 0 {
		if n := r.budget.TryAcquire(want); n > 0 {
			got := r.global.TryAcquire(n)
			if got < n {
				r.budget.Release(n - got)
			}
			if got > 0 {
				r.log.Debug("group share grew", "from", s.rate, "to", s.rate+got)
				s.rate += got
			}
		}
	}
	return s.rate
}

// discoveryShare is the part of a group's work that host discovery stands
// for in its progress; the rest is spread over the live hosts it found.
const discoveryShare = 0.2

// groupProgress sums the addresses that the running groups count as done:
// a group whose discovery ended counts discoveryShare of its size, plus the
// rest in proportion to its live hosts with a final result (a partial
// result counts half). A running group never counts its whole size.
func (r *run) groupProgress() int64 {
	var sum int64
	r.active.Range(func(k, v any) bool {
		gs, g := k.(*groupStats), v.(*group)
		gs.mu.Lock()
		discovered, live, done := gs.discovered, gs.live, float64(gs.hostsUp)+0.5*float64(len(gs.interim))
		gs.mu.Unlock()
		if !discovered || g.size <= 1 {
			return true
		}
		f := discoveryShare
		if live > 0 {
			f += (1 - discoveryShare) * min(1, done/float64(live))
		}
		sum += min(int64(f*float64(g.size)), int64(g.size-1))
		return true
	})
	return sum
}

// minHostsForSanity: below this many live hosts the ratio says little.
const minHostsForSanity = 8
