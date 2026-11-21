// Command scanprobe is a development CLI for the scan engine. It runs one
// plan without the database and prints each HostResult as a JSON line on
// stdout, then one summary line. Logs and chunk events go to stderr.
//
//	scanprobe -targets "10.77.0.0/22" -ports top-100 -pps 500
//	scanprobe -targets "10.77.0.0/22" -pps 200 -stop-after 6s -resume
//
// Scan only networks you own or are allowed to scan.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/scan"
	"github.com/iwosmu/aghpen/internal/sig"
	"github.com/iwosmu/aghpen/internal/targets"
)

// memSink keeps the run in memory and prints hosts as they arrive.
type memSink struct {
	mu     sync.Mutex
	out    *json.Encoder
	chunks map[int]model.Chunk
	hosts  int
	last   model.RunStats
	quiet  bool
}

func (m *memSink) OnPlan(_ context.Context, _ int64, chunks []model.Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range chunks {
		m.chunks[c.Seq] = c
	}
	fmt.Fprintf(os.Stderr, "plan: %d chunks\n", len(chunks))
	return nil
}

func (m *memSink) OnChunk(_ context.Context, c model.Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chunks[c.Seq] = c
	return nil
}

func (m *memSink) OnHost(_ context.Context, h model.HostResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts++
	return m.out.Encode(h)
}

func (m *memSink) OnProgress(_ context.Context, _ int64, s model.RunStats) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = s
	if !m.quiet {
		fmt.Fprintf(os.Stderr, "progress: %d/%d addresses, %d/%d chunks, %d hosts up, %d services, %d packets, now %.0f pps, avg %.0f pps, elapsed %ds, eta %ds\n",
			s.AddressesDone, s.AddressesTotal, s.ChunksDone, s.ChunksTotal, s.HostsUp, s.ServicesOpen, s.PacketsSent, s.CurrentPPS, s.AvgPPS, s.ElapsedSec, s.ETASec)
	}
	return nil
}

// remaining returns the chunks that a resume has to do.
func (m *memSink) remaining() []model.Chunk {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Chunk
	for _, c := range m.chunks {
		if c.Status != model.ChunkDone {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

func (m *memSink) byStatus() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, c := range m.chunks {
		out[string(c.Status)]++
	}
	return out
}

// ifaceMeter samples the transmit packet counter of a network interface
// once per second (Linux). It measures all traffic of this machine or
// container on that interface, so it is an upper bound for probe packets.
type ifaceMeter struct {
	path    string
	stop    chan struct{}
	done    chan struct{}
	first   int64
	lastVal int64
	peak    int64
	samples []int64
	ok      bool
}

func readCounter(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

func startMeter(iface string) *ifaceMeter {
	m := &ifaceMeter{path: "/sys/class/net/" + iface + "/statistics/tx_packets", stop: make(chan struct{}), done: make(chan struct{})}
	m.first, m.ok = readCounter(m.path)
	m.lastVal = m.first
	if !m.ok {
		close(m.done)
		return m
	}
	go func() {
		defer close(m.done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				m.sample()
			case <-m.stop:
				return
			}
		}
	}()
	return m
}

func (m *ifaceMeter) sample() {
	if v, ok := readCounter(m.path); ok {
		d := v - m.lastVal
		m.lastVal = v
		m.samples = append(m.samples, d)
		if d > m.peak {
			m.peak = d
		}
	}
}

func (m *ifaceMeter) finish() {
	if !m.ok {
		return
	}
	close(m.stop)
	<-m.done
}

type summary struct {
	Status        string            `json:"status"`
	PauseReason   string            `json:"pause_reason,omitempty"`
	Error         string            `json:"error,omitempty"`
	Prober        string            `json:"prober"`
	Privileged    bool              `json:"privileged"`
	Sessions      int               `json:"sessions"`
	WallMs        int64             `json:"wall_ms"`
	Stats         model.RunStats    `json:"stats"`
	LimitPPS      int               `json:"limit_pps"`
	GroupSizes    []int             `json:"group_sizes"` // adaptive chunk sizes, in start order
	Groups        []scan.GroupEvent `json:"groups"`
	Chunks        map[string]int    `json:"chunks_by_status"`
	HostsReported int               `json:"hosts_reported"`
	HTTPSent      int64             `json:"http_requests_sent,omitempty"` // counted by the collector, one per request
	Iface         string            `json:"iface,omitempty"`
	IfaceTxTotal  int64             `json:"iface_tx_packets,omitempty"`
	IfaceTxPeak   int64             `json:"iface_tx_peak_pps,omitempty"`
	IfaceTxPerSec []int64           `json:"iface_tx_per_second,omitempty"`
	Extrapolation map[string]string `json:"extrapolation,omitempty"`
}

func main() {
	var (
		targetsFlag = flag.String("targets", "", "targets: IPs, CIDRs, ranges, domains (comma or space separated)")
		targetsFile = flag.String("targets-file", "", "CSV, JSON or text file with targets")
		exclude     = flag.String("exclude", "", "exclusions: IPs, CIDRs (comma separated)")
		ports       = flag.String("ports", "top-100", "port spec: top-100, top-1000, lists and ranges")
		allowed     = flag.String("allowed-ports", "", "safety policy: allowed ports (empty = all)")
		denied      = flag.String("denied-ports", "", "safety policy: denied ports")
		pps         = flag.Int("pps", 300, "probe packets per second, all workers together")
		parallel    = flag.Int("parallel", 2, "parallel chunk workers")
		chunkInit   = flag.Int("chunk-initial", 256, "addresses in the first chunk group")
		chunkMin    = flag.Int("chunk-min", 256, "smallest chunk group")
		chunkMax    = flag.Int("chunk-max", 4096, "largest chunk group")
		chunkTarget = flag.Int("chunk-target", 30, "wanted seconds per chunk group")
		fixed       = flag.Bool("fixed-chunks", false, "turn the adaptive sizing off")
		noSV        = flag.Bool("no-sv", false, "skip service and version detection")
		intensity   = flag.Int("intensity", 5, "nmap --version-intensity (0..9)")
		discMode    = flag.String("discovery", "balanced", "discovery mode: fast | balanced | thorough")
		noARP       = flag.Bool("no-arp", false, "do not use ARP on local networks (use ICMP and TCP probes)")
		skipDisc    = flag.Bool("skip-discovery", false, "treat every address as up (-Pn)")
		hintsFlag   = flag.String("hints", "", "known hosts: ip[:port/port],ip ... (density-first order and retries)")
		retries     = flag.Int("retries", 2, "extra probe rounds for a hinted host that does not answer")
		backoff     = flag.Duration("backoff", time.Second, "wait before the first retry round (doubles each round)")
		stopAfter   = flag.Duration("stop-after", 0, "close the scan window after this time (shows pause)")
		resume      = flag.Bool("resume", false, "after a window pause, resume at once and finish the remaining chunks")
		native      = flag.Bool("native", false, "use the native Go prober even when nmap is installed")
		nmapPath    = flag.String("nmap", "", "path to nmap")
		iface       = flag.String("measure-iface", "", "measure transmitted packets on this interface (Linux), e.g. eth0")
		estimate    = flag.Bool("estimate", false, "print the traffic estimate and exit")
		emergency   = flag.Bool("emergency-stop", false, "set the policy emergency stop (the run must be refused)")
		udp         = flag.Bool("udp", false, "also probe the allow-listed UDP services (DNS, NTP, NetBIOS-NS, SNMP, IKE, SSDP, mDNS); needs raw sockets")
		udpPorts    = flag.String("udp-ports", "", "with -udp: subset of the UDP allow-list, e.g. 53,123,161")
		httpStage   = flag.Bool("http", false, "HTTP/TLS fingerprints and signatures: the real collector and the built-in signature library")
		noSigPaths  = flag.Bool("no-sig-paths", false, "with -http: do not GET the extra safe paths that signatures ask for")
		httpRPS     = flag.Float64("http-rps", 10, "with -http: HTTP requests per second, all hosts together")
		hostRPS     = flag.Float64("per-host-rps", 5, "with -http: HTTP requests per second to one host")
		maxPaths    = flag.Int("max-paths", 12, "with -http: extra signature paths per HTTP service")
		verbose     = flag.Bool("v", false, "debug logs (nmap command lines)")
		quiet       = flag.Bool("quiet", false, "no progress lines")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var parsed targets.ParseResult
	if *targetsFile != "" {
		data, err := os.ReadFile(*targetsFile)
		if err != nil {
			fatal(err)
		}
		parsed, err = targets.ParseFile(*targetsFile, data)
		if err != nil {
			fatal(err)
		}
	}
	if *targetsFlag != "" {
		p := targets.ParseText(*targetsFlag)
		parsed.Targets = append(parsed.Targets, p.Targets...)
		parsed.Invalid = append(parsed.Invalid, p.Invalid...)
	}
	for _, inv := range parsed.Invalid {
		fmt.Fprintf(os.Stderr, "invalid target (line %d) %q: %s\n", inv.Line, inv.Value, inv.Reason)
	}
	if len(parsed.Targets) == 0 {
		fatal(fmt.Errorf("no valid targets; use -targets or -targets-file"))
	}

	var exclusions []string
	for _, e := range strings.FieldsFunc(*exclude, func(r rune) bool { return r == ',' || r == ' ' }) {
		exclusions = append(exclusions, e)
	}
	var hints []model.HostHint
	for _, h := range strings.FieldsFunc(*hintsFlag, func(r rune) bool { return r == ',' || r == ' ' }) {
		ip, portList, _ := strings.Cut(h, ":")
		hint := model.HostHint{IP: ip, Stability: 1, LastUp: time.Now().Add(-24 * time.Hour)}
		for _, p := range strings.Split(portList, "/") {
			if n, err := strconv.Atoi(p); err == nil {
				hint.OpenPorts = append(hint.OpenPorts, n)
			}
		}
		hints = append(hints, hint)
	}

	plan := model.ScanPlan{
		RunID:   1,
		Targets: parsed.Targets,
		Hints:   hints,
		Profile: model.ScanProfile{
			Name:             "scanprobe",
			Ports:            *ports,
			Discovery:        model.DiscoveryOpts{ICMPEcho: true, ICMPTimestamp: true, TCPSynPorts: []int{22, 80, 443, 3389, 8080}, TCPAckPorts: []int{80, 443}, ARP: !*noARP, SkipDiscovery: *skipDisc, Mode: *discMode},
			ServiceDetection: !*noSV,
			VersionIntensity: *intensity,
			UDP:              model.UDPOpts{Enabled: *udp, Ports: *udpPorts},
			Rate:             model.RateLimits{MaxPPS: *pps, MaxParallelChunks: *parallel},
			Chunking:         model.ChunkingOpts{Adaptive: !*fixed, InitialSize: *chunkInit, MinSize: *chunkMin, MaxSize: *chunkMax, TargetSeconds: *chunkTarget},
			Retry:            model.RetryOpts{UnstableRetries: *retries, BackoffMs: int(backoff.Milliseconds())},
		},
		Policy: model.SafetyPolicy{AllowedPorts: *allowed, DeniedPorts: *denied, Exclusions: exclusions, EmergencyStop: *emergency},
	}

	deps := scan.Deps{Logger: log, NmapPath: *nmapPath, ForceNative: *native}
	var httpSent atomic.Int64
	if *httpStage {
		sigs, err := sig.NewBuiltinEngine()
		if err != nil {
			fatal(fmt.Errorf("built-in signatures: %w", err))
		}
		collector := httpfp.New()
		collector.Wait = scan.HTTPWait // every request waits for the per-host and the global limit
		collector.OnRequest = func(string, string) { httpSent.Add(1) }
		deps.Fingerprinter, deps.Signatures = collector, sigs
		plan.Profile.HTTP = model.HTTPOpts{Enabled: true, MaxRedirects: 5, SignaturePaths: !*noSigPaths, Favicon: true, TimeoutMs: 8000}
		plan.Profile.Rate.HTTPRPS = *httpRPS
		plan.Policy.MaxHTTPRPS, plan.Policy.MaxPerHostRPS, plan.Policy.MaxPathsPerHost = *httpRPS, *hostRPS, *maxPaths
		plan.Policy.UserAgent = httpfp.DefaultUserAgent
		total, enabled := sigs.Count()
		fmt.Fprintf(os.Stderr, "http stage: real collector, %d signatures (%d enabled), %.0f requests/s in total, %.0f per host, %d extra paths per service\n", total, enabled, *httpRPS, *hostRPS, *maxPaths)
	}

	var groupMu sync.Mutex
	var groups []scan.GroupEvent
	deps.OnGroup = func(ev scan.GroupEvent) {
		groupMu.Lock()
		groups = append(groups, ev)
		groupMu.Unlock()
	}
	engine := scan.New(deps)

	est := engine.Estimate(plan)
	fmt.Fprintf(os.Stderr, "estimate: %d addresses, %d chunks, about %d packets, about %ds at %d pps, discovery mode %s\n",
		est.Addresses, est.Chunks, est.EstPackets, est.EstDurationSec, est.EffectivePPS, est.DiscoveryMode)
	if *estimate {
		_ = json.NewEncoder(os.Stdout).Encode(est)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sink := &memSink{out: json.NewEncoder(os.Stdout), chunks: map[int]model.Chunk{}, quiet: *quiet}
	var meter *ifaceMeter
	if *iface != "" {
		meter = startMeter(*iface)
		if !meter.ok {
			fmt.Fprintf(os.Stderr, "cannot read the packet counter of %s; no interface measurement\n", *iface)
		}
	}

	start := time.Now()
	if *stopAfter > 0 {
		end := start.Add(*stopAfter)
		plan.WindowEnd = &end
		fmt.Fprintf(os.Stderr, "scan window closes in %s\n", *stopAfter)
	}
	sessions := 1
	out := engine.Run(ctx, plan, sink)
	if out.Status == model.RunPaused && out.PauseReason == model.PauseWindowClosed && *resume {
		rest := sink.remaining()
		fmt.Fprintf(os.Stderr, "\nPAUSED: window closed after %s. Done %d/%d addresses, %d chunks deferred. Resuming the same run in a new window.\n\n",
			time.Since(start).Round(time.Millisecond), out.Stats.AddressesDone, out.Stats.AddressesTotal, len(rest))
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "paused", "pause_reason": out.PauseReason, "stats": out.Stats, "deferred_chunks": len(rest)})
		plan.WindowEnd = nil
		plan.Chunks = rest
		prev := out.Stats
		plan.PrevStats = &prev
		sessions++
		out = engine.Run(ctx, plan, sink)
	}
	wall := time.Since(start)

	sum := summary{
		Status: string(out.Status), PauseReason: out.PauseReason, Prober: engine.Prober().Name(), Privileged: engine.Prober().Privileged(),
		Sessions: sessions, WallMs: wall.Milliseconds(), Stats: out.Stats, LimitPPS: scan.EffectiveLimits(plan.Profile, plan.Policy).PPS,
		Groups: groups, Chunks: sink.byStatus(), HostsReported: sink.hosts, HTTPSent: httpSent.Load(),
	}
	if out.Err != nil {
		sum.Error = out.Err.Error()
	}
	for _, g := range groups {
		sum.GroupSizes = append(sum.GroupSizes, g.Size)
	}
	if meter != nil && meter.ok {
		meter.finish()
		meter.sample()
		sum.Iface = *iface
		sum.IfaceTxTotal = meter.lastVal - meter.first
		sum.IfaceTxPeak = meter.peak
		sum.IfaceTxPerSec = meter.samples
	}
	if out.Status == model.RunCompleted && out.Stats.AddressesDone > 0 && sessions == 1 {
		per := wall.Seconds() / float64(out.Stats.AddressesDone)
		sum.Extrapolation = map[string]string{
			"basis":  fmt.Sprintf("%d addresses in %.1fs (%.4fs per address) at %d pps, same share of live hosts", out.Stats.AddressesDone, wall.Seconds(), per, sum.LimitPPS),
			"10000":  (time.Duration(per * 10000 * float64(time.Second))).Round(time.Second).String(),
			"65536":  (time.Duration(per * 65536 * float64(time.Second))).Round(time.Second).String(),
			"100000": (time.Duration(per * 100000 * float64(time.Second))).Round(time.Second).String(),
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"summary": sum})

	fmt.Fprintf(os.Stderr, "\n%s: %d/%d addresses, %d hosts up, %d open services, %d packets (avg %.0f pps, limit %d), %s, group sizes %v\n",
		strings.ToUpper(string(out.Status)), out.Stats.AddressesDone, out.Stats.AddressesTotal, out.Stats.HostsUp, out.Stats.ServicesOpen,
		out.Stats.PacketsSent, out.Stats.AvgPPS, sum.LimitPPS, wall.Round(time.Millisecond), sum.GroupSizes)
	if out.Status == model.RunFailed {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "scanprobe:", err)
	os.Exit(2)
}
