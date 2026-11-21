package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

// fakeNet is an in-memory network behind the Prober interface. No packet
// leaves the machine in these tests.
type fakeNet struct {
	mu          sync.Mutex
	hosts       map[string][]int // ip → open ports
	missFirst   map[string]int   // ip → discovery calls that get no answer
	delay       time.Duration    // per discovery call
	perAddr     time.Duration    // extra delay per address
	calls       int
	inflight    int
	maxInflight int
	rate        int
	maxRate     int
	discovered  [][]string
	failAll     bool
	portMiss    map[string]int // ip → port-scan calls that get no answer at all
	portTimeout map[string]int // ip → port-scan calls where nmap gives up on the host
	timeouts    []time.Duration
}

func (f *fakeNet) Name() string     { return "fake" }
func (f *fakeNet) Privileged() bool { return true }

func (f *fakeNet) enter(rate int) {
	f.mu.Lock()
	f.calls++
	f.inflight++
	f.rate += rate
	f.maxInflight = max(f.maxInflight, f.inflight)
	f.maxRate = max(f.maxRate, f.rate)
	f.mu.Unlock()
}

func (f *fakeNet) leave(rate int) {
	f.mu.Lock()
	f.inflight--
	f.rate -= rate
	f.mu.Unlock()
}

func (f *fakeNet) Discover(ctx context.Context, req probe.DiscoverRequest) (*probe.Result, error) {
	f.enter(req.MaxRate)
	defer f.leave(req.MaxRate)
	if f.failAll {
		return nil, errors.New("fake: nmap exploded")
	}
	st := targets.Build(req.Targets)
	d := f.delay + time.Duration(st.V4.Count())*f.perAddr
	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discovered = append(f.discovered, req.Targets)
	res := &probe.Result{Packets: st.V4.Count() * 2, PacketsExact: true, Scanned: int(st.V4.Count())}
	for ip := range f.hosts {
		p, _ := targets.ParseValue(ip)
		if !st.V4.Contains(p.Range.Lo) {
			continue
		}
		if f.missFirst[ip] > 0 {
			f.missFirst[ip]--
			continue
		}
		res.Hosts = append(res.Hosts, probe.Host{IP: ip, Up: true, Reason: "echo-reply", RTTMs: 1.5, Responded: true})
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].IP < res.Hosts[j].IP })
	return res, nil
}

func (f *fakeNet) PortScan(ctx context.Context, req probe.PortScanRequest) (*probe.Result, error) {
	f.enter(req.MaxRate)
	defer f.leave(req.MaxRate)
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	res := &probe.Result{Packets: int64(len(req.Hosts) * req.Ports.Count()), PacketsExact: true}
	f.mu.Lock()
	f.timeouts = append(f.timeouts, req.HostTimeout)
	f.mu.Unlock()
	for _, ip := range req.Hosts {
		h := probe.Host{IP: ip, Up: true}
		ports, ok := f.hosts[ip]
		f.mu.Lock()
		if f.portMiss[ip] > 0 {
			f.portMiss[ip]--
			ok, ports = false, nil
		}
		if f.portTimeout[ip] > 0 {
			f.portTimeout[ip]--
			ok, ports = false, nil
			h.TimedOut = true
		}
		f.mu.Unlock()
		h.Responded = ok
		for _, p := range ports {
			if req.Ports.Has(p) {
				// like nmap: the port table names the well-known ports (method="table")
				name := map[int]string{22: "ssh", 80: "http", 443: "https"}[p]
				if name == "" {
					name = "unknown"
				}
				h.Ports = append(h.Ports, probe.Port{Port: p, Proto: "tcp", State: "open", Reason: "syn-ack", Name: name, Confidence: 0.3})
			}
		}
		res.Hosts = append(res.Hosts, h)
	}
	return res, nil
}

func (f *fakeNet) ServiceScan(ctx context.Context, req probe.ServiceRequest) (*probe.Result, error) {
	f.enter(req.MaxRate)
	defer f.leave(req.MaxRate)
	res := &probe.Result{Packets: 10}
	for _, hp := range req.Hosts {
		h := probe.Host{IP: hp.IP, Up: true}
		for _, p := range hp.Ports {
			port := probe.Port{Port: p, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.27.0", Confidence: 1, CPE: []string{"cpe:/a:igor_sysoev:nginx:1.27.0"}}
			if p == 443 {
				port.Tunnel = "ssl"
			}
			if p == 22 {
				port.Name, port.Product, port.Version, port.CPE = "ssh", "OpenSSH", "9.7", nil
			}
			h.Ports = append(h.Ports, port)
		}
		res.Hosts = append(res.Hosts, h)
	}
	return res, nil
}

// memSink records everything the engine reports.
type memSink struct {
	mu       sync.Mutex
	plans    [][]model.Chunk
	chunks   map[int]model.Chunk
	history  []model.Chunk
	hosts    []model.HostResult
	progress []model.RunStats
}

func newSink() *memSink { return &memSink{chunks: map[int]model.Chunk{}} }

func (m *memSink) OnPlan(_ context.Context, _ int64, c []model.Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans = append(m.plans, c)
	for _, x := range c {
		m.chunks[x.Seq] = x
	}
	return nil
}
func (m *memSink) OnChunk(_ context.Context, c model.Chunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chunks[c.Seq] = c
	m.history = append(m.history, c)
	return nil
}
func (m *memSink) OnHost(_ context.Context, h model.HostResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hosts = append(m.hosts, h)
	return nil
}
func (m *memSink) OnProgress(_ context.Context, _ int64, s model.RunStats) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress = append(m.progress, s)
	return nil
}
func (m *memSink) host(ip string) *model.HostResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.hosts) - 1; i >= 0; i-- { // the last report: a partial one may come first
		if m.hosts[i].IP == ip {
			return &m.hosts[i]
		}
	}
	return nil
}
func (m *memSink) notDone() []model.Chunk {
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
func (m *memSink) count(st model.ChunkStatus) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.chunks {
		if c.Status == st {
			n++
		}
	}
	return n
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func tgt(vals ...string) []model.Target {
	var out []model.Target
	for _, v := range vals {
		out = append(out, model.Target{Value: v, Enabled: true})
	}
	return out
}

func basePlan(vals ...string) model.ScanPlan {
	return model.ScanPlan{
		RunID:   7,
		Targets: tgt(vals...),
		Profile: model.ScanProfile{
			// the general tests use one discovery pass; discovery_test.go covers the two-pass modes
			Discovery: model.DiscoveryOpts{Mode: model.DiscoveryThorough},
			Ports:     "22,80,443,8080", ServiceDetection: true,
			Rate:     model.RateLimits{MaxPPS: 400, MaxParallelChunks: 2},
			Chunking: model.ChunkingOpts{Adaptive: true, InitialSize: 256, MinSize: 256, MaxSize: 1024, TargetSeconds: 1},
			Retry:    model.RetryOpts{UnstableRetries: 2, BackoffMs: 5},
		},
		Policy: model.SafetyPolicy{MaxPPS: 300},
	}
}

func TestRunDiscoversHostsRetriesAndReports(t *testing.T) {
	net := &fakeNet{
		hosts: map[string][]int{
			"10.0.0.10": {80, 443}, "10.0.1.20": {22}, "10.0.2.30": {8080, 9999}, "10.0.3.40": {}, "10.0.3.41": {80},
		},
		missFirst: map[string]int{"10.0.3.41": 1}, // unstable: silent in the first round
	}
	e := New(Deps{Prober: net, Logger: quiet})
	var direct []string
	e.direct = func(_ context.Context, ip string, ports []int, _ time.Duration, _ *probe.Limiter) (probe.Host, int64) {
		direct = append(direct, ip)
		return probe.Host{IP: ip}, int64(len(ports))
	}
	plan := basePlan("10.0.0.0/22", "10.0.0.0/24") // overlapping targets are scanned once
	plan.Policy.Exclusions = []string{"10.0.0.200-10.0.0.255"}
	plan.Hints = []model.HostHint{
		{IP: "10.0.3.41", OpenPorts: []int{80}},  // answers on the second round
		{IP: "10.0.2.99", OpenPorts: []int{443}}, // gone
		{IP: "192.168.9.9"},                      // outside the scope: ignored
	}
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)

	if out.Status != model.RunCompleted || out.Err != nil {
		t.Fatalf("outcome = %+v", out)
	}
	if len(sink.plans) != 1 || len(sink.plans[0]) != 4 {
		t.Fatalf("OnPlan calls = %d, chunks = %d", len(sink.plans), len(sink.plans[0]))
	}
	// density-first: both hinted /24 blocks come before the others
	first, second := sink.plans[0][0], sink.plans[0][1]
	if first.Priority < 1 || second.Priority < 1 || sink.plans[0][2].Priority != 0 {
		t.Errorf("priorities = %d %d %d", first.Priority, second.Priority, sink.plans[0][2].Priority)
	}
	hinted := []string{first.Spec[0], second.Spec[0]}
	sort.Strings(hinted)
	if !reflect.DeepEqual(hinted, []string{"10.0.2.0/24", "10.0.3.0/24"}) {
		t.Errorf("hinted blocks first, got %v", hinted)
	}
	if got := out.Stats.AddressesTotal; got != 1024-56 {
		t.Errorf("addresses total = %d, want %d (exclusion removed)", got, 1024-56)
	}
	if out.Stats.AddressesDone != out.Stats.AddressesTotal || out.Stats.ChunksDone != 4 || out.Stats.ChunksTotal != 4 {
		t.Errorf("stats = %+v", out.Stats)
	}
	if out.Stats.HostsUp != 5 || out.Stats.ServicesOpen != 5 || out.Stats.Retried != 2 || out.Stats.PacketsSent == 0 {
		t.Errorf("stats = %+v", out.Stats)
	}
	if sink.count(model.ChunkDone) != 4 {
		t.Errorf("chunks done = %d", sink.count(model.ChunkDone))
	}

	web := sink.host("10.0.0.10")
	if web == nil || !web.Up || web.Attempts != 1 || len(web.Services) != 2 || web.Reason != "echo-reply" || web.RunID != 7 {
		t.Fatalf("10.0.0.10 = %+v", web)
	}
	if s := web.Services[1]; s.Port != 443 || s.Tunnel != "ssl" || s.Product != "nginx" || s.Confidence != 1 || len(s.CPE) != 1 || s.State != "open" || s.Proto != "tcp" {
		t.Errorf("443 = %+v", s)
	}
	// port 9999 is open on the host but not in the profile: never reported
	if h := sink.host("10.0.2.30"); h == nil || len(h.Services) != 1 || h.Services[0].Port != 8080 {
		t.Errorf("10.0.2.30 = %+v", h)
	}
	if h := sink.host("10.0.3.40"); h == nil || !h.Up || len(h.Services) != 0 {
		t.Errorf("a live host without open ports is still reported: %+v", h)
	}
	if h := sink.host("10.0.3.41"); h == nil || !h.Up || h.Attempts != 2 {
		t.Errorf("unstable host should be found on attempt 2: %+v", h)
	}
	gone := sink.host("10.0.2.99")
	if gone == nil || gone.Up || gone.Attempts != 3 || gone.Reason != "no-response" {
		t.Errorf("gone host = %+v", gone)
	}
	if !reflect.DeepEqual(direct, []string{"10.0.2.99"}) {
		t.Errorf("the last round must probe the hinted ports directly: %v", direct)
	}
	if sink.host("192.168.9.9") != nil || sink.host("10.0.0.201") != nil {
		t.Error("an address outside the scope was reported")
	}
	if len(sink.hosts) != 6 {
		t.Errorf("hosts reported = %d, want 6 (each once)", len(sink.hosts))
	}
	// rate budget: the sum of --max-rate of running processes stays under min(profile, policy)
	if net.maxRate > 300 {
		t.Errorf("rate in flight = %d, limit 300", net.maxRate)
	}
	for _, c := range sink.chunks {
		if c.StartedAt == nil || c.FinishedAt == nil || c.PPS <= 0 {
			t.Errorf("chunk %d lacks timing: %+v", c.Seq, c)
		}
	}
	up := 0
	for _, c := range sink.chunks {
		up += c.HostsUp
	}
	if up != 5 {
		t.Errorf("sum of chunk hosts_up = %d", up)
	}
}

func TestWindowPauseThenResume(t *testing.T) {
	hosts := map[string][]int{}
	for _, ip := range []string{"10.1.0.5", "10.1.1.5", "10.1.2.5", "10.1.3.5", "10.1.4.5", "10.1.5.5", "10.1.6.5", "10.1.7.5"} {
		hosts[ip] = []int{80}
	}
	net := &fakeNet{hosts: hosts, delay: 60 * time.Millisecond}
	e := New(Deps{Prober: net, Logger: quiet})
	plan := basePlan("10.1.0.0/21")
	plan.Profile.Rate.MaxParallelChunks = 1
	plan.Profile.Rate.MaxPPS, plan.Policy.MaxPPS = 1000000, 0 // the packet estimate of a chunk is then a few ms
	plan.Profile.Chunking = model.ChunkingOpts{Adaptive: false, InitialSize: 256}
	end := time.Now().Add(200 * time.Millisecond)
	plan.WindowEnd = &end
	sink := newSink()

	start := time.Now()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunPaused || out.PauseReason != model.PauseWindowClosed {
		t.Fatalf("first session = %+v", out)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Errorf("the run must stop at the window end, took %v", d)
	}
	doneFirst := sink.count(model.ChunkDone)
	if doneFirst == 0 || doneFirst == 8 {
		t.Fatalf("chunks done in the first window = %d, want some but not all", doneFirst)
	}
	if got := sink.count(model.ChunkDeferred); got != 8-doneFirst {
		t.Fatalf("deferred = %d, want %d (statuses %v)", got, 8-doneFirst, sink.chunks)
	}
	if out.Stats.ChunksDone != doneFirst || out.Stats.AddressesDone != int64(doneFirst)*256 || out.Stats.HostsUp != doneFirst {
		t.Errorf("stats after pause = %+v (done %d)", out.Stats, doneFirst)
	}

	// next window: the scheduler hands the remaining chunks back
	plan.WindowEnd = nil
	plan.Chunks = sink.notDone()
	prev := out.Stats
	plan.PrevStats = &prev
	out = e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("second session = %+v", out)
	}
	if len(sink.plans) != 2 || len(sink.plans[1]) != 8-doneFirst {
		t.Errorf("resume plan = %d chunks, want %d", len(sink.plans[1]), 8-doneFirst)
	}
	if sink.count(model.ChunkDone) != 8 {
		t.Errorf("all chunks must be done: %v", sink.chunks)
	}
	if out.Stats.ChunksDone != 8 || out.Stats.ChunksTotal != 8 || out.Stats.AddressesDone != 2048 || out.Stats.AddressesTotal != 2048 || out.Stats.HostsUp != 8 {
		t.Errorf("final stats = %+v", out.Stats)
	}
	seen := map[string]int{}
	for _, h := range sink.hosts {
		seen[h.IP]++
	}
	if len(seen) != 8 {
		t.Errorf("hosts = %v", seen)
	}
	for ip, n := range seen {
		if n != 1 {
			t.Errorf("%s reported %d times", ip, n)
		}
	}
}

func TestWindowGuardDoesNotStartWhatCannotFit(t *testing.T) {
	net := &fakeNet{hosts: map[string][]int{}, delay: 80 * time.Millisecond}
	e := New(Deps{Prober: net, Logger: quiet})
	plan := basePlan("10.2.0.0/22")
	plan.Profile.Rate.MaxParallelChunks = 1
	plan.Profile.Chunking = model.ChunkingOpts{Adaptive: false, InitialSize: 256}
	end := time.Now().Add(130 * time.Millisecond) // the first chunk fits by the packet estimate, the measured 80 ms then says no
	plan.WindowEnd = &end
	plan.Profile.Rate.MaxPPS = 100000
	plan.Policy.MaxPPS = 0
	sink := newSink()
	start := time.Now()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunPaused || out.PauseReason != model.PauseWindowClosed {
		t.Fatalf("outcome = %+v", out)
	}
	// one chunk done (80 ms), the second would end at 160 ms > 130 ms: not started, no wait for the deadline
	if sink.count(model.ChunkDone) != 1 || sink.count(model.ChunkDeferred) != 3 {
		t.Errorf("chunks = %v", sink.chunks)
	}
	if d := time.Since(start); d > 125*time.Millisecond {
		t.Errorf("the guard should return early, took %v", d)
	}
	if net.calls != 1 {
		t.Errorf("probe calls = %d, want 1", net.calls)
	}

	// a window that is already over: nothing is probed
	net2 := &fakeNet{hosts: map[string][]int{}}
	past := time.Now().Add(-time.Second)
	plan.WindowEnd = &past
	out = New(Deps{Prober: net2, Logger: quiet}).Run(context.Background(), plan, newSink())
	if out.Status != model.RunPaused || net2.calls != 0 {
		t.Errorf("closed window: %+v, calls %d", out, net2.calls)
	}
}

func TestCancelAndPauseCauses(t *testing.T) {
	cases := []struct {
		cause  error
		status model.RunStatus
		reason string
	}{
		{ErrPauseManual, model.RunPaused, model.PauseManual},
		{ErrPauseEmergency, model.RunPaused, model.PauseEmergency},
		{PauseCause(model.PauseWindowClosed), model.RunPaused, model.PauseWindowClosed},
		{nil, model.RunCancelled, ""},
	}
	for _, c := range cases {
		net := &fakeNet{hosts: map[string][]int{"10.3.0.1": {80}}, delay: 5 * time.Second}
		e := New(Deps{Prober: net, Logger: quiet})
		ctx, cancel := context.WithCancelCause(context.Background())
		sink := newSink()
		go func() {
			time.Sleep(40 * time.Millisecond)
			cancel(c.cause)
		}()
		start := time.Now()
		out := e.Run(ctx, basePlan("10.3.0.0/23"), sink)
		if out.Status != c.status || out.PauseReason != c.reason {
			t.Errorf("cause %v: outcome %+v", c.cause, out)
		}
		if time.Since(start) > time.Second {
			t.Errorf("cause %v: cancel was slow", c.cause)
		}
		if sink.count(model.ChunkDeferred) != 2 {
			t.Errorf("cause %v: unfinished chunks must be deferred: %v", c.cause, sink.chunks)
		}
		if out.Stats.AddressesDone != 0 || out.Stats.HostsUp != 0 {
			t.Errorf("cause %v: stats %+v", c.cause, out.Stats)
		}
	}
}

func TestEmergencyStopRefusesToStart(t *testing.T) {
	net := &fakeNet{hosts: map[string][]int{}}
	e := New(Deps{Prober: net, Logger: quiet})
	plan := basePlan("10.4.0.0/24")
	plan.Policy.EmergencyStop = true
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunFailed || !errors.Is(out.Err, ErrEmergencyStop) {
		t.Fatalf("outcome = %+v", out)
	}
	if net.calls != 0 || len(sink.plans) != 0 {
		t.Error("nothing may be sent or planned under the emergency stop")
	}
	// a paused run stays paused and keeps its chunks
	plan.Chunks = []model.Chunk{{Seq: 1, Spec: []string{"10.4.0.0/24"}, Size: 256, Status: model.ChunkDeferred}}
	out = e.Run(context.Background(), plan, sink)
	if out.Status != model.RunPaused || out.PauseReason != model.PauseEmergency || net.calls != 0 {
		t.Fatalf("resume under emergency stop = %+v", out)
	}
}

func TestProberFailureFailsTheRun(t *testing.T) {
	e := New(Deps{Prober: &fakeNet{failAll: true}, Logger: quiet})
	sink := newSink()
	out := e.Run(context.Background(), basePlan("10.5.0.0/24"), sink)
	if out.Status != model.RunFailed || out.Err == nil || sink.count(model.ChunkFailed) != 1 || out.Stats.Errors != 1 {
		t.Fatalf("outcome = %+v chunks %v", out, sink.chunks)
	}
	if sink.chunks[1].Error == "" {
		t.Error("the failed chunk must carry the error text")
	}
}

func TestPolicyFiltersPorts(t *testing.T) {
	net := &fakeNet{hosts: map[string][]int{"10.6.0.1": {22, 80, 443}}}
	e := New(Deps{Prober: net, Logger: quiet})
	plan := basePlan("10.6.0.0/24")
	plan.Policy.AllowedPorts = "1-1024"
	plan.Policy.DeniedPorts = "22"
	sink := newSink()
	if out := e.Run(context.Background(), plan, sink); out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	var ports []int
	for _, s := range sink.host("10.6.0.1").Services {
		ports = append(ports, s.Port)
	}
	if !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Errorf("ports = %v, want [80 443] (22 denied)", ports)
	}
	plan.Policy.AllowedPorts = "9000"
	if out := e.Run(context.Background(), plan, newSink()); out.Status != model.RunFailed {
		t.Errorf("no port left must fail, got %+v", out)
	}
}

type fakeFP struct {
	mu   sync.Mutex
	reqs []model.FingerprintRequest
}

func (f *fakeFP) Fingerprint(_ context.Context, req model.FingerprintRequest) (*model.HTTPFingerprint, *model.TLSInfo, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if req.Port == 22 {
		return nil, nil, nil
	}
	h := &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Panel", Host: req.Hostname}
	for _, p := range req.Paths {
		h.Paths = append(h.Paths, model.PathProbe{Path: p, Status: 404})
	}
	var tl *model.TLSInfo
	if req.TLSHint || req.NameHint == "https" { // like httpfp's tlsFirst
		h.Scheme = "https"
		tl = &model.TLSInfo{SubjectCN: "x"}
	}
	return h, tl, nil
}

type fakeSig struct{}

func (fakeSig) Match(svc *model.ServiceResult) ([]model.SigMatch, []model.Technology, []string) {
	if svc.HTTP == nil {
		return nil, nil, nil
	}
	return []model.SigMatch{{Signature: "panel", Name: "Panel", Confidence: 0.9}},
		[]model.Technology{{Name: "nginx", Confidence: 0.9}}, []string{model.ClassAdminPanel}
}
func (fakeSig) ExtraPaths() []string {
	return []string{"/login", "/admin", "/version", "/wp-login.php"}
}

type fakeDNS map[string]string

func (f fakeDNS) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if ip, ok := f[host]; ok {
		return []net.IP{net.ParseIP(ip)}, nil
	}
	return nil, errors.New("no such host")
}

func TestHTTPAndSignatureStage(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 80, 443}}}
	fp := &fakeFP{}
	e := New(Deps{Prober: netw, Logger: quiet, Fingerprinter: fp, Signatures: fakeSig{}, Resolver: fakeDNS{"panel.example.com": "10.7.0.5"}})
	plan := basePlan("panel.example.com", "10.7.0.0/30", "nowhere.example.com")
	plan.Profile.HTTP = model.HTTPOpts{Enabled: true, SignaturePaths: true, Favicon: true, MaxRedirects: 3}
	plan.Profile.Rate.HTTPRPS = 1000
	plan.Policy.MaxHTTPRPS = 500
	plan.Policy.MaxPerHostRPS = 500
	plan.Policy.MaxPathsPerHost = 2
	plan.Policy.UserAgent = "Czujka-test"
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	h := sink.host("10.7.0.5")
	if h == nil || !reflect.DeepEqual(h.Hostnames, []string{"panel.example.com"}) {
		t.Fatalf("host = %+v", h)
	}
	if len(fp.reqs) != 2 {
		t.Fatalf("fingerprint calls = %d, want one per open TCP port except ssh (not HTTP)", len(fp.reqs))
	}
	for _, r := range fp.reqs {
		if r.IP != "10.7.0.5" || r.Hostname != "panel.example.com" || r.UserAgent != "Czujka-test" || !r.Opts.Enabled {
			t.Errorf("request = %+v", r)
		}
		if !reflect.DeepEqual(r.Paths, []string{"/login", "/admin"}) {
			t.Errorf("paths must be capped by the policy: %v", r.Paths)
		}
		// small run: the HTTP stage runs before version detection, so the
		// hint is the port table's name ("https"); otherwise nmap's tunnel
		if hint := r.TLSHint || r.NameHint == "https"; hint != (r.Port == 443) {
			t.Errorf("TLS hint on %d = %v (%q)", r.Port, r.TLSHint, r.NameHint)
		}
	}
	for _, s := range h.Services {
		switch s.Port {
		case 22:
			if s.HTTP != nil || len(s.Matches) != 0 || s.Matches == nil {
				t.Errorf("ssh = %+v", s)
			}
		case 80, 443:
			if s.HTTP == nil || s.HTTP.Title != "Panel" || len(s.Matches) != 1 || len(s.Technologies) != 1 || !reflect.DeepEqual(s.Classes, []string{model.ClassAdminPanel}) {
				t.Errorf("%d = %+v", s.Port, s)
			}
			if (s.TLS != nil) != (s.Port == 443) {
				t.Errorf("%d TLS = %v", s.Port, s.TLS)
			}
		}
	}
	// 2 calls pay one request each (ssh is not HTTP and gets no request),
	// the two HTTP answers carry two extra paths each
	if out.Stats.HTTPServices != 2 || out.Stats.HTTPRequests != 6 {
		t.Errorf("http stats = %+v", out.Stats)
	}

	// without a fingerprinter the stage is skipped and nothing breaks
	sink = newSink()
	out = New(Deps{Prober: netw, Logger: quiet, Resolver: fakeDNS{"panel.example.com": "10.7.0.5"}}).Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted || sink.host("10.7.0.5") == nil || sink.host("10.7.0.5").Services[1].HTTP != nil {
		t.Errorf("nil fingerprinter: %+v", out)
	}
}

func TestSkipDiscoveryReportsOnlyAnsweringHosts(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{"10.8.0.2": {80}, "10.8.0.3": {}}}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.8.0.0/29")
	plan.Profile.Discovery = model.DiscoveryOpts{SkipDiscovery: true}
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted || len(sink.hosts) != 2 || len(netw.discovered) != 0 {
		t.Fatalf("outcome %+v hosts %d discover calls %d", out, len(sink.hosts), len(netw.discovered))
	}
	if h := sink.host("10.8.0.2"); h.Reason != "syn-ack" {
		t.Errorf("reason = %q", h.Reason)
	}
	if h := sink.host("10.8.0.3"); h.Reason != "reset" {
		t.Errorf("reason = %q", h.Reason)
	}
}

func TestAdaptiveGroupsGrowWithSpeed(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{}, perAddr: 40 * time.Microsecond} // 256 addresses ≈ 10 ms
	var mu sync.Mutex
	var sizes []int
	e := New(Deps{Prober: netw, Logger: quiet, OnGroup: func(ev GroupEvent) {
		mu.Lock()
		sizes = append(sizes, ev.Size)
		mu.Unlock()
	}})
	plan := basePlan("10.9.0.0/19") // 8192 addresses, 32 units
	plan.Profile.Rate.MaxParallelChunks = 1
	plan.Profile.Chunking = model.ChunkingOpts{Adaptive: true, InitialSize: 256, MinSize: 256, MaxSize: 2048, TargetSeconds: 1}
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted || out.Stats.AddressesDone != 8192 || len(sink.plans[0]) != 32 {
		t.Fatalf("outcome = %+v", out)
	}
	if sizes[0] != 256 {
		t.Errorf("first group = %d, want initial_size 256", sizes[0])
	}
	// EWMA: 256 → 1152 → 1600 → 1824 ... toward max_size 2048; a group holds whole chunks
	if !reflect.DeepEqual(sizes[:4], []int{256, 1024, 1536, 1792}) {
		t.Errorf("fast chunks should grow the group toward max_size: %v", sizes)
	}
	for i := 1; i < len(sizes)-1; i++ {
		if sizes[i] < sizes[i-1] {
			t.Errorf("sizes should not shrink on a fast network: %v", sizes)
		}
	}
	if len(sizes) >= 32 {
		t.Errorf("adaptive sizing should need fewer groups than chunks: %d", len(sizes))
	}
	if sink.count(model.ChunkDone) != 32 {
		t.Errorf("every planned chunk must be done")
	}
}

func TestParallelismAndBudget(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{}, delay: 15 * time.Millisecond}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.10.0.0/20")
	plan.Profile.Rate = model.RateLimits{MaxPPS: 900, MaxParallelChunks: 3}
	plan.Policy.MaxPPS = 600
	plan.Profile.Chunking = model.ChunkingOpts{Adaptive: false, InitialSize: 256}
	out := e.Run(context.Background(), plan, newSink())
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if netw.maxInflight != 3 {
		t.Errorf("parallel workers = %d, want 3", netw.maxInflight)
	}
	// the 600 pps cap minus the HTTP reserve (default 10 rps x 8 packets)
	want := EffectiveLimits(plan.Profile, plan.Policy).ProbePPS()
	if want != 520 || netw.maxRate > want || netw.maxRate < want-3 {
		t.Errorf("rate in flight = %d, want the probe budget %d (600 pps cap minus the HTTP reserve)", netw.maxRate, want)
	}
}

func TestHTTPReserve(t *testing.T) {
	for _, c := range []struct {
		pps     int
		httpRPS float64
		probe   int
	}{{1000, 20, 840}, {200, 20, 150}, {2000, 50, 1600}, {2, 10, 2}} {
		l := Limits{PPS: c.pps, HTTPRPS: c.httpRPS}
		if got := l.ProbePPS(); got != c.probe {
			t.Errorf("cap %d, http %v rps: probe budget %d, want %d", c.pps, c.httpRPS, got, c.probe)
		}
	}
}

// A host that discovery found but that gave the port scan no answer is
// scanned once more; its ports are not lost.
func TestSilentHostGetsASecondPortScan(t *testing.T) {
	net := &fakeNet{
		hosts:    map[string][]int{"10.0.0.10": {80}, "10.0.0.11": {22}},
		portMiss: map[string]int{"10.0.0.11": 1},
	}
	e := New(Deps{Prober: net, Logger: quiet})
	sink := newSink()
	out := e.Run(context.Background(), basePlan("10.0.0.0/24"), sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	h := sink.host("10.0.0.11")
	if h == nil || len(h.Services) != 1 || h.Services[0].Port != 22 {
		t.Fatalf("host 10.0.0.11 = %+v, want port 22 from the second port scan", h)
	}
	if out.Stats.Retried < 1 {
		t.Errorf("retried = %d, want the silent host counted", out.Stats.Retried)
	}
}

func TestHTTPRateFollowsALowCap(t *testing.T) {
	l := EffectiveLimits(model.ScanProfile{Rate: model.RateLimits{MaxPPS: 200, HTTPRPS: 20}}, model.SafetyPolicy{})
	if l.HTTPRPS != 6.25 || l.HTTPReserve() != 50 || l.ProbePPS() != 150 {
		t.Errorf("cap 200: http %v rps, reserve %d, probes %d", l.HTTPRPS, l.HTTPReserve(), l.ProbePPS())
	}
}

// nmap gave up on a host (--host-timeout): the host is scanned once more,
// and when it times out again its ports are unknown, the run says so, and
// the host is not reported as a host without services.
func TestTimedOutHostIsRetriedThenReportedUnknown(t *testing.T) {
	net := &fakeNet{
		hosts:       map[string][]int{"10.0.0.10": {80}, "10.0.0.11": {22}, "10.0.0.12": {443}},
		portTimeout: map[string]int{"10.0.0.11": 1, "10.0.0.12": 2},
	}
	e := New(Deps{Prober: net, Logger: quiet})
	sink := newSink()
	out := e.Run(context.Background(), basePlan("10.0.0.0/24"), sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if h := sink.host("10.0.0.11"); h == nil || len(h.Services) != 1 || h.PortsUnknown {
		t.Fatalf("10.0.0.11 = %+v, want port 22 from the second scan", h)
	}
	h := sink.host("10.0.0.12")
	if h == nil || !h.Up || !h.PortsUnknown || h.Reason != model.ReasonPortsUnknown || !h.HasUnknownPorts() {
		t.Fatalf("10.0.0.12 = %+v, want up with unknown ports", h)
	}
	if out.Stats.PortsUnknown != 1 || len(out.Stats.Warnings) != 1 {
		t.Errorf("stats: ports_unknown %d, warnings %q", out.Stats.PortsUnknown, out.Stats.Warnings)
	}
}

// Most live hosts without any answer to the port scan: the run ends, but
// with a warning, not as a clean success.
func TestSanityCheckWarnsWhenPortsAreLost(t *testing.T) {
	hosts, miss := map[string][]int{}, map[string]int{}
	for i := 10; i < 22; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		hosts[ip] = []int{80}
		if i < 20 {
			miss[ip] = 2
		}
	}
	net := &fakeNet{hosts: hosts, portMiss: miss}
	out := New(Deps{Prober: net, Logger: quiet}).Run(context.Background(), basePlan("10.0.0.0/24"), newSink())
	if out.Stats.HostsUp != 12 || len(out.Stats.Warnings) != 1 || !strings.Contains(out.Stats.Warnings[0], "tylko 2") {
		t.Errorf("hosts up %d, warnings %q", out.Stats.HostsUp, out.Stats.Warnings)
	}
	net = &fakeNet{hosts: hosts}
	if out = New(Deps{Prober: net, Logger: quiet}).Run(context.Background(), basePlan("10.0.0.0/24"), newSink()); len(out.Stats.Warnings) != 0 {
		t.Errorf("a clean run warns: %q", out.Stats.Warnings)
	}
}

func TestPortScanTimeoutGrowsWithTheWork(t *testing.T) {
	if got := portScanTimeout(1, 1000, 840); got != portScanHostTimeout {
		t.Errorf("one host: %v", got)
	}
	// the public instance: 35 live hosts, 1000 ports, 105 pps per group
	if got := portScanTimeout(35, 1000, 105); got < 900*time.Second {
		t.Errorf("35 hosts at 105 pps: %v, want at least 3 x 333 s", got)
	}
	if got := portScanTimeout(10, 100, 0); got < portScanHostTimeout {
		t.Errorf("rate 0: %v", got)
	}
}

// A host with many open ports in the profile's list gets one more scan over
// the rest of ports 1-10000; a host with a few open ports does not.
func TestDenseHostGetsAWidePortPass(t *testing.T) {
	many := []int{}
	for p := 100; p < 110; p++ {
		many = append(many, p)
	}
	many = append(many, 9001, 47001) // 47001 is above the wide range
	net := &fakeNet{hosts: map[string][]int{"10.0.0.10": many, "10.0.0.11": {22, 9002}}}
	sink := newSink()
	plan := basePlan("10.0.0.0/24")
	plan.Profile.Ports = "1-1000"
	out := New(Deps{Prober: net, Logger: quiet}).Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if h := sink.host("10.0.0.10"); h == nil || len(h.Services) != 11 {
		t.Fatalf("dense host = %+v, want 11 ports with 9001", h)
	}
	if h := sink.host("10.0.0.11"); h == nil || len(h.Services) != 1 {
		t.Fatalf("sparse host = %+v, want only port 22", h)
	}
}

func TestNameServiceNeverEmpty(t *testing.T) {
	for _, c := range []struct {
		in   model.ServiceResult
		want string
	}{
		{model.ServiceResult{Name: "ssh"}, "ssh"},
		{model.ServiceResult{Name: "tcpwrapped"}, "tcpwrapped"},
		{model.ServiceResult{Name: "tcpwrapped", HTTP: &model.HTTPFingerprint{}}, "http"},
		{model.ServiceResult{}, "unknown"},
		{model.ServiceResult{Name: "unknown", HTTP: &model.HTTPFingerprint{}}, "http"},
		{model.ServiceResult{HTTP: &model.HTTPFingerprint{}, Tunnel: "ssl"}, "https"},
	} {
		s := c.in
		if nameService(&s); s.Name != c.want {
			t.Errorf("%+v: %q, want %q", c.in, s.Name, c.want)
		}
	}
}

func TestNotHTTPSkipsKnownProtocolsOnly(t *testing.T) {
	for _, c := range []struct {
		s    model.ServiceResult
		want bool
	}{
		{model.ServiceResult{Name: "ssh"}, true},
		{model.ServiceResult{Name: "postgresql"}, true},
		{model.ServiceResult{Name: "amqp"}, true},
		{model.ServiceResult{Name: "imap", Tunnel: "ssl"}, false},
		{model.ServiceResult{Name: "tcpwrapped"}, false},
		{model.ServiceResult{Name: "unknown"}, false},
		{model.ServiceResult{Name: "http-proxy"}, false},
		{model.ServiceResult{Name: ""}, false},
	} {
		if got := notHTTP(&c.s); got != c.want {
			t.Errorf("%+v: %v, want %v", c.s, got, c.want)
		}
	}
}

// slowSV is a network whose version detection hangs on HTTP ports, like
// nmap's -sV on Gitea (42 s for one port).
type slowSV struct{ *fakeNet }

func (s slowSV) ServiceScan(ctx context.Context, req probe.ServiceRequest) (*probe.Result, error) {
	for _, hp := range req.Hosts {
		for _, p := range hp.Ports {
			if p == 80 || p == 8080 {
				select {
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				case <-time.After(20 * time.Second):
				}
			}
		}
	}
	return s.fakeNet.ServiceScan(ctx, req)
}

func TestQuickPathHTTPStopsSlowVersionDetection(t *testing.T) {
	netw := slowSV{&fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 80, 8080}}}}
	e := New(Deps{Prober: netw, Logger: quiet, Fingerprinter: &fakeFP{}, Signatures: fakeSig{}})
	plan := basePlan("10.7.0.5")
	plan.Profile.HTTP = model.HTTPOpts{Enabled: true}
	plan.Policy.MaxPerHostRPS = 100
	start := time.Now()
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("run took %v: the HTTP answer must stop version detection on port 80", d)
	}
	h := sink.host("10.7.0.5")
	if h == nil || len(h.Services) != 3 {
		t.Fatalf("host = %+v", h)
	}
	for _, s := range h.Services {
		switch s.Port {
		case 22:
			if s.Name != "ssh" || s.Product != "OpenSSH" || s.HTTP != nil {
				t.Errorf("ssh = %+v", s)
			}
		case 80, 8080: // 8080: the port table says "unknown" here (nmap says "ppp" for 3000), the page says http
			if s.Name != "http" || s.HTTP == nil {
				t.Errorf("http = %+v", s)
			}
		}
	}
}

// slowSSH is a network whose version detection on port 22 takes a while,
// like nmap on AMQP (22 s).
type slowSSH struct{ *fakeNet }

func (s slowSSH) ServiceScan(ctx context.Context, req probe.ServiceRequest) (*probe.Result, error) {
	if len(req.Hosts) == 1 && len(req.Hosts[0].Ports) == 1 && req.Hosts[0].Ports[0] == 22 {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(300 * time.Millisecond):
		}
	}
	return s.fakeNet.ServiceScan(ctx, req)
}

func TestQuickPathStoresAPartialResultFirst(t *testing.T) {
	defer func(d time.Duration) { quickStoreEvery = d }(quickStoreEvery)
	quickStoreEvery = 50 * time.Millisecond
	netw := slowSSH{&fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 80, 8080}}}}
	e := New(Deps{Prober: netw, Logger: quiet, Fingerprinter: &fakeFP{}, Signatures: fakeSig{}})
	plan := basePlan("10.7.0.5")
	plan.Profile.HTTP = model.HTTPOpts{Enabled: true}
	plan.Policy.MaxPerHostRPS = 100
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	sink.mu.Lock()
	reports := append([]model.HostResult(nil), sink.hosts...)
	sink.mu.Unlock()
	if len(reports) < 2 {
		t.Fatalf("reports = %d, want partial ones and the final one", len(reports))
	}
	part, final := reports[0], reports[len(reports)-1]
	for _, p := range reports[:len(reports)-1] {
		if !p.PortsUnknown {
			t.Errorf("a partial result must be marked PortsUnknown: %+v", p)
		}
	}
	// the first partial comes before the slow version detection of ssh ended
	for _, s := range part.Services {
		if s.Port == 22 && s.Product != "" {
			t.Errorf("partial = %+v", part)
		}
	}
	if len(part.Services) == 0 {
		t.Errorf("empty partial")
	}
	if final.PortsUnknown || final.Services[0].Product != "OpenSSH" {
		t.Errorf("final = %+v", final)
	}
	if out.Stats.HostsUp != 1 || out.Stats.ServicesOpen != 3 || out.Stats.HTTPServices != 2 {
		t.Errorf("stats counted the partial result twice: %+v", out.Stats)
	}
}

func TestSmallScopeGetsTheFullPortRange(t *testing.T) {
	netw := &fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 80, 40000}}}
	e := New(Deps{Prober: netw, Logger: quiet, Fingerprinter: &fakeFP{}, Signatures: fakeSig{}})
	plan := basePlan("10.7.0.5")
	plan.Profile.Ports = "top-100"
	plan.Profile.HTTP = model.HTTPOpts{Enabled: true}
	plan.Policy.MaxPerHostRPS = 100
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	h := sink.host("10.7.0.5")
	if h == nil || len(h.Services) != 3 || h.Services[2].Port != 40000 || h.PortsUnknown {
		t.Fatalf("final host = %+v", h)
	}
	sink.mu.Lock()
	first := sink.hosts[0]
	sink.mu.Unlock()
	if !first.PortsUnknown || len(first.Services) != 2 {
		t.Errorf("the top ports must be stored first as a partial result: %+v", first)
	}
	p := out.Stats.Passes
	if len(p) != 2 || p[0].Name != model.PassTopPorts || p[1].Name != model.PassFullRange {
		t.Fatalf("passes = %+v", p)
	}
	if p[0].State != model.PassDone || p[0].PortsTotal != 100 || p[0].PortsDone != 100 || p[0].Hosts != 1 {
		t.Errorf("top ports pass = %+v", p[0])
	}
	if p[1].State != model.PassDone || p[1].PortsTotal != 65535-100 || p[1].PortsDone != p[1].PortsTotal {
		t.Errorf("full range pass = %+v", p[1])
	}
	if out.Stats.ServicesOpen != 3 || out.Stats.HostsUp != 1 {
		t.Errorf("stats = %+v", out.Stats)
	}

	// an explicit port list is scanned as written: one pass, no array
	plan = basePlan("10.7.0.5")
	plan.Profile.HTTP = model.HTTPOpts{Enabled: true}
	sink = newSink()
	out = e.Run(context.Background(), plan, sink)
	if h := sink.host("10.7.0.5"); h == nil || len(h.Services) != 2 || out.Stats.Passes != nil {
		t.Errorf("explicit list: host %+v, passes %+v", h, out.Stats.Passes)
	}
}

func TestFullRangeHostBudget(t *testing.T) {
	hosts := map[string][]int{}
	for i := 1; i <= 20; i++ {
		hosts[fmt.Sprintf("10.7.0.%d", i)] = []int{80, 40000}
	}
	netw := &fakeNet{hosts: hosts}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.7.0.0/27")
	plan.Profile.Ports = "top-100"
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if h := sink.host("10.7.0.3"); h == nil || len(h.Services) != 1 {
		t.Errorf("20 live hosts are over the budget of %d: host %+v", fullRangeMaxHosts, h)
	}
	p := out.Stats.Passes
	if len(p) != 2 || p[1].State != model.PassSkipped {
		t.Errorf("passes = %+v", p)
	}
}

func TestEstimateCountsTheFullRange(t *testing.T) {
	e := New(Deps{Prober: &fakeNet{}, Logger: quiet})
	plan := basePlan("10.7.0.5")
	plan.Profile.Ports = "top-1000"
	est := e.Estimate(plan)
	if est.FullRangeMaxHosts != fullRangeMaxHosts || est.EstPackets < 64000 || est.EstDurationSec < 60 ||
		est.FullRangeMaxAddresses != 256 || est.FullRangePorts != 64535 || math.Abs(est.EstFullRangeSecPerHost-64535/(float64(EffectiveLimits(plan.Profile, plan.Policy).ProbePPS())*0.9)) > 0.1 {
		t.Errorf("one host with top-1000: %+v", est)
	}
	plan.Profile.Ports = "22,80,443"
	if est := e.Estimate(plan); est.FullRangeMaxHosts != 0 || est.EstPackets > 1000 {
		t.Errorf("explicit list: %+v", est)
	}
}

// The extra passes keep the policy's port lists: a stack whose policy allows
// only its own published ports must never see another port probed.
func TestExtraPassesKeepTheAllowedPorts(t *testing.T) {
	netw := &recordingNet{fakeNet: &fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 80, 40000}}}}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.7.0.5")
	plan.Profile.Ports = "top-100"
	plan.Policy.AllowedPorts = "22,80,8080"
	sink := newSink()
	if out := e.Run(context.Background(), plan, sink); out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	allowed, _ := probe.ParsePorts("22,80,8080")
	for _, ps := range netw.scanned {
		for _, p := range ps.List() {
			if !allowed.Has(p) {
				t.Fatalf("port %d probed outside allowed_ports", p)
			}
		}
	}
	if h := sink.host("10.7.0.5"); h == nil || len(h.Services) != 2 {
		t.Errorf("host = %+v", h)
	}
}

type recordingNet struct {
	*fakeNet
	mu      sync.Mutex
	scanned []*probe.PortSet
}

func (n *recordingNet) PortScan(ctx context.Context, req probe.PortScanRequest) (*probe.Result, error) {
	n.mu.Lock()
	n.scanned = append(n.scanned, req.Ports)
	n.mu.Unlock()
	return n.fakeNet.PortScan(ctx, req)
}

func TestExplicitFullRangeGoesTopPortsFirst(t *testing.T) {
	netw := &recordingNet{fakeNet: &fakeNet{hosts: map[string][]int{"10.7.0.5": {22, 40000}}}}
	e := New(Deps{Prober: netw, Logger: quiet})
	plan := basePlan("10.7.0.5")
	plan.Profile.Ports = "1-65535"
	sink := newSink()
	out := e.Run(context.Background(), plan, sink)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}
	if len(netw.scanned) < 2 || netw.scanned[0].Count() != 1000 || netw.scanned[0].Count()+netw.scanned[len(netw.scanned)-1].Count() != 65535 {
		t.Errorf("scans: %d", len(netw.scanned))
	}
	if h := sink.host("10.7.0.5"); h == nil || len(h.Services) != 2 {
		t.Errorf("host = %+v", h)
	}
	if p := out.Stats.Passes; len(p) != 2 || p[1].PortsTotal != 64535 {
		t.Errorf("passes = %+v", p)
	}
}
