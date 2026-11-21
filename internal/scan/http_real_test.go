package scan

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/sig"
)

// loopNet is a prober that reports fixed loopback hosts. The HTTP stage
// behind it is real: real collector, real signature engine, real sockets.
type loopNet struct{ hosts map[string][]int }

func (l loopNet) Name() string     { return "loop" }
func (l loopNet) Privileged() bool { return false }

func (l loopNet) Discover(_ context.Context, req probe.DiscoverRequest) (*probe.Result, error) {
	res := &probe.Result{}
	for ip := range l.hosts {
		if (net.ParseIP(ip).To4() == nil) == req.IPv6 {
			res.Hosts = append(res.Hosts, probe.Host{IP: ip, Up: true, Reason: "syn-ack", Responded: true})
		}
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].IP < res.Hosts[j].IP })
	return res, nil
}

func (l loopNet) PortScan(_ context.Context, req probe.PortScanRequest) (*probe.Result, error) {
	res := &probe.Result{}
	for _, ip := range req.Hosts {
		h := probe.Host{IP: ip, Up: true, Responded: true}
		for _, p := range l.hosts[ip] {
			h.Ports = append(h.Ports, probe.Port{Port: p, Proto: "tcp", State: "open", Name: "http"})
		}
		res.Hosts = append(res.Hosts, h)
	}
	return res, nil
}

func (l loopNet) ServiceScan(context.Context, probe.ServiceRequest) (*probe.Result, error) {
	return &probe.Result{}, nil
}

// hitLog records when each request reached a test server.
type hitLog struct {
	mu   sync.Mutex
	hits map[string][]time.Time // host IP → arrival times
	path map[string]int
}

func (h *hitLog) serve(t *testing.T, ip string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[ip] = append(h.hits[ip], time.Now())
		h.path[r.URL.Path]++
		h.mu.Unlock()
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("unsafe method %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx/1.27.2")
		_, _ = w.Write([]byte("<html><head><title>Lab</title></head><body>ok</body></html>"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// maxInWindow returns the largest number of events inside any window of length d.
func maxInWindow(ts []time.Time, d time.Duration) int {
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	best, lo := 0, 0
	for hi := range ts {
		for ts[hi].Sub(ts[lo]) >= d {
			lo++
		}
		best = max(best, hi-lo+1)
	}
	return best
}

// The request caps of the safety policy must hold for every request that
// leaves the machine: root pages, favicons and the extra signature paths.
// The servers count what really arrived.
func TestHTTPRequestCapsHoldWithRealCollector(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 4 seconds")
	}
	second := "::1" // 127.0.0.2 is not configured on every system; ::1 is a second address everywhere
	hl := &hitLog{hits: map[string][]time.Time{}, path: map[string]int{}}
	a1, a2 := hl.serve(t, "127.0.0.1"), hl.serve(t, "127.0.0.1")
	b1 := hl.serve(t, second)

	sigs, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	collector := httpfp.New()
	collector.Wait = HTTPWait
	var sent int
	var sentMu sync.Mutex
	collector.OnRequest = func(string, string) { sentMu.Lock(); sent++; sentMu.Unlock() }

	const globalRPS, hostRPS, maxPaths = 12, 8, 8
	e := New(Deps{Prober: loopNet{hosts: map[string][]int{"127.0.0.1": {a1, a2}, second: {b1}}}, Logger: quiet, Fingerprinter: collector, Signatures: sigs})
	plan := model.ScanPlan{
		RunID: 3, Targets: tgt("127.0.0.1", second),
		Profile: model.ScanProfile{
			Ports: strconv.Itoa(a1) + "," + strconv.Itoa(a2) + "," + strconv.Itoa(b1),
			HTTP:  model.HTTPOpts{Enabled: true, SignaturePaths: true, Favicon: true, MaxRedirects: 2, TimeoutMs: 3000},
			Rate:  model.RateLimits{MaxPPS: 100, HTTPRPS: 50, PerHostConcurrency: 2},
		},
		Policy: model.SafetyPolicy{MaxHTTPRPS: globalRPS, MaxPerHostRPS: hostRPS, MaxPathsPerHost: maxPaths},
	}
	sink := newSink()
	start := time.Now()
	out := e.Run(context.Background(), plan, sink)
	took := time.Since(start)
	if out.Status != model.RunCompleted {
		t.Fatalf("outcome = %+v", out)
	}

	hl.mu.Lock()
	defer hl.mu.Unlock()
	var all []time.Time
	for _, ts := range hl.hits {
		all = append(all, ts...)
	}
	extra := 0
	for p, n := range hl.path {
		if p != "/" && p != "/favicon.ico" {
			extra += n
		}
	}
	t.Logf("%d requests in %s: host A %d, host B %d, extra signature paths %d; peak per second: all %d (cap %d), host A %d, host B %d (cap %d)",
		len(all), took.Round(time.Millisecond), len(hl.hits["127.0.0.1"]), len(hl.hits[second]), extra,
		maxInWindow(all, time.Second), globalRPS, maxInWindow(hl.hits["127.0.0.1"], time.Second), maxInWindow(hl.hits[second], time.Second), hostRPS)

	if extra < 3*maxPaths {
		t.Errorf("extra signature paths requested = %d, want %d per service", extra, maxPaths)
	}
	for p, n := range hl.path {
		if p != "/" && n > 3 {
			t.Errorf("path %s requested %d times for 3 services", p, n)
		}
	}
	// a bucket without burst lets at most rate+1 requests into any one-second window
	if got := maxInWindow(all, time.Second); got > globalRPS+1 {
		t.Errorf("global cap: %d requests in one second, cap %d", got, globalRPS)
	}
	for ip, ts := range hl.hits {
		if got := maxInWindow(ts, time.Second); got > hostRPS+1 {
			t.Errorf("per-host cap on %s: %d requests in one second, cap %d", ip, got, hostRPS)
		}
	}
	if floor := time.Duration(float64(len(all)-1) / globalRPS * float64(time.Second)); took < floor {
		t.Errorf("%d requests in %s is faster than %d per second allows", len(all), took, globalRPS)
	}
	// the counter of the run is exact: every request the servers saw is counted
	if int64(len(all)) != out.Stats.HTTPRequests || sent != len(all) {
		t.Errorf("servers saw %d requests, collector sent %d, RunStats.HTTPRequests = %d", len(all), sent, out.Stats.HTTPRequests)
	}
	for _, ip := range []string{"127.0.0.1", second} {
		h := sink.host(ip)
		if h == nil || len(h.Services) == 0 || h.Services[0].HTTP == nil || h.Services[0].HTTP.Title != "Lab" {
			t.Fatalf("host %s = %+v", ip, h)
		}
		found := false
		for _, tech := range h.Services[0].Technologies {
			if tech.Name == "nginx" && tech.Version == "1.27.2" {
				found = true
			}
		}
		if !found {
			t.Errorf("host %s: nginx 1.27.2 not detected by the real signature engine: %+v", ip, h.Services[0].Technologies)
		}
	}
}
