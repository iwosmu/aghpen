package scan

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/targets"
)

// answers says which discovery probes a fake host reacts to.
type answers struct {
	echo bool
	syn  []int
}

// probeNet is a network whose hosts answer only some probe types, so the
// tests can tell which probes each discovery pass sent.
type probeNet struct {
	mu      sync.Mutex
	hosts   map[string]answers
	passes  []probe.DiscoverRequest
	packets int64
}

func (p *probeNet) Name() string     { return "probe-fake" }
func (p *probeNet) Privileged() bool { return true }

func (p *probeNet) Discover(_ context.Context, req probe.DiscoverRequest) (*probe.Result, error) {
	st := targets.Build(req.Targets)
	res := &probe.Result{Packets: st.V4.Count() * int64(probeCount(req.Opts, true)) * int64(1+req.MaxRetries), PacketsExact: true}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passes = append(p.passes, req)
	p.packets += res.Packets
	for ip, a := range p.hosts {
		v, _ := targets.ParseValue(ip)
		if !st.V4.Contains(v.Range.Lo) {
			continue
		}
		hit := req.Opts.ICMPEcho && a.echo
		for _, port := range req.Opts.TCPSynPorts {
			for _, open := range a.syn {
				hit = hit || port == open
			}
		}
		if hit {
			res.Hosts = append(res.Hosts, probe.Host{IP: ip, Up: true, Reason: "syn-ack", Responded: true})
		}
	}
	return res, nil
}

func (p *probeNet) PortScan(_ context.Context, req probe.PortScanRequest) (*probe.Result, error) {
	res := &probe.Result{}
	for _, ip := range req.Hosts {
		h := probe.Host{IP: ip, Up: true, Responded: true}
		for _, port := range p.hosts[ip].syn {
			h.Ports = append(h.Ports, probe.Port{Port: port, Proto: "tcp", State: "open"})
		}
		res.Hosts = append(res.Hosts, h)
	}
	return res, nil
}

func (p *probeNet) ServiceScan(context.Context, probe.ServiceRequest) (*probe.Result, error) {
	return &probe.Result{}, nil
}

func TestDiscoveryModes(t *testing.T) {
	hosts := map[string]answers{
		"10.8.0.10": {echo: true},      // answers ping: every mode finds it in the first pass
		"10.8.0.20": {syn: []int{80}},  // drops ICMP, web port open: the first pass finds it by TCP
		"10.8.0.30": {syn: []int{22}},  // drops ICMP, SSH only, in a block with live hosts
		"10.8.2.40": {syn: []int{22}},  // drops ICMP, SSH only, alone in its /24, unknown to the inventory
		"10.8.3.50": {syn: []int{22}},  // the same, but the inventory knows it
		"10.8.1.60": {syn: []int{443}}, // web port in another block
	}
	full := model.DiscoveryOpts{ICMPEcho: true, ICMPTimestamp: true, TCPSynPorts: []int{22, 80, 443, 3389, 8080}, TCPAckPorts: []int{80, 443}}
	run := func(mode string) (found []string, netw *probeNet) {
		netw = &probeNet{hosts: hosts}
		plan := basePlan("10.8.0.0/22")
		plan.Profile.Discovery = full
		plan.Profile.Discovery.Mode = mode
		plan.Profile.ServiceDetection = false
		plan.Profile.Retry.UnstableRetries = 0
		plan.Profile.Rate.MaxParallelChunks = 1
		plan.Profile.Chunking = model.ChunkingOpts{InitialSize: 1024, MinSize: 1024, MaxSize: 1024}
		plan.Hints = []model.HostHint{{IP: "10.8.3.50", OpenPorts: []int{22}}}
		sink := newSink()
		if out := New(Deps{Prober: netw, Logger: quiet}).Run(context.Background(), plan, sink); out.Status != model.RunCompleted {
			t.Fatalf("%s: %+v", mode, out)
		}
		for _, h := range sink.hosts {
			if h.Up {
				found = append(found, h.IP)
			}
		}
		sort.Strings(found)
		return found, netw
	}

	thorough, tn := run(model.DiscoveryThorough)
	if len(thorough) != 6 || len(tn.passes) != 1 || tn.packets != 1024*9*2 {
		t.Errorf("thorough: found %v in %d passes with %d packets", thorough, len(tn.passes), tn.packets)
	}

	balanced, bn := run("") // the default
	want := []string{"10.8.0.10", "10.8.0.20", "10.8.0.30", "10.8.1.60", "10.8.3.50"}
	if !reflect.DeepEqual(balanced, want) {
		t.Errorf("balanced found %v, want %v (a silent host alone in an unknown block is the accepted miss)", balanced, want)
	}
	if len(bn.passes) != 2 {
		t.Fatalf("balanced passes = %d", len(bn.passes))
	}
	p1, p2 := bn.passes[0], bn.passes[1]
	if !p1.Opts.ICMPEcho || p1.Opts.ICMPTimestamp || !reflect.DeepEqual(p1.Opts.TCPSynPorts, []int{80, 443}) || len(p1.Opts.TCPAckPorts) != 0 || p1.MaxRetries != 1 {
		t.Errorf("first pass = %+v", p1)
	}
	if p2.Opts.ICMPEcho || !p2.Opts.ICMPTimestamp || !reflect.DeepEqual(p2.Opts.TCPSynPorts, []int{22, 3389, 8080}) || !reflect.DeepEqual(p2.Opts.TCPAckPorts, []int{80, 443}) {
		t.Errorf("second pass must send only the probes the first pass left out: %+v", p2.Opts)
	}
	// second pass: blocks 0, 1 (a host answered) and 3 (a hint), without the 3 hosts already found
	second := targets.Build(p2.Targets).V4
	if second.Count() != 3*256-3 || second.Contains(targets.Build([]string{"10.8.2.40"}).V4.Ranges()[0].Lo) || second.Contains(targets.Build([]string{"10.8.0.10"}).V4.Ranges()[0].Lo) {
		t.Errorf("second pass targets = %v (%d addresses)", p2.Targets, second.Count())
	}
	if bn.packets >= tn.packets {
		t.Errorf("balanced sent %d packets, thorough %d", bn.packets, tn.packets)
	}

	fast, fn := run(model.DiscoveryFast)
	want = []string{"10.8.0.10", "10.8.0.20", "10.8.1.60", "10.8.3.50"}
	if !reflect.DeepEqual(fast, want) {
		t.Errorf("fast found %v, want %v (the host that drops ICMP and the hinted host must not be lost)", fast, want)
	}
	// one retry also in fast mode: nmap without retries sends only the first probe type
	if len(fn.passes) != 2 || fn.passes[0].MaxRetries != 1 || !reflect.DeepEqual(fn.passes[1].Targets, []string{"10.8.3.50"}) {
		t.Errorf("fast passes = %+v", fn.passes)
	}
	if fn.packets != 1024*3*2+1*6*2 || fn.packets >= bn.packets {
		t.Errorf("fast sent %d packets (balanced %d)", fn.packets, bn.packets)
	}
	t.Logf("packets for 1024 addresses: thorough %d, balanced %d, fast %d", tn.packets, bn.packets, fn.packets)
}

func TestSplitDiscoveryAndCost(t *testing.T) {
	full := probe.NormalizeDiscovery(model.DiscoveryOpts{})
	first, rest, ok := splitDiscovery(full, true)
	if !ok || probeCount(first, true) != 3 || probeCount(rest, true) != 6 || probeCount(full, true) != 9 {
		t.Fatalf("split = %+v | %+v | %v", first, rest, ok)
	}
	// without raw sockets only the SYN ports count
	if f, r, ok := splitDiscovery(full, false); !ok || probeCount(f, false) != 2 || probeCount(r, false) != 3 {
		t.Errorf("unprivileged split = %+v | %+v", f, r)
	}
	// a profile with one probe cannot be split
	if _, _, ok := splitDiscovery(model.DiscoveryOpts{ICMPEcho: true}, true); ok {
		t.Error("a single probe must stay one pass")
	}
	// no web port: the first SYN port leads
	if f, r, ok := splitDiscovery(model.DiscoveryOpts{TCPSynPorts: []int{22, 3389}}, true); !ok || !reflect.DeepEqual(f.TCPSynPorts, []int{22}) || !reflect.DeepEqual(r.TCPSynPorts, []int{3389}) {
		t.Errorf("no web port: %+v | %+v", f, r)
	}
	if c := deadCost(full, true, model.DiscoveryThorough, 0); c != 18 {
		t.Errorf("thorough cost = %v", c)
	}
	if c := deadCost(full, true, model.DiscoveryBalanced, 0); c != 6 {
		t.Errorf("balanced cost in an empty block = %v", c)
	}
	if c := deadCost(full, true, model.DiscoveryBalanced, 1); c != 18 {
		t.Errorf("balanced cost in a live block = %v", c)
	}
	if c := deadCost(full, true, model.DiscoveryFast, 1); c != 6 {
		t.Errorf("fast cost = %v", c)
	}
	if discoveryMode("") != model.DiscoveryBalanced || discoveryMode("nonsense") != model.DiscoveryBalanced || discoveryMode("fast") != model.DiscoveryFast {
		t.Error("mode defaults")
	}
	e := New(Deps{Prober: &probeNet{}, Logger: quiet})
	plan := basePlan("10.0.0.0/16")
	var sec [3]int64
	for i, m := range []string{model.DiscoveryFast, model.DiscoveryBalanced, model.DiscoveryThorough} {
		plan.Profile.Discovery = model.DiscoveryOpts{Mode: m}
		est := e.Estimate(plan)
		if est.DiscoveryMode != m {
			t.Errorf("estimate mode = %q, want %q", est.DiscoveryMode, m)
		}
		sec[i] = est.EstDurationSec
	}
	if !(sec[0] < sec[1] && sec[1] < sec[2]) {
		t.Errorf("estimated seconds fast/balanced/thorough = %v", sec)
	}
}

func TestMergeHostsDropsDuplicates(t *testing.T) {
	live := []probe.Host{{IP: "10.0.0.7", Up: true}, {IP: "10.0.0.9", Up: true}}
	more := []probe.Host{{IP: "10.0.0.7", Up: true}, {IP: "10.0.0.8", Up: true}}
	got := mergeHosts(live, more)
	if len(got) != 3 {
		t.Fatalf("merged = %+v, want 3 distinct hosts", got)
	}
	ips := map[string]int{}
	for _, h := range got {
		ips[h.IP]++
	}
	for ip, n := range ips {
		if n != 1 {
			t.Errorf("%s appears %d times", ip, n)
		}
	}
}
