package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iwosmu/aghpen/internal/targets"
)

// Nmap runs nmap as a child process. The argument list is built in code from
// validated values only. Targets go to nmap on stdin ("-iL -"), never
// through a shell.
type Nmap struct {
	Path       string
	Version    string
	privileged bool
	euid       int
	log        *slog.Logger
	xmlOnFD    atomic.Bool // XML on fd 3, so that stdout carries the packet statistics
	seq        atomic.Int64
}

var (
	privOnce sync.Once
	privOK   bool
)

// DetectPrivileges reports once whether raw sockets are available.
func DetectPrivileges() bool {
	privOnce.Do(func() { privOK = rawSocketsAvailable() })
	return privOK
}

// NewNmap finds nmap and detects privileges.
func NewNmap(path string, log *slog.Logger) (*Nmap, error) {
	if path == "" {
		path = "nmap"
	}
	full, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("nmap not found (%s): %w", path, err)
	}
	if log == nil {
		log = slog.Default()
	}
	n := &Nmap{Path: full, privileged: DetectPrivileges(), euid: os.Geteuid(), log: log}
	n.xmlOnFD.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, full, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("nmap --version failed: %w", err)
	}
	if m := regexp.MustCompile(`Nmap version ([0-9.]+)`).FindSubmatch(out); m != nil {
		n.Version = string(m[1])
	}
	return n, nil
}

func (n *Nmap) Name() string     { return "nmap" }
func (n *Nmap) Privileged() bool { return n.privileged }

var reTarget = regexp.MustCompile(`^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2}|-[0-9]{1,3})?|[0-9A-Fa-f:]+(?:\.[0-9]{1,3}){0,3})$`)

// validateTargets rejects everything that is not an IP address, an IPv4
// CIDR or an "a.b.c.d-N" range. Host names never reach nmap.
func validateTargets(ts []string) error {
	if len(ts) == 0 {
		return errors.New("no targets")
	}
	for _, t := range ts {
		if !reTarget.MatchString(t) || strings.HasPrefix(t, "-") {
			return fmt.Errorf("unsafe or invalid nmap target %q", t)
		}
	}
	return nil
}

func portList(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			parts = append(parts, strconv.Itoa(p))
		}
	}
	return strings.Join(parts, ",")
}

// commonArgs are on every command line: no DNS, a hard packet-rate cap, a
// retry cap and a host timeout. No "--script" option is ever added.
func (n *Nmap) commonArgs(maxRate, maxRetries int, hostTimeout time.Duration, v6 bool) []string {
	if maxRate < 1 {
		maxRate = 1
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	// --max-rate alone caps the average since the start of the process: after
	// a slow phase nmap sends bursts far above it to catch up (measured: 1000
	// pps for seconds against a 500 pps limit). --min-rate with the same
	// value pins the pace, so the cap also holds second by second.
	rate := strconv.Itoa(maxRate)
	args := []string{"-n", "-T4", "-v", "--min-rate", rate, "--max-rate", rate, "--max-retries", strconv.Itoa(maxRetries)}
	if hostTimeout > 0 {
		args = append(args, "--host-timeout", strconv.Itoa(int(hostTimeout.Seconds()+0.5))+"s")
	}
	if v6 {
		args = append(args, "-6")
	}
	switch {
	case !n.privileged:
		args = append(args, "--unprivileged")
	case n.euid != 0:
		args = append(args, "--privileged") // raw sockets through capabilities, not uid 0
	}
	return args
}

// DiscoverArgs builds the host-discovery command line (without targets).
func (n *Nmap) DiscoverArgs(req DiscoverRequest) []string {
	o := NormalizeDiscovery(req.Opts)
	args := []string{"-sn"}
	if n.privileged && req.ARPOnly && !req.IPv6 {
		args = append(args, "-PR")
		return append(args, n.commonArgs(req.MaxRate, req.MaxRetries, req.HostTimeout, req.IPv6)...)
	}
	if n.privileged {
		if o.ICMPEcho && !req.IPv6 {
			args = append(args, "-PE")
		}
		if o.ICMPTimestamp && !req.IPv6 {
			args = append(args, "-PP")
		}
		if req.IPv6 && (o.ICMPEcho || o.ICMPTimestamp) {
			args = append(args, "-PE")
		}
		if s := portList(o.TCPSynPorts); s != "" {
			args = append(args, "-PS"+s)
		}
		if s := portList(o.TCPAckPorts); s != "" {
			args = append(args, "-PA"+s)
		}
		if !o.ARP {
			args = append(args, "--disable-arp-ping")
		}
	} else {
		// Without raw sockets nmap can only do a TCP-connect ping.
		ports := o.TCPSynPorts
		if len(ports) == 0 {
			ports = DefaultSynPorts
		}
		args = append(args, "-PS"+portList(ports))
	}
	return append(args, n.commonArgs(req.MaxRate, req.MaxRetries, req.HostTimeout, req.IPv6)...)
}

func (n *Nmap) scanType() string {
	if n.privileged {
		return "-sS"
	}
	return "-sT"
}

// PortScanArgs builds the port-scan command line (without targets).
func (n *Nmap) PortScanArgs(req PortScanRequest) []string {
	args := []string{n.scanType(), "-Pn", "-p", req.Ports.String()}
	return append(args, n.commonArgs(req.MaxRate, req.MaxRetries, req.HostTimeout, req.IPv6)...)
}

// ServiceArgs builds the version-detection command line for one group of
// hosts that share the port list.
func (n *Nmap) ServiceArgs(ports []int, intensity, maxRate int, hostTimeout time.Duration, v6 bool) []string {
	if intensity < 0 {
		intensity = 0
	}
	if intensity > 9 {
		intensity = 9
	}
	args := []string{n.scanType(), "-sV", "--version-intensity", strconv.Itoa(intensity), "-Pn", "-p", portList(ports)}
	return append(args, n.commonArgs(maxRate, 1, hostTimeout, v6)...)
}

func (n *Nmap) Discover(ctx context.Context, req DiscoverRequest) (*Result, error) {
	if req.MaxRetries <= 0 {
		// never 0: nmap then sends only the first ping probe type to each host
		req.MaxRetries = 1
	}
	res, err := n.run(ctx, "discover", n.DiscoverArgs(req), req.Targets)
	if err != nil {
		return res, err
	}
	if !res.PacketsExact {
		o := NormalizeDiscovery(req.Opts)
		probes := len(o.TCPSynPorts)
		if probes == 0 {
			probes = len(DefaultSynPorts)
		}
		addrs := int64(res.Scanned)
		if addrs == 0 {
			st := targets.Build(req.Targets)
			addrs = st.V4.Count() + int64(len(st.V6))
		}
		res.Packets = addrs * int64(probes) * int64(1+req.MaxRetries)
	}
	return res, nil
}

func (n *Nmap) PortScan(ctx context.Context, req PortScanRequest) (*Result, error) {
	if req.Ports == nil || req.Ports.Count() == 0 {
		return nil, errors.New("port scan: empty port set")
	}
	if req.MaxRetries == 0 {
		req.MaxRetries = 2
	}
	res, err := n.run(ctx, "portscan", n.PortScanArgs(req), req.Hosts)
	if err != nil {
		return res, err
	}
	if !res.PacketsExact {
		res.Packets = int64(len(req.Hosts)) * int64(req.Ports.Count())
	}
	return res, nil
}

// maxServiceGroups caps the number of nmap processes of one service stage.
const maxServiceGroups = 6

// groupByPorts puts hosts with the same open-port list into one group, so
// that version detection touches the open ports only. When there are more
// than max different lists, the smallest groups are merged into one group
// that scans the union of their ports.
func groupByPorts(hosts []HostPorts, max int) []serviceGroup {
	byKey := map[string]*serviceGroup{}
	var order []string
	for _, h := range hosts {
		if len(h.Ports) == 0 {
			continue
		}
		ports := append([]int{}, h.Ports...)
		sort.Ints(ports)
		key := portList(ports)
		g, ok := byKey[key]
		if !ok {
			g = &serviceGroup{Ports: ports}
			byKey[key] = g
			order = append(order, key)
		}
		g.IPs = append(g.IPs, h.IP)
	}
	groups := make([]serviceGroup, 0, len(order))
	for _, k := range order {
		groups = append(groups, *byKey[k])
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].IPs) > len(groups[j].IPs) })
	if max < 1 || len(groups) <= max {
		return groups
	}
	rest := serviceGroup{}
	union := &PortSet{}
	for _, g := range groups[max-1:] {
		rest.IPs = append(rest.IPs, g.IPs...)
		for _, p := range g.Ports {
			union.Add(p)
		}
	}
	rest.Ports = union.List()
	return append(groups[:max-1:max-1], rest)
}

type serviceGroup struct {
	IPs   []string
	Ports []int
}

// svPacketsPerPort is what nmap's version detection sends to one open port:
// it opens a new TCP connection for each probe it tries, and these
// ordinary sockets are not paced by --max-rate. Measured on the lab (64
// HTTP ports, 8 per process): 75 connections in one second, about 4.7
// packets each (SYN, ACK, request, FIN, ACK), so about 9 connections and 45
// packets per port, sent within a fraction of a second.
const svPacketsPerPort = 45

// serviceBatches splits a group so that one nmap process probes at most
// maxPairs host-port pairs: a host with more ports than that gets several
// processes, hosts with few ports share one.
func serviceBatches(g serviceGroup, maxPairs int) []serviceGroup {
	maxPairs = max(1, maxPairs)
	var out []serviceGroup
	if len(g.Ports) > maxPairs {
		for _, ip := range g.IPs {
			for i := 0; i < len(g.Ports); i += maxPairs {
				out = append(out, serviceGroup{IPs: []string{ip}, Ports: g.Ports[i:min(i+maxPairs, len(g.Ports))]})
			}
		}
		return out
	}
	per := max(1, maxPairs/max(1, len(g.Ports)))
	for i := 0; i < len(g.IPs); i += per {
		out = append(out, serviceGroup{IPs: g.IPs[i:min(i+per, len(g.IPs))], Ports: g.Ports})
	}
	return out
}

// ServiceScan runs version detection. The port-list groups run in parallel:
// nmap waits several seconds for slow banners, and that wait does not add
// up this way. The groups split the packet rate between them. Inside a
// group the hosts and ports go in paced batches (svPacketsPerPort): one
// batch sends at most the group's rate in packets, and the next batch starts
// only when the average is back under the rate. Without this, version
// detection on a host with 64 web ports sent 570-720 packets per second at
// a share of 210 (the lab gate, 2026-11-21).
func (n *Nmap) ServiceScan(ctx context.Context, req ServiceRequest) (*Result, error) {
	total := &Result{}
	start := time.Now()
	groups := groupByPorts(req.Hosts, maxServiceGroups)
	if len(groups) == 0 {
		return total, nil
	}
	rate := req.MaxRate / len(groups)
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batches := serviceBatches(g, max(1, rate)/svPacketsPerPort)
			for i, b := range batches {
				if ctx.Err() != nil {
					return
				}
				bstart := time.Now()
				args := n.ServiceArgs(b.Ports, req.Intensity, rate, req.HostTimeout, req.IPv6)
				res, err := n.run(ctx, "service", args, b.IPs)
				mu.Lock()
				if res != nil {
					total.Hosts = append(total.Hosts, res.Hosts...)
					pk := res.Packets
					if !res.PacketsExact {
						pk = int64(len(b.IPs) * len(b.Ports))
					}
					// Version probes use ordinary sockets; nmap does not count them. Add an estimate.
					open := 0
					for _, h := range res.Hosts {
						open += len(h.Ports)
					}
					total.Packets += pk + int64(open)*svPacketsPerPort
				}
				if err != nil && firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				if i == len(batches)-1 {
					break
				}
				due := time.Duration(float64(len(b.IPs)*len(b.Ports)*svPacketsPerPort) / float64(max(1, rate)) * float64(time.Second))
				if wait := due - time.Since(bstart); wait > 0 {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	total.Elapsed = time.Since(start)
	if ctx.Err() != nil {
		return total, context.Cause(ctx)
	}
	if len(total.Hosts) == 0 && firstErr != nil {
		return total, firstErr
	}
	return total, nil
}

var reRawPackets = regexp.MustCompile(`Raw packets sent: (\d+)`)

// tail keeps the last bytes written to it.
type tail struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// run starts nmap and parses its XML. The XML goes to file descriptor 3 so
// that stdout still carries the "Raw packets sent" line, which nmap prints
// only there. If that fails once, the runner falls back to "-oX -".
func (n *Nmap) run(ctx context.Context, stage string, args, targetList []string) (*Result, error) {
	if err := validateTargets(targetList); err != nil {
		return nil, err
	}
	res, err := n.exec(ctx, stage, args, targetList, n.xmlOnFD.Load())
	if err != nil && ctx.Err() == nil && n.xmlOnFD.Load() && strings.Contains(err.Error(), "/dev/fd/3") {
		n.log.Warn("nmap cannot write XML to fd 3, falling back to -oX - (packet counts become estimates)")
		n.xmlOnFD.Store(false)
		return n.exec(ctx, stage, args, targetList, false)
	}
	return res, err
}

func (n *Nmap) exec(ctx context.Context, stage string, args, targetList []string, onFD bool) (*Result, error) {
	full := append([]string{}, args...)
	stdoutTail := &tail{max: 4096}
	stderrTail := &tail{max: 2048}
	var xmlOut bytes.Buffer
	var pr, pw *os.File
	if onFD {
		var err error
		pr, pw, err = os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("nmap pipe: %w", err)
		}
		full = append(full, "-oX", "/dev/fd/3")
	} else {
		full = append(full, "-oX", "-")
	}
	full = append(full, "-iL", "-")

	cmd := exec.CommandContext(ctx, n.Path, full...)
	cmd.Stdin = strings.NewReader(strings.Join(targetList, "\n") + "\n")
	cmd.Stderr = stderrTail
	cmd.WaitDelay = 3 * time.Second
	if onFD {
		cmd.Stdout = stdoutTail
		cmd.ExtraFiles = []*os.File{pw}
	} else {
		cmd.Stdout = &xmlOut
	}
	id := n.seq.Add(1)
	n.log.Debug("nmap start", "id", id, "stage", stage, "targets", len(targetList), "args", strings.Join(full, " "))
	start := time.Now()
	if err := cmd.Start(); err != nil {
		if onFD {
			pr.Close()
			pw.Close()
		}
		return nil, fmt.Errorf("nmap start: %w", err)
	}
	var res *Result
	var perr error
	if onFD {
		pw.Close()
		res, perr = ParseXML(pr)
		_, _ = xmlOut.ReadFrom(pr) // drain so that nmap never blocks on the pipe
		pr.Close()
	}
	werr := cmd.Wait()
	if !onFD {
		res, perr = ParseXML(&xmlOut)
	}
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		return res, context.Cause(ctx)
	}
	if werr != nil {
		return res, fmt.Errorf("nmap %s failed: %v: %s", stage, werr, lastLines(stderrTail.String()+"\n"+stdoutTail.String(), 3))
	}
	if perr != nil {
		return res, fmt.Errorf("nmap %s: %w: %s", stage, perr, lastLines(stderrTail.String(), 3))
	}
	res.Elapsed = elapsed
	if m := reRawPackets.FindStringSubmatch(stdoutTail.String()); m != nil {
		res.Packets, _ = strconv.ParseInt(m[1], 10, 64)
		res.PacketsExact = true
	}
	n.log.Debug("nmap done", "id", id, "stage", stage, "hosts_up", len(res.Hosts), "packets", res.Packets, "exact", res.PacketsExact, "ms", elapsed.Milliseconds())
	return res, nil
}

func lastLines(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
