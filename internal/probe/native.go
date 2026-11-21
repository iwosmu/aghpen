package probe

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/iwosmu/aghpen/internal/targets"
)

// Native is the fallback prober for machines without nmap. It uses plain
// TCP connects from a worker pool: discovery by connecting to a few ports,
// a connect port scan, and a passive banner read. It never writes
// application data to a service.
type Native struct {
	log         *slog.Logger
	DialTimeout time.Duration
	BannerWait  time.Duration
	MaxWorkers  int
}

// NewNative returns the native prober with safe defaults.
func NewNative(log *slog.Logger) *Native {
	if log == nil {
		log = slog.Default()
	}
	return &Native{log: log, DialTimeout: time.Second, BannerWait: 1500 * time.Millisecond, MaxWorkers: 256}
}

func (n *Native) Name() string     { return "native" }
func (n *Native) Privileged() bool { return false }

func (n *Native) workers(rate int) int {
	w := rate
	if w < 4 {
		w = 4
	}
	if w > n.MaxWorkers {
		w = n.MaxWorkers
	}
	return w
}

// dialOutcome classifies one connect attempt.
type dialOutcome int

const (
	dialOpen dialOutcome = iota
	dialRefused
	dialSilent
)

// Dial makes one TCP connect and reports what came back.
func (n *Native) dial(ctx context.Context, ip string, port int) (dialOutcome, net.Conn, time.Duration) {
	d := net.Dialer{Timeout: n.DialTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	rtt := time.Since(start)
	if err == nil {
		return dialOpen, conn, rtt
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return dialRefused, nil, rtt
	}
	return dialSilent, nil, rtt
}

// forEach runs fn for every job on a worker pool and stops early on cancel.
func forEach[T any](ctx context.Context, workers int, feed func(yield func(T) bool), fn func(T)) {
	jobs := make(chan T, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				fn(j)
			}
		}()
	}
	feed(func(j T) bool {
		select {
		case jobs <- j:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(jobs)
	wg.Wait()
}

func (n *Native) Discover(ctx context.Context, req DiscoverRequest) (*Result, error) {
	st := targets.Build(req.Targets)
	if len(st.Invalid) > 0 {
		return nil, errors.New("native discover: invalid target " + st.Invalid[0].Value)
	}
	o := NormalizeDiscovery(req.Opts)
	ports := o.TCPSynPorts
	if len(ports) == 0 {
		ports = DefaultSynPorts
	}
	lim := NewLimiter(float64(req.MaxRate), max(1, req.MaxRate/10))
	passes := 1 + req.MaxRetries
	var sent atomic.Int64
	var mu sync.Mutex
	res := &Result{}
	start := time.Now()
	probe := func(ip string) {
		for pass := 0; pass < passes; pass++ {
			for _, port := range ports {
				if lim.Wait(ctx) != nil {
					return
				}
				sent.Add(1)
				out, conn, rtt := n.dial(ctx, ip, port)
				if out == dialSilent {
					continue
				}
				h := Host{IP: ip, Up: true, Reason: "tcp-connect", RTTMs: float64(rtt.Microseconds()) / 1000, Responded: true}
				if out == dialRefused {
					h.Reason = "reset"
				} else {
					sent.Add(2) // ACK and FIN of the completed handshake
					conn.Close()
				}
				mu.Lock()
				res.Hosts = append(res.Hosts, h)
				mu.Unlock()
				return
			}
		}
	}
	forEach(ctx, n.workers(req.MaxRate), func(yield func(string) bool) {
		ok := true
		st.V4.Each(func(u uint32) bool {
			res.Scanned++
			ok = yield(targets.IPString(u))
			return ok
		})
		for _, a := range st.V6 {
			if !ok {
				return
			}
			res.Scanned++
			ok = yield(a.String())
		}
	}, probe)
	res.Packets = sent.Load()
	res.Elapsed = time.Since(start)
	if ctx.Err() != nil {
		return res, context.Cause(ctx)
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].IP < res.Hosts[j].IP })
	return res, nil
}

// ConnectProbe checks one host directly: it connects to the given ports in
// order and stops at the first answer. An open port and a refused connection
// both prove that the host is up. It returns the number of probes sent.
func ConnectProbe(ctx context.Context, ip string, ports []int, timeout time.Duration, lim *Limiter) (h Host, sent int64) {
	n := &Native{DialTimeout: timeout}
	h = Host{IP: ip}
	for _, port := range ports {
		if lim.Wait(ctx) != nil {
			return h, sent
		}
		sent++
		out, conn, rtt := n.dial(ctx, ip, port)
		if out == dialSilent {
			continue
		}
		h.Up, h.Responded, h.Reason, h.RTTMs = true, true, "tcp-connect", float64(rtt.Microseconds())/1000
		if out == dialRefused {
			h.Reason = "reset"
		} else {
			sent += 2
			conn.Close()
		}
		return h, sent
	}
	return h, sent
}

type hostPort struct {
	host int
	port int
}

func (n *Native) PortScan(ctx context.Context, req PortScanRequest) (*Result, error) {
	if req.Ports == nil || req.Ports.Count() == 0 {
		return nil, errors.New("port scan: empty port set")
	}
	ports := req.Ports.List()
	lim := NewLimiter(float64(req.MaxRate), max(1, req.MaxRate/10))
	res := &Result{Hosts: make([]Host, len(req.Hosts)), Scanned: len(req.Hosts)}
	for i, ip := range req.Hosts {
		res.Hosts[i] = Host{IP: ip, Up: true}
	}
	var sent atomic.Int64
	var mu sync.Mutex
	start := time.Now()
	forEach(ctx, n.workers(req.MaxRate), func(yield func(hostPort) bool) {
		for _, port := range ports {
			for i := range req.Hosts {
				if !yield(hostPort{i, port}) {
					return
				}
			}
		}
	}, func(j hostPort) {
		if lim.Wait(ctx) != nil {
			return
		}
		sent.Add(1)
		out, conn, _ := n.dial(ctx, req.Hosts[j.host], j.port)
		if out == dialSilent {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		h := &res.Hosts[j.host]
		h.Responded = true
		if out == dialOpen {
			sent.Add(2)
			conn.Close()
			h.Ports = append(h.Ports, Port{Port: j.port, Proto: "tcp", State: "open", Reason: "tcp-connect", Name: wellKnown[j.port], Method: "table", Confidence: 0.3})
		}
	})
	for i := range res.Hosts {
		sort.Slice(res.Hosts[i].Ports, func(a, b int) bool { return res.Hosts[i].Ports[a].Port < res.Hosts[i].Ports[b].Port })
	}
	res.Packets = sent.Load()
	res.Elapsed = time.Since(start)
	if ctx.Err() != nil {
		return res, context.Cause(ctx)
	}
	return res, nil
}

func (n *Native) ServiceScan(ctx context.Context, req ServiceRequest) (*Result, error) {
	lim := NewLimiter(float64(req.MaxRate), max(1, req.MaxRate/10))
	res := &Result{Hosts: make([]Host, len(req.Hosts)), Scanned: len(req.Hosts)}
	for i, h := range req.Hosts {
		res.Hosts[i] = Host{IP: h.IP, Up: true}
	}
	var sent atomic.Int64
	var mu sync.Mutex
	start := time.Now()
	forEach(ctx, min(n.workers(req.MaxRate), 32), func(yield func(hostPort) bool) {
		for i, h := range req.Hosts {
			for _, port := range h.Ports {
				if !yield(hostPort{i, port}) {
					return
				}
			}
		}
	}, func(j hostPort) {
		if lim.Wait(ctx) != nil {
			return
		}
		sent.Add(3)
		out, conn, _ := n.dial(ctx, req.Hosts[j.host].IP, j.port)
		if out != dialOpen {
			return
		}
		// Passive read only: wait for the server to speak first, send nothing.
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(n.BannerWait))
		k, _ := conn.Read(buf)
		conn.Close()
		p := IdentifyBanner(j.port, buf[:k])
		mu.Lock()
		res.Hosts[j.host].Ports = append(res.Hosts[j.host].Ports, p)
		res.Hosts[j.host].Responded = true
		mu.Unlock()
	})
	for i := range res.Hosts {
		sort.Slice(res.Hosts[i].Ports, func(a, b int) bool { return res.Hosts[i].Ports[a].Port < res.Hosts[i].Ports[b].Port })
	}
	res.Packets = sent.Load()
	res.Elapsed = time.Since(start)
	if ctx.Err() != nil {
		return res, context.Cause(ctx)
	}
	return res, nil
}

var (
	reSSH   = regexp.MustCompile(`^SSH-([0-9.]+)-([^\s_-]+)[_-]?(\S*)\s*(.*)`)
	reMySQL = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+[-\w.]*)`)
)

// IdentifyBanner names a service from what it said first, or from the port
// number when it said nothing. The confidence tells the two cases apart.
func IdentifyBanner(port int, raw []byte) Port {
	p := Port{Port: port, Proto: "tcp", State: "open", Reason: "tcp-connect", Name: wellKnown[port], Method: "table", Confidence: 0.3}
	if p.Name == "" {
		p.Confidence = 0
	}
	if len(raw) == 0 {
		return p
	}
	text := printable(raw)
	first, _, _ := strings.Cut(text, "\n")
	first = strings.TrimSpace(first)
	p.Banner = first
	lower := strings.ToLower(first)
	probed := func(name string) {
		p.Name, p.Method, p.Confidence = name, "probed", 0.8
	}
	switch {
	case strings.HasPrefix(first, "SSH-"):
		probed("ssh")
		if m := reSSH.FindStringSubmatch(first); m != nil {
			p.Product, p.Version = m[2], m[3]
			p.ExtraInfo = strings.TrimSpace(strings.TrimSpace(m[4]) + " protocol " + m[1])
		}
	case strings.HasPrefix(first, "220") && strings.Contains(lower, "ftp"):
		probed("ftp")
	case strings.HasPrefix(first, "220") && (strings.Contains(lower, "smtp") || strings.Contains(lower, "mail")):
		probed("smtp")
	case strings.HasPrefix(first, "+OK"):
		probed("pop3")
	case strings.HasPrefix(first, "* OK"):
		probed("imap")
	case strings.HasPrefix(first, "RFB "):
		probed("vnc")
		p.Version = strings.TrimSpace(strings.TrimPrefix(first, "RFB "))
	case strings.HasPrefix(first, "HTTP/1."):
		probed("http")
	case len(raw) > 6 && raw[3] == 0 && raw[4] == 10:
		// MySQL handshake v10: 3-byte length, sequence 0, protocol 10, version string
		if m := reMySQL.FindString(string(raw[5:])); m != "" {
			probed("mysql")
			p.Product = "MySQL"
			if strings.Contains(strings.ToLower(m), "mariadb") {
				p.Product = "MariaDB"
			}
			p.Version = m
			p.Banner = p.Product + " " + m
		}
	}
	return p
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		switch {
		case r == '\n':
			sb.WriteRune(r)
		case r == '\r':
			// dropped
		case r == unicode.ReplacementChar || !unicode.IsPrint(r):
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// wellKnown maps a port to its usual service name. It is a guess with low
// confidence, like nmap's method="table".
var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 81: "http", 88: "kerberos-sec",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap",
	443: "https", 445: "microsoft-ds", 465: "smtps", 514: "shell", 515: "printer", 548: "afp", 554: "rtsp",
	587: "submission", 631: "ipp", 636: "ldapssl", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
	1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2375: "docker", 3000: "http", 3128: "http-proxy",
	3306: "mysql", 3389: "ms-wbt-server", 5000: "http", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
	5985: "wsman", 6379: "redis", 6443: "https", 8000: "http", 8008: "http", 8080: "http-proxy", 8081: "http",
	8443: "https-alt", 8888: "http", 9000: "http", 9090: "http", 9100: "jetdirect", 9200: "http", 9443: "https",
	11211: "memcache", 27017: "mongodb",
}
