package probe

import (
	"context"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestParsePorts(t *testing.T) {
	p, err := ParsePorts("top-100")
	if err != nil || p.Count() != 100 {
		t.Fatalf("top-100: %v, %d ports", err, p.Count())
	}
	if !p.Has(22) || !p.Has(443) || !p.Has(8080) || p.Has(6379) {
		t.Error("top-100 content is wrong")
	}
	p, err = ParsePorts("top-1000")
	if err != nil || p.Count() != 1000 {
		t.Fatalf("top-1000: %v, %d ports", err, p.Count())
	}
	p, err = ParsePorts("22, 80,443 8000-8003;T:9000")
	if err != nil || !reflect.DeepEqual(p.List(), []int{22, 80, 443, 8000, 8001, 8002, 8003, 9000}) {
		t.Fatalf("list: %v %v", err, p.List())
	}
	if got := p.String(); got != "22,80,443,8000-8003,9000" {
		t.Errorf("String = %q", got)
	}
	p, _ = ParsePorts("top-100,6379,8765")
	if p.Count() != 102 {
		t.Errorf("mix count = %d", p.Count())
	}
	if p, _ := ParsePorts("all"); p.Count() != 65535 || p.String() != "1-65535" {
		t.Errorf("all = %d %s", p.Count(), p.String())
	}
	for _, bad := range []string{"", "0", "65536", "80-70", "abc", "top-50", "U:53", "22,,x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestEffectivePorts(t *testing.T) {
	p, err := EffectivePorts("22,80,443,3306,8000-8010", "1-1024,8000-8005", "23,443,8003")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "22,80,8000-8002,8004-8005" {
		t.Fatalf("effective = %s", got)
	}
	p, _ = EffectivePorts("", "", "")
	if p.Count() != 100 {
		t.Errorf("default should be top-100, got %d", p.Count())
	}
	p, _ = EffectivePorts("top-100", "", "22,3389")
	if p.Count() != 98 || p.Has(22) {
		t.Errorf("deny: %d", p.Count())
	}
	if _, err := EffectivePorts("80", "bogus", ""); err == nil {
		t.Error("a bad policy spec must be an error")
	}
	got, _ := FilterPorts([]int{443, 22, 80, 3389}, "1-1024", "22")
	if !reflect.DeepEqual(got, []int{443, 80}) {
		t.Errorf("FilterPorts = %v", got)
	}
}

func parseFixture(t *testing.T, name string) *Result {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := ParseXML(f)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func hostByIP(res *Result, ip string) *Host {
	for i := range res.Hosts {
		if res.Hosts[i].IP == ip {
			return &res.Hosts[i]
		}
	}
	return nil
}

func TestParseXMLDiscovery(t *testing.T) {
	res := parseFixture(t, "discover_arp.xml") // 10.77.0.0/27, privileged, ARP on the local net
	if res.Scanned != 32 {
		t.Errorf("scanned = %d, want 32", res.Scanned)
	}
	var ips []string
	for _, h := range res.Hosts {
		ips = append(ips, h.IP)
	}
	// nmap lists the scanner's own address (10.77.0.2) last
	if !reflect.DeepEqual(ips, []string{"10.77.0.1", "10.77.0.10", "10.77.0.20", "10.77.0.2"}) {
		t.Fatalf("up hosts = %v", ips)
	}
	h := hostByIP(res, "10.77.0.10")
	if h.Reason != "arp-response" || h.MAC == "" || h.RTTMs <= 0 || !h.Up {
		t.Errorf("nginx host = %+v", *h)
	}
	if self := hostByIP(res, "10.77.0.2"); self.Reason != "localhost-response" {
		t.Errorf("scanner itself: reason %q", self.Reason)
	}

	res = parseFixture(t, "discover_noarp.xml") // 10.77.3.48/28 with --disable-arp-ping
	if len(res.Hosts) != 2 {
		t.Fatalf("hosts = %+v", res.Hosts)
	}
	if h := hostByIP(res, "10.77.3.50"); h == nil || h.Reason != "echo-reply" {
		t.Errorf("https host: %+v", h)
	}
	// 10.77.3.60 drops ICMP: found by the TCP probe
	if h := hostByIP(res, "10.77.3.60"); h == nil || h.Reason != "reset" {
		t.Errorf("no-icmp host: %+v", h)
	}
}

func TestParseXMLPortScan(t *testing.T) {
	res := parseFixture(t, "portscan.xml")
	want := map[string][]int{
		"10.77.0.10": {80}, "10.77.0.20": {22}, "10.77.1.30": {6379}, "10.77.2.40": {8765},
		"10.77.2.41": {8081}, "10.77.3.50": {9443}, "10.77.3.60": {80},
	}
	if len(res.Hosts) != len(want) {
		t.Fatalf("hosts = %d", len(res.Hosts))
	}
	for ip, ports := range want {
		h := hostByIP(res, ip)
		if h == nil {
			t.Fatalf("%s missing", ip)
		}
		var got []int
		for _, p := range h.Ports {
			got = append(got, p.Port)
			if p.State != "open" || p.Proto != "tcp" || p.Reason != "syn-ack" {
				t.Errorf("%s:%d = %+v", ip, p.Port, p)
			}
		}
		if !reflect.DeepEqual(got, ports) {
			t.Errorf("%s open ports = %v, want %v", ip, got, ports)
		}
		if !h.Responded {
			t.Errorf("%s: Responded should be true", ip)
		}
	}
}

func TestParseXMLService(t *testing.T) {
	res := parseFixture(t, "service.xml")
	nginx := hostByIP(res, "10.77.0.10").Ports
	if len(nginx) != 1 || nginx[0].Name != "http" || nginx[0].Product != "nginx" || nginx[0].Version == "" || nginx[0].Confidence != 1 || nginx[0].Method != "probed" {
		t.Errorf("nginx = %+v", nginx)
	}
	if len(nginx[0].CPE) != 1 || !strings.HasPrefix(nginx[0].CPE[0], "cpe:/a:igor_sysoev:nginx") {
		t.Errorf("nginx cpe = %v", nginx[0].CPE)
	}
	ssh := hostByIP(res, "10.77.0.20").Ports[0]
	if ssh.Name != "ssh" || ssh.Product != "OpenSSH" || ssh.ExtraInfo != "protocol 2.0" || !strings.Contains(ssh.Banner, "OpenSSH") || !strings.Contains(ssh.Banner, "(protocol 2.0)") {
		t.Errorf("ssh = %+v", ssh)
	}
	redis := hostByIP(res, "10.77.1.30").Ports[0]
	if redis.Port != 6379 || redis.Name != "redis" || !strings.Contains(redis.Product, "Redis") {
		t.Errorf("redis = %+v", redis)
	}
	https := hostByIP(res, "10.77.3.50").Ports[0]
	if https.Port != 9443 || https.Tunnel != "ssl" || https.Name != "http" {
		t.Errorf("https = %+v", https)
	}
}

func TestParseXMLErrors(t *testing.T) {
	if _, err := ParseXML(strings.NewReader("not xml at all")); err == nil {
		t.Error("garbage must fail")
	}
	trunc := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="echo-reply"/><address addr="10.0.0.1" addrtype="ipv4"/></host>`
	res, err := ParseXML(strings.NewReader(trunc))
	if err == nil {
		t.Error("truncated output must be reported")
	}
	if res == nil || len(res.Hosts) != 1 {
		t.Errorf("complete hosts of truncated output should be kept: %+v", res)
	}
}

func TestNmapArgs(t *testing.T) {
	priv := &Nmap{privileged: true, euid: 0}
	args := strings.Join(priv.DiscoverArgs(DiscoverRequest{MaxRate: 250, MaxRetries: 1, HostTimeout: 30 * time.Second}), " ")
	for _, want := range []string{"-sn", "-PE", "-PP", "-PS22,80,443,3389,8080", "-PA80,443", "-n", "--max-rate 250", "--max-retries 1", "--host-timeout 30s"} {
		if !strings.Contains(args, want) {
			t.Errorf("privileged discovery args lack %q: %s", want, args)
		}
	}
	if strings.Contains(args, "--disable-arp-ping") || strings.Contains(args, "privileged") {
		t.Errorf("unexpected flag: %s", args)
	}
	args = strings.Join(priv.DiscoverArgs(DiscoverRequest{MaxRate: 100, Opts: model.DiscoveryOpts{ICMPEcho: true, TCPSynPorts: []int{443}}}), " ")
	if !strings.Contains(args, "-PE") || strings.Contains(args, "-PP") || !strings.Contains(args, "-PS443") || strings.Contains(args, "-PA") || !strings.Contains(args, "--disable-arp-ping") {
		t.Errorf("custom discovery args: %s", args)
	}

	unpriv := &Nmap{privileged: false, euid: 501}
	args = strings.Join(unpriv.DiscoverArgs(DiscoverRequest{MaxRate: 100}), " ")
	if strings.Contains(args, "-PE") || strings.Contains(args, "-PA") || !strings.Contains(args, "-PS22,80,443,3389,8080") || !strings.Contains(args, "--unprivileged") {
		t.Errorf("unprivileged discovery args: %s", args)
	}
	args = strings.Join(unpriv.PortScanArgs(PortScanRequest{Ports: PortsOf(22, 80, 81, 82), MaxRate: 0, MaxRetries: 2}), " ")
	if !strings.HasPrefix(args, "-sT -Pn -p 22,80-82") || !strings.Contains(args, "--max-rate 1 ") {
		t.Errorf("unprivileged port scan args: %s", args)
	}
	args = strings.Join(priv.PortScanArgs(PortScanRequest{Ports: PortsOf(443), MaxRate: 300, MaxRetries: 2, HostTimeout: 5 * time.Minute}), " ")
	if !strings.HasPrefix(args, "-sS -Pn -p 443") || !strings.Contains(args, "--host-timeout 300s") {
		t.Errorf("privileged port scan args: %s", args)
	}
	caps := &Nmap{privileged: true, euid: 1000}
	args = strings.Join(caps.ServiceArgs([]int{22, 80}, 12, 300, time.Minute, false), " ")
	if !strings.HasPrefix(args, "-sS -sV --version-intensity 9 -Pn -p 22,80") || !strings.Contains(args, "--privileged") {
		t.Errorf("service args: %s", args)
	}
	for _, a := range [][]string{priv.DiscoverArgs(DiscoverRequest{}), priv.PortScanArgs(PortScanRequest{Ports: PortsOf(1)}), priv.ServiceArgs([]int{1}, 5, 1, 0, false)} {
		for _, x := range a {
			if strings.Contains(x, "script") || x == "-sC" || x == "-A" || x == "-O" {
				t.Errorf("forbidden nmap option %q", x)
			}
		}
	}
}

func TestValidateTargets(t *testing.T) {
	ok := []string{"10.0.0.1", "10.0.0.0/24", "10.0.0.5-90", "2001:db8::1", "::ffff:10.0.0.1"}
	if err := validateTargets(ok); err != nil {
		t.Errorf("valid targets rejected: %v", err)
	}
	for _, bad := range []string{"example.com", "10.0.0.1; rm -rf /", "-iL /etc/passwd", "--script=vuln", "10.0.0.1 10.0.0.2", "$(id)", ""} {
		if err := validateTargets([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if err := validateTargets(nil); err == nil {
		t.Error("an empty list must be rejected")
	}
}

func TestGroupByPorts(t *testing.T) {
	hosts := []HostPorts{
		{"10.0.0.1", []int{80, 22}}, {"10.0.0.2", []int{22, 80}}, {"10.0.0.3", []int{443}},
		{"10.0.0.4", nil}, {"10.0.0.5", []int{8080}}, {"10.0.0.6", []int{3306}},
	}
	g := groupByPorts(hosts, 6)
	if len(g) != 4 || len(g[0].IPs) != 2 || !reflect.DeepEqual(g[0].Ports, []int{22, 80}) {
		t.Fatalf("groups = %+v", g)
	}
	g = groupByPorts(hosts, 2)
	if len(g) != 2 || len(g[1].IPs) != 3 || !reflect.DeepEqual(g[1].Ports, []int{443, 3306, 8080}) {
		t.Fatalf("merged groups = %+v", g)
	}
}

func TestLimiterRate(t *testing.T) {
	l := NewLimiter(200, 1)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 41; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// 41 tokens at 200/s with a burst of 1: about 200 ms
	if d := time.Since(start); d < 180*time.Millisecond || d > 600*time.Millisecond {
		t.Errorf("41 tokens took %v, want about 200ms", d)
	}
	c, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	slow := NewLimiter(1, 1)
	_ = slow.Wait(c)
	if err := slow.Wait(c); err == nil {
		t.Error("Wait must return when the context ends")
	}
	var unlimited *Limiter
	if err := unlimited.Wait(ctx); err != nil {
		t.Error("a nil limiter must not block")
	}
}

func TestIdentifyBanner(t *testing.T) {
	p := IdentifyBanner(2222, []byte("SSH-2.0-OpenSSH_9.7\r\n"))
	if p.Name != "ssh" || p.Product != "OpenSSH" || p.Version != "9.7" || p.Confidence != 0.8 || p.Banner != "SSH-2.0-OpenSSH_9.7" {
		t.Errorf("ssh = %+v", p)
	}
	p = IdentifyBanner(21, []byte("220 ProFTPD Server (FTP) ready\r\n"))
	if p.Name != "ftp" || p.Method != "probed" {
		t.Errorf("ftp = %+v", p)
	}
	p = IdentifyBanner(3306, append([]byte{0x4a, 0, 0, 0, 10}, []byte("8.0.36-0ubuntu0\x00rest")...))
	if p.Name != "mysql" || p.Version != "8.0.36-0ubuntu0" {
		t.Errorf("mysql = %+v", p)
	}
	p = IdentifyBanner(6379, nil)
	if p.Name != "redis" || p.Confidence != 0.3 || p.Method != "table" {
		t.Errorf("silent redis = %+v", p)
	}
	p = IdentifyBanner(31337, nil)
	if p.Name != "" || p.Confidence != 0 {
		t.Errorf("unknown port = %+v", p)
	}
}

// The native prober is tested against listeners on 127.0.0.1.
func TestNativeProber(t *testing.T) {
	banner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback:", err)
	}
	defer banner.Close()
	go func() {
		for {
			c, err := banner.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9 test\r\n"))
			c.Close()
		}
	}()
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(300 * time.Millisecond); c.Close() }()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	bp := banner.Addr().(*net.TCPAddr).Port
	sp := silent.Addr().(*net.TCPAddr).Port

	n := NewNative(nil)
	n.DialTimeout = 300 * time.Millisecond
	n.BannerWait = 200 * time.Millisecond
	ctx := context.Background()

	// discovery: a refused connection also proves that the host is up
	res, err := n.Discover(ctx, DiscoverRequest{Targets: []string{"127.0.0.1"}, Opts: model.DiscoveryOpts{TCPSynPorts: []int{closedPort}}, MaxRate: 100})
	if err != nil || len(res.Hosts) != 1 || res.Hosts[0].Reason != "reset" || res.Packets < 1 {
		t.Fatalf("discover refused: %v %+v", err, res)
	}
	res, err = n.Discover(ctx, DiscoverRequest{Targets: []string{"127.0.0.1"}, Opts: model.DiscoveryOpts{TCPSynPorts: []int{bp}}, MaxRate: 100})
	if err != nil || len(res.Hosts) != 1 || res.Hosts[0].Reason != "tcp-connect" {
		t.Fatalf("discover open: %v %+v", err, res)
	}

	ps, err := n.PortScan(ctx, PortScanRequest{Hosts: []string{"127.0.0.1"}, Ports: PortsOf(bp, sp, closedPort), MaxRate: 100})
	if err != nil || len(ps.Hosts) != 1 || len(ps.Hosts[0].Ports) != 2 || !ps.Hosts[0].Responded {
		t.Fatalf("port scan: %v %+v", err, ps)
	}

	sv, err := n.ServiceScan(ctx, ServiceRequest{Hosts: []HostPorts{{IP: "127.0.0.1", Ports: []int{bp, sp}}}, MaxRate: 100})
	if err != nil || len(sv.Hosts[0].Ports) != 2 {
		t.Fatalf("service scan: %v %+v", err, sv)
	}
	for _, p := range sv.Hosts[0].Ports {
		switch p.Port {
		case bp:
			if p.Name != "ssh" || p.Product != "OpenSSH" || p.Version != "9.9" {
				t.Errorf("banner port = %+v", p)
			}
		case sp:
			if p.Banner != "" {
				t.Errorf("silent port = %+v", p)
			}
		}
	}

	// cancel stops the pool
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := n.PortScan(c, PortScanRequest{Hosts: []string{"127.0.0.1"}, Ports: PortsOf(bp), MaxRate: 100}); err == nil {
		t.Error("a cancelled scan must return an error")
	}
}

func TestNormalizeDiscovery(t *testing.T) {
	o := NormalizeDiscovery(model.DiscoveryOpts{})
	if !o.ICMPEcho || !o.ICMPTimestamp || !o.ARP || len(o.TCPSynPorts) == 0 || len(o.TCPAckPorts) == 0 {
		t.Errorf("defaults = %+v", o)
	}
	o = NormalizeDiscovery(model.DiscoveryOpts{ICMPEcho: true})
	if o.ARP || len(o.TCPSynPorts) != 0 {
		t.Errorf("explicit options must stay: %+v", o)
	}
}

func TestDiscoverArgsARPOnly(t *testing.T) {
	priv := &Nmap{privileged: true, euid: 10001}
	args := strings.Join(priv.DiscoverArgs(DiscoverRequest{MaxRate: 250, MaxRetries: 2, ARPOnly: true,
		Opts: model.DiscoveryOpts{ICMPEcho: true, TCPSynPorts: []int{80}, ARP: true}}), " ")
	if !strings.Contains(args, "-PR") || strings.Contains(args, "-PE") || strings.Contains(args, "-PS") || strings.Contains(args, "--disable-arp-ping") {
		t.Errorf("ARP-only args = %q", args)
	}
	// without raw sockets ARP is impossible: the TCP-connect ping stays
	unpriv := &Nmap{}
	if args := strings.Join(unpriv.DiscoverArgs(DiscoverRequest{ARPOnly: true}), " "); strings.Contains(args, "-PR") {
		t.Errorf("unprivileged ARP-only args = %q", args)
	}
}
