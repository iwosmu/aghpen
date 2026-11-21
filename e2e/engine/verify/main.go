// Command verify reads the JSON lines that scanprobe printed, shows what
// was found and checks it against the known content of the engine test lab.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Summary mirrors the summary line of scanprobe.
type Summary struct {
	Status      string         `json:"status"`
	PauseReason string         `json:"pause_reason"`
	Error       string         `json:"error"`
	Prober      string         `json:"prober"`
	Privileged  bool           `json:"privileged"`
	Sessions    int            `json:"sessions"`
	WallMs      int64          `json:"wall_ms"`
	Stats       model.RunStats `json:"stats"`
	LimitPPS    int            `json:"limit_pps"`
	GroupSizes  []int          `json:"group_sizes"`
	Groups      []struct {
		ID         int     `json:"id"`
		FirstSeq   int     `json:"first_seq"`
		LastSeq    int     `json:"last_seq"`
		Size       int     `json:"size"`
		RatePPS    int     `json:"rate_pps"`
		Status     string  `json:"status"`
		DurationMs int64   `json:"duration_ms"`
		HostsUp    int     `json:"hosts_up"`
		Packets    int64   `json:"packets"`
		PPS        float64 `json:"pps"`
		NextSize   int     `json:"next_size"`
	} `json:"groups"`
	Chunks        map[string]int    `json:"chunks_by_status"`
	HostsReported int               `json:"hosts_reported"`
	HTTPSent      int64             `json:"http_requests_sent"`
	Iface         string            `json:"iface"`
	IfaceTxTotal  int64             `json:"iface_tx_packets"`
	IfaceTxPeak   int64             `json:"iface_tx_peak_pps"`
	IfaceTxPerSec []int64           `json:"iface_tx_per_second"`
	Extrapolation map[string]string `json:"extrapolation"`
}

// Output is everything one scanprobe run printed on stdout.
type Output struct {
	Hosts   []model.HostResult
	Summary *Summary
}

// Parse reads scanprobe stdout.
func Parse(r io.Reader) (Output, error) {
	var out Output
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, `{"summary"`) {
			var w struct {
				Summary Summary `json:"summary"`
			}
			if err := json.Unmarshal([]byte(line), &w); err != nil {
				return out, fmt.Errorf("summary line: %w", err)
			}
			out.Summary = &w.Summary
			continue
		}
		var h model.HostResult
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			return out, fmt.Errorf("host line: %w", err)
		}
		out.Hosts = append(out.Hosts, h)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return ipKey(out.Hosts[i].IP) < ipKey(out.Hosts[j].IP) })
	return out, sc.Err()
}

func ipKey(ip string) string {
	var a, b, c, d int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return fmt.Sprintf("%03d.%03d.%03d.%03d", a, b, c, d)
}

// Want is one expected lab service.
type Want struct {
	IP      string
	Port    int
	Name    string // nmap service name
	Product string // substring of the product
	Tunnel  string
}

// Lab is the ground truth of e2e/engine/lab.sh.
var Lab = []Want{
	{"10.77.0.10", 80, "http", "nginx", ""},
	{"10.77.0.20", 22, "ssh", "OpenSSH", ""},
	{"10.77.1.30", 6379, "redis", "Redis", ""},
	{"10.77.2.40", 8765, "http", "SimpleHTTPServer", ""},
	{"10.77.2.41", 8081, "http", "SimpleHTTPServer", ""},
	{"10.77.3.50", 9443, "http", "SimpleHTTPServer", "ssl"},
	{"10.77.3.60", 80, "http", "SimpleHTTPServer", ""}, // this host drops ICMP
}

// CheckLab compares the hosts with the ground truth. With names=false only
// hosts and ports are compared (native prober, or service detection off).
func CheckLab(out Output, names bool) (fails []string) {
	byIP := map[string]model.HostResult{}
	for _, h := range out.Hosts {
		if _, dup := byIP[h.IP]; dup {
			fails = append(fails, fmt.Sprintf("%s is reported more than once", h.IP))
		}
		byIP[h.IP] = h
	}
	wantIP := map[string]bool{}
	for _, w := range Lab {
		wantIP[w.IP] = true
		h, ok := byIP[w.IP]
		if !ok || !h.Up {
			fails = append(fails, fmt.Sprintf("host %s was not found", w.IP))
			continue
		}
		if len(h.Services) != 1 || h.Services[0].Port != w.Port {
			fails = append(fails, fmt.Sprintf("%s: open ports %v, want only %d", w.IP, ports(h), w.Port))
			continue
		}
		s := h.Services[0]
		if !names {
			continue
		}
		if s.Name != w.Name || !strings.Contains(s.Product, w.Product) || s.Tunnel != w.Tunnel {
			fails = append(fails, fmt.Sprintf("%s:%d identified as %q %q tunnel=%q, want %q %q tunnel=%q", w.IP, w.Port, s.Name, s.Product, s.Tunnel, w.Name, w.Product, w.Tunnel))
		}
	}
	for ip, h := range byIP {
		if !wantIP[ip] && h.Up {
			fails = append(fails, fmt.Sprintf("unexpected live host %s (false positive or exclusion not applied)", ip))
		}
	}
	return fails
}

// WantApp is one expected application of the fingerprint lab (lab.sh apps).
type WantApp struct {
	IP      string
	Port    int
	Tech    string // technology name the signature engine must report
	Version string // prefix of its version; empty: any
	Class   string // service class that must be present; empty: any
	TLSSelf bool   // the certificate must be reported as self-signed
}

// Apps is the ground truth of the application lab.
var Apps = []WantApp{
	{"10.76.0.10", 3306, "MariaDB", "11.", "database", false},
	{"10.76.0.11", 80, "WordPress", "6.", "login", false},
	{"10.76.0.11", 80, "PHP", "8.", "", false},
	{"10.76.0.20", 3000, "Grafana", "11.3.0", "login", false},
	{"10.76.0.21", 3000, "Gitea", "1.22", "dev-tool", false},
	{"10.76.0.21", 22, "OpenSSH", "", "remote-access", false},
	{"10.76.0.30", 80, "phpMyAdmin", "5.", "admin-panel", false},
	{"10.76.0.40", 8080, "Apache Tomcat", "10.1", "", false},
	{"10.76.0.50", 8443, "Python", "", "", true},
	{"10.76.0.60", 8181, "nginx", "1.", "default-page", false},
}

// CheckApps compares technologies, versions and classes with the ground truth.
func CheckApps(out Output) (fails []string) {
	type key struct {
		ip   string
		port int
	}
	svc := map[key]model.ServiceResult{}
	seen := map[string]bool{}
	for _, h := range out.Hosts {
		if seen[h.IP] {
			fails = append(fails, fmt.Sprintf("%s is reported more than once", h.IP))
		}
		seen[h.IP] = true
		for _, s := range h.Services {
			svc[key{h.IP, s.Port}] = s
		}
	}
	for _, w := range Apps {
		s, ok := svc[key{w.IP, w.Port}]
		if !ok {
			fails = append(fails, fmt.Sprintf("%s:%d was not found", w.IP, w.Port))
			continue
		}
		found := false
		for _, t := range s.Technologies {
			if t.Name == w.Tech && strings.HasPrefix(t.Version, w.Version) {
				found = true
			}
		}
		if !found {
			fails = append(fails, fmt.Sprintf("%s:%d: technology %s %s* not reported, got %v", w.IP, w.Port, w.Tech, w.Version, techs(s)))
		}
		if w.Class != "" && !contains(s.Classes, w.Class) {
			fails = append(fails, fmt.Sprintf("%s:%d: class %s not reported, got %v", w.IP, w.Port, w.Class, s.Classes))
		}
		if w.TLSSelf && (s.TLS == nil || !s.TLS.SelfSigned || s.Tunnel != "ssl") {
			fails = append(fails, fmt.Sprintf("%s:%d: self-signed TLS not reported", w.IP, w.Port))
		}
	}
	if s := out.Summary; s != nil && s.HTTPSent != s.Stats.HTTPRequests {
		fails = append(fails, fmt.Sprintf("the run counted %d HTTP requests, the collector sent %d", s.Stats.HTTPRequests, s.HTTPSent))
	}
	return fails
}

func techs(s model.ServiceResult) []string {
	var out []string
	for _, t := range s.Technologies {
		out = append(out, strings.TrimSpace(t.Name+" "+t.Version))
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func printApps(w io.Writer, out Output) {
	fmt.Fprintf(w, "%-11s %-5s %-34s %-52s %s\n", "IP", "PORT", "HTTP / TLS", "TECHNOLOGIES (signature engine)", "CLASSES")
	for _, h := range out.Hosts {
		for _, s := range h.Services {
			web := "-"
			if s.HTTP != nil {
				title := s.HTTP.Title
				if len(title) > 22 {
					title = title[:22]
				}
				web = fmt.Sprintf("%d %q", s.HTTP.Status, title)
			}
			if s.TLS != nil {
				web += fmt.Sprintf(" tls self-signed=%v", s.TLS.SelfSigned)
			}
			fmt.Fprintf(w, "%-11s %-5d %-34s %-52s %s\n", h.IP, s.Port, web, strings.Join(techs(s), ", "), strings.Join(s.Classes, ", "))
		}
	}
	if s := out.Summary; s != nil {
		fmt.Fprintf(w, "http requests: %d counted by the run, %d sent by the collector, %d HTTP services\n", s.Stats.HTTPRequests, s.HTTPSent, s.Stats.HTTPServices)
	}
}

// CheckRate checks the intensity limit: no nmap group ran above its
// --max-rate share and the run average stays under the limit.
func CheckRate(s *Summary) (fails []string) {
	if s == nil {
		return []string{"no summary line"}
	}
	if s.Stats.AvgPPS > float64(s.LimitPPS) {
		fails = append(fails, fmt.Sprintf("average %.1f pps is over the limit %d", s.Stats.AvgPPS, s.LimitPPS))
	}
	sum := 0
	for _, g := range s.Groups {
		if g.RatePPS > 0 && g.PPS > float64(g.RatePPS) {
			fails = append(fails, fmt.Sprintf("group %d sent %.1f pps, its share was %d", g.ID, g.PPS, g.RatePPS))
		}
		sum = max(sum, g.RatePPS)
	}
	if sum > s.LimitPPS {
		fails = append(fails, fmt.Sprintf("a group got a share of %d pps, over the limit %d", sum, s.LimitPPS))
	}
	// Independent measurement: packets that left the interface in each
	// second. 3% tolerance: the counter is read by a one-second ticker, and
	// a read that comes 20 ms late adds 2% to that sample.
	if s.Iface != "" && float64(s.IfaceTxPeak) > float64(s.LimitPPS)*1.03 {
		fails = append(fails, fmt.Sprintf("interface %s sent %d packets in one second, limit %d", s.Iface, s.IfaceTxPeak, s.LimitPPS))
	}
	return fails
}

func ports(h model.HostResult) []int {
	var out []int
	for _, s := range h.Services {
		out = append(out, s.Port)
	}
	return out
}

func printTable(w io.Writer, out Output) {
	fmt.Fprintf(w, "%-12s %-5s %-14s %-4s %-9s %s\n", "IP", "UP", "REASON", "TRY", "RTT ms", "SERVICES")
	for _, h := range out.Hosts {
		var svc []string
		for _, s := range h.Services {
			t := fmt.Sprintf("%d/%s", s.Port, s.Name)
			if s.Tunnel != "" {
				t += "+" + s.Tunnel
			}
			if p := strings.TrimSpace(s.Product + " " + s.Version); p != "" {
				t += " (" + p + ")"
			}
			if s.Banner != "" && s.Product == "" {
				t += " [" + s.Banner + "]"
			}
			t += fmt.Sprintf(" conf=%.1f", s.Confidence)
			svc = append(svc, t)
		}
		fmt.Fprintf(w, "%-12s %-5v %-14s %-4d %-9.3f %s\n", h.IP, h.Up, h.Reason, h.Attempts, h.RTTMs, strings.Join(svc, ", "))
	}
	s := out.Summary
	if s == nil {
		return
	}
	fmt.Fprintf(w, "status=%s", s.Status)
	if s.PauseReason != "" {
		fmt.Fprintf(w, " pause_reason=%s", s.PauseReason)
	}
	if s.Error != "" {
		fmt.Fprintf(w, " error=%q", s.Error)
	}
	fmt.Fprintf(w, " prober=%s privileged=%v sessions=%d wall=%.1fs\n", s.Prober, s.Privileged, s.Sessions, float64(s.WallMs)/1000)
	fmt.Fprintf(w, "addresses %d/%d, chunks %d/%d %v, hosts up %d, open services %d, retried %d, errors %d\n",
		s.Stats.AddressesDone, s.Stats.AddressesTotal, s.Stats.ChunksDone, s.Stats.ChunksTotal, s.Chunks, s.Stats.HostsUp, s.Stats.ServicesOpen, s.Stats.Retried, s.Stats.Errors)
	fmt.Fprintf(w, "packets %d, average %.1f pps, limit %d pps\n", s.Stats.PacketsSent, s.Stats.AvgPPS, s.LimitPPS)
	if s.Iface != "" {
		fmt.Fprintf(w, "measured on %s: %d packets sent, peak %d pps in one second (limit %d); per second: %v\n", s.Iface, s.IfaceTxTotal, s.IfaceTxPeak, s.LimitPPS, s.IfaceTxPerSec)
	}
	fmt.Fprintf(w, "adaptive group sizes (addresses): %v\n", s.GroupSizes)
	for _, g := range s.Groups {
		fmt.Fprintf(w, "  group %d: chunks %d-%d, %4d addresses, %-8s %6.1fs, %d hosts up, %5d packets, %6.1f pps (share %d), next size %d\n",
			g.ID, g.FirstSeq, g.LastSeq, g.Size, g.Status, float64(g.DurationMs)/1000, g.HostsUp, g.Packets, g.PPS, g.RatePPS, g.NextSize)
	}
	if len(s.Extrapolation) > 0 {
		fmt.Fprintf(w, "timing: %s\n  extrapolated: 10 000 addresses %s, 65 536 addresses %s\n", s.Extrapolation["basis"], s.Extrapolation["10000"], s.Extrapolation["65536"])
	}
}

func main() {
	in := flag.String("in", "", "file with scanprobe stdout")
	expect := flag.String("expect", "lab", "lab | lab-ports | apps | none")
	status := flag.String("status", "completed", "expected final status")
	sessions := flag.Int("sessions", 0, "expected number of sessions (2 = paused and resumed); 0 = any")
	flag.Parse()
	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()
	out, err := Parse(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	printTable(os.Stdout, out)
	var fails []string
	switch *expect {
	case "lab":
		fails = append(fails, CheckLab(out, true)...)
	case "lab-ports":
		fails = append(fails, CheckLab(out, false)...)
	case "apps":
		printApps(os.Stdout, out)
		fails = append(fails, CheckApps(out)...)
	}
	fails = append(fails, CheckRate(out.Summary)...)
	if s := out.Summary; s != nil {
		if s.Status != *status {
			fails = append(fails, fmt.Sprintf("status %q, want %q", s.Status, *status))
		}
		if *sessions > 0 && s.Sessions != *sessions {
			fails = append(fails, fmt.Sprintf("sessions %d, want %d", s.Sessions, *sessions))
		}
		if *status == "completed" && (s.Chunks["done"] != s.Stats.ChunksTotal || s.Stats.AddressesDone != s.Stats.AddressesTotal) {
			fails = append(fails, fmt.Sprintf("not everything was scanned: chunks %v, addresses %d/%d", s.Chunks, s.Stats.AddressesDone, s.Stats.AddressesTotal))
		}
	}
	if len(fails) > 0 {
		for _, f := range fails {
			fmt.Println("FAIL:", f)
		}
		os.Exit(1)
	}
	fmt.Println("PASS")
}
