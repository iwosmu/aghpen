// Command ppsbins reads "tcpdump -n -tt" text from the scanner's lab
// interface and counts the sent packets in one-second bins. It separates the
// packets that nmap sends itself (raw ARP, raw TCP SYN, ICMP, UDP probes),
// which the rate cap governs, from the kernel's TCP traffic (HTTP, version
// detection connects, RST answers to SYN-ACKs) and from DNS lookups.
//
// Capture without "-Q out": tcpdump then misses the IP packets that nmap
// sends through its raw socket (measured: the SYN probes were not in the
// capture, only the ARP frames). Filter on the source instead; -src keeps
// only the lines the scanner sent.
//
//	tcpdump -i eth2 -n -tt -l 'src host 10.66.0.30 or arp'
//	go run ./e2e/ppsbins -cap 1000 -src 10.66.0.30 tcpdump.txt
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Class names, in report order.
const (
	ClassARP    = "arp"
	ClassSYN    = "raw_syn"
	ClassICMP   = "icmp"
	ClassUDP    = "udp_probe"
	ClassDNS    = "dns"
	ClassRST    = "kernel_rst"
	ClassKernel = "kernel_tcp"
	ClassOther  = "other"
)

var classes = []string{ClassARP, ClassSYN, ClassICMP, ClassUDP, ClassDNS, ClassRST, ClassKernel, ClassOther}

// Raw reports whether nmap sends packets of the class itself (under its rate pacing).
func Raw(c string) bool {
	return c == ClassARP || c == ClassSYN || c == ClassICMP || c == ClassUDP
}

// Classify returns the class of one tcpdump line (without the timestamp).
func Classify(line string) string {
	switch {
	case strings.HasPrefix(line, "ARP"):
		return ClassARP
	case strings.Contains(line, ": ICMP"):
		return ClassICMP
	case strings.Contains(line, "Flags [S],"):
		// nmap's raw SYN carries only an MSS option; a kernel connect() also
		// sends SACK, timestamps and window scaling.
		if strings.Contains(line, "options [mss 1460], length 0") || strings.Contains(line, "options [mss 1460],length 0") {
			return ClassSYN
		}
		return ClassKernel
	case strings.Contains(line, "Flags [R]"):
		return ClassRST
	case strings.Contains(line, "Flags ["):
		return ClassKernel
	case strings.Contains(line, ".53: "):
		return ClassDNS
	case strings.HasPrefix(line, "IP ") || strings.HasPrefix(line, "IP6 "):
		return ClassUDP
	}
	return ClassOther
}

// Summary is the result for one capture.
type Summary struct {
	Seconds int            `json:"seconds"`
	Cap     int            `json:"cap"`
	Total   map[string]int `json:"total"`
	RawMax  int            `json:"raw_max_per_s"`
	RawP99  int            `json:"raw_p99_per_s"`
	RawAvg  float64        `json:"raw_avg_per_s"`
	AllMax  int            `json:"all_max_per_s"`
	AllP99  int            `json:"all_p99_per_s"`
	Over    int            `json:"raw_seconds_over_cap"`
	OverTol int            `json:"raw_seconds_over_cap_plus_5pct"`
	Busiest []int          `json:"raw_top5"`
}

// Sent reports whether a tcpdump line (without the timestamp) is a packet
// that src sent. An empty src keeps every line.
func Sent(line, src string) bool {
	if src == "" {
		return true
	}
	if strings.HasPrefix(line, "ARP") {
		return strings.Contains(line, "Request") && strings.Contains(line, " tell "+src+",")
	}
	return strings.HasPrefix(line, "IP "+src+".") || strings.HasPrefix(line, "IP "+src+" >")
}

// Bin counts the lines of r that src sent, per second and class.
func Bin(r io.Reader, src string) (map[int64]map[string]int, error) {
	bins := map[int64]map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		ts, err := strconv.ParseFloat(line[:sp], 64)
		if err != nil {
			continue
		}
		if !Sent(line[sp+1:], src) {
			continue
		}
		sec := int64(ts)
		if bins[sec] == nil {
			bins[sec] = map[string]int{}
		}
		bins[sec][Classify(line[sp+1:])]++
	}
	return bins, sc.Err()
}

// Summarize computes the per-second figures. Seconds with no packet inside
// the capture count as zero.
func Summarize(bins map[int64]map[string]int, cap int) Summary {
	s := Summary{Cap: cap, Total: map[string]int{}}
	if len(bins) == 0 {
		return s
	}
	var lo, hi int64 = 1 << 62, 0
	for sec := range bins {
		lo, hi = min(lo, sec), max(hi, sec)
	}
	var raw, all []int
	for sec := lo; sec <= hi; sec++ {
		r, a := 0, 0
		for c, n := range bins[sec] {
			s.Total[c] += n
			a += n
			if Raw(c) {
				r += n
			}
		}
		raw, all = append(raw, r), append(all, a)
		if cap > 0 && r > cap {
			s.Over++
		}
		if cap > 0 && float64(r) > float64(cap)*1.05 {
			s.OverTol++
		}
	}
	s.Seconds = len(raw)
	sum := 0
	for _, v := range raw {
		sum += v
	}
	s.RawAvg = float64(int(float64(sum)/float64(len(raw))*10)) / 10
	s.RawMax, s.RawP99 = pct(raw, 1), pct(raw, 0.99)
	s.AllMax, s.AllP99 = pct(all, 1), pct(all, 0.99)
	top := append([]int{}, raw...)
	sort.Sort(sort.Reverse(sort.IntSlice(top)))
	s.Busiest = top[:min(5, len(top))]
	return s
}

func pct(v []int, p float64) int {
	s := append([]int{}, v...)
	sort.Ints(s)
	i := int(float64(len(s)-1) * p)
	return s[i]
}

func main() {
	capPPS := flag.Int("cap", 0, "the profile's packet cap (packets per second)")
	asJSON := flag.Bool("json", false, "print JSON")
	src := flag.String("src", "", "count only packets this address sent")
	flag.Parse()
	in := io.Reader(os.Stdin)
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}
	bins, err := Bin(in, *src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := Summarize(bins, *capPPS)
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(s)
		return
	}
	fmt.Printf("seconds %d, cap %d pps\n", s.Seconds, s.Cap)
	fmt.Printf("nmap raw packets per second: max %d, p99 %d, avg %.1f, top5 %v; seconds over cap %d (over cap+5%%: %d)\n", s.RawMax, s.RawP99, s.RawAvg, s.Busiest, s.Over, s.OverTol)
	fmt.Printf("all sent packets per second: max %d, p99 %d\n", s.AllMax, s.AllP99)
	for _, c := range classes {
		fmt.Printf("  %-11s %d\n", c, s.Total[c])
	}
}
