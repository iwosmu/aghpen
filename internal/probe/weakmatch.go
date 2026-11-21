package probe

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Weak nmap matches. Some match lines of nmap-service-probes identify a
// product from an unsolicited banner (the NULL probe) by its length or by
// one byte: "Nagios NSCA" is any 132-byte greeting (^.{128}[\x52-\x7F]...$),
// "ThinPrint" the single byte 0x94. nmap reports them with full
// confidence, but any service that sends such a banner matches (a
// Portainer tunnel port read as Nagios NSCA in the lab). The engine keeps
// such a result as a service-name hint with low confidence and does not
// turn the product into a technology. The list comes from the installed
// nmap's own probe file, so it follows nmap's updates; nothing is keyed to
// a host or a port.

var (
	matchLine   = regexp.MustCompile(`^match (\S+) m(.)`)
	productPart = regexp.MustCompile(`(?:^| )p(.)`)
	countedQuan = regexp.MustCompile(`^\{\d*(,\d*)?\}`)
)

// literalBytes counts the bytes a regex pattern requires literally: escapes
// such as \x94 or \r count, character classes, dots and quantifiers do not.
func literalBytes(re string) int {
	n := 0
	for i := 0; i < len(re); i++ {
		c := re[i]
		switch {
		case c == '\\' && i+1 < len(re):
			d := re[i+1]
			switch {
			case d == 'x':
				n++
				i += 3
			case strings.IndexByte("dwsDWSbB", d) >= 0:
				i++
			default:
				n++
				i++
			}
		case c == '[':
			j := i + 1
			if j < len(re) && re[j] == '^' {
				j++
			}
			if j < len(re) && re[j] == ']' {
				j++
			}
			for j < len(re) && re[j] != ']' {
				if re[j] == '\\' {
					j++
				}
				j++
			}
			i = j
		case c == '{' && countedQuan.MatchString(re[i:]):
			i += len(countedQuan.FindString(re[i:])) - 1
		case c == '(' && i+1 < len(re) && re[i+1] == '?':
			i++
		case strings.IndexByte(".^$|()*+?", c) >= 0:
		default:
			n++
		}
	}
	return n
}

// delimited returns the text up to the next delim and the rest after it.
func delimited(s string, delim byte) (string, string, bool) {
	i := strings.IndexByte(s, delim)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ParseWeakMatches reads nmap-service-probes and returns the service and
// product pairs ("name\x00product") whose every match line is a NULL-probe
// pattern with fewer than 2 literal bytes.
func ParseWeakMatches(r io.Reader) map[string]bool {
	type count struct{ weak, strong int }
	pairs := map[string]*count{}
	probe := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Probe ") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				probe = f[1] + " " + f[2]
			}
			continue
		}
		m := matchLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pattern, rest, ok := delimited(line[len(m[0]):], m[2][0])
		if !ok {
			continue
		}
		pm := productPart.FindStringSubmatchIndex(rest)
		if pm == nil {
			continue
		}
		product, _, ok := delimited(rest[pm[1]:], rest[pm[2]])
		if !ok || product == "" || strings.Contains(product, "$") {
			continue
		}
		k := m[1] + "\x00" + product
		if pairs[k] == nil {
			pairs[k] = &count{}
		}
		if probe == "TCP NULL" && literalBytes(pattern) < 2 {
			pairs[k].weak++
		} else {
			pairs[k].strong++
		}
	}
	out := map[string]bool{}
	for k, c := range pairs {
		if c.weak > 0 && c.strong == 0 {
			out[k] = true
		}
	}
	return out
}

// loadWeakMatches finds nmap-service-probes next to the nmap binary or in
// the usual data directories. Not found: no weak matches (nothing changes).
func loadWeakMatches(nmapPath string) map[string]bool {
	var dirs []string
	if p, err := exec.LookPath(nmapPath); err == nil {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		dirs = append(dirs, filepath.Join(filepath.Dir(p), "..", "share", "nmap"))
	}
	dirs = append(dirs, "/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap")
	for _, d := range dirs {
		f, err := os.Open(filepath.Join(d, "nmap-service-probes"))
		if err != nil {
			continue
		}
		w := ParseWeakMatches(f)
		f.Close()
		return w
	}
	return nil
}

// demoteWeak turns weak matches into service-name hints: the product goes
// to ExtraInfo, version and CPE are cleared, the confidence drops to 0.3.
func demoteWeak(res *Result, weak map[string]bool) {
	if res == nil || len(weak) == 0 {
		return
	}
	for i := range res.Hosts {
		for j := range res.Hosts[i].Ports {
			p := &res.Hosts[i].Ports[j]
			if p.Product == "" || !weak[p.Name+"\x00"+p.Product] {
				continue
			}
			p.ExtraInfo = "nmap guess: " + p.Product + " (pattern of the banner's length, not its content)"
			p.Product, p.Version, p.CPE = "", "", nil
			p.Confidence = min(p.Confidence, 0.3)
		}
	}
}
