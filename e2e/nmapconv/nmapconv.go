// Package nmapconv turns nmap XML output into Czujka host results
// ([]model.HostResult). It is the baseline used to check the lab itself:
// a plain nmap run, converted and scored against the ground truth.
// It also reads the output of four safe NSE scripts when present:
// http-title, http-server-header, http-headers and ssl-cert.
package nmapconv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

type nmapRun struct {
	Start int64   `xml:"start,attr"`
	Hosts []xHost `xml:"host"`
}

type xHost struct {
	StartTime int64 `xml:"starttime,attr"`
	EndTime   int64 `xml:"endtime,attr"`
	Status    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []xPort `xml:"ports>port"`
	Times struct {
		SRTT string `xml:"srtt,attr"`
	} `xml:"times"`
}

type xPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Method    string   `xml:"method,attr"`
		Conf      int      `xml:"conf,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []xScript `xml:"script"`
}

type xScript struct {
	ID     string   `xml:"id,attr"`
	Output string   `xml:"output,attr"`
	Elems  []xElem  `xml:"elem"`
	Tables []xTable `xml:"table"`
}

type xElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type xTable struct {
	Key    string   `xml:"key,attr"`
	Elems  []xElem  `xml:"elem"`
	Tables []xTable `xml:"table"`
}

func (t xTable) elem(key string) string {
	for _, e := range t.Elems {
		if e.Key == key {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func (s xScript) table(key string) (xTable, bool) {
	for _, t := range s.Tables {
		if t.Key == key {
			return t, true
		}
	}
	return xTable{}, false
}

func (s xScript) elem(key string) string {
	for _, e := range s.Elems {
		if e.Key == key {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

// Parse reads one nmap XML document.
func Parse(r io.Reader) ([]model.HostResult, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	var out []model.HostResult
	for _, h := range run.Hosts {
		res := model.HostResult{Up: h.Status.State == "up", Reason: h.Status.Reason, Attempts: 1, Hostnames: []string{}, Services: []model.ServiceResult{}}
		for _, a := range h.Addresses {
			switch a.Type {
			case "ipv4", "ipv6":
				res.IP = a.Addr
			case "mac":
				res.MAC, res.Vendor = a.Addr, a.Vendor
			}
		}
		if res.IP == "" {
			continue
		}
		for _, n := range h.Hostnames {
			res.Hostnames = append(res.Hostnames, n.Name)
		}
		if us, err := strconv.ParseFloat(h.Times.SRTT, 64); err == nil {
			res.RTTMs = us / 1000
		}
		at := h.EndTime
		if at == 0 {
			at = h.StartTime
		}
		if at == 0 {
			at = run.Start
		}
		if at != 0 {
			res.ObservedAt = time.Unix(at, 0).UTC()
		}
		for _, p := range h.Ports {
			res.Services = append(res.Services, convertPort(res.IP, res.Hostnames, p, res.ObservedAt))
		}
		out = append(out, res)
	}
	return out, nil
}

func convertPort(ip string, hostnames []string, p xPort, at time.Time) model.ServiceResult {
	s := model.ServiceResult{
		Port: p.PortID, Proto: p.Protocol, State: p.State.State,
		Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, ExtraInfo: p.Service.ExtraInfo,
		CPE: p.Service.CPE, Tunnel: p.Service.Tunnel, Confidence: float64(p.Service.Conf) / 10,
		Matches: []model.SigMatch{}, Technologies: []model.Technology{}, Classes: []string{},
	}
	if s.CPE == nil {
		s.CPE = []string{}
	}
	var fp *model.HTTPFingerprint
	httpFP := func() *model.HTTPFingerprint {
		if fp == nil {
			scheme := "http"
			if s.Tunnel == "ssl" {
				scheme = "https"
			}
			fp = &model.HTTPFingerprint{Scheme: scheme, URL: fmt.Sprintf("%s://%s:%d/", scheme, ip, s.Port), Host: ip,
				Headers: map[string][]string{}, Cookies: []model.Cookie{}, Redirects: []model.Redirect{}, Paths: []model.PathProbe{}}
		}
		return fp
	}
	for _, sc := range p.Scripts {
		switch sc.ID {
		case "http-title":
			h := httpFP()
			h.Title = Unescape(sc.elem("title"))
			if to := sc.elem("redirect_url"); to != "" {
				h.Redirects = append(h.Redirects, model.Redirect{From: h.URL, To: to})
			}
		case "http-server-header":
			h := httpFP()
			if len(sc.Elems) > 0 {
				h.Server = strings.TrimSpace(sc.Elems[0].Value)
			} else {
				h.Server = strings.TrimSpace(sc.Output)
			}
		case "http-headers":
			h := httpFP()
			ParseHeaders(sc.Output, h)
		case "ssl-cert":
			s.TLS = parseCert(sc, ip, hostnames, at)
		}
	}
	if fp != nil {
		if fp.Server == "" {
			if v := fp.Headers["Server"]; len(v) > 0 {
				fp.Server = v[0]
			}
		}
		if v := fp.Headers["X-Powered-By"]; len(v) > 0 {
			fp.PoweredBy = v[0]
		}
		s.HTTP = fp
	}
	return s
}

// Unescape turns the \xHH escapes nmap writes for non-ASCII bytes back into text.
func Unescape(s string) string {
	if !strings.Contains(s, "\\x") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				out = append(out, byte(v))
				i += 3
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

// ParseHeaders reads the text of the http-headers script into a fingerprint.
func ParseHeaders(output string, h *model.HTTPFingerprint) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "(Request type") {
			continue
		}
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		name := canonical(strings.TrimSpace(line[:i]))
		value := strings.TrimSpace(line[i+1:])
		h.Headers[name] = append(h.Headers[name], value)
		if name == "Set-Cookie" {
			if c, ok := ParseCookie(value); ok {
				h.Cookies = append(h.Cookies, c)
			}
		}
		if name == "Location" && len(h.Redirects) == 0 {
			h.Redirects = append(h.Redirects, model.Redirect{From: h.URL, To: value})
		}
	}
}

func canonical(name string) string {
	parts := strings.Split(name, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}

// ParseCookie reads one Set-Cookie value.
func ParseCookie(v string) (model.Cookie, bool) {
	parts := strings.Split(v, ";")
	nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nv) != 2 || nv[0] == "" {
		return model.Cookie{}, false
	}
	sum := sha256.Sum256([]byte(nv[1]))
	c := model.Cookie{Name: nv[0], ValueLen: len(nv[1]), ValueHash: hex.EncodeToString(sum[:8])}
	for _, attr := range parts[1:] {
		kv := strings.SplitN(strings.TrimSpace(attr), "=", 2)
		switch strings.ToLower(kv[0]) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		case "samesite":
			if len(kv) == 2 {
				c.SameSite = strings.ToLower(kv[1])
			}
		case "path":
			if len(kv) == 2 {
				c.Path = kv[1]
			}
		case "domain":
			if len(kv) == 2 {
				c.Domain = kv[1]
			}
		}
	}
	return c, true
}

func parseNmapTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func parseCert(sc xScript, ip string, hostnames []string, at time.Time) *model.TLSInfo {
	t := &model.TLSInfo{SANs: []string{}}
	subject, _ := sc.table("subject")
	issuer, _ := sc.table("issuer")
	t.SubjectCN, t.SubjectOrg, t.Issuer = subject.elem("commonName"), subject.elem("organizationName"), issuer.elem("commonName")
	if v, ok := sc.table("validity"); ok {
		t.NotBefore, t.NotAfter = parseNmapTime(v.elem("notBefore")), parseNmapTime(v.elem("notAfter"))
	}
	if pk, ok := sc.table("pubkey"); ok {
		t.KeyType = pk.elem("type")
		t.KeyBits, _ = strconv.Atoi(pk.elem("bits"))
	}
	if ext, ok := sc.table("extensions"); ok {
		for _, e := range ext.Tables {
			if strings.Contains(e.elem("name"), "Subject Alternative Name") {
				for _, part := range strings.Split(e.elem("value"), ",") {
					part = strings.TrimSpace(part)
					part = strings.TrimPrefix(part, "DNS:")
					part = strings.TrimPrefix(part, "IP Address:")
					if part != "" {
						t.SANs = append(t.SANs, part)
					}
				}
			}
		}
	}
	if block, _ := pem.Decode([]byte(sc.elem("pem"))); block != nil {
		sum := sha256.Sum256(block.Bytes)
		t.SHA256 = hex.EncodeToString(sum[:])
	}
	t.SelfSigned = sameName(subject, issuer)
	ref := at
	if ref.IsZero() {
		ref = time.Now()
	}
	if !t.NotAfter.IsZero() {
		t.Expired = ref.After(t.NotAfter)
		t.DaysLeft = int(t.NotAfter.Sub(ref).Hours() / 24)
	}
	t.HostMismatch = !covers(t, append([]string{ip}, hostnames...))
	return t
}

// sameName tells if subject and issuer are the same name. Two empty names
// are the same too: some products ship a self-signed certificate with no subject at all.
func sameName(a, b xTable) bool {
	if len(a.Elems) != len(b.Elems) {
		return false
	}
	am := map[string]string{}
	for _, e := range a.Elems {
		am[e.Key] = strings.TrimSpace(e.Value)
	}
	for _, e := range b.Elems {
		if am[e.Key] != strings.TrimSpace(e.Value) {
			return false
		}
	}
	return true
}

// covers tells if the certificate is valid for at least one of the names.
func covers(t *model.TLSInfo, names []string) bool {
	pats := append([]string{}, t.SANs...)
	if len(pats) == 0 && t.SubjectCN != "" {
		pats = append(pats, t.SubjectCN)
	}
	for _, n := range names {
		for _, p := range pats {
			if strings.EqualFold(p, n) {
				return true
			}
			if strings.HasPrefix(p, "*.") && net.ParseIP(n) == nil {
				if i := strings.Index(n, "."); i > 0 && strings.EqualFold(n[i:], p[1:]) {
					return true
				}
			}
		}
	}
	return false
}

// Merge joins the results of several scans (for example a TCP and a UDP
// scan). A host is up when any scan saw it up; services are joined by port
// and protocol, and the later scan wins on a conflict.
func Merge(scans ...[]model.HostResult) []model.HostResult {
	byIP := map[string]*model.HostResult{}
	var order []string
	for _, scan := range scans {
		for _, h := range scan {
			cur, ok := byIP[h.IP]
			if !ok {
				c := h
				c.Services = append([]model.ServiceResult(nil), h.Services...)
				byIP[h.IP] = &c
				order = append(order, h.IP)
				continue
			}
			if h.Up && !cur.Up {
				cur.Up, cur.Reason = true, h.Reason
			}
			if len(h.Hostnames) > len(cur.Hostnames) {
				cur.Hostnames = h.Hostnames
			}
			if cur.MAC == "" {
				cur.MAC, cur.Vendor = h.MAC, h.Vendor
			}
			// ObservedAt stays the time of the first scan that saw the host:
			// for an unstable host that is the moment it was reachable.
			if cur.ObservedAt.IsZero() {
				cur.ObservedAt = h.ObservedAt
			}
			for _, s := range h.Services {
				replaced := false
				for i := range cur.Services {
					if cur.Services[i].Port == s.Port && cur.Services[i].Proto == s.Proto {
						cur.Services[i] = s
						replaced = true
					}
				}
				if !replaced {
					cur.Services = append(cur.Services, s)
				}
			}
		}
	}
	out := make([]model.HostResult, 0, len(order))
	for _, ip := range order {
		h := byIP[ip]
		sort.SliceStable(h.Services, func(i, j int) bool {
			if h.Services[i].Port != h.Services[j].Port {
				return h.Services[i].Port < h.Services[j].Port
			}
			return h.Services[i].Proto < h.Services[j].Proto
		})
		out = append(out, *h)
	}
	return out
}
