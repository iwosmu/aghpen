package interchange

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// MaxInvalidReported caps ImportReport.Invalid. More invalid rows are only counted.
const MaxInvalidReported = 500

// rowError is an invalid row with its reason (Polish, shown in the UI).
type rowError struct{ value, reason string }

func (e *rowError) Error() string { return e.reason }

// collector builds HostResult records from flat rows. Rows of one address
// are merged into one host; rows of one port are merged into one service.
type collector struct {
	now   time.Time
	runID int64
	hosts map[string]*model.HostResult
	order []string
	// explicitDown marks hosts that a row declared down.
	explicitDown map[string]bool
	merged       int
}

func newCollector(now time.Time, runID int64) *collector {
	return &collector{now: now, runID: runID, hosts: map[string]*model.HostResult{}, explicitDown: map[string]bool{}}
}

var timeLayouts = []string{
	time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02",
	"02.01.2006 15:04:05", "02.01.2006 15:04", "02.01.2006", time.RFC1123Z, time.RFC1123,
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 1e8 {
		if n > 1e12 {
			return time.UnixMilli(n).UTC(), true
		}
		return time.Unix(n, 0).UTC(), true
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func parseBool(s string) (val, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y", "up", "alive", "tak", "open", "ssl", "tls", "https":
		return true, true
	case "0", "false", "f", "no", "n", "down", "dead", "nie", "":
		return false, s != ""
	}
	return false, false
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' })
	out := f[:0]
	for _, x := range f {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

var portStates = map[string]bool{
	"open": true, "closed": true, "filtered": true, "unfiltered": true, "open|filtered": true, "closed|filtered": true,
}

// add applies one flat row. It returns a *rowError for an invalid row.
func (c *collector) add(v map[Field]string) error {
	get := func(f Field) string { return strings.TrimSpace(v[f]) }

	ip, hostname := get(FIP), get(FHostname)
	if h := get(FHost); h != "" {
		if _, err := netip.ParseAddr(h); err == nil && ip == "" {
			ip = h
		} else if hostname == "" {
			hostname = h
		}
	}
	if ip == "" {
		return &rowError{hostname, "brak adresu IP"}
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return &rowError{ip, "niepoprawny adres IP"}
	}
	ip = a.Unmap().String()

	// Validate the service part before touching the host.
	var svc *model.ServiceResult
	portText := get(FPort)
	proto := strings.ToLower(get(FProto))
	if i := strings.IndexByte(portText, '/'); i > 0 { // "443/tcp"
		if proto == "" {
			proto = strings.ToLower(portText[i+1:])
		}
		portText = portText[:i]
	}
	if portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return &rowError{portText, "niepoprawny numer portu"}
		}
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			return &rowError{proto, "nieznany protokół (dozwolone: tcp, udp, sctp)"}
		}
		state := strings.ToLower(get(FState))
		if state == "" {
			state = "open"
		}
		if !portStates[state] {
			return &rowError{state, "nieznany stan portu (dozwolone: open, closed, filtered)"}
		}
		svc = &model.ServiceResult{Port: port, Proto: proto, State: state}
	}
	statusText := get(FStatus)
	httpStatus := 0
	hostUp, hostUpSet := parseBool(get(FUp))
	if statusText != "" {
		if n, err := strconv.Atoi(statusText); err == nil {
			if n < 100 || n > 599 {
				return &rowError{statusText, "niepoprawny kod HTTP"}
			}
			httpStatus = n
		} else if b, ok := parseBool(statusText); ok && !hostUpSet {
			hostUp, hostUpSet = b, true
		} else if !ok {
			return &rowError{statusText, "niepoprawny kod HTTP"}
		}
	}
	observed := c.now
	if s := get(FObservedAt); s != "" {
		t, ok := parseTime(s)
		if !ok {
			return &rowError{s, "niepoprawna data (oczekiwany format RFC 3339)"}
		}
		observed = t
	}

	h, ok := c.hosts[ip]
	if !ok {
		h = &model.HostResult{RunID: c.runID, IP: ip, Up: true, Reason: "imported", Attempts: 1, ObservedAt: observed,
			Hostnames: []string{}, Services: []model.ServiceResult{}}
		c.hosts[ip] = h
		c.order = append(c.order, ip)
	} else if observed.After(h.ObservedAt) {
		h.ObservedAt = observed
	}
	for _, name := range splitList(strings.ReplaceAll(hostname, ",", ";")) {
		if !contains(h.Hostnames, name) {
			h.Hostnames = append(h.Hostnames, name)
		}
	}
	if hostUpSet && !hostUp {
		c.explicitDown[ip] = true
	}
	setIfEmpty(&h.OSGuess, get(FOS))
	setIfEmpty(&h.MAC, get(FMAC))
	setIfEmpty(&h.Vendor, get(FVendor))
	if r := get(FReason); r != "" {
		h.Reason = r
	}
	if s := get(FRTT); s != "" {
		if f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64); err == nil && f >= 0 {
			h.RTTMs = f
		}
	}
	if svc == nil {
		return nil
	}

	svc.Name = get(FService)
	svc.Product = get(FProduct)
	svc.Version = get(FVersion)
	svc.ExtraInfo = get(FExtraInfo)
	svc.Banner = get(FBanner)
	if s := get(FConfidence); s != "" {
		if f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64); err == nil && f >= 0 {
			if f > 1 {
				f /= 100
			}
			svc.Confidence = f
		}
	}
	tlsOn := false
	if s := get(FTLS); s != "" {
		tlsOn, _ = parseBool(s)
	}
	u := get(FURL)
	if strings.HasPrefix(strings.ToLower(u), "https://") {
		tlsOn = true
	}
	if tlsOn {
		svc.Tunnel = "ssl"
	}
	for _, cpe := range splitList(strings.ReplaceAll(get(FCPE), " ", ";")) {
		svc.CPE = append(svc.CPE, cpe)
	}
	for _, t := range splitList(get(FTech)) {
		name, ver := splitTech(t)
		svc.Technologies = append(svc.Technologies, model.Technology{Name: name, Version: ver, Sources: []string{"import"}})
	}
	for _, cl := range splitList(strings.ReplaceAll(get(FClasses), ",", ";")) {
		svc.Classes = append(svc.Classes, cl)
	}
	title, server, redirect := get(FTitle), get(FServer), get(FRedirect)
	cookies := splitList(strings.ReplaceAll(get(FCookies), ",", ";"))
	if title != "" || server != "" || redirect != "" || httpStatus != 0 || u != "" || len(cookies) > 0 {
		scheme := "http"
		if tlsOn {
			scheme = "https"
		}
		fp := &model.HTTPFingerprint{Scheme: scheme, URL: u, Status: httpStatus, Title: title, Server: server, FinalURL: redirect}
		if u != "" {
			if pu, err := url.Parse(u); err == nil {
				fp.Host = pu.Hostname()
			}
		}
		if server != "" {
			fp.Headers = map[string][]string{"Server": {server}}
		}
		for _, name := range cookies {
			fp.Cookies = append(fp.Cookies, model.Cookie{Name: name})
		}
		svc.HTTP = fp
	}
	cn, issuer, sha, notAfter := get(FCertCN), get(FCertIssuer), get(FCertSHA256), get(FCertExpires)
	if cn != "" || issuer != "" || sha != "" || notAfter != "" {
		t := &model.TLSInfo{SubjectCN: cn, Issuer: issuer, SHA256: sha}
		if na, ok := parseTime(notAfter); ok {
			t.NotAfter = na
			left := na.Sub(observed)
			t.Expired = left < 0
			t.DaysLeft = int(left.Hours() / 24)
		} else if notAfter != "" {
			return &rowError{notAfter, "niepoprawna data ważności certyfikatu"}
		}
		t.SelfSigned = cn != "" && cn == issuer
		svc.TLS = t
		svc.Tunnel = "ssl"
	}

	for i := range h.Services {
		if h.Services[i].Port == svc.Port && h.Services[i].Proto == svc.Proto {
			mergeService(&h.Services[i], svc)
			c.merged++
			return nil
		}
	}
	h.Services = append(h.Services, *svc)
	return nil
}

// results returns the hosts in first-seen order. A host that a row declared
// down and that has no open port is down.
func (c *collector) results() []model.HostResult {
	out := make([]model.HostResult, 0, len(c.order))
	for _, ip := range c.order {
		h := c.hosts[ip]
		if c.explicitDown[ip] {
			h.Up = false
			for _, s := range h.Services {
				if s.State == "open" {
					h.Up = true
				}
			}
			if !h.Up && h.Reason == "imported" {
				h.Reason = "no-response"
			}
		}
		sort.SliceStable(h.Services, func(i, j int) bool { return h.Services[i].Port < h.Services[j].Port })
		out = append(out, *h)
	}
	return out
}

func mergeService(dst, src *model.ServiceResult) {
	setIfEmpty(&dst.Name, src.Name)
	setIfEmpty(&dst.Product, src.Product)
	setIfEmpty(&dst.Version, src.Version)
	setIfEmpty(&dst.ExtraInfo, src.ExtraInfo)
	setIfEmpty(&dst.Banner, src.Banner)
	setIfEmpty(&dst.Tunnel, src.Tunnel)
	if dst.Confidence == 0 {
		dst.Confidence = src.Confidence
	}
	if dst.HTTP == nil {
		dst.HTTP = src.HTTP
	}
	if dst.TLS == nil {
		dst.TLS = src.TLS
	}
	for _, t := range src.Technologies {
		found := false
		for _, e := range dst.Technologies {
			if strings.EqualFold(e.Name, t.Name) {
				found = true
			}
		}
		if !found {
			dst.Technologies = append(dst.Technologies, t)
		}
	}
	for _, cl := range src.Classes {
		if !contains(dst.Classes, cl) {
			dst.Classes = append(dst.Classes, cl)
		}
	}
	for _, cpe := range src.CPE {
		if !contains(dst.CPE, cpe) {
			dst.CPE = append(dst.CPE, cpe)
		}
	}
}

// splitTech splits "WordPress:6.4" or "WordPress 6.4" into name and version.
func splitTech(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexAny(s, ": "); i > 0 && i < len(s)-1 && s[i+1] >= '0' && s[i+1] <= '9' {
		return strings.TrimSpace(s[:i]), s[i+1:]
	}
	return s, ""
}

func techText(t model.Technology) string {
	if t.Version == "" {
		return t.Name
	}
	return t.Name + ":" + t.Version
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// validateHost checks a decoded HostResult and fills defaults.
func validateHost(h *model.HostResult) error {
	a, err := netip.ParseAddr(strings.TrimSpace(h.IP))
	if err != nil {
		if h.IP == "" {
			return &rowError{"", "brak adresu IP"}
		}
		return &rowError{h.IP, "niepoprawny adres IP"}
	}
	h.IP = a.Unmap().String()
	for i := range h.Services {
		s := &h.Services[i]
		if s.Port < 1 || s.Port > 65535 {
			return &rowError{fmt.Sprintf("%s port %d", h.IP, s.Port), "niepoprawny numer portu"}
		}
		if s.Proto == "" {
			s.Proto = "tcp"
		}
		if s.State == "" {
			s.State = "open"
		}
	}
	return nil
}
