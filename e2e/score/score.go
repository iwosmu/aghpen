package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/lab/truth"
)

// Metric counts one compared category.
type Metric struct {
	Name      string   `json:"name"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	F1        float64  `json:"f1"`
	Missed    []string `json:"missed"`          // in the truth, not in the export
	Extra     []string `json:"false_positives"` // in the export, not in the truth
	Note      string   `json:"note,omitempty"`
}

func (m *Metric) finish() {
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	sort.Strings(m.Missed)
	sort.Strings(m.Extra)
	if m.Missed == nil {
		m.Missed = []string{}
	}
	if m.Extra == nil {
		m.Extra = []string{}
	}
}

// Accuracy is a recall-only check: of N things the truth names, how many the export has right.
type Accuracy struct {
	Name    string   `json:"name"`
	Right   int      `json:"right"`
	Total   int      `json:"total"`
	Share   float64  `json:"share"`
	Wrong   []string `json:"wrong"`
	Comment string   `json:"comment,omitempty"`
}

func (a *Accuracy) add(ok bool, what string) {
	a.Total++
	if ok {
		a.Right++
	} else {
		a.Wrong = append(a.Wrong, what)
	}
}

func (a *Accuracy) finish() {
	if a.Total > 0 {
		a.Share = float64(a.Right) / float64(a.Total)
	}
	sort.Strings(a.Wrong)
	if a.Wrong == nil {
		a.Wrong = []string{}
	}
}

// UnstableReport says what the export saw of one unstable host.
type UnstableReport struct {
	IP         string `json:"ip"`
	Name       string `json:"name"`
	SeenUp     bool   `json:"seen_up"`
	ExpectedUp *bool  `json:"expected_up,omitempty"` // from the availability model at the observation time, when known
	ObservedAt string `json:"observed_at,omitempty"`
}

// Report is the full result of one comparison.
type Report struct {
	State      string           `json:"state"`
	Strict     bool             `json:"strict"`
	Metrics    []Metric         `json:"metrics"`
	Accuracies []Accuracy       `json:"accuracies"`
	HardMisses []string         `json:"hard_misses"` // documented hard cases the export missed; not counted unless strict
	Unstable   []UnstableReport `json:"unstable"`
}

// Options control the comparison.
type Options struct {
	Strict        bool    // count hard cases as ordinary misses
	MinConfidence float64 // ignore export technologies under this confidence
}

func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normService maps nmap service names to a family, so "https", "http-alt"
// and "ssl/http" all count as http.
func normService(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimPrefix(n, "ssl/")
	n = strings.TrimSuffix(n, "?")
	if strings.HasPrefix(n, "http") {
		return "http"
	}
	return n
}

func serviceNameOK(t truth.Service, got string) bool {
	g := normService(got)
	if g == "" {
		return false
	}
	if g == normService(t.Name) {
		return true
	}
	for _, alt := range t.NameAlt {
		if alt == "*" || normService(alt) == g {
			return true
		}
		// "mosquitto*" accepts every name with that prefix.
		if p, ok := strings.CutSuffix(strings.ToLower(alt), "*"); ok && strings.HasPrefix(g, p) {
			return true
		}
	}
	return false
}

// versionMatch accepts a version when one is a dotted prefix of the other:
// truth "6.9.4" matches "6.9.4" and "6.9", truth "10" matches "10.6.22".
func versionMatch(want, got string) bool {
	want, got = strings.TrimSpace(strings.ToLower(want)), strings.TrimSpace(strings.ToLower(got))
	if want == "" {
		return true
	}
	if got == "" {
		return false
	}
	if want == got {
		return true
	}
	prefix := func(a, b string) bool {
		if !strings.HasPrefix(b, a) {
			return false
		}
		rest := b[len(a):]
		return rest == "" || strings.ContainsRune(".-_ p+~", rune(rest[0]))
	}
	return prefix(want, got) || prefix(got, want)
}

func isOpen(s model.ServiceResult) bool {
	return s.State == "" || s.State == "open"
}

func portKey(ip string, port int, proto string) string {
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s:%d/%s", ip, port, proto)
}

// normTitle makes titles comparable: HTML entities decoded, no-break spaces
// and runs of white space turned into one space.
func normTitle(s string) string {
	s = strings.ReplaceAll(html.UnescapeString(s), "\u00a0", " ")
	return strings.Join(strings.Fields(s), " ")
}

func hasHeader(h *model.HTTPFingerprint, name string) bool {
	if h == nil {
		return false
	}
	for k, v := range h.Headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return true
		}
	}
	return false
}

func findCookie(h *model.HTTPFingerprint, name string) *model.Cookie {
	if h == nil {
		return nil
	}
	for i := range h.Cookies {
		if h.Cookies[i].Name == name {
			return &h.Cookies[i]
		}
	}
	return nil
}

// flagged tells if the export marks a header or cookie as interesting: a
// signature match of the header or cookie category, or evidence that points at it.
func flagged(s model.ServiceResult, kind, name string) bool {
	ln := strings.ToLower(name)
	for _, m := range s.Matches {
		if (m.Category == model.CatHeader || m.Category == model.CatCookie) && strings.Contains(strings.ToLower(m.Name), ln) {
			return true
		}
		for _, e := range m.Evidence {
			if e.Matcher == kind && strings.Contains(strings.ToLower(e.Where+" "+e.Snippet), ln) {
				return true
			}
		}
	}
	return false
}

// Score compares an export with the ground truth of one lab state.
func Score(t *truth.File, export []model.HostResult, opt Options) *Report {
	rep := &Report{State: t.State, Strict: opt.Strict}
	ignore := map[string]bool{}
	for _, ip := range t.Ignore {
		ignore[ip] = true
	}
	exp := map[string]*model.HostResult{}
	for i := range export {
		h := &export[i]
		if h.Up && !ignore[h.IP] {
			exp[h.IP] = h
		}
	}
	// A host that was not seen has no observation time; the latest time in
	// the export stands in for it.
	var latest time.Time
	for _, h := range export {
		if h.ObservedAt.After(latest) {
			latest = h.ObservedAt
		}
	}
	truthHosts := map[string]*truth.Host{}
	unstable := map[string]bool{}
	for i := range t.Hosts {
		h := &t.Hosts[i]
		if h.Availability != nil {
			unstable[h.IP] = true
			ur := UnstableReport{IP: h.IP, Name: h.Name}
			at := latest
			if e, ok := exp[h.IP]; ok {
				ur.SeenUp = true
				at = e.ObservedAt
			}
			if !at.IsZero() {
				up := h.Availability.UpAt(at)
				ur.ExpectedUp, ur.ObservedAt = &up, at.UTC().Format("2006-01-02T15:04:05Z")
				if !ur.SeenUp {
					ur.ObservedAt += " (latest observation in the export; the host was not seen)"
				}
			}
			rep.Unstable = append(rep.Unstable, ur)
			continue
		}
		truthHosts[h.IP] = h
	}

	hosts := Metric{Name: "hosts"}
	ports := Metric{Name: "ports"}
	names := Metric{Name: "service names", Note: "open ports whose service name is right"}
	techs := Metric{Name: "technologies"}
	classes := Metric{Name: "classes"}
	svcVersion := Accuracy{Name: "service versions", Comment: "product version where the truth knows it"}
	techVersion := Accuracy{Name: "technology versions"}
	titles := Accuracy{Name: "page titles"}
	captured := Accuracy{Name: "interesting headers and cookies: collected", Comment: "the header or cookie is present in the export"}
	flaggedAcc := Accuracy{Name: "interesting headers and cookies: flagged", Comment: "a signature match points at it"}
	cookieFlags := Accuracy{Name: "cookie flags", Comment: "Secure and HttpOnly as in the truth"}
	tlsFlags := Accuracy{Name: "TLS: self-signed and expired"}
	favicons := Accuracy{Name: "favicon hash"}
	sigs := Accuracy{Name: "custom signatures"}

	for ip, th := range truthHosts {
		if _, ok := exp[ip]; ok {
			hosts.TP++
		} else {
			hosts.FN++
			label := ip + " " + th.Name
			if len(th.Hard) > 0 {
				label += " (hard: " + strings.Join(th.Hard, ", ") + ")"
			}
			hosts.Missed = append(hosts.Missed, label)
		}
	}
	for ip := range exp {
		if _, ok := truthHosts[ip]; !ok && !unstable[ip] {
			hosts.FP++
			hosts.Extra = append(hosts.Extra, ip)
		}
	}

	for ip, th := range truthHosts {
		eh := exp[ip]
		got := map[string]*model.ServiceResult{}
		if eh != nil {
			for i := range eh.Services {
				s := &eh.Services[i]
				if isOpen(*s) {
					got[portKey(ip, s.Port, s.Proto)] = s
				}
			}
		}
		want := map[string]bool{}
		for _, ts := range th.Services {
			key := portKey(ip, ts.Port, ts.Proto)
			want[key] = true
			label := key + " " + ts.Name + " (" + th.Name + ")"
			es := got[key]
			if es == nil {
				if ts.Hard != "" && !opt.Strict {
					rep.HardMisses = append(rep.HardMisses, label+" hard: "+ts.Hard)
					continue
				}
				ports.FN++
				ports.Missed = append(ports.Missed, label)
				names.FN++
				names.Missed = append(names.Missed, label)
				for _, tt := range ts.Technologies {
					techs.FN++
					techs.Missed = append(techs.Missed, key+" "+tt.Name)
				}
				for _, c := range ts.Classes {
					classes.FN++
					classes.Missed = append(classes.Missed, key+" "+c)
				}
				continue
			}
			ports.TP++
			// service name
			nameHard := ts.Hard == "name-unknown" || ts.Hard == "tarpit"
			if !(nameHard && !opt.Strict) {
				if serviceNameOK(ts, es.Name) {
					names.TP++
				} else {
					names.FN++
					names.Missed = append(names.Missed, fmt.Sprintf("%s want %s, got %q", key, ts.Name, es.Name))
					if es.Name != "" {
						names.FP++
						names.Extra = append(names.Extra, fmt.Sprintf("%s %q (want %s)", key, es.Name, ts.Name))
					}
				}
			}
			if ts.Version != "" {
				svcVersion.add(versionMatch(ts.Version, es.Version), fmt.Sprintf("%s %s: want %s, got %q", key, ts.Product, ts.Version, es.Version))
			}
			scoreTechs(key, ts, es, opt, &techs, &techVersion)
			scoreClasses(key, ts, es, &classes)
			if ts.HTTP != nil {
				if ts.HTTP.Title != "" {
					gotTitle := ""
					if es.HTTP != nil {
						gotTitle = es.HTTP.Title
					}
					titles.add(normTitle(gotTitle) == normTitle(ts.HTTP.Title), fmt.Sprintf("%s want %q, got %q", key, ts.HTTP.Title, gotTitle))
				}
				if ts.HTTP.FaviconMMH3 != nil {
					ok := es.HTTP != nil && es.HTTP.FaviconMMH3 != nil && *es.HTTP.FaviconMMH3 == *ts.HTTP.FaviconMMH3
					favicons.add(ok, fmt.Sprintf("%s want mmh3 %d", key, *ts.HTTP.FaviconMMH3))
				}
				for _, tc := range ts.HTTP.Cookies {
					if c := findCookie(es.HTTP, tc.Name); c != nil {
						cookieFlags.add(c.Secure == tc.Secure && c.HTTPOnly == tc.HTTPOnly,
							fmt.Sprintf("%s cookie %s: want Secure=%v HttpOnly=%v, got Secure=%v HttpOnly=%v", key, tc.Name, tc.Secure, tc.HTTPOnly, c.Secure, c.HTTPOnly))
					}
				}
			}
			for _, in := range ts.Interesting {
				var have bool
				if in.Kind == "cookie" {
					have = findCookie(es.HTTP, in.Name) != nil
				} else {
					have = hasHeader(es.HTTP, in.Name)
				}
				what := fmt.Sprintf("%s %s %s", key, in.Kind, in.Name)
				captured.add(have, what)
				flaggedAcc.add(flagged(*es, in.Kind, in.Name), what)
			}
			if ts.TLS != nil {
				if es.TLS == nil {
					tlsFlags.add(false, key+" no TLS data in the export")
				} else {
					tlsFlags.add(es.TLS.SelfSigned == ts.TLS.SelfSigned && es.TLS.Expired == ts.TLS.Expired,
						fmt.Sprintf("%s want self_signed=%v expired=%v, got self_signed=%v expired=%v", key, ts.TLS.SelfSigned, ts.TLS.Expired, es.TLS.SelfSigned, es.TLS.Expired))
				}
			}
			for _, slug := range ts.Signatures {
				ok := false
				for _, m := range es.Matches {
					if m.Signature == slug {
						ok = true
					}
				}
				sigs.add(ok, key+" "+slug)
			}
		}
		for key, es := range got {
			if !want[key] {
				ports.FP++
				ports.Extra = append(ports.Extra, key+" "+es.Name+" ("+th.Name+")")
			}
		}
	}
	// Ports on hosts that are not in the truth are false positives too.
	for ip, eh := range exp {
		if _, ok := truthHosts[ip]; ok || unstable[ip] {
			continue
		}
		for _, s := range eh.Services {
			if isOpen(s) {
				ports.FP++
				ports.Extra = append(ports.Extra, portKey(ip, s.Port, s.Proto)+" "+s.Name+" (unknown host)")
			}
		}
	}

	for _, m := range []*Metric{&hosts, &ports, &names, &techs, &classes} {
		m.finish()
		rep.Metrics = append(rep.Metrics, *m)
	}
	for _, a := range []*Accuracy{&svcVersion, &techVersion, &titles, &captured, &flaggedAcc, &cookieFlags, &tlsFlags, &favicons, &sigs} {
		a.finish()
		rep.Accuracies = append(rep.Accuracies, *a)
	}
	sort.Strings(rep.HardMisses)
	if rep.HardMisses == nil {
		rep.HardMisses = []string{}
	}
	sort.Slice(rep.Unstable, func(i, j int) bool { return rep.Unstable[i].IP < rep.Unstable[j].IP })
	return rep
}

func techAliases(t truth.Tech) map[string]bool {
	m := map[string]bool{norm(t.Name): true}
	for _, a := range t.Aliases {
		m[norm(a)] = true
	}
	return m
}

func scoreTechs(key string, ts truth.Service, es *model.ServiceResult, opt Options, m *Metric, ver *Accuracy) {
	optional := map[string]bool{}
	for _, o := range ts.TechOptional {
		optional[norm(o)] = true
	}
	matched := make([]bool, len(ts.Technologies))
	seenExtra := map[string]bool{}
	for _, et := range es.Technologies {
		if et.Category == model.CatHeader || et.Category == model.CatCookie {
			continue
		}
		if opt.MinConfidence > 0 && et.Confidence > 0 && et.Confidence < opt.MinConfidence {
			continue
		}
		n := norm(et.Name)
		hit := -1
		for i, tt := range ts.Technologies {
			if techAliases(tt)[n] {
				hit = i
				break
			}
		}
		switch {
		case hit >= 0:
			if !matched[hit] {
				matched[hit] = true
				m.TP++
				if tt := ts.Technologies[hit]; tt.Version != "" {
					ver.add(versionMatch(tt.Version, et.Version), fmt.Sprintf("%s %s: want %s, got %q", key, tt.Name, tt.Version, et.Version))
				}
			}
		case optional[n]:
		default:
			if !seenExtra[n] {
				seenExtra[n] = true
				m.FP++
				m.Extra = append(m.Extra, key+" "+et.Name)
			}
		}
	}
	for i, tt := range ts.Technologies {
		if !matched[i] {
			m.FN++
			m.Missed = append(m.Missed, key+" "+tt.Name)
		}
	}
}

func scoreClasses(key string, ts truth.Service, es *model.ServiceResult, m *Metric) {
	want, optional, got := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range ts.Classes {
		want[c] = true
	}
	for _, c := range ts.ClassOptional {
		optional[c] = true
	}
	for _, c := range es.Classes {
		got[c] = true
	}
	for c := range want {
		if got[c] {
			m.TP++
		} else {
			m.FN++
			m.Missed = append(m.Missed, key+" "+c)
		}
	}
	for c := range got {
		if !want[c] && !optional[c] {
			m.FP++
			m.Extra = append(m.Extra, key+" "+c)
		}
	}
}
