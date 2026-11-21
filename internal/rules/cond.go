package rules

import (
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
)

// HostRec is one host of the inventory with its services, as the evaluator sees it.
type HostRec struct {
	Host     model.Host
	Scopes   []string // lower-case names and tags of the scopes the host belongs to
	Services []*SvcRec
}

// SvcRec is one service with its newest stored observation (nil when none).
type SvcRec struct {
	Service model.Service
	Result  *model.ServiceResult
}

// Cond is a condition over a host and, for service conditions, one of its services.
type Cond interface {
	eval(c *ectx, h *HostRec, s *SvcRec) (bool, []model.Evidence)
	describe() string
}

type ectx struct{ now time.Time }

type allCond struct{ parts []Cond }
type anyCond struct{ parts []Cond }
type notCond struct{ inner Cond }

// leaf is one condition. svc is true when it needs a service.
type leaf struct {
	key  string
	desc string
	svc  bool
	fn   func(c *ectx, h *HostRec, s *SvcRec) (bool, string)
}

func (a allCond) eval(c *ectx, h *HostRec, s *SvcRec) (bool, []model.Evidence) {
	var ev []model.Evidence
	for _, p := range a.parts {
		ok, e := p.eval(c, h, s)
		if !ok {
			return false, nil
		}
		ev = append(ev, e...)
	}
	return true, ev
}

func (a allCond) describe() string {
	if len(a.parts) == 0 {
		return "zawsze"
	}
	return joinDesc(a.parts, " i ")
}

func (a anyCond) eval(c *ectx, h *HostRec, s *SvcRec) (bool, []model.Evidence) {
	var ev []model.Evidence
	hit := false
	for _, p := range a.parts {
		if ok, e := p.eval(c, h, s); ok {
			hit = true
			ev = append(ev, e...)
		}
	}
	return hit, ev
}

func (a anyCond) describe() string { return joinDesc(a.parts, " lub ") }

func (n notCond) eval(c *ectx, h *HostRec, s *SvcRec) (bool, []model.Evidence) {
	if ok, _ := n.inner.eval(c, h, s); ok {
		return false, nil
	}
	return true, []model.Evidence{{Matcher: "policy", Where: "not", Snippet: "nie zachodzi: " + n.inner.describe()}}
}

func (n notCond) describe() string { return "nie (" + n.inner.describe() + ")" }

func (l *leaf) eval(c *ectx, h *HostRec, s *SvcRec) (bool, []model.Evidence) {
	if l.svc && s == nil {
		return false, nil
	}
	ok, snip := l.fn(c, h, s)
	if !ok {
		return false, nil
	}
	if len(snip) > 200 {
		snip = snip[:200]
	}
	return true, []model.Evidence{{Matcher: "policy", Where: l.key, Snippet: snip}}
}

func (l *leaf) describe() string { return l.desc }

func joinDesc(parts []Cond, sep string) string {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = p.describe()
	}
	return strings.Join(s, sep)
}

type condInfo struct {
	state bool // the match names a service state
	svc   bool // the match has at least one service condition
}

// parseCond reads a condition map. Several keys in one map are joined with "and".
func (p *parser) parseCond(n *yaml.Node, path string, info *condInfo) Cond {
	n = deref(n)
	if n != nil && n.Kind == yaml.SequenceNode {
		p.errf(path, n, "warunek jest mapą; listę warunków zapisz jako all: [...] albo any: [...]")
		return nil
	}
	fields, ok := p.mapping(n, path)
	if !ok {
		return nil
	}
	if len(fields) == 0 {
		return allCond{}
	}
	var parts []Cond
	for _, f := range fields {
		fp := join(path, f.key)
		var c Cond
		switch f.key {
		case "all", "any":
			list := deref(f.val)
			if list == nil || list.Kind != yaml.SequenceNode || len(list.Content) == 0 {
				p.errf(fp, f.val, "%s wymaga niepustej listy warunków", f.key)
				continue
			}
			var sub []Cond
			for i, item := range list.Content {
				if sc := p.parseCond(item, idx(fp, i), info); sc != nil {
					sub = append(sub, sc)
				}
			}
			if f.key == "all" {
				c = allCond{sub}
			} else {
				c = anyCond{sub}
			}
		case "not":
			if inner := p.parseCond(f.val, fp, info); inner != nil {
				c = notCond{inner}
			}
		default:
			l := p.parseLeaf(f.key, f.knod, f.val, fp)
			if l == nil {
				continue
			}
			if l.svc {
				info.svc = true
			}
			if l.key == "state" {
				info.state = true
			}
			c = l
		}
		if c != nil {
			parts = append(parts, c)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return allCond{parts}
}

var knownClasses = map[string]bool{model.ClassAdminPanel: true, model.ClassLogin: true, model.ClassStaging: true, model.ClassIoT: true,
	model.ClassDefaultPage: true, model.ClassAPI: true, model.ClassDevTool: true, model.ClassDatabase: true, model.ClassRemoteAccess: true,
	model.ClassDirListing: true, model.ClassErrorPage: true, model.ClassInstallPage: true, model.ClassUnauthControlAPI: true}

const leafKeys = "class, tech, port, proto, service, product, banner, state, tls, scheme, http_status, header, cookie, title, url, hostname, new_within_days, tags, host_status, redirects_to_https, min_interest, all, any, not"

func (p *parser) parseLeaf(key string, knod, val *yaml.Node, path string) *leaf {
	switch key {
	case "class", "classes":
		vals := lowerAll(p.strList(val, path))
		for _, v := range vals {
			if !knownClasses[v] {
				p.warnf(path, val, "nieznana klasa usługi „%s”", v)
			}
		}
		return &leaf{key: "class", svc: true, desc: "klasa " + strings.Join(vals, "/"), fn: func(_ *ectx, h *HostRec, s *SvcRec) (bool, string) {
			for _, c := range classesOf(h, s) {
				if contains(vals, c) {
					return true, c
				}
			}
			return false, ""
		}}
	case "tech", "technology":
		specs := p.techSpecs(val, path)
		if len(specs) == 0 {
			return nil
		}
		ds := make([]string, len(specs))
		for i, t := range specs {
			ds[i] = t.String()
		}
		return &leaf{key: "tech", svc: true, desc: "technologia " + strings.Join(ds, " / "), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			for _, t := range techsOf(s) {
				for _, sp := range specs {
					if sp.match(t) {
						return true, strings.TrimSpace(t.Name + " " + t.Version)
					}
				}
			}
			return false, ""
		}}
	case "port", "ports":
		spans := p.portSpans(val, path)
		if len(spans) == 0 {
			return nil
		}
		return &leaf{key: "port", svc: true, desc: "port " + spansText(spans), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			for _, sp := range spans {
				if s.Service.Port >= sp[0] && s.Service.Port <= sp[1] {
					return true, strconv.Itoa(s.Service.Port) + "/" + protoOf(s)
				}
			}
			return false, ""
		}}
	case "proto":
		v := strings.ToLower(p.str(val, path))
		if v != "tcp" && v != "udp" {
			p.errf(path, val, "protokół „%s”: dozwolone tcp albo udp", v)
			return nil
		}
		return &leaf{key: "proto", svc: true, desc: "protokół " + v, fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			return protoOf(s) == v, v
		}}
	case "service", "name":
		vals := lowerAll(p.strList(val, path))
		return &leaf{key: "service", svc: true, desc: "usługa " + strings.Join(vals, "/"), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			n := strings.ToLower(s.Service.Name)
			if n == "" && s.Result != nil {
				n = strings.ToLower(s.Result.Name)
			}
			return n != "" && contains(vals, n), n
		}}
	case "product", "banner", "title", "url", "hostname":
		re := p.regex(val, path)
		if re == nil {
			return nil
		}
		k := key
		return &leaf{key: k, svc: k != "hostname", desc: k + " ~ /" + re.String() + "/", fn: func(_ *ectx, h *HostRec, s *SvcRec) (bool, string) {
			for _, v := range textOf(k, h, s) {
				if v != "" && re.MatchString(v) {
					return true, v
				}
			}
			return false, ""
		}}
	case "state", "states":
		vals := p.states(val, path)
		return &leaf{key: "state", svc: true, desc: "stan " + strings.Join(vals, "/"), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			return contains(vals, string(s.Service.State)), string(s.Service.State)
		}}
	case "host_status":
		vals := p.hostStatuses(val, path)
		return &leaf{key: "host_status", desc: "stan hosta " + strings.Join(vals, "/"), fn: func(_ *ectx, h *HostRec, _ *SvcRec) (bool, string) {
			return contains(vals, string(h.Host.Status)), string(h.Host.Status)
		}}
	case "tls":
		return p.tlsLeaf(val, path)
	case "scheme":
		v := strings.ToLower(p.str(val, path))
		if v != "http" && v != "https" {
			p.errf(path, val, "schemat „%s”: dozwolone http albo https", v)
			return nil
		}
		return &leaf{key: "scheme", svc: true, desc: "schemat " + v, fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			sc := schemeOf(s)
			return sc == v, sc
		}}
	case "http_status", "status":
		pats := p.statusPatterns(val, path)
		if len(pats) == 0 {
			return nil
		}
		return &leaf{key: "http_status", svc: true, desc: "kod HTTP " + strings.Join(pats, "/"), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			st := statusOf(s)
			if st == 0 {
				return false, ""
			}
			code := strconv.Itoa(st)
			for _, pt := range pats {
				if pt == code || (len(pt) == 3 && strings.HasSuffix(pt, "xx") && pt[0] == code[0]) {
					return true, code
				}
			}
			return false, ""
		}}
	case "header", "headers":
		return p.headerLeaf(val, path)
	case "cookie", "cookies":
		return p.cookieLeaf(val, path)
	case "new_within_days":
		d, ok := p.integer(val, path, 0, 3650)
		if !ok {
			return nil
		}
		return &leaf{key: "new_within_days", desc: fmt.Sprintf("nowe od %d dni", d), fn: func(c *ectx, h *HostRec, s *SvcRec) (bool, string) {
			first := h.Host.FirstSeen
			if s != nil {
				first = s.Service.FirstSeen
			}
			if first.IsZero() {
				return false, ""
			}
			return c.now.Sub(first) <= time.Duration(d)*24*time.Hour, "pierwszy raz " + first.UTC().Format("2006-01-02 15:04")
		}}
	case "tags", "tag":
		vals := lowerAll(p.strList(val, path))
		return &leaf{key: "tags", desc: "etykieta " + strings.Join(vals, "/"), fn: func(_ *ectx, h *HostRec, s *SvcRec) (bool, string) {
			for _, t := range tagsOf(h, s) {
				if contains(vals, strings.ToLower(t)) {
					return true, t
				}
			}
			return false, ""
		}}
	case "redirects_to_https":
		want, ok := p.boolean(val, path)
		if !ok {
			return nil
		}
		return &leaf{key: "redirects_to_https", svc: true, desc: fmt.Sprintf("przekierowanie na HTTPS: %v", want), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			if s.Result == nil || s.Result.HTTP == nil {
				return false, "" // no data is not "no redirect"
			}
			got, where := redirectsToHTTPS(s.Result.HTTP)
			if got != want {
				return false, ""
			}
			if !got {
				where = "brak przekierowania na https://"
			}
			return true, where
		}}
	case "min_interest":
		v, ok := p.integer(val, path, 0, 100)
		if !ok {
			return nil
		}
		return &leaf{key: "min_interest", svc: true, desc: fmt.Sprintf("ocena co najmniej %d", v), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
			return s.Service.Interest >= v, strconv.Itoa(s.Service.Interest)
		}}
	}
	p.errf(path, knod, "nieznany warunek „%s”: dozwolone %s", key, leafKeys)
	return nil
}

func (p *parser) tlsLeaf(val *yaml.Node, path string) *leaf {
	fields, ok := p.mapping(val, path)
	if !ok {
		return nil
	}
	type check struct {
		desc string
		fn   func(c *ectx, t *model.TLSInfo) (bool, string)
	}
	present := true
	var checks []check
	for _, f := range fields {
		fp := join(path, f.key)
		switch f.key {
		case "present":
			present, _ = p.boolean(f.val, fp)
		case "expired", "self_signed", "host_mismatch":
			want, ok := p.boolean(f.val, fp)
			if !ok {
				continue
			}
			k := f.key
			checks = append(checks, check{fmt.Sprintf("%s: %v", k, want), func(c *ectx, t *model.TLSInfo) (bool, string) {
				var got bool
				switch k {
				case "expired":
					got = t.Expired || (!t.NotAfter.IsZero() && c.now.After(t.NotAfter))
				case "self_signed":
					got = t.SelfSigned
				default:
					got = t.HostMismatch
				}
				return got == want, fmt.Sprintf("%s=%v", k, got)
			}})
		case "days_left_below":
			d, ok := p.integer(f.val, fp, 0, 3650)
			if !ok {
				continue
			}
			checks = append(checks, check{fmt.Sprintf("ważny krócej niż %d dni", d), func(c *ectx, t *model.TLSInfo) (bool, string) {
				left := daysLeft(c, t)
				return left < d, fmt.Sprintf("zostało %d dni (do %s)", left, t.NotAfter.UTC().Format("2006-01-02"))
			}})
		case "issuer", "subject", "version":
			re := p.regex(f.val, fp)
			if re == nil {
				continue
			}
			k := f.key
			checks = append(checks, check{k + " ~ /" + re.String() + "/", func(_ *ectx, t *model.TLSInfo) (bool, string) {
				v := t.Issuer
				switch k {
				case "subject":
					v = t.SubjectCN + " " + t.SubjectOrg + " " + strings.Join(t.SANs, " ")
				case "version":
					v = t.Version
				}
				return re.MatchString(v), strings.TrimSpace(v)
			}})
		default:
			p.errf(fp, f.knod, "nieznane pole „%s” w tls: dozwolone present, expired, self_signed, host_mismatch, days_left_below, issuer, subject, version", f.key)
		}
	}
	descs := []string{fmt.Sprintf("present: %v", present)}
	for _, c := range checks {
		descs = append(descs, c.desc)
	}
	return &leaf{key: "tls", svc: true, desc: "TLS {" + strings.Join(descs, ", ") + "}", fn: func(c *ectx, _ *HostRec, s *SvcRec) (bool, string) {
		var t *model.TLSInfo
		if s.Result != nil {
			t = s.Result.TLS
		}
		if t == nil {
			if !present && s.Result != nil && s.Result.HTTP != nil {
				return true, "usługa HTTP bez TLS"
			}
			return false, ""
		}
		if !present {
			return false, ""
		}
		snips := []string{"CN=" + t.SubjectCN}
		for _, ch := range checks {
			ok, snip := ch.fn(c, t)
			if !ok {
				return false, ""
			}
			snips = append(snips, snip)
		}
		return true, strings.Join(snips, ", ")
	}}
}

func daysLeft(c *ectx, t *model.TLSInfo) int {
	if t.NotAfter.IsZero() {
		return t.DaysLeft
	}
	return int(math.Floor(t.NotAfter.Sub(c.now).Hours() / 24))
}

type headerSpec struct {
	name    string
	present bool
	re      *regexp.Regexp
}

func (p *parser) headerLeaf(val *yaml.Node, path string) *leaf {
	var specs []headerSpec
	one := func(n *yaml.Node, path string) {
		n = deref(n)
		if n != nil && n.Kind == yaml.ScalarNode {
			specs = append(specs, headerSpec{name: http.CanonicalHeaderKey(strings.TrimSpace(n.Value)), present: true})
			return
		}
		fields, ok := p.mapping(n, path)
		if !ok {
			return
		}
		hs := headerSpec{present: true}
		for _, f := range fields {
			fp := join(path, f.key)
			switch f.key {
			case "name":
				hs.name = http.CanonicalHeaderKey(p.str(f.val, fp))
			case "present":
				hs.present, _ = p.boolean(f.val, fp)
			case "regex", "matches":
				hs.re = p.regex(f.val, fp)
			default:
				p.errf(fp, f.knod, "nieznane pole „%s” w header: dozwolone name, present, regex", f.key)
			}
		}
		if hs.name == "" {
			p.errf(join(path, "name"), n, "header wymaga pola name")
			return
		}
		if !hs.present && hs.re != nil {
			p.errf(path, n, "present: false wyklucza regex")
			return
		}
		specs = append(specs, hs)
	}
	if v := deref(val); v != nil && v.Kind == yaml.SequenceNode {
		for i, c := range v.Content {
			one(c, idx(path, i))
		}
	} else {
		one(val, path)
	}
	if len(specs) == 0 {
		return nil
	}
	var ds []string
	for _, h := range specs {
		d := h.name
		switch {
		case !h.present:
			d += " nieobecny"
		case h.re != nil:
			d += " ~ /" + h.re.String() + "/"
		}
		ds = append(ds, d)
	}
	return &leaf{key: "header", svc: true, desc: "nagłówek " + strings.Join(ds, " / "), fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
		if s.Result == nil || s.Result.HTTP == nil || s.Result.HTTP.Status == 0 {
			return false, "" // no HTTP answer: absence cannot be proven
		}
		hd := s.Result.HTTP.Headers
		for _, h := range specs {
			vals, has := lookupHeader(hd, h.name)
			switch {
			case !h.present:
				if !has {
					return true, h.name + ": (brak)"
				}
			case has && h.re == nil:
				return true, h.name + ": " + strings.Join(vals, ", ")
			case has:
				for _, v := range vals {
					if h.re.MatchString(v) {
						return true, h.name + ": " + v
					}
				}
			}
		}
		return false, ""
	}}
}

func lookupHeader(hd map[string][]string, name string) ([]string, bool) {
	if v, ok := hd[name]; ok {
		return v, true
	}
	for k, v := range hd {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

func (p *parser) cookieLeaf(val *yaml.Node, path string) *leaf {
	fields, ok := p.mapping(val, path)
	if !ok {
		return nil
	}
	var name string
	var nameRe *regexp.Regexp
	var secure, httpOnly *bool
	sameSite := ""
	for _, f := range fields {
		fp := join(path, f.key)
		switch f.key {
		case "name":
			name = p.str(f.val, fp)
		case "name_regex":
			nameRe = p.regex(f.val, fp)
		case "secure", "http_only":
			b, ok := p.boolean(f.val, fp)
			if !ok {
				continue
			}
			if f.key == "secure" {
				secure = &b
			} else {
				httpOnly = &b
			}
		case "same_site":
			sameSite = strings.ToLower(p.str(f.val, fp))
		default:
			p.errf(fp, f.knod, "nieznane pole „%s” w cookie: dozwolone name, name_regex, secure, http_only, same_site", f.key)
		}
	}
	desc := "ciasteczko"
	if name != "" {
		desc += " " + name
	}
	if nameRe != nil {
		desc += " ~ /" + nameRe.String() + "/"
	}
	if secure != nil {
		desc += fmt.Sprintf(" secure=%v", *secure)
	}
	if httpOnly != nil {
		desc += fmt.Sprintf(" http_only=%v", *httpOnly)
	}
	if sameSite != "" {
		desc += " same_site=" + sameSite
	}
	return &leaf{key: "cookie", svc: true, desc: desc, fn: func(_ *ectx, _ *HostRec, s *SvcRec) (bool, string) {
		if s.Result == nil || s.Result.HTTP == nil {
			return false, ""
		}
		for _, ck := range s.Result.HTTP.Cookies {
			if name != "" && !strings.EqualFold(ck.Name, name) {
				continue
			}
			if nameRe != nil && !nameRe.MatchString(ck.Name) {
				continue
			}
			if secure != nil && ck.Secure != *secure {
				continue
			}
			if httpOnly != nil && ck.HTTPOnly != *httpOnly {
				continue
			}
			if sameSite != "" && !strings.EqualFold(ck.SameSite, sameSite) {
				continue
			}
			return true, fmt.Sprintf("%s (secure=%v, http_only=%v, same_site=%s)", ck.Name, ck.Secure, ck.HTTPOnly, ck.SameSite)
		}
		return false, ""
	}}
}

func (p *parser) portSpans(val *yaml.Node, path string) [][2]int {
	var out [][2]int
	for i, s := range p.strList(val, path) {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			lo, hi, isRange := strings.Cut(part, "-")
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b := a
			var err2 error
			if isRange {
				b, err2 = strconv.Atoi(strings.TrimSpace(hi))
			}
			if err1 != nil || err2 != nil || a < 0 || b > 65535 || b < a {
				p.errf(idx(path, i), val, "„%s” nie jest portem (0–65535) ani zakresem portów", part)
				continue
			}
			out = append(out, [2]int{a, b})
		}
	}
	return out
}

func spansText(spans [][2]int) string {
	var s []string
	for _, sp := range spans {
		if sp[0] == sp[1] {
			s = append(s, strconv.Itoa(sp[0]))
		} else {
			s = append(s, fmt.Sprintf("%d-%d", sp[0], sp[1]))
		}
	}
	return strings.Join(s, ",")
}

var statusPat = regexp.MustCompile(`^[1-5]([0-9]{2}|xx)$`)

func (p *parser) statusPatterns(val *yaml.Node, path string) []string {
	var out []string
	for _, s := range p.strList(val, path) {
		s = strings.ToLower(s)
		if !statusPat.MatchString(s) {
			p.errf(path, val, "„%s” nie jest kodem HTTP (np. 200) ani klasą kodów (np. 4xx)", s)
			continue
		}
		out = append(out, s)
	}
	return out
}

// ---------- technology names and versions ----------

type techSpec struct {
	name string // lower case
	op   string // "", <, <=, >, >=, =, !=
	ver  string
}

func (t techSpec) String() string {
	if t.op == "" {
		return t.name
	}
	return t.name + " " + t.op + " " + t.ver
}

var techExpr = regexp.MustCompile(`^(.+?)\s*(<=|>=|!=|==|=|<|>)\s*v?([0-9][0-9A-Za-z.\-]*)$`)

func parseTechExpr(s string) (techSpec, bool) {
	s = strings.TrimSpace(s)
	if m := techExpr.FindStringSubmatch(s); m != nil {
		op := m[2]
		if op == "==" {
			op = "="
		}
		if strings.ContainsAny(m[1], "<>=!") {
			return techSpec{}, false
		}
		return techSpec{name: strings.ToLower(strings.TrimSpace(m[1])), op: op, ver: m[3]}, true
	}
	if strings.ContainsAny(s, "<>=!") {
		return techSpec{}, false
	}
	return techSpec{name: strings.ToLower(s)}, s != ""
}

func (p *parser) techSpecs(val *yaml.Node, path string) []techSpec {
	val = deref(val)
	var out []techSpec
	one := func(n *yaml.Node, path string) {
		n = deref(n)
		if n != nil && n.Kind == yaml.MappingNode {
			fields, _ := p.mapping(n, path)
			var name, ver string
			for _, f := range fields {
				switch f.key {
				case "name":
					name = p.str(f.val, join(path, f.key))
				case "version":
					ver = p.str(f.val, join(path, f.key))
				default:
					p.errf(join(path, f.key), f.knod, "nieznane pole „%s” w tech: dozwolone name, version", f.key)
				}
			}
			expr := name
			if ver != "" {
				expr = name + " " + ver
			}
			ts, ok := parseTechExpr(expr)
			if !ok || name == "" {
				p.errf(path, n, "niepoprawny warunek technologii „%s”: zapisz np. name: WordPress, version: \"< 6.5\"", expr)
				return
			}
			out = append(out, ts)
			return
		}
		s := p.str(n, path)
		ts, ok := parseTechExpr(s)
		if !ok {
			p.errf(path, n, "niepoprawny warunek technologii „%s”: zapisz np. \"WordPress < 6.5\"", s)
			return
		}
		out = append(out, ts)
	}
	if val != nil && val.Kind == yaml.SequenceNode {
		for i, c := range val.Content {
			one(c, idx(path, i))
		}
	} else {
		one(val, path)
	}
	return out
}

func (t techSpec) match(tech model.Technology) bool {
	if !strings.EqualFold(strings.TrimSpace(tech.Name), t.name) {
		return false
	}
	if t.op == "" {
		return true
	}
	if tech.Version == "" {
		return false // unknown version: the constraint cannot be checked
	}
	c := CompareVersions(tech.Version, t.ver)
	switch t.op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "=":
		return c == 0
	case "!=":
		return c != 0
	}
	return false
}

// CompareVersions compares dotted versions by their numeric parts
// ("6.4.3" < "6.10"). Missing parts count as 0. A non-numeric tail is ignored.
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".") {
		digits := part
		for i, r := range part {
			if r < '0' || r > '9' {
				digits = part[:i]
				break
			}
		}
		if digits == "" {
			break
		}
		n, _ := strconv.Atoi(digits)
		out = append(out, n)
		if len(digits) != len(part) {
			break
		}
	}
	return out
}

// ---------- accessors ----------

func lowerAll(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func protoOf(s *SvcRec) string {
	if s.Service.Proto != "" {
		return strings.ToLower(s.Service.Proto)
	}
	return "tcp"
}

func classesOf(_ *HostRec, s *SvcRec) []string {
	out := append([]string(nil), s.Service.Classes...)
	if s.Result != nil {
		out = append(out, s.Result.Classes...)
	}
	return out
}

func techsOf(s *SvcRec) []model.Technology {
	out := append([]model.Technology(nil), s.Service.Technologies...)
	if s.Result != nil {
		out = append(out, s.Result.Technologies...)
	}
	return out
}

func tagsOf(h *HostRec, s *SvcRec) []string {
	out := append([]string(nil), h.Host.Tags...)
	if s != nil {
		out = append(out, s.Service.Tags...)
	}
	return out
}

func textOf(key string, h *HostRec, s *SvcRec) []string {
	switch key {
	case "product":
		v := []string{s.Service.Product}
		if s.Result != nil {
			v = append(v, s.Result.Product)
		}
		return v
	case "banner":
		v := []string{s.Service.Banner}
		if s.Result != nil {
			v = append(v, s.Result.Banner)
		}
		return v
	case "title":
		v := []string{s.Service.Title}
		if s.Result != nil && s.Result.HTTP != nil {
			v = append(v, s.Result.HTTP.Title)
		}
		return v
	case "url":
		v := []string{s.Service.URL}
		if s.Result != nil && s.Result.HTTP != nil {
			v = append(v, s.Result.HTTP.URL, s.Result.HTTP.FinalURL)
		}
		return v
	case "hostname":
		v := append([]string(nil), h.Host.Hostnames...)
		if s != nil {
			v = append(v, s.Service.Hostname)
		}
		return v
	}
	return nil
}

func schemeOf(s *SvcRec) string {
	if s.Result != nil && s.Result.HTTP != nil && s.Result.HTTP.Scheme != "" {
		return strings.ToLower(s.Result.HTTP.Scheme)
	}
	switch u := strings.ToLower(s.Service.URL); {
	case strings.HasPrefix(u, "https://"):
		return "https"
	case strings.HasPrefix(u, "http://"):
		return "http"
	}
	return ""
}

func statusOf(s *SvcRec) int {
	if s.Service.HTTPStatus != 0 {
		return s.Service.HTTPStatus
	}
	if s.Result != nil && s.Result.HTTP != nil {
		return s.Result.HTTP.Status
	}
	return 0
}

func redirectsToHTTPS(h *model.HTTPFingerprint) (bool, string) {
	if strings.HasPrefix(strings.ToLower(h.Scheme), "https") {
		return true, "usługa już działa po HTTPS"
	}
	for _, r := range h.Redirects {
		if strings.HasPrefix(strings.ToLower(r.To), "https://") {
			return true, "przekierowanie na " + r.To
		}
	}
	if loc, ok := lookupHeader(h.Headers, "Location"); ok {
		for _, l := range loc {
			if strings.HasPrefix(strings.ToLower(l), "https://") {
				return true, "Location: " + l
			}
		}
	}
	if strings.HasPrefix(strings.ToLower(h.FinalURL), "https://") {
		return true, "adres końcowy " + h.FinalURL
	}
	return false, ""
}
