package sig

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// text is one value a rule looks at. The lower-case form is made once.
type text struct {
	orig   string
	low    string
	hasLow bool
	hits   []uint64 // literal hits of the body automaton; nil for other texts
}

func (t *text) lower() string {
	if !t.hasLow {
		t.low, t.hasLow = strings.ToLower(t.orig), true
	}
	return t.low
}

// view is one service prepared for matching. It is built once per Match call
// and shared by every signature.
type view struct {
	svc       *model.ServiceResult
	http      *model.HTTPFingerprint
	tls       *model.TLSInfo
	body      text
	title     text
	headers   map[string][]string // lower-case name → values
	paths     map[string]*pathView
	metas     map[string]string
	metasDone bool
	hostnames []string
}

type pathView struct {
	probe *model.PathProbe
	body  text
	// soft is true when the answer is a catch-all page (a "soft 404"): the
	// same body came back for other paths too. Path rules never match it.
	soft bool
}

func newView(svc *model.ServiceResult, set *set, hostnames []string) *view {
	v := &view{svc: svc, http: svc.HTTP, tls: svc.TLS}
	seen := map[string]bool{}
	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" || seen[h] || net.ParseIP(h) != nil {
			return
		}
		seen[h] = true
		v.hostnames = append(v.hostnames, h)
	}
	for _, h := range hostnames {
		addHost(h)
	}
	if v.http == nil {
		return v
	}
	addHost(v.http.Host)
	v.body.orig = v.http.BodyExcerpt
	v.title.orig = v.http.Title
	if set != nil && set.ac != nil && v.body.orig != "" {
		v.body.hits = make([]uint64, set.ac.words())
		set.ac.scan(v.body.lower(), v.body.hits)
	}
	v.headers = make(map[string][]string, len(v.http.Headers))
	for k, vals := range v.http.Headers {
		v.headers[strings.ToLower(k)] = vals
	}
	if len(v.http.Paths) > 0 {
		v.paths = make(map[string]*pathView, len(v.http.Paths))
		same := map[string]int{}
		for i := range v.http.Paths {
			if pp := &v.http.Paths[i]; pp.Status == 200 && pp.BodySHA256 != "" {
				same[pp.BodySHA256]++
			}
		}
		rootPath := pathOf(v.http.FinalURL)
		for i := range v.http.Paths {
			pp := &v.http.Paths[i]
			if _, dup := v.paths[pp.Path]; dup {
				continue
			}
			pv := &pathView{probe: pp, body: text{orig: pp.Excerpt}}
			if pp.Status == 200 && pp.BodySHA256 != "" {
				sameAsRoot := v.http.Status == 200 && pp.BodySHA256 == v.http.BodySHA256 && pp.Path != rootPath && pp.Path != "/"
				pv.soft = same[pp.BodySHA256] >= softNotFoundRepeats || sameAsRoot
			}
			v.paths[pp.Path] = pv
		}
	}
	return v
}

// softNotFoundRepeats is the number of extra paths with an identical body
// that marks a catch-all answer.
const softNotFoundRepeats = 3

var metaTagRe = regexp.MustCompile(`(?is)<meta\s[^>]{0,600}>`)
var metaAttrRe = regexp.MustCompile(`(?is)\b(name|property|http-equiv|content)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)

// meta returns the content of a <meta> tag by name. The generator tag comes
// from the collector; other names are read from the stored body excerpt.
func (v *view) meta(name string) string {
	if name == "generator" && v.http.MetaGenerator != "" {
		return v.http.MetaGenerator
	}
	if !v.metasDone {
		v.metasDone = true
		v.metas = map[string]string{}
		head := v.body.orig
		if len(head) > 64<<10 {
			head = head[:64<<10]
		}
		for _, tag := range metaTagRe.FindAllString(head, 200) {
			var key, content string
			for _, m := range metaAttrRe.FindAllStringSubmatch(tag, 8) {
				val := m[2] + m[3] + m[4]
				if strings.EqualFold(m[1], "content") {
					content = val
				} else if key == "" {
					key = strings.ToLower(val)
				}
			}
			if key != "" {
				if _, dup := v.metas[key]; !dup {
					v.metas[key] = content
				}
			}
		}
	}
	return v.metas[name]
}

// matchText applies the text matchers of a rule to one value. Every kind of
// matcher that the rule has must hold; inside one kind any alternative is enough.
func (r *rule) matchText(t *text) (ok bool, snippet, version string) {
	if !r.hasText {
		return t.orig != "", clip(t.orig, 120), ""
	}
	if len(r.equals) > 0 {
		val := strings.TrimSpace(t.orig)
		found := false
		for _, e := range r.equals {
			if r.cs && val == e || !r.cs && strings.EqualFold(val, e) {
				found = true
				break
			}
		}
		if !found {
			return false, "", ""
		}
		snippet = clip(val, 120)
	}
	if len(r.contains) > 0 {
		found := false
		for i := range r.contains {
			if at := r.find(t, &r.contains[i]); at >= 0 {
				found = true
				if snippet == "" {
					snippet = around(t, at, len(r.contains[i].exact))
				}
				break
			}
		}
		if !found {
			return false, "", ""
		}
	}
	for i := range r.containsAll {
		at := r.find(t, &r.containsAll[i])
		if at < 0 {
			return false, "", ""
		}
		if snippet == "" {
			snippet = around(t, at, len(r.containsAll[i].exact))
		}
	}
	if len(r.regex) > 0 {
		found := false
		for i := range r.regex {
			x := &r.regex[i]
			if t.hits != nil && len(x.ids) > 0 && !anyBit(t.hits, x.ids) {
				continue // none of the literals a match needs is in the body
			}
			if r.vgroup > 0 {
				m := x.re.FindStringSubmatch(t.orig)
				if m == nil {
					continue
				}
				found = true
				snippet = clip(m[0], 120)
				if r.vgroup < len(m) {
					version = m[r.vgroup]
				}
			} else {
				loc := x.re.FindStringIndex(t.orig)
				if loc == nil {
					continue
				}
				found = true
				snippet = clip(t.orig[loc[0]:loc[1]], 120)
			}
			break
		}
		if !found {
			return false, "", ""
		}
	}
	return true, snippet, version
}

// find returns the position of a literal in the text, or -1.
func (r *rule) find(t *text, l *lit) int {
	if t.hits != nil && l.id >= 0 && !bit(t.hits, l.id) {
		return -1
	}
	if r.cs {
		return strings.Index(t.orig, l.exact)
	}
	return strings.Index(t.lower(), l.low)
}

// around returns the matched literal with a little context for the evidence.
func around(t *text, at, n int) string {
	src := t.orig
	if t.hasLow && len(t.low) != len(t.orig) {
		src = t.low // offsets differ after case mapping of non-ASCII text
	}
	from, to := max(at-30, 0), min(at+n+30, len(src))
	return clip(strings.ToValidUTF8(src[from:to], ""), 120)
}

func (r *rule) nameMatches(name string) bool {
	if r.name != "" && !strings.EqualFold(name, r.name) {
		return false
	}
	if r.nameRe != nil && !r.nameRe.MatchString(name) {
		return false
	}
	return true
}

func statusIn(list []int, st int) bool {
	for _, s := range list {
		if s == st {
			return true
		}
	}
	return false
}

// anyText runs matchText over several values and reports the first match.
func (r *rule) anyText(vals []string) (bool, string, string) {
	for _, val := range vals {
		if val == "" {
			continue
		}
		t := text{orig: val}
		if ok, snip, ver := r.matchText(&t); ok {
			// A short value (a host name, a banner, a URL) is better evidence whole.
			if len(val) <= 120 {
				snip = strings.ToValidUTF8(val, "")
			}
			return true, snip, ver
		}
	}
	return false, "", ""
}

// eval evaluates one rule. For a rule with absent: true the result is true
// when the thing is missing; data that was never collected is not "missing".
func (v *view) eval(r *rule) (ok bool, ev model.Evidence, version string) {
	ev.Matcher = r.typ
	found, snippet := false, ""
	applicable := true

	switch r.typ {
	case TypeHeader:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "header:" + r.nameShown
		if r.name != "" && r.nameRe == nil {
			found, snippet, version = r.anyHeader(r.nameShown, v.headers[r.name], &ev)
			break
		}
		for name, vals := range v.http.Headers {
			if !r.nameMatches(name) {
				continue
			}
			if r.name == "" && r.nameRe == nil {
				// No name given: match "Name: value" lines.
				lines := make([]string, len(vals))
				for i, val := range vals {
					lines[i] = name + ": " + val
				}
				vals = lines
			}
			if found, snippet, version = r.anyHeader(name, vals, &ev); found {
				break
			}
		}
	case TypeCookie:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "cookie:" + r.nameShown
		for i := range v.http.Cookies {
			c := &v.http.Cookies[i]
			if !r.nameMatches(c.Name) {
				continue
			}
			if r.secure != nil && *r.secure != c.Secure || r.httpOnly != nil && *r.httpOnly != c.HTTPOnly {
				continue
			}
			if r.sameSite != nil && !strings.EqualFold(*r.sameSite, c.SameSite) {
				continue
			}
			if r.hasText {
				target := c.Value
				if r.field == "name" {
					target = c.Name
				}
				if target == "" {
					continue
				}
				t := text{orig: target}
				m, _, ver := r.matchText(&t)
				if !m {
					continue
				}
				version = ver
			}
			found = true
			ev.Where = "cookie:" + c.Name
			// The value of a cookie is a secret: the evidence shows its shape only.
			snippet = fmt.Sprintf("%s (%d B; Secure=%t; HttpOnly=%t; SameSite=%s)", c.Name, c.ValueLen, c.Secure, c.HTTPOnly, orDash(c.SameSite))
			break
		}
	case TypeBody:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "body"
		if v.body.orig != "" {
			found, snippet, version = r.matchText(&v.body)
		}
	case TypeTitle:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "title"
		if v.title.orig != "" {
			found, snippet, version = r.matchText(&v.title)
		}
	case TypeMeta:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "meta:" + r.nameShown
		if val := v.meta(r.name); val != "" {
			t := text{orig: val}
			found, snippet, version = r.matchText(&t)
		}
	case TypeFavicon:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "favicon"
		if v.http.FaviconMMH3 == nil && v.http.FaviconSHA256 == "" {
			break
		}
		if len(r.mmh3) == 0 && len(r.sha256) == 0 {
			found = true
		}
		if v.http.FaviconMMH3 != nil {
			for _, h := range r.mmh3 {
				if h == *v.http.FaviconMMH3 {
					found, snippet = true, fmt.Sprintf("mmh3 %d", h)
				}
			}
		}
		for _, h := range r.sha256 {
			if h == strings.ToLower(v.http.FaviconSHA256) {
				found, snippet = true, "sha256 "+h[:16]+"…"
			}
		}
	case TypePath:
		ev.Where = "path:" + r.path
		pv := v.paths[r.path]
		if applicable = pv != nil && !pv.soft; !applicable {
			break
		}
		st := pv.probe.Status
		if len(r.status) > 0 {
			if !statusIn(r.status, st) {
				break
			}
		} else if !r.hasText && st != 200 {
			break
		}
		switch r.field {
		case "title":
			found, snippet, version = r.anyText([]string{pv.probe.Title})
		case "header":
			for name, vals := range pv.probe.Headers {
				if strings.EqualFold(name, r.name) {
					found, snippet, version = r.anyText(vals)
				}
			}
		case "location":
			found, snippet, version = r.anyText([]string{pv.probe.Location})
		default:
			if !r.hasText {
				found = true
			} else if pv.body.orig != "" {
				found, snippet, version = r.matchText(&pv.body)
			}
		}
		if found {
			snippet = strings.TrimSpace(fmt.Sprintf("HTTP %d %s", st, snippet))
		}
	case TypeStatus:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "status"
		if statusIn(r.status, v.http.Status) {
			found, snippet = true, fmt.Sprintf("HTTP %d", v.http.Status)
		}
	case TypeBanner:
		ev.Where = "banner"
		found, snippet, version = r.anyText([]string{v.svc.Banner})
	case TypeService:
		ev.Where = "service"
		var vals []string
		switch r.field {
		case "name":
			vals = []string{v.svc.Name}
		case "product":
			vals = []string{v.svc.Product}
		case "version":
			vals = []string{v.svc.Version}
		case "extrainfo", "extra_info":
			vals = []string{v.svc.ExtraInfo}
		case "cpe":
			vals = v.svc.CPE
		default:
			vals = []string{v.svc.Product, v.svc.Name, strings.TrimSpace(v.svc.Product + " " + v.svc.Version), v.svc.ExtraInfo}
		}
		if r.field != "" && r.field != "any" {
			ev.Where = "service:" + r.field
		}
		found, snippet, version = r.anyText(vals)
	case TypeTLS:
		if applicable = v.tls != nil; !applicable {
			break
		}
		ev.Where = "tls"
		var vals []string
		switch r.field {
		case "subject", "cn", "subject_cn":
			vals = []string{v.tls.SubjectCN}
		case "issuer":
			vals = []string{v.tls.Issuer}
		case "san", "sans":
			vals = v.tls.SANs
		case "org", "subject_org":
			vals = []string{v.tls.SubjectOrg}
		case "version":
			vals = []string{v.tls.Version}
		case "cipher":
			vals = []string{v.tls.Cipher}
		default:
			vals = append([]string{v.tls.SubjectCN, v.tls.SubjectOrg, v.tls.Issuer}, v.tls.SANs...)
		}
		if r.field != "" && r.field != "any" {
			ev.Where = "tls:" + r.field
		}
		found, snippet, version = r.anyText(vals)
	case TypeURL:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "url"
		found, snippet, version = r.anyText([]string{v.http.FinalURL, v.http.URL})
	case TypeRedirect:
		if applicable = v.http != nil; !applicable {
			break
		}
		ev.Where = "redirect"
		vals := make([]string, 0, len(v.http.Redirects)+1)
		for _, rd := range v.http.Redirects {
			vals = append(vals, rd.To)
		}
		vals = append(vals, v.headers["location"]...)
		found, snippet, version = r.anyText(vals)
	case TypeHostname:
		ev.Where = "hostname"
		applicable = len(v.hostnames) > 0
		found, snippet, version = r.anyText(v.hostnames)
	}

	if !applicable {
		return false, ev, ""
	}
	if r.absent {
		if found {
			return false, ev, ""
		}
		ev.Snippet = "brak"
		return true, ev, ""
	}
	ev.Snippet = snippet
	return found, ev, version
}

func (r *rule) anyHeader(name string, vals []string, ev *model.Evidence) (bool, string, string) {
	for _, val := range vals {
		t := text{orig: val}
		if !r.hasText {
			ev.Where = "header:" + name
			return true, clip(val, 120), ""
		}
		if ok, _, ver := r.matchText(&t); ok {
			ev.Where = "header:" + name
			return true, clip(val, 120), ver
		}
	}
	return false, "", ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// evalSig evaluates one signature against a view.
//
// Confidence is the noisy-OR of the weights of the positive rules that
// matched: 1 - Π(1 - w). Rules with not: true are constraints: when one of
// them matches, the signature does not. Rules with required: true must match.
// With condition: all every positive rule must match.
func (v *view) evalSig(s *Sig) (model.SigMatch, bool) {
	if s.needHTTP && v.http == nil {
		return model.SigMatch{}, false
	}
	prod := 1.0
	var evidence []model.Evidence
	version := ""
	matched := 0
	for _, r := range s.rules {
		ok, ev, ver := v.eval(r)
		if r.not {
			if ok {
				return model.SigMatch{}, false
			}
			continue
		}
		if !ok {
			if r.required || s.All {
				return model.SigMatch{}, false
			}
			continue
		}
		matched++
		prod *= 1 - r.weight
		evidence = append(evidence, ev)
		if version == "" {
			version = cleanVersion(ver)
		}
	}
	if matched == 0 {
		return model.SigMatch{}, false
	}
	conf := 1 - prod
	if conf+1e-9 < s.MinConfidence {
		return model.SigMatch{}, false
	}
	for _, r := range s.version {
		if version != "" {
			break
		}
		if ok, ev, ver := v.eval(r); ok {
			if ver = cleanVersion(ver); ver != "" {
				version = ver
				ev.Snippet = "wersja: " + ev.Snippet
				evidence = append(evidence, ev)
			}
		}
	}
	return model.SigMatch{
		Signature:  s.Slug,
		Name:       s.Name,
		Category:   s.Category,
		Version:    version,
		Confidence: round3(conf),
		Interest:   s.Interest,
		Classes:    append([]string{}, s.classes...),
		Tags:       append([]string{}, s.Tags...),
		Evidence:   evidence,
	}, true
}

// cleanVersion keeps a captured version only when it looks like one.
func cleanVersion(ver string) string {
	ver = strings.Trim(strings.TrimSpace(ver), ".,;:-_ ")
	if ver == "" || len(ver) > 40 {
		return ""
	}
	digit := false
	for _, c := range ver {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-', c == '_', c == '+', c == '~':
		default:
			return ""
		}
	}
	if !digit {
		return ""
	}
	return ver
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }
