// Package sigsuggest proposes a Czujka signature from one example service.
//
// Given a stored service observation it collects candidate features (header
// names and values, cookie names, favicon hash, title, meta generator,
// distinctive body tokens, TLS subject, fetched paths), drops the volatile
// ones (dates, tokens, request ids, session values) and the ones that change
// between observations of the example, scores the rest by how rare they are
// in the latest observation of every other stored service (document
// frequency, streamed in bounded memory), and emits a signature in the Czujka
// DSL. The signature then goes through the safe-mode validator and a
// retro-hunt over stored data. Nothing is sent to the network.
package sigsuggest

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Feature kinds.
const (
	KindHeaderName  = "header"
	KindHeaderValue = "header-value"
	KindCookie      = "cookie"
	KindFavicon     = "favicon"
	KindTitle       = "title"
	KindMeta        = "meta"
	KindAsset       = "asset"
	KindCSS         = "css"
	KindComment     = "comment"
	KindVersionText = "version-text"
	KindTLS         = "tls"
	KindPath        = "path"
)

// Feature is one candidate feature of a service.
type Feature struct {
	Kind     string  `json:"kind"`
	Key      string  `json:"key"`   // identity for the document frequency
	Label    string  `json:"label"` // Polish, for the explanation
	Value    string  `json:"value"`
	Rule     string  `json:"rule"` // the rule in YAML flow style, without weight
	Strength float64 `json:"strength"`
	TLS      bool    `json:"-"` // counted over services with TLS data, not HTTP data
	// Version is a version rule (YAML flow style) when the feature shows a version.
	Version string `json:"-"`
	// Product is a product name the feature reveals (for the signature name).
	Product string `json:"-"`
}

// Rejected is a feature that was not used, with the reason in Polish.
type Rejected struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

var (
	reDate     = regexp.MustCompile(`\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}:\d{2}|\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} `)
	reHexLong  = regexp.MustCompile(`(?i)[0-9a-f]{12,}`)
	reUUID     = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reDigits   = regexp.MustCompile(`\d{5,}`)
	reB64      = regexp.MustCompile(`[A-Za-z0-9+/_=-]{24,}`)
	reSecretKw = regexp.MustCompile(`(?i)csrf|nonce|token|session[_-]?id|request[_-]?id|timestamp`)
	reVersion  = regexp.MustCompile(`v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)`)

	reAttr    = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*["']([^"'#?\s]{3,200})`)
	reClass   = regexp.MustCompile(`(?i)\bclass\s*=\s*["']([^"']{1,300})["']`)
	reID      = regexp.MustCompile(`(?i)\bid\s*=\s*["']([^"'\s]{1,100})["']`)
	reComment = regexp.MustCompile(`(?s)<!--(.{3,200}?)-->`)
	reTags    = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]*>`)
	reVerText = regexp.MustCompile(`\b([A-Z][A-Za-z0-9]{2,30}(?:[ -][A-Z][A-Za-z0-9]{2,30})?)[ /]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b`)
	reSpace   = regexp.MustCompile(`\s+`)
)

// volatile says whether a value changes on its own (dates, tokens, ids).
func volatile(s string) bool {
	return reDate.MatchString(s) || reUUID.MatchString(s) || reHexLong.MatchString(s) || reDigits.MatchString(s) ||
		(reB64.MatchString(s) && strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0)
}

var commonHeaders = map[string]bool{}

func init() {
	for _, h := range strings.Fields(`date content-type content-length connection keep-alive cache-control pragma expires last-modified
		etag vary accept-ranges transfer-encoding content-encoding set-cookie location x-frame-options x-content-type-options
		x-xss-protection strict-transport-security content-security-policy content-security-policy-report-only referrer-policy
		permissions-policy feature-policy age via x-cache x-cache-hits x-served-by x-timer cf-ray cf-cache-status x-request-id
		x-correlation-id x-runtime alt-svc report-to nel cross-origin-opener-policy cross-origin-embedder-policy
		cross-origin-resource-policy x-ua-compatible content-language content-disposition upgrade link server x-powered-by
		www-authenticate access-control-allow-origin access-control-allow-methods access-control-allow-headers
		access-control-allow-credentials access-control-expose-headers access-control-max-age x-dns-prefetch-control
		x-download-options x-permitted-cross-domain-policies expect-ct timing-allow-origin x-robots-tag p3p`) {
		commonHeaders[h] = true
	}
}

var valueHeaders = []string{"Server", "X-Powered-By", "X-Generator", "X-AspNet-Version", "X-Application", "X-Product"}

var genericCookies = map[string]bool{"phpsessid": true, "jsessionid": true, "asp.net_sessionid": true, "aspsessionid": true, "sessionid": true,
	"session": true, "sid": true, "csrftoken": true, "xsrf-token": true, "_csrf": true, "connect.sid": true, "laravel_session": true, "lang": true}

var genericTitles = map[string]bool{"login": true, "logowanie": true, "log in": true, "sign in": true, "index": true, "home": true, "welcome": true,
	"strona główna": true, "dashboard": true, "untitled": true, "document": true, "404 not found": true, "not found": true, "error": true,
	"403 forbidden": true, "it works!": true, "admin": true, "web": true, "portal": true}

var genericCSS = map[string]bool{}

func init() {
	for _, c := range strings.Fields(`container container-fluid row col wrapper content main header footer nav navbar menu active hidden
		clearfix btn button form input label title logo left right center text icon item list link links page section box panel card
		modal footer-text copyright login loginbar username password submit error alert table odd even first last inner outer top bottom`) {
		genericCSS[c] = true
	}
}

var libraryTokens = []string{"jquery", "bootstrap", "font-awesome", "fontawesome", "googleapis", "gstatic", "cdnjs", "unpkg", "jsdelivr",
	"analytics", "gtag", "recaptcha", "polyfill", "modernizr", "favicon", "react", "vue.", "angular", "normalize", "lodash"}

func isLibrary(s string) bool {
	l := strings.ToLower(s)
	for _, t := range libraryTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// distinctiveCSS keeps class and id names that look product-specific.
func distinctiveCSS(tok string) bool {
	if len(tok) < 4 || len(tok) > 40 || genericCSS[strings.ToLower(tok)] {
		return false
	}
	if strings.HasPrefix(tok, "col-") || strings.HasPrefix(tok, "fa-") || strings.HasPrefix(tok, "btn-") || strings.HasPrefix(tok, "js-") {
		return false
	}
	return strings.ContainsAny(tok, "-_") || (strings.ToLower(tok) != tok)
}

// Extract returns the candidate features of one observation and the
// features it rejected as volatile or generic.
func Extract(r *model.ServiceResult) ([]Feature, []Rejected) {
	var out []Feature
	var rej []Rejected
	seen := map[string]bool{}
	add := func(f Feature) {
		if f.Key == "" || seen[f.Key] {
			return
		}
		seen[f.Key] = true
		out = append(out, f)
	}
	reject := func(kind, value, reason string) {
		if len(rej) < 200 {
			rej = append(rej, Rejected{Kind: kind, Value: value, Reason: reason})
		}
	}
	if h := r.HTTP; h != nil && h.Status != 0 {
		// Header names that are not standard.
		names := make([]string, 0, len(h.Headers))
		for k := range h.Headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			lk := strings.ToLower(k)
			if commonHeaders[lk] || strings.HasPrefix(lk, "access-control-") {
				continue
			}
			if volatile(k) || reSecretKw.MatchString(k) {
				reject(KindHeaderName, k, "nazwa nagłówka wygląda na zmienną (identyfikator żądania, token)")
				continue
			}
			add(Feature{Kind: KindHeaderName, Key: "hname:" + lk, Label: "nagłówek " + k, Value: k,
				Rule: "{type: header, name: " + q(k) + "}", Strength: 0.7})
		}
		// Product headers: the product token without its version.
		for _, k := range valueHeaders {
			vals, ok := h.Headers[k]
			if !ok || len(vals) == 0 {
				continue
			}
			v := strings.TrimSpace(vals[0])
			prod := v
			if i := strings.IndexAny(prod, "/ ("); i > 0 {
				prod = prod[:i]
			}
			if len(prod) < 3 {
				continue
			}
			if volatile(prod) {
				reject(KindHeaderValue, k+": "+v, "wartość zmienna")
				continue
			}
			f := Feature{Kind: KindHeaderValue, Key: "hval:" + strings.ToLower(k) + ":" + lower(prod), Label: "nagłówek " + k + ": " + prod, Value: k + ": " + v,
				Rule: "{type: header, name: " + q(k) + ", regex: " + q("^"+regexp.QuoteMeta(prod)) + "}", Strength: 0.6, Product: prod}
			if strings.HasPrefix(v[len(prod):], "/") && reVersion.MatchString(v[len(prod):]) {
				f.Version = "{type: header, name: " + q(k) + ", regex: " + q("^"+regexp.QuoteMeta(prod)+"/([0-9][0-9.]*)") + "}"
			}
			add(f)
		}
		for _, c := range h.Cookies {
			ln := lower(c.Name)
			if ln == "" {
				continue
			}
			if volatile(c.Name) {
				reject(KindCookie, c.Name, "nazwa ciasteczka zawiera zmienny identyfikator")
				continue
			}
			st := 0.7
			if genericCookies[ln] {
				st = 0.3
			}
			add(Feature{Kind: KindCookie, Key: "cookie:" + ln, Label: "ciasteczko " + c.Name, Value: c.Name,
				Rule: "{type: cookie, name: " + q(c.Name) + "}", Strength: st})
		}
		if h.FaviconMMH3 != nil {
			n := strconv.Itoa(int(*h.FaviconMMH3))
			add(Feature{Kind: KindFavicon, Key: "favicon:" + n, Label: "ikona (favicon mmh3 " + n + ")", Value: n,
				Rule: "{type: favicon, mmh3: [" + n + "]}", Strength: 0.9})
		}
		if t := strings.TrimSpace(h.Title); t != "" {
			prefix := titlePrefix(t)
			switch {
			case prefix == "":
				reject(KindTitle, t, "tytuł zaczyna się od zmiennej części (liczby, identyfikatora)")
			case genericTitles[strings.ToLower(prefix)]:
				reject(KindTitle, t, "tytuł ogólny, występuje w wielu aplikacjach")
			case prefix == t:
				add(Feature{Kind: KindTitle, Key: "title:" + lower(t), Label: "tytuł „" + t + "”", Value: t, Rule: "{type: title, equals: " + q(t) + "}", Strength: 0.6})
			default:
				add(Feature{Kind: KindTitle, Key: "title^" + lower(prefix), Label: "tytuł zaczyna się od „" + prefix + "”", Value: t,
					Rule: "{type: title, regex: " + q("^"+regexp.QuoteMeta(prefix)) + "}", Strength: 0.55})
			}
		}
		if g := strings.TrimSpace(h.MetaGenerator); g != "" {
			prod := strings.TrimSpace(reVersion.ReplaceAllString(g, ""))
			if len(prod) >= 3 && !volatile(prod) {
				f := Feature{Kind: KindMeta, Key: "meta:" + lower(prod), Label: "znacznik meta generator „" + prod + "”", Value: g,
					Rule: "{type: meta, name: generator, regex: " + q("^"+regexp.QuoteMeta(prod)) + "}", Strength: 0.8, Product: prod}
				if reVersion.MatchString(g) {
					f.Version = "{type: meta, name: generator, regex: " + q(regexp.QuoteMeta(prod)+" v?([0-9][0-9.]*)") + "}"
				}
				add(f)
			}
		}
		bodyFeatures(h.BodyExcerpt, add, reject)
		for _, p := range h.Paths {
			t := strings.TrimSpace(p.Title)
			if p.Status != 200 || t == "" || genericTitles[strings.ToLower(t)] || volatile(t) {
				continue
			}
			add(Feature{Kind: KindPath, Key: "path:" + p.Path + ":" + lower(t), Label: "ścieżka " + p.Path + " z tytułem „" + t + "”", Value: p.Path,
				Rule: "{type: path, path: " + q(p.Path) + ", status: 200, field: title, contains: " + q(t) + "}", Strength: 0.6})
		}
	}
	if t := r.TLS; t != nil {
		cn := strings.TrimSpace(t.SubjectCN)
		switch {
		case cn == "" || net.ParseIP(cn) != nil || strings.EqualFold(cn, "localhost"):
		case volatile(cn):
			reject(KindTLS, cn, "nazwa w certyfikacie zawiera zmienny identyfikator")
		default:
			add(Feature{Kind: KindTLS, Key: "tls:cn:" + lower(cn), Label: "certyfikat TLS z nazwą " + cn, Value: cn, TLS: true,
				Rule: "{type: tls, field: subject, contains: " + q(cn) + "}", Strength: 0.5})
		}
		if org := strings.TrimSpace(t.SubjectOrg); org != "" && !volatile(org) {
			add(Feature{Kind: KindTLS, Key: "tls:org:" + lower(org), Label: "certyfikat TLS organizacji " + org, Value: org, TLS: true,
				Rule: "{type: tls, field: org, contains: " + q(org) + "}", Strength: 0.5})
		}
	}
	return out, rej
}

// titlePrefix returns the title up to its first volatile word (a word with a digit).
func titlePrefix(t string) string {
	words := strings.Fields(t)
	var keep []string
	for _, w := range words {
		if strings.IndexFunc(w, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
			break
		}
		keep = append(keep, w)
	}
	p := strings.TrimRight(strings.Join(keep, " "), " -—|:·")
	if len([]rune(p)) < 4 {
		return ""
	}
	return p
}

func bodyFeatures(body string, add func(Feature), reject func(kind, value, reason string)) {
	if body == "" {
		return
	}
	for _, m := range reAttr.FindAllStringSubmatch(body, 40) {
		v := m[1]
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, "data:") || strings.HasPrefix(lv, "javascript:") || strings.HasPrefix(lv, "mailto:") || !strings.ContainsAny(v, "/.") {
			continue
		}
		if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") || strings.HasPrefix(lv, "//") {
			continue // another host: not a property of this application
		}
		if v == "/" || len(v) < 5 || isLibrary(v) {
			continue
		}
		if volatile(v) {
			reject(KindAsset, v, "ścieżka zasobu zawiera skrót albo znacznik czasu (zmienia się przy wdrożeniu)")
			continue
		}
		add(Feature{Kind: KindAsset, Key: "asset:" + lv, Label: "zasób " + v + " w treści strony", Value: v,
			Rule: "{type: body, contains: " + q(v) + "}", Strength: 0.5})
	}
	var css []string
	for _, m := range reClass.FindAllStringSubmatch(body, 60) {
		css = append(css, strings.Fields(m[1])...)
	}
	for _, m := range reID.FindAllStringSubmatch(body, 40) {
		css = append(css, m[1])
	}
	for _, tok := range css {
		if !distinctiveCSS(tok) {
			continue
		}
		if volatile(tok) {
			continue
		}
		add(Feature{Kind: KindCSS, Key: "css:" + strings.ToLower(tok), Label: "klasa lub id „" + tok + "” w HTML", Value: tok,
			Rule: "{type: body, contains: " + q(tok) + "}", Strength: 0.4})
	}
	for _, m := range reComment.FindAllStringSubmatch(body, 20) {
		c := strings.TrimSpace(reSpace.ReplaceAllString(m[1], " "))
		if len(c) < 6 || strings.HasPrefix(c, "[if") || strings.HasPrefix(c, "<") {
			continue
		}
		stable := c
		var ver string
		if loc := reVersion.FindStringIndex(c); loc != nil {
			stable = strings.TrimSpace(c[:loc[0]])
			ver = c
		}
		if len(stable) < 6 || volatile(stable) {
			reject(KindComment, c, "komentarz krótki albo zmienny")
			continue
		}
		f := Feature{Kind: KindComment, Key: "comment:" + lower(stable), Label: "komentarz HTML „" + stable + "”", Value: c,
			Rule: "{type: body, contains: " + q("<!-- "+stable) + "}", Strength: 0.5}
		if ver != "" {
			f.Version = "{type: body, regex: " + q(regexp.QuoteMeta(stable)+" v?([0-9]+(?:\\.[0-9]+)+)") + "}"
		}
		add(f)
	}
	text := reSpace.ReplaceAllString(reTags.ReplaceAllString(body, " "), " ")
	for _, m := range reVerText.FindAllStringSubmatch(text, 10) {
		prod := m[1]
		if isLibrary(prod) || strings.EqualFold(prod, "copyright") || strings.EqualFold(prod, "version") || strings.EqualFold(prod, "http") {
			continue
		}
		pat := regexp.QuoteMeta(prod) + "[ /]v?([0-9]+(?:\\.[0-9]+)+)"
		add(Feature{Kind: KindVersionText, Key: "vtext:" + lower(prod), Label: "napis „" + prod + " " + m[2] + "” z numerem wersji", Value: m[0],
			Rule: "{type: body, regex: " + q(regexp.QuoteMeta(prod)+"[ /]v?[0-9]+\\.[0-9]+") + "}", Strength: 0.6, Product: prod,
			Version: "{type: body, regex: " + q(pat) + "}"})
	}
}
