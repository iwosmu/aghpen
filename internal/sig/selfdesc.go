package sig

import (
	"html"
	"regexp"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Self-description: a web application that no signature knows often says its
// own name: <meta name="application-name">, og:site_name, the generator meta,
// or a login title such as "Sign in · Gitea". When no signature names the
// product, the engine reports that name as a technology with a low confidence
// and the source "self-described". It reads only the root page that the HTTP
// stage already fetched: no extra request.

// SelfDescribedSource marks a technology that comes from the page's own words.
const SelfDescribedSource = "self-described"

// selfDescribedConfidence is visibly under every signature match.
const selfDescribedConfidence = 0.4

// platformCats are categories that do not name the application itself: a
// page served by nginx with PHP and jQuery still has an unknown product.
var platformCats = map[string]bool{
	model.CatWebServer: true, model.CatLanguage: true, model.CatLibrary: true, model.CatOS: true,
	model.CatHeader: true, model.CatCookie: true, model.CatEnvironment: true, model.CatFramework: true,
	model.CatAppServer: true,
}

var (
	sdMetaTagRe  = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	sdMetaAttrRe = regexp.MustCompile(`(?i)\b(name|property|content)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	// Login and setup titles that carry the product name.
	titleNameRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(?:sign in|log ?in|login|sign up|register)\s*(?:·|\||-|–|—|:)\s*(.+)$`),
		regexp.MustCompile(`(?i)^(.+?)\s*(?:·|\||-|–|—|:)\s*(?:sign in|log ?in|login|sign up|register|setup|installation)$`),
		regexp.MustCompile(`(?i)^(?:log ?in|sign in) (?:to|into) (.+)$`),
		regexp.MustCompile(`(?i)^(.+?) (?:login|log in|sign in)$`),
	}
	nameVersionRe = regexp.MustCompile(`^(.*?)[\s/v]*\b([0-9]+\.[0-9]+(?:\.[0-9]+)*)\b.*$`)
	assetVerRe    = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'?#]+)\?(?:[^"'#]*&)?(?:ver|v|version)=([0-9]+\.[0-9]+(?:\.[0-9]+)*)["'&]`)
	tokenVerRe    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]*)/v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)`)
)

// genericNames never become a product: titles of empty shells and words that
// every application uses.
var genericNames = map[string]bool{
	"welcome": true, "login": true, "log in": true, "sign in": true, "signin": true, "home": true, "homepage": true,
	"index": true, "dashboard": true, "admin": true, "administration": true, "admin panel": true, "control panel": true,
	"portal": true, "website": true, "web site": true, "my site": true, "site": true, "default": true, "test": true,
	"untitled": true, "document": true, "app": true, "application": true, "web app": true, "react app": true,
	"vite app": true, "vue app": true, "angular": true, "loading": true, "loading...": true, "error": true,
	"not found": true, "page not found": true, "forbidden": true, "unauthorized": true, "access denied": true,
	"null": true, "undefined": true, "page title": true, "title": true, "main": true, "start": true, "setup": true,
	"installation": true, "install": true, "management": true, "console": true, "web console": true, "server": true,
	"web server": true, "api": true, "user login": true, "member login": true, "secure login": true, "account": true,
	"my account": true, "authentication": true, "auth": true, "password": true, "redirecting": true, "redirect": true,
	"maintenance": true, "coming soon": true, "under construction": true, "it works!": true, "it works": true,
	"web ui": true, "webui": true, "ui": true, "gui": true, "web interface": true, "system": true, "monitor": true,
}

// productNamed reports whether a signature (not nmap alone) names the application.
func productNamed(techs []model.Technology) bool {
	for _, t := range techs {
		if platformCats[t.Category] {
			continue
		}
		for _, s := range t.Sources {
			if s != "nmap" && !strings.HasPrefix(s, "header:") {
				return true
			}
		}
	}
	return false
}

// selfDescribe returns the product the page names itself, with a version when
// the page states one, and the evidence ("meta application-name", ...).
func selfDescribe(svc *model.ServiceResult) (name, version, how string) {
	h := svc.HTTP
	if h == nil || h.Status < 200 || h.Status >= 400 && h.Status != 401 {
		return "", "", ""
	}
	metas := map[string]string{}
	for _, tag := range sdMetaTagRe.FindAllString(h.BodyExcerpt, 200) {
		var key, content string
		for _, a := range sdMetaAttrRe.FindAllStringSubmatch(tag, -1) {
			val := a[2] + a[3]
			switch strings.ToLower(a[1]) {
			case "name", "property":
				key = strings.ToLower(strings.TrimSpace(val))
			case "content":
				content = val
			}
		}
		if key != "" && content != "" {
			if _, seen := metas[key]; !seen {
				metas[key] = strings.TrimSpace(html.UnescapeString(content))
			}
		}
	}
	gen := h.MetaGenerator
	if gen == "" {
		gen = metas["generator"]
	}
	cands := []struct{ text, how string }{
		{metas["application-name"], "meta application-name"},
		{metas["apple-mobile-web-app-title"], "meta apple-mobile-web-app-title"},
		{metas["og:site_name"], "og:site_name"},
		{gen, "meta generator"},
	}
	for _, c := range cands {
		if n, v := splitNameVersion(c.text); usableName(n, svc) {
			return n, v, c.how
		}
	}
	title := strings.TrimSpace(html.UnescapeString(h.Title))
	for _, re := range titleNameRes {
		if m := re.FindStringSubmatch(title); m != nil {
			if n, v := splitNameVersion(m[1]); usableName(n, svc) {
				return n, v, "title"
			}
			return "", "", "" // the first pattern that fits decides: "Admin - Login" is not "Admin -"
		}
	}
	return "", "", ""
}

// nameCutRe cuts a tagline off a name: "Gitea: Git with a cup of tea" -> "Gitea".
var nameCutRe = regexp.MustCompile(`\s+[-–—|·]\s+|:\s+`)

// splitNameVersion: "WordPress 6.4.2" -> "WordPress", "6.4.2".
func splitNameVersion(s string) (string, string) {
	s = strings.TrimSpace(s)
	if loc := nameCutRe.FindStringIndex(s); loc != nil && loc[0] > 0 {
		s = strings.TrimSpace(s[:loc[0]])
	}
	if m := nameVersionRe.FindStringSubmatch(s); m != nil && strings.TrimSpace(m[1]) != "" {
		return strings.Trim(strings.TrimSpace(m[1]), "-–|·:,"), m[2]
	}
	return s, ""
}

// usableName rejects generic words, host names, addresses and long sentences.
func usableName(n string, svc *model.ServiceResult) bool {
	n = strings.TrimSpace(n)
	low := strings.ToLower(n)
	if len(n) < 3 || len(n) > 40 || genericNames[low] || strings.Count(n, " ") > 4 {
		return false
	}
	letters := 0
	for _, r := range n {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r > 127 {
			letters++
		}
	}
	if letters < 3 {
		return false
	}
	if strings.ContainsAny(n, "{}<>/\\") || strings.HasPrefix(low, "http") || strings.Contains(low, "localhost") {
		return false
	}
	// A host name or address ("intranet.example.com", "10.0.0.5") is not a product.
	if strings.Count(n, ".") >= 1 && !strings.Contains(n, " ") {
		return false
	}
	if svc.HTTP != nil && strings.EqualFold(n, svc.HTTP.Host) {
		return false
	}
	return true
}

// genericVersion finds a version for a product without one: the Server or
// X-Powered-By token with the product's name, or the same ?ver= on at least
// two local assets with no other value.
func genericVersion(name string, h *model.HTTPFingerprint) string {
	if h == nil {
		return ""
	}
	k := foldName(name)
	for _, hv := range []string{h.Server, h.PoweredBy} {
		for _, tok := range strings.Fields(hv) {
			if m := tokenVerRe.FindStringSubmatch(tok); m != nil && foldName(m[1]) == k {
				return m[2]
			}
		}
	}
	count := map[string]int{}
	for _, m := range assetVerRe.FindAllStringSubmatch(h.BodyExcerpt, 400) {
		u := strings.ToLower(m[1])
		if strings.HasPrefix(u, "http") || strings.HasPrefix(u, "//") {
			continue // a CDN asset carries its own version
		}
		count[m[2]]++
	}
	if len(count) != 1 {
		return ""
	}
	for v, n := range count {
		if n >= 2 {
			return v
		}
	}
	return ""
}

func foldName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// addSelfDescribed appends the self-described product when no signature
// names one.
func addSelfDescribed(svc *model.ServiceResult, techs []model.Technology) []model.Technology {
	if svc.HTTP == nil || productNamed(techs) {
		return techs
	}
	name, version, how := selfDescribe(svc)
	if name == "" {
		return techs
	}
	for _, t := range techs {
		if foldName(t.Name) == foldName(name) {
			return techs // a platform technology names itself (the generator says "WordPress" and we know it)
		}
	}
	if version == "" {
		version = genericVersion(name, svc.HTTP)
	}
	out := append(techs, model.Technology{
		Name: name, Category: model.CatOther, Version: version, Confidence: selfDescribedConfidence,
		Sources: []string{SelfDescribedSource + ": " + how},
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}
