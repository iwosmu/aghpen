// Command sigimport converts passive templates from an open fingerprint corpus
// (projectdiscovery/nuclei-templates, MIT) into Czujka signatures under
// signatures/community, and evaluates them against stored scan results.
//
//	git clone https://github.com/projectdiscovery/nuclei-templates /tmp/nt
//	git -C /tmp/nt checkout 1ad258956016afba455d4284539812eb24be690a
//	go run ./cmd/sigimport -src /tmp/nt -commit 1ad258956016afba455d4284539812eb24be690a
//
// The converter keeps only what Czujka can check without new requests: rules on
// the root page and redirects we already follow, the favicon hash, and paths the
// hand-written library already fetches. A template that needs a path of its own
// is written disabled (enabled: false, tag opt-in-path). The hand-written
// signatures win: an import that names a technology we already know is dropped.
// The safe-mode validator checks every converted signature.
//
// -eval reruns the candidates on stored exports (lab, zoo) and writes the
// denylist: every signature that fires where the ground truth says otherwise.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

// The parts of the corpus that describe what a service is.
var corpusDirs = []string{"http/technologies", "http/exposed-panels", "http/misconfiguration/installer"}

const (
	repo    = "projectdiscovery/nuclei-templates"
	licence = "MIT"
)

type candidate struct {
	ID, Upstream, File, Group string
	Tech                      string
	YAML                      string
	OptIn                     bool
}

type tally struct {
	Templates, Converted, Kept, OptIn int
	Dropped                           map[string]int
}

func main() {
	src := flag.String("src", "", "nuclei-templates checkout")
	commit := flag.String("commit", "", "pinned upstream commit (must match the checkout)")
	sigDir := flag.String("signatures", "signatures", "hand-written signature directory")
	out := flag.String("out", "signatures/community", "output directory")
	deny := flag.String("deny", "signatures/community/denylist.tsv", "denylist written by -eval")
	eval := flag.String("eval", "", "comma-separated export files (czujka-json) to evaluate the candidates on; writes the denylist")
	labTruth := flag.String("lab-truth", "lab/ground-truth/t0.json", "lab ground truth for -eval")
	zooTruth := flag.String("zoo-truth", "e2e/zoo/truth.tsv", "zoo truth for -eval (exports under e2e/zoo/out/<phase>/<batch>/export.json)")
	flag.Parse()
	if *src == "" || *commit == "" {
		fmt.Fprintln(os.Stderr, "usage: sigimport -src DIR -commit SHA [-eval exports]")
		os.Exit(2)
	}
	if head := gitHead(*src); head != "" && head != *commit {
		fail("checkout is at %s, not the pinned commit %s", head, *commit)
	}
	ours, ourPaths := loadOurs(*sigDir)
	cands, t := convert(*src, *commit, ours, ourPaths)
	if *eval != "" {
		rows := evaluate(cands, strings.Split(*eval, ","), *labTruth, *zooTruth)
		writeDeny(*deny, rows)
	}
	denied := readDeny(*deny)
	write(*out, *commit, cands, denied, t)
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "sigimport: "+f+"\n", a...)
	os.Exit(1)
}

func gitHead(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD"))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "ref: ") {
		b, err = os.ReadFile(filepath.Join(dir, ".git", strings.TrimPrefix(s, "ref: ")))
		if err != nil {
			return ""
		}
		s = strings.TrimSpace(string(b))
	}
	return s
}

// key folds a technology name for comparison: "Apache Tomcat" = "apache-tomcat".
func key(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// loadOurs reads the hand-written library: technology names, aliases, ids and
// the paths it already fetches.
func loadOurs(dir string) (map[string]string, map[string]bool) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	names, paths := map[string]string{}, map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fail("%v", err)
		}
		sigs, _ := sig.Parse(string(b))
		for _, s := range sigs {
			for _, n := range append([]string{s.Slug, s.Name, s.Technology}, s.Aliases...) {
				if k := key(n); len(k) >= 3 {
					names[k] = s.Slug
				}
			}
			for _, p := range s.Paths() {
				paths[p] = true
			}
		}
	}
	return names, paths
}

func convert(src, commit string, ours map[string]string, ourPaths map[string]bool) ([]candidate, *tally) {
	t := &tally{Dropped: map[string]int{}}
	var out []candidate
	seenID := map[string]bool{}
	for _, dir := range corpusDirs {
		var files []string
		_ = filepath.WalkDir(filepath.Join(src, dir), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yaml") {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		for _, f := range files {
			rel, _ := filepath.Rel(src, f)
			b, err := os.ReadFile(f)
			if err != nil {
				fail("%v", err)
			}
			for _, tpl := range split(b) {
				t.Templates++
				c, reason := one(tpl, rel, dir, commit, ours, ourPaths)
				if reason != "" {
					t.Dropped[reason]++
					continue
				}
				if seenID[c.ID] {
					t.Dropped["duplicate id"]++
					continue
				}
				seenID[c.ID] = true
				t.Converted++
				out = append(out, c)
			}
		}
	}
	return out, t
}

// split turns a template whose matchers carry their own names (tech-detect,
// favicon-detect: one matcher per technology, joined with "or") into one
// template per named matcher. Other templates pass unchanged.
func split(b []byte) [][]byte {
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) == 0 {
		return [][]byte{b}
	}
	root := doc.Content[0]
	httpN := mget(root, "http")
	if httpN == nil || httpN.Kind != yaml.SequenceNode || len(httpN.Content) != 1 {
		return [][]byte{b}
	}
	block := httpN.Content[0]
	if c := mget(block, "matchers-condition"); c != nil && strings.EqualFold(c.Value, "and") {
		return [][]byte{b}
	}
	ms := mget(block, "matchers")
	if ms == nil || ms.Kind != yaml.SequenceNode || len(ms.Content) < 2 {
		return [][]byte{b}
	}
	named := 0
	for _, m := range ms.Content {
		if mget(m, "name") != nil {
			named++
		}
	}
	if named < 2 {
		return [][]byte{b}
	}
	id := ""
	if v := mget(root, "id"); v != nil {
		id = v.Value
	}
	// Matchers with the same name are one technology: keep them together (or).
	var order []string
	groups := map[string][]*yaml.Node{}
	for _, m := range ms.Content {
		nv := mget(m, "name")
		if nv == nil || nv.Value == "" {
			continue
		}
		if groups[nv.Value] == nil {
			order = append(order, nv.Value)
		}
		groups[nv.Value] = append(groups[nv.Value], m)
	}
	var out [][]byte
	for _, name := range order {
		nv := &yaml.Node{Value: name}
		ms.Content = groups[name]
		mset(block, "matchers-condition", "or")
		mdel(block, "extractors") // shared extractors would give every technology the same version
		mset(root, "id", id+"-"+nv.Value)
		if info := mget(root, "info"); info != nil {
			mset(info, "name", pretty(nv.Value))
		}
		y, err := yaml.Marshal(&doc)
		if err == nil {
			out = append(out, y)
		}
	}
	return out
}

func mget(m *yaml.Node, k string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1]
		}
	}
	return nil
}

func mset(m *yaml.Node, k, v string) {
	if n := mget(m, k); n != nil {
		n.Kind, n.Tag, n.Value, n.Content, n.Style = yaml.ScalarNode, "!!str", v, nil, 0
		return
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
}

func mdel(m *yaml.Node, k string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// pretty makes a display name of a matcher name: "atlassian-jira" -> "Atlassian Jira".
func pretty(s string) string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == ' ' })
	for i, w := range f {
		if len(w) <= 3 && strings.ToLower(w) == w && !strings.ContainsAny(w, "aeiouy") {
			f[i] = strings.ToUpper(w)
			continue
		}
		f[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(f, " ")
}

// detectSuffix strips the corpus' naming habits from a template name to get the
// technology: "Grafana Login Panel - Detect" -> "Grafana".
var detectSuffix = regexp.MustCompile("(?i)(?:[\\s\\-–:|(]+(?:detect(?:ion)?|exposure|discovery|installer?|install(?:ation)? (?:page|wizard)|setup(?: wizard| page)?|login|log-in|sign[ -]in|admin(?:istration)?|admin(?:istrator)? login|panel|page|portal|console|interface|dashboard|web ui|ui|technology|version|\\))\\s*)+$")

func one(tpl []byte, rel, dir, commit string, ours map[string]string, ourPaths map[string]bool) (candidate, string) {
	conv, val := sig.Convert(string(tpl))
	for _, is := range val.Issues {
		if is.Level == "error" {
			if strings.Contains(is.Message, "tryb bezpieczny") || strings.Contains(strings.ToLower(is.Path), "safe") {
				return candidate{}, "unsafe (safe mode)"
			}
			return candidate{}, "not passive / unsupported: " + firstWords(is.Message)
		}
	}
	sigs, val := sig.Parse(conv)
	if len(sigs) != 1 || hasError(val) {
		return candidate{}, "rejected by the validator"
	}
	s := sigs[0]
	d := s.Def
	upstream := d.ID
	tech := strings.TrimSpace(detectSuffix.ReplaceAllString(d.Name, ""))
	if tech == "" {
		tech = d.Name
	}
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(upstream, "-detect"), "-panel"), "-login")
	if ours[key(tech)] != "" || ours[key(upstream)] != "" || ours[key(base)] != "" || sameAsOurs(tech, ours) {
		return candidate{}, "technology already in the hand-written library"
	}
	if libraryRe.MatchString(tech) || libraryRe.MatchString(upstream) {
		return candidate{}, "front-end library, CDN, font or analytics (not a service)"
	}
	if why := generic(d); why != "" {
		return candidate{}, "generic: " + why
	}
	if len(key(tech)) < 3 {
		return candidate{}, "no usable technology name"
	}
	optIn := false
	for _, p := range s.Paths() {
		if !ourPaths[p] {
			optIn = true
		}
	}
	d.ID = shortID(upstream)
	d.Name = tech
	d.Technology = ""
	d.Source = fmt.Sprintf("%s@%s %s id=%s licence=%s", repo, commit[:12], rel, upstream, licence)
	// Precision first: a corpus "panel" tag says nothing about a password field
	// (our classifier sees that itself); keep only the installer class.
	d.Classes = nil
	if dir == "http/misconfiguration/installer" {
		d.Classes = []string{model.ClassInstallPage}
	}
	d.Tags = append(d.Tags, "nuclei-templates")
	if optIn {
		d.Disabled = true
		d.Tags = append(d.Tags, "opt-in-path")
	}
	y := d.YAML()
	re, v := sig.Parse(y)
	if hasError(v) || len(re) != 1 {
		return candidate{}, "rejected by the validator after rewrite"
	}
	d.ID = re[0].Slug // the id as the loader sees it (at most 64 characters)
	group := map[string]string{"http/technologies": "technologies", "http/exposed-panels": "panels", "http/misconfiguration/installer": "installers"}[dir]
	if strings.Contains(rel, "favicon-detect") {
		group = "favicons"
	}
	return candidate{ID: d.ID, Upstream: upstream, File: rel, Group: group, Tech: tech, YAML: y, OptIn: optIn}, ""
}

// vendorWords name a vendor or a platform, not one product: "Apache Airflow"
// is not Apache HTTP Server, "Oracle WebLogic" is not Oracle Database.
var vendorWords = map[string]bool{
	"apache": true, "java": true, "php": true, "python": true, "node": true, "nodejs": true, "microsoft": true, "oracle": true,
	"ibm": true, "cisco": true, "google": true, "amazon": true, "aws": true, "azure": true, "server": true, "http": true,
	"https": true, "web": true, "default": true, "admin": true, "login": true, "panel": true, "page": true, "open": true,
	"cloud": true, "portal": true, "console": true, "manager": true, "management": true, "system": true, "service": true,
	"api": true, "app": true, "application": true, "dashboard": true, "network": true, "router": true, "camera": true,
	"version": true, "status": true, "debug": true, "test": true, "hashicorp": true, "apilayer": true, "jboss": true,
	"red": true, "hat": true, "redhat": true, "vmware": true, "sap": true, "dell": true, "hp": true, "huawei": true,
	"framework": true, "cms": true, "ui": true, "the": true, "for": true, "and": true, "spring": true, "elastic": true,
}

// sameAsOurs: a word or a pair of words of the name is a technology the
// hand-written library knows ("Default Nginx Page" -> nginx).
func sameAsOurs(name string, ours map[string]string) bool {
	// A shorter name of one of ours: "Swagger" is our "Swagger UI".
	if k := key(name); len(k) >= 5 {
		for o := range ours {
			if len(o) > len(k) && strings.HasPrefix(o, k) {
				return true
			}
		}
	}
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.')
	})
	for i, w := range words {
		w = key(w)
		if len(w) >= 3 && !vendorWords[w] && ours[w] != "" {
			return true
		}
		if i+1 < len(words) {
			if p := w + key(words[i+1]); ours[p] != "" {
				return true
			}
		}
	}
	return false
}

// libraryRe: names of front-end libraries, CDNs, fonts, widgets and analytics.
// They are real, but they are not what a service is, and the jury's truth does
// not list them: as technologies they would only be noise.
var libraryRe = regexp.MustCompile("(?i)(?:^|[- _])(?:font|fonts|icons?|glyphicons|cdn|cdnjs|jsdelivr|unpkg|cloudflare|akamai|fastly|google|analytics|tag[- ]manager|gtm|hotjar|matomo|piwik|pixel|facebook|twitter|addthis|sharethis|disqus|recaptcha|captcha|gravatar|jquery|bootstrap|lodash|underscore|moment|momentjs|modernizr|polyfill|requirejs|react|vue|vuejs|angular|angularjs|ember|backbone|knockout|handlebars|mustache|d3|chart|charts|highcharts|three|swiper|slick|owl|lightbox|fancybox|slider|carousel|select2|datatables|tinymce|ckeditor|prism|highlight|mathjax|leaflet|mapbox|openlayers|video|videojs|youtube|vimeo|player|webpack|vite|babel|typescript|sentry|newrelic|new relic|datadog|stripe|paypal|cookie|consent|gdpr|onetrust|optimizely|segment|mixpanel|intercom|zendesk|livechat|tawk|crisp|hubspot|mailchimp|wix|squarespace|shopify|amp|pwa|webp|lazy|emoji|twemoji|animate|aos|gsap|popper|tippy|toastr|sweetalert|alpine|alpinejs|htmx|stimulus|turbo|turbolinks|svelte|preact|lit|polymer|mootools|prototype|scriptaculous|yui|extjs|dojo|kendo|semantic|foundation|bulma|tailwind|materialize|material|uikit|pure)(?:$|[- _.0-9])")

// generic: the signature has no pattern long enough to be specific. A favicon
// hash, a cookie or header name, or a literal of at least 8 characters is.
func generic(d sig.Def) string {
	best := 0
	for _, r := range d.Rules {
		if r.Not || r.Absent {
			continue
		}
		if len(r.MMH3) > 0 || len(r.SHA256) > 0 {
			return ""
		}
		if (r.Type == "cookie" || r.Type == "header") && len(r.Name) >= 6 && !commonHeader[strings.ToLower(r.Name)] && (r.Exists || len(r.Contains)+len(r.Regex)+len(r.Equals) == 0) {
			return ""
		}
		for _, l := range append(append(append([]string{}, r.Contains...), r.ContainsAll...), r.Equals...) {
			best = max(best, len(strings.TrimSpace(l)))
		}
		for _, x := range r.Regex {
			best = max(best, longestLiteral(x))
		}
	}
	if best < 8 {
		return fmt.Sprintf("longest pattern %d characters", best)
	}
	return ""
}

var commonHeader = map[string]bool{"server": true, "x-powered-by": true, "set-cookie": true, "content-type": true, "location": true, "www-authenticate": true, "via": true, "cache-control": true}

// longestLiteral is the longest run of plain characters in a regular expression.
func longestLiteral(x string) int {
	best, cur := 0, 0
	esc := false
	for _, r := range x {
		switch {
		case esc:
			esc = false
			if strings.ContainsRune(".()[]{}*+?|^$\\/-", r) {
				cur++
			} else {
				cur = 0
			}
		case r == '\\':
			esc = true
		case strings.ContainsRune(".()[]{}*+?|^$", r):
			cur = 0
		default:
			cur++
		}
		best = max(best, cur)
	}
	return best
}

// shortID keeps ids inside the 64-character limit without collisions:
// "fingerprinthub-web-fingerprints-x" -> "nuclei-fph-x".
func shortID(upstream string) string {
	id := upstream
	for long, short := range map[string]string{"fingerprinthub-web-fingerprints-": "fph-", "tech-detect-": "td-", "favicon-detect-": "fav-"} {
		if strings.HasPrefix(id, long) {
			id = short + strings.TrimPrefix(id, long)
		}
	}
	id = "nuclei-" + id
	if len(id) > 64 {
		h := uint32(2166136261)
		for i := 0; i < len(upstream); i++ {
			h = (h ^ uint32(upstream[i])) * 16777619
		}
		id = strings.TrimRight(id[:55], "-") + fmt.Sprintf("-%08x", h)
	}
	return id
}

func hasError(v model.SignatureValidation) bool {
	for _, is := range v.Issues {
		if is.Level == "error" {
			return true
		}
	}
	return false
}

func firstWords(s string) string {
	if i := strings.IndexAny(s, ";:("); i > 0 {
		s = s[:i]
	}
	if len(s) > 70 {
		s = s[:70]
	}
	return strings.TrimSpace(s)
}

func write(dir, commit string, cands []candidate, denied map[string]string, t *tally) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail("%v", err)
	}
	old, _ := filepath.Glob(filepath.Join(dir, "nuclei-*.yaml"))
	old2, _ := filepath.Glob(filepath.Join(dir, "opt-in", "nuclei-*.yaml"))
	old = append(old, old2...)
	for _, f := range old {
		_ = os.Remove(f)
	}
	byGroup := map[string][]candidate{}
	for _, c := range cands {
		g := c.Group
		if c.OptIn {
			g = "opt-in"
		}
		if why := denied[c.ID]; why != "" {
			t.Dropped["evaluation: "+why]++
			continue
		}
		byGroup[g] = append(byGroup[g], c)
	}
	var groups []string
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		part := 1
		var b strings.Builder
		header := func() {
			b.Reset()
			fmt.Fprintf(&b, "# Imported from %s at commit %s (%s licence, see LICENSES.md).\n", repo, commit, licence)
			fmt.Fprintf(&b, "# Generated by: go run ./cmd/sigimport -src <checkout> -commit %s\n# Do not edit by hand; edit the converter or the denylist and rerun it.\n", commit)
			if g == "opt-in" {
				b.WriteString("# Each of these needs a path of its own, so the default set leaves them out. To opt in, upload\n# this file (or a part of it) as custom signatures in the UI and enable the ones you want.\n")
			}
		}
		flush := func() {
			target := filepath.Join(dir, fmt.Sprintf("nuclei-%s-%d.yaml", g, part))
			if g == "opt-in" {
				// Not embedded: the binary loads only signatures/community/*.yaml.
				target = filepath.Join(dir, "opt-in", fmt.Sprintf("nuclei-opt-in-%d.yaml", part))
				_ = os.MkdirAll(filepath.Dir(target), 0o755)
			}
			if err := os.WriteFile(target, []byte(b.String()), 0o644); err != nil {
				fail("%v", err)
			}
			part++
		}
		header()
		for _, c := range byGroup[g] {
			// The loader takes files up to 1 MiB.
			if b.Len()+len(c.YAML) > 900_000 {
				flush()
				header()
			}
			b.WriteString("---\n")
			b.WriteString(c.YAML)
			if c.OptIn {
				t.OptIn++
			} else {
				t.Kept++
			}
		}
		flush()
	}
	var r strings.Builder
	fmt.Fprintf(&r, "source\t%s@%s\ntemplates\t%d\nconverted\t%d\nkept (default set)\t%d\nopt-in (disabled, own path)\t%d\n", repo, commit, t.Templates, t.Converted, t.Kept, t.OptIn)
	var reasons []string
	for k := range t.Dropped {
		reasons = append(reasons, k)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if t.Dropped[reasons[i]] != t.Dropped[reasons[j]] {
			return t.Dropped[reasons[i]] > t.Dropped[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	for _, k := range reasons {
		fmt.Fprintf(&r, "dropped: %s\t%d\n", k, t.Dropped[k])
	}
	for _, g := range groups {
		fmt.Fprintf(&r, "group %s\t%d\n", g, len(byGroup[g]))
	}
	if err := os.WriteFile(filepath.Join(dir, "import-report.tsv"), []byte(r.String()), 0o644); err != nil {
		fail("%v", err)
	}
	fmt.Print(r.String())
}

func readDeny(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		why := "denylist"
		if len(parts) > 1 {
			why = parts[1]
		}
		out[parts[0]] = why
	}
	return out
}

// ---- evaluation ----

type truthSvc struct {
	names []string // product, technology names and aliases, host description
	known bool
}

type evalRow struct {
	ID, Reason, Where string
}

type labGT struct {
	Hosts []struct {
		IP       string `json:"ip"`
		Desc     string `json:"desc"`
		Services []struct {
			Port    int    `json:"port"`
			Proto   string `json:"proto"`
			Product string `json:"product"`
			Techs   []struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"technologies"`
		} `json:"services"`
	} `json:"hosts"`
}

type exportEnv struct {
	Hosts []model.HostResult `json:"hosts"`
}

func evaluate(cands []candidate, exports []string, labTruth, zooTruth string) []evalRow {
	idx := map[string]candidate{}
	var recs []model.Signature
	for _, c := range cands {
		idx[c.ID] = c
		ss, _ := sig.Parse(c.YAML)
		for _, s := range ss {
			s.Builtin = true
			m := s.Model()
			m.Enabled = true // evaluate the opt-in ones too: an opt-in must not be wrong either
			recs = append(recs, m)
		}
	}
	e := sig.NewEngine()
	if rep := e.Load(recs); len(rep.Rejected) > 0 {
		fail("%d candidates rejected on load, first %s", len(rep.Rejected), rep.Rejected[0].Slug)
	}
	truth := map[string]truthSvc{}
	loadLabTruth(labTruth, truth)
	loadZooTruth(zooTruth, truth)
	fires := map[string][]string{}
	wrong := map[string][]string{}
	nsvc := 0
	for _, ex := range exports {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		tag := exportTag(ex)
		b, err := os.ReadFile(ex)
		if err != nil {
			fail("%v", err)
		}
		var env exportEnv
		if err := json.Unmarshal(b, &env); err != nil {
			fail("%s: %v", ex, err)
		}
		for hi := range env.Hosts {
			h := &env.Hosts[hi]
			for si := range h.Services {
				svc := &h.Services[si]
				nsvc++
				where := fmt.Sprintf("%s %s:%d/%s", tag, h.IP, svc.Port, svc.Proto)
				ts := truth[truthKey(tag, h.IP, svc.Port, svc.Proto)]
				ms, _, _ := e.MatchHost(svc, h.Hostnames...)
				for _, m := range ms {
					c := idx[m.Signature]
					fires[m.Signature] = append(fires[m.Signature], where)
					if !ts.known {
						wrong[m.Signature] = append(wrong[m.Signature], where+" (no truth)")
						continue
					}
					if !explains(c.Tech, c.Upstream, ts.names) {
						wrong[m.Signature] = append(wrong[m.Signature], where+" (truth: "+strings.Join(ts.names[:min(3, len(ts.names))], ", ")+")")
					}
				}
			}
		}
	}
	var rows []evalRow
	for _, c := range cands {
		w := wrong[c.ID]
		switch {
		case len(w) > 0:
			rows = append(rows, evalRow{c.ID, "fires against the truth", strings.Join(w[:min(3, len(w))], "; ")})
		case len(fires[c.ID]) > 3:
			rows = append(rows, evalRow{c.ID, "generic (fires on more than 3 services)", strings.Join(fires[c.ID][:3], "; ")})
		}
	}
	var good []string
	for id, f := range fires {
		if len(wrong[id]) == 0 && len(f) <= 3 {
			good = append(good, id+" on "+strings.Join(f, "; "))
		}
	}
	sort.Strings(good)
	fmt.Fprintf(os.Stderr, "eval: %d services in %d exports; %d candidates fired; %d only where the truth agrees; %d denied\n", nsvc, len(exports), len(fires), len(good), len(rows))
	for _, g := range good {
		fmt.Fprintln(os.Stderr, "  correct: "+g)
	}
	return rows
}

func exportTag(path string) string {
	// e2e/zoo/out/before/03-devtools/export.json -> zoo:03-devtools; anything else is the lab.
	if i := strings.Index(path, "/zoo/out/"); i >= 0 {
		parts := strings.Split(path[i+len("/zoo/out/"):], "/")
		if len(parts) >= 2 {
			return "zoo:" + parts[1]
		}
	}
	return "lab"
}

func truthKey(tag, ip string, port int, proto string) string {
	if strings.HasPrefix(tag, "zoo:") {
		return fmt.Sprintf("%s|%d/%s", tag, port, proto)
	}
	return fmt.Sprintf("lab|%s:%d/%s", ip, port, proto)
}

func loadLabTruth(path string, truth map[string]truthSvc) {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("%v", err)
	}
	var gt labGT
	if err := json.Unmarshal(b, &gt); err != nil {
		fail("%s: %v", path, err)
	}
	for _, h := range gt.Hosts {
		for _, s := range h.Services {
			names := []string{s.Product, h.Desc}
			for _, t := range s.Techs {
				names = append(names, t.Name)
				names = append(names, t.Aliases...)
			}
			truth[fmt.Sprintf("lab|%s:%d/%s", h.IP, s.Port, s.Proto)] = truthSvc{names: clean(names), known: true}
		}
	}
}

func loadZooTruth(path string, truth map[string]truthSvc) {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("%v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 9 || strings.HasPrefix(line, "#") || f[0] == "batch" || strings.HasPrefix(f[0], "held") {
			continue
		}
		port, _ := strconv.Atoi(f[1])
		img := f[4]
		if i := strings.LastIndex(img, "/"); i >= 0 {
			img = img[i+1:]
		}
		img = strings.SplitN(img, ":", 2)[0]
		names := []string{img}
		names = append(names, strings.Split(f[6], "|")...)
		names = append(names, strings.Split(f[8], ",")...)
		if len(f) > 11 {
			for _, o := range strings.Split(f[11], ",") {
				if strings.HasPrefix(o, "tech:") {
					names = append(names, strings.TrimPrefix(o, "tech:"))
				}
			}
		}
		truth[fmt.Sprintf("zoo:%s|%d/%s", f[0], port, f[2])] = truthSvc{names: clean(names), known: true}
	}
}

func clean(xs []string) []string {
	var out []string
	for _, x := range xs {
		x = strings.Trim(strings.TrimSpace(x), "^$\\()?")
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// explains: the truth names the technology the signature reports.
func explains(tech, upstream string, names []string) bool {
	keys := []string{key(tech), key(strings.TrimSuffix(strings.TrimSuffix(upstream, "-detect"), "-panel"))}
	for _, n := range names {
		kn := key(n)
		for _, k := range keys {
			if len(k) < 3 || kn == "" {
				continue
			}
			if strings.Contains(kn, k) || (len(kn) >= 4 && strings.Contains(k, kn)) {
				return true
			}
		}
	}
	return false
}

func writeDeny(path string, rows []evalRow) {
	var b strings.Builder
	b.WriteString("# Imported signatures dropped by the offline evaluation (go run ./cmd/sigimport ... -eval <exports>).\n")
	b.WriteString("# id\treason\twhere it fired (first three)\n")
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, r := range rows {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", r.ID, r.Reason, r.Where)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail("%v", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		fail("%v", err)
	}
}
