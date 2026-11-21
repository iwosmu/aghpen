package sig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
)

// The nuclei converter reads the passive subset of nuclei HTTP templates:
// GET requests to fixed paths with word, regex and status matchers, the
// favicon hash idiom, and regex extractors for the version. Everything that
// is not presence detection is refused with a reason: another method, a
// request body, payloads, fuzzing, raw requests, custom headers, template
// variables and DSL helpers, and every protocol but HTTP. The result goes
// through the same compiler and safe-mode checks as a native signature.

var nucleiProtocols = []string{"dns", "tcp", "network", "file", "headless", "ssl", "websocket", "whois", "code", "javascript", "workflows", "flow", "cloud"}

// nucleiForbidden are request fields that make a template active.
var nucleiForbidden = map[string]string{
	"raw": "surowe żądania (raw)", "body": "treść żądania", "payloads": "ładunki (payloads)", "attack": "tryb ataku z ładunkami",
	"fuzzing": "fuzzing", "race": "wyścig żądań", "race_count": "wyścig żądań", "threads": "równoległe żądania",
	"pipeline": "potokowanie żądań", "unsafe": "tryb surowych, niepoprawnych żądań", "headers": "własne nagłówki żądania",
	"cookie_reuse": "ponowne wysyłanie ciasteczek", "req_condition": "warunki między żądaniami", "iterate_all": "iteracja ładunków",
	"digest_username": "dane logowania", "digest_password": "dane logowania", "self_contained": "żądania do innych hostów",
	"signature": "podpisywanie żądań", "pre_condition": "warunki wstępne DSL", "analyzer": "analizator fuzzingu",
}

func isNuclei(n *yaml.Node) bool {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return false
	}
	if info := mappingValue(n, "info"); info == nil || info.Kind != yaml.MappingNode {
		return false
	}
	for _, k := range append([]string{"http", "requests"}, nucleiProtocols...) {
		if mappingValue(n, k) != nil {
			return true
		}
	}
	return false
}

type nucleiMatcher struct {
	kind   string // word | regex | status | favicon
	header bool   // part: header
	words  []string
	regex  []string
	status []int
	mmh3   []int32
	and    bool
	neg    bool
	cs     bool
	ypath  string
	line   int
}

// convertNuclei turns a nuclei template into a signature definition. It
// records an error for everything it must refuse.
func (p *parser) convertNuclei(n *yaml.Node, prefix string) *Def {
	n = deref(n)
	m := p.asMap(n, prefix)
	at := func(k string) string { return join(prefix, k) }
	d := &Def{node: n, MinConfidence: DefaultMinConfidence, Category: model.CatOther}
	errorsBefore := p.errorCount()

	if v, k := m.get("id"); v != nil {
		d.ID = strings.TrimSpace(p.str(v, at(k)))
	}
	if d.ID != "" && !validSlug(d.ID) {
		d.ID = slugify(d.ID)
	}
	if d.ID == "" {
		p.errf(at("id"), n, "szablon nuclei nie ma pola id")
	}
	d.Name = d.ID
	if iv, ik := m.get("info"); iv != nil {
		info := p.asMap(iv, at(ik))
		ip := at(ik)
		if v, k := info.get("name"); v != nil {
			d.Name = strings.TrimSpace(p.str(v, join(ip, k)))
		}
		if v, k := info.get("author"); v != nil {
			d.Author = strings.Join(splitCommas(p.strList(v, join(ip, k))), ", ")
		}
		if v, k := info.get("description"); v != nil {
			d.Description = strings.TrimSpace(p.str(v, join(ip, k)))
		}
		if v, k := info.get("severity"); v != nil {
			d.Interest = severityInterest(p.str(v, join(ip, k)))
		}
		if v, k := info.get("tags"); v != nil {
			d.Tags = splitCommas(p.strList(v, join(ip, k)))
		}
		if cv, ck := info.get("classification"); cv != nil && cv.Kind == yaml.MappingNode {
			if v, k := p.asMap(cv, join(ip, ck)).get("cpe"); v != nil {
				if cpe := strings.TrimSpace(p.str(v, join(ip, ck+"."+k))); strings.HasPrefix(cpe, "cpe:2.3:") {
					// Keep "cpe:2.3:a:vendor:product"; the engine adds the detected version.
					if f := strings.Split(cpe, ":"); len(f) >= 5 {
						d.CPE = strings.Join(f[:5], ":")
					}
				}
			}
		}
	}
	if len(d.Name) > 120 {
		d.Name = d.Name[:120]
	}
	d.Category, d.Classes = nucleiCategory(d.Tags)
	if !strings.Contains(strings.Join(d.Tags, ","), "tech") && d.Category == model.CatEnvironment {
		d.NoTech = true
	}

	for _, proto := range nucleiProtocols {
		if v, k := m.get(proto); v != nil {
			p.unsafe(at(k), v, "szablon nuclei używa protokołu „%s”; Czujka konwertuje tylko pasywne żądania HTTP GET", proto)
		}
	}
	if v, k := m.get("variables"); v != nil {
		p.unsafe(at(k), v, "zmienne szablonu nuclei nie są obsługiwane: Czujka wysyła tylko stałe ścieżki")
	}
	rv, rk := m.get("http", "requests")
	if rv == nil {
		if p.errorCount() == errorsBefore {
			p.errf(prefix, n, "szablon nuclei nie ma sekcji http")
		}
		return nil
	}
	var blocks []*yaml.Node
	switch rv.Kind {
	case yaml.SequenceNode:
		blocks = rv.Content
	case yaml.MappingNode:
		blocks = []*yaml.Node{rv}
	default:
		p.errf(at(rk), rv, "sekcja http musi być listą żądań")
		return nil
	}

	// Count the alternatives (request × path): "required" rules are only
	// correct when there is exactly one.
	type block struct {
		paths    []string
		matchers []nucleiMatcher
		and      bool
		ypath    string
		node     *yaml.Node
		bm       *ymap
	}
	var parsed []block
	alternatives := 0
	for bi, bn := range blocks {
		bn = deref(bn)
		bp := fmt.Sprintf("%s[%d]", at(rk), bi)
		bm := p.asMap(bn, bp)
		if bm == nil {
			p.errf(bp, bn, "żądanie musi być mapą")
			continue
		}
		b := block{ypath: bp, node: bn, bm: bm}
		method := "GET"
		if v, k := bm.get("method"); v != nil {
			method = strings.ToUpper(strings.TrimSpace(p.str(v, join(bp, k))))
		}
		if method != "GET" && method != "HEAD" {
			p.unsafe(join(bp, "method"), bn, "metoda %s jest zabroniona: tryb bezpieczny dopuszcza tylko GET i HEAD", method)
		}
		for _, k := range bm.keys {
			if what, bad := nucleiForbidden[k]; bad {
				bm.used[k] = true
				p.unsafe(join(bp, k), bm.vals[k], "szablon nuclei używa pola „%s” (%s); Czujka konwertuje tylko pasywne żądania GET bez treści, nagłówków i ładunków", k, what)
			}
		}
		if v, k := bm.get("redirects", "host_redirects"); v != nil {
			if on, _ := p.boolean(v, join(bp, k)); on {
				p.warnf(join(bp, k), v, "Czujka nie podąża za przekierowaniami przy dodatkowych ścieżkach; dopasowanie dotyczy pierwszej odpowiedzi")
			}
		}
		for _, k := range []string{"max_redirects", "stop_at_first_match", "max_size", "read_all", "disable_cookie", "skip_variables_check", "name", "id", "disable_path_automerge"} {
			bm.used[k] = true
		}
		pv, pk := bm.get("path")
		if pv == nil {
			if !bm.has("raw") {
				p.errf(join(bp, "path"), bn, "żądanie nuclei nie ma pola path")
			}
		} else {
			for i, raw := range p.strList(pv, join(bp, pk)) {
				pp := fmt.Sprintf("%s[%d]", join(bp, pk), i)
				path := strings.TrimSpace(raw)
				switch {
				case strings.HasPrefix(path, "{{BaseURL}}"):
					path = strings.TrimPrefix(path, "{{BaseURL}}")
				case strings.HasPrefix(path, "{{RootURL}}"):
					path = strings.TrimPrefix(path, "{{RootURL}}")
				default:
					p.unsafe(pp, pv, "ścieżka „%s” musi zaczynać się od {{BaseURL}}: Czujka pyta tylko skanowaną usługę", clip(raw, 80))
					continue
				}
				if strings.Contains(path, "{{") {
					p.unsafe(pp, pv, "ścieżka „%s” używa zmiennych albo funkcji pomocniczych nuclei ({{...}}); Czujka wysyła tylko stałe ścieżki", clip(raw, 80))
					continue
				}
				if path == "" {
					path = "/"
				}
				b.paths = append(b.paths, path)
			}
		}
		if v, k := bm.get("matchers_condition"); v != nil {
			b.and = strings.EqualFold(strings.TrimSpace(p.str(v, join(bp, k))), "and")
		}
		if v, k := bm.get("matchers"); v != nil && v.Kind == yaml.SequenceNode {
			for i, mn := range v.Content {
				if nm, ok := p.nucleiMatcher(deref(mn), fmt.Sprintf("%s[%d]", join(bp, k), i)); ok {
					b.matchers = append(b.matchers, nm)
				}
			}
		} else {
			p.errf(join(bp, "matchers"), bn, "żądanie nuclei nie ma listy matchers: nie ma czego wykrywać")
		}
		alternatives += len(b.paths)
		parsed = append(parsed, b)
	}

	for _, b := range parsed {
		for _, path := range b.paths {
			d.Rules = append(d.Rules, p.nucleiRules(b.matchers, b.and, path, alternatives == 1, b.ypath)...)
		}
		// Extractors of type regex give the version.
		if v, k := b.bm.get("extractors"); v != nil && v.Kind == yaml.SequenceNode {
			for i, en := range v.Content {
				ep := fmt.Sprintf("%s[%d]", join(b.ypath, k), i)
				em := p.asMap(deref(en), ep)
				if em == nil {
					continue
				}
				typ := ""
				if tv, tk := em.get("type"); tv != nil {
					typ = normKey(p.str(tv, join(ep, tk)))
				}
				if typ != "regex" {
					p.warnf(ep, en, "ekstraktor nuclei typu „%s” został pominięty (obsługiwany: regex)", typ)
					continue
				}
				group := 0
				if gv, gk := em.get("group"); gv != nil {
					if f, ok := p.number(gv, join(ep, gk)); ok {
						group = int(f)
					}
				}
				header := false
				if pv, pk := em.get("part"); pv != nil {
					part := normKey(p.str(pv, join(ep, pk)))
					header = part == "header" || part == "all_headers"
				}
				xv, xk := em.get("regex")
				if xv == nil {
					continue
				}
				for _, pat := range p.strList(xv, join(ep, xk)) {
					re, err := regexp.Compile(pat)
					if err != nil || re.NumSubexp() == 0 {
						p.warnf(ep, en, "ekstraktor „%s” nie ma grupy w nawiasach z wersją; pominięto", clip(pat, 60))
						continue
					}
					if group == 0 {
						group = 1
					}
					for _, path := range b.paths {
						r := RuleDef{Regex: []string{pat}, VersionGroup: group, ypath: ep, line: en.Line}
						switch {
						case path == "/" && header:
							r.Type = TypeHeader
						case path == "/":
							r.Type = TypeBody
						case header:
							r.Type, r.Path, r.Field = TypePath, path, "header"
						default:
							r.Type, r.Path = TypePath, path
						}
						d.Version = append(d.Version, r)
					}
				}
			}
		}
	}
	if p.errorCount() != errorsBefore {
		return nil // refused: the reasons are in the issues
	}
	return d
}

// nucleiCategory picks a category and classes from the tags of a template.
func nucleiCategory(tags []string) (string, []string) {
	has := func(names ...string) bool {
		for _, t := range tags {
			for _, n := range names {
				if strings.EqualFold(t, n) {
					return true
				}
			}
		}
		return false
	}
	var classes []string
	if has("panel", "login") {
		classes = append(classes, model.ClassLogin)
	}
	switch {
	case has("iot", "camera", "router", "printer", "nas", "scada", "ics"):
		return model.CatIoT, classes
	case has("cms", "wordpress", "joomla", "drupal", "wp"):
		return model.CatCMS, classes
	case has("database", "db"):
		return model.CatDatabase, classes
	case has("devops", "ci", "cicd", "kubernetes", "docker"):
		return model.CatDevOps, classes
	case has("panel", "login"):
		return model.CatPanel, classes
	case has("exposure", "debug", "misconfig", "config", "listing"):
		return model.CatEnvironment, classes
	}
	return model.CatOther, classes
}

var (
	// "-123" == mmh3(base64_py(body)), in either order.
	nucleiFaviconRe = regexp.MustCompile(`\(?\s*(?:["'](-?[0-9]{1,11})["']\s*==\s*mmh3\(base64_py\(body\)\)|mmh3\(base64_py\(body\)\)\s*==\s*["'](-?[0-9]{1,11})["'])\s*\)?`)
	nucleiStatusRe  = regexp.MustCompile(`status_code\s*==\s*200`)
)

// faviconDSL reads the one DSL idiom that is passive: comparing the favicon
// hash. It returns false for every other expression.
func faviconDSL(expr string) ([]int32, bool) {
	var out []int32
	for _, m := range nucleiFaviconRe.FindAllStringSubmatch(expr, -1) {
		num := m[1]
		if num == "" {
			num = m[2]
		}
		i, err := strconv.ParseInt(num, 10, 32)
		if err != nil {
			return nil, false
		}
		out = append(out, int32(i))
	}
	rest := nucleiFaviconRe.ReplaceAllString(expr, "")
	rest = nucleiStatusRe.ReplaceAllString(rest, "")
	rest = strings.NewReplacer("&&", "", "||", "", "(", "", ")", "", " ", "", "\t", "", "\n", "").Replace(rest)
	return out, len(out) > 0 && rest == ""
}

func (p *parser) nucleiMatcher(n *yaml.Node, path string) (nucleiMatcher, bool) {
	nm := nucleiMatcher{ypath: path, cs: true}
	m := p.asMap(n, path)
	if m == nil {
		p.errf(path, n, "dopasowanie nuclei musi być mapą")
		return nm, false
	}
	nm.line = n.Line
	typ := ""
	if v, k := m.get("type"); v != nil {
		typ = normKey(p.str(v, join(path, k)))
	}
	part := "body"
	if v, k := m.get("part"); v != nil {
		part = normKey(p.str(v, join(path, k)))
	}
	switch part {
	case "body", "response", "all", "raw", "data", "":
	case "header", "all_headers":
		nm.header = true
	default:
		if strings.HasPrefix(part, "interactsh") {
			p.unsafe(join(path, "part"), n, "dopasowanie „%s” wymaga serwera zewnętrznego (interactsh): to nie jest pasywna detekcja", part)
		} else {
			p.errf(join(path, "part"), n, "część odpowiedzi „%s” nie jest obsługiwana (obsługiwane: body, header, all)", part)
		}
		return nm, false
	}
	if v, k := m.get("condition"); v != nil {
		nm.and = strings.EqualFold(strings.TrimSpace(p.str(v, join(path, k))), "and")
	}
	if v, k := m.get("negative"); v != nil {
		nm.neg, _ = p.boolean(v, join(path, k))
	}
	if v, k := m.get("case_insensitive"); v != nil {
		if b, ok := p.boolean(v, join(path, k)); ok {
			nm.cs = !b
		}
	}
	m.get("internal", "name", "encoding", "match_all")
	for _, k := range []string{"internal", "name", "encoding", "match_all"} {
		m.used[k] = true
	}
	helpers := func(vals []string, key string) bool {
		for _, s := range vals {
			if strings.Contains(s, "{{") {
				p.unsafe(join(path, key), n, "dopasowanie używa zmiennych albo funkcji pomocniczych nuclei ({{...}}), których Czujka nie wykonuje")
				return true
			}
		}
		return false
	}
	switch typ {
	case "word":
		v, k := m.get("words")
		if v == nil {
			p.errf(path, n, "dopasowanie word nie ma listy words")
			return nm, false
		}
		nm.kind, nm.words = "word", p.strList(v, join(path, k))
		if helpers(nm.words, k) {
			return nm, false
		}
	case "regex":
		v, k := m.get("regex")
		if v == nil {
			p.errf(path, n, "dopasowanie regex nie ma listy regex")
			return nm, false
		}
		nm.kind, nm.regex = "regex", p.strList(v, join(path, k))
		if helpers(nm.regex, k) {
			return nm, false
		}
	case "status":
		v, k := m.get("status")
		if v == nil {
			p.errf(path, n, "dopasowanie status nie ma listy status")
			return nm, false
		}
		nm.kind, nm.status = "status", p.intList(v, join(path, k))
	case "dsl":
		v, k := m.get("dsl")
		nm.kind = "favicon"
		for _, expr := range p.strList(v, join(path, k)) {
			hashes, ok := faviconDSL(expr)
			if !ok {
				p.unsafe(join(path, k), n, "wyrażenie DSL nuclei „%s” nie jest obsługiwane: Czujka nie wykonuje funkcji pomocniczych (wyjątek: porównanie skrótu ikony mmh3(base64_py(body)))", clip(expr, 80))
				return nm, false
			}
			nm.mmh3 = append(nm.mmh3, hashes...)
		}
		if len(nm.mmh3) == 0 {
			return nm, false
		}
	default:
		p.errf(join(path, "type"), n, "typ dopasowania nuclei „%s” nie jest obsługiwany (obsługiwane: word, regex, status oraz dsl ze skrótem ikony)", typ)
		return nm, false
	}
	p.unknownKeys(m, path)
	return nm, true
}

// nucleiRules turns the matchers of one request and one path into rules.
// single is true when the template has exactly one request and one path.
func (p *parser) nucleiRules(ms []nucleiMatcher, and bool, path string, single bool, ypath string) []RuleDef {
	root := path == "/"
	var out []RuleDef
	text := func(nm *nucleiMatcher) RuleDef {
		r := RuleDef{CaseSensitive: nm.cs, ypath: nm.ypath, line: nm.line}
		switch {
		case root && nm.header:
			r.Type = TypeHeader
		case root:
			r.Type = TypeBody
		case nm.header:
			r.Type, r.Path, r.Field = TypePath, path, "header"
		default:
			r.Type, r.Path = TypePath, path
		}
		if nm.kind == "word" {
			if nm.and {
				r.ContainsAll = nm.words
			} else {
				r.Contains = nm.words
			}
		} else {
			r.Regex = nm.regex
		}
		return r
	}
	statusRule := func(nm *nucleiMatcher) RuleDef {
		if root {
			return RuleDef{Type: TypeStatus, Status: nm.status, ypath: nm.ypath, line: nm.line}
		}
		return RuleDef{Type: TypePath, Path: path, Status: nm.status, ypath: nm.ypath, line: nm.line}
	}

	var pos, neg []*nucleiMatcher
	var status []int
	for i := range ms {
		nm := &ms[i]
		switch {
		case nm.kind == "favicon":
			// Czujka computes the favicon hash itself; the rule does not depend on the path.
			out = append(out, RuleDef{Type: TypeFavicon, MMH3: nm.mmh3, Weight: 0.9, ypath: nm.ypath, line: nm.line})
		case nm.neg && nm.kind != "status":
			neg = append(neg, nm)
		case nm.kind == "status" && !nm.neg:
			status = append(status, nm.status...)
			pos = append(pos, nm)
		case !nm.neg:
			pos = append(pos, nm)
		}
	}
	for _, nm := range neg {
		r := text(nm)
		r.Not = true
		out = append(out, r)
	}

	if !and {
		// Any matcher is enough: one rule each.
		for _, nm := range pos {
			if nm.kind == "status" {
				r := statusRule(nm)
				r.Weight = 0.3
				out = append(out, r)
				continue
			}
			r := text(nm)
			r.Weight = 0.8
			out = append(out, r)
		}
		return out
	}

	// Every matcher must hold. Try to fold them into one rule.
	var texts []*nucleiMatcher
	for _, nm := range pos {
		if nm.kind != "status" {
			texts = append(texts, nm)
		}
	}
	merged, ok := RuleDef{}, len(texts) > 0
	anyWords, anyRegex := 0, 0
	for i, nm := range texts {
		if i == 0 {
			merged = text(nm)
			merged.Contains, merged.ContainsAll, merged.Regex = nil, nil, nil
		} else if nm.header != texts[0].header || nm.cs != texts[0].cs {
			ok = false
		}
		switch {
		case nm.kind == "word" && (nm.and || len(nm.words) == 1):
			merged.ContainsAll = append(merged.ContainsAll, nm.words...)
		case nm.kind == "word":
			merged.Contains = nm.words
			anyWords++
		case nm.kind == "regex" && (!nm.and || len(nm.regex) == 1):
			merged.Regex = nm.regex
			anyRegex++
		default:
			ok = false
		}
	}
	if anyWords > 1 || anyRegex > 1 {
		ok = false
	}
	switch {
	case ok && !root:
		merged.Status, merged.Weight = status, 0.9
		out = append(out, merged)
	case ok && root:
		merged.Weight = 0.9
		if len(status) > 0 && single {
			merged.Required = true
			out = append(out, merged, RuleDef{Type: TypeStatus, Status: status, Required: true, ypath: ypath})
		} else {
			if len(status) > 0 {
				p.warnf(ypath, nil, "warunek statusu strony głównej pominięto: szablon ma kilka żądań albo ścieżek")
			}
			out = append(out, merged)
		}
	case len(texts) == 0 && len(status) > 0:
		out = append(out, statusRule(&nucleiMatcher{status: status, ypath: ypath}))
	case single:
		// Not foldable: separate rules, every one required.
		for _, nm := range texts {
			r := text(nm)
			r.Required, r.Weight = true, 0.6
			if !root {
				r.Status = status
			}
			out = append(out, r)
		}
		if root && len(status) > 0 {
			out = append(out, RuleDef{Type: TypeStatus, Status: status, Required: true, ypath: ypath})
		}
	default:
		p.errf(ypath, nil, "warunki „and” tego żądania są zbyt złożone dla kilku ścieżek; podziel szablon na osobne sygnatury")
	}
	return out
}
