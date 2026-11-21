// Package sig is the signature engine of Czujka: a small YAML DSL for passive
// detection rules, a safe-mode validator, a fast matcher, a classifier and a
// retro-hunt over stored observations. It implements model.SignatureEngine.
//
// The DSL is documented in docs/SIGNATURES.md.
package sig

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
)

// Limits of one signature. They keep a signature cheap and passive.
const (
	MaxRequestsPerSignature = 5
	MaxRulesPerSignature    = 60
	MaxRegexLen             = 500
	MaxLiteralLen           = 500
	MaxPathLen              = 200
	MaxSignaturesPerFile    = 2000
	MaxYAMLBytes            = 1 << 20
	DefaultMinConfidence    = 0.3
)

// Rule types of the DSL.
const (
	TypeHeader   = "header"
	TypeCookie   = "cookie"
	TypeBody     = "body"
	TypeTitle    = "title"
	TypeMeta     = "meta"
	TypeFavicon  = "favicon"
	TypePath     = "path"
	TypeStatus   = "status"
	TypeBanner   = "banner"
	TypeService  = "service"
	TypeTLS      = "tls"
	TypeURL      = "url"
	TypeRedirect = "redirect"
	TypeHostname = "hostname"
)

// defaultWeights are used when a rule gives no weight.
var defaultWeights = map[string]float64{
	TypeFavicon: 0.9, TypePath: 0.8, TypeMeta: 0.8, TypeService: 0.7, TypeHeader: 0.6,
	TypeCookie: 0.6, TypeBanner: 0.6, TypeTitle: 0.5, TypeTLS: 0.5, TypeBody: 0.4,
	TypeURL: 0.4, TypeRedirect: 0.4, TypeHostname: 0.3, TypeStatus: 0.3,
}

var typeAliases = map[string]string{
	"headers": TypeHeader, "cookies": TypeCookie, "html": TypeBody, "content": TypeBody, "response": TypeBody,
	"generator": TypeMeta, "icon": TypeFavicon, "favicon_hash": TypeFavicon, "request": TypePath,
	"status_code": TypeStatus, "code": TypeStatus, "nmap": TypeService, "cert": TypeTLS, "certificate": TypeTLS,
	"ssl": TypeTLS, "location": TypeRedirect, "host": TypeHostname, "final_url": TypeURL,
}

func canonType(t string) (string, bool) {
	t = normKey(t)
	if a, ok := typeAliases[t]; ok {
		t = a
	}
	_, ok := defaultWeights[t]
	return t, ok
}

var validCategories = map[string]bool{
	model.CatCMS: true, model.CatFramework: true, model.CatAppServer: true, model.CatWebServer: true,
	model.CatIoT: true, model.CatPanel: true, model.CatDatabase: true, model.CatDevOps: true,
	model.CatLanguage: true, model.CatProxy: true, model.CatSecurity: true, model.CatOS: true,
	model.CatLibrary: true, model.CatEnvironment: true, model.CatHeader: true, model.CatCookie: true,
	model.CatOther: true,
}

var validClasses = map[string]bool{
	model.ClassAdminPanel: true, model.ClassLogin: true, model.ClassStaging: true, model.ClassIoT: true,
	model.ClassDefaultPage: true, model.ClassAPI: true, model.ClassDevTool: true, model.ClassDatabase: true,
	model.ClassRemoteAccess: true, model.ClassDirListing: true, model.ClassErrorPage: true,
}

// Def is one parsed signature, before compilation.
type Def struct {
	ID            string
	Name          string
	Category      string
	Description   string
	Author        string
	CPE           string
	Technology    string // technology name this signature supports; default Name
	NoTech        bool   // true: a finding, not a technology
	Disabled      bool   // "enabled: false" in the YAML: off until someone turns it on
	Tags          []string
	Classes       []string
	Implies       []string
	Aliases       []string
	Interest      int
	Requests      []string
	All           bool // condition: all
	MinConfidence float64
	Rules         []RuleDef
	Version       []RuleDef

	node *yaml.Node
}

// RuleDef is one rule of a signature.
type RuleDef struct {
	Type          string
	Name          string   // header, cookie or meta name
	NameRegex     string   // header or cookie name pattern
	Field         string   // part of the target: tls subject|issuer|san|org, service name|product|version, path body|title|header|location
	Path          string   // path rule: the extra path
	Status        []int    // status rule and path rule
	Contains      []string // any of
	ContainsAll   []string // every one of
	Regex         []string // any of
	Equals        []string // any of
	Exists        bool
	Absent        bool
	MMH3          []int32
	SHA256        []string
	Secure        *bool
	HTTPOnly      *bool
	SameSite      *string
	CaseSensitive bool
	Not           bool
	Required      bool
	Weight        float64
	VersionGroup  int

	ypath string
	line  int
}

// parser collects issues while it walks the YAML tree.
type parser struct {
	issues []model.SignatureIssue
}

func (p *parser) add(level string, safety bool, path string, n *yaml.Node, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if n != nil && n.Line > 0 {
		msg += fmt.Sprintf(" (wiersz %d)", n.Line)
	}
	p.issues = append(p.issues, model.SignatureIssue{Level: level, Path: path, Message: msg, Safety: safety})
}

func (p *parser) errf(path string, n *yaml.Node, format string, args ...any) {
	p.add("error", false, path, n, format, args...)
}

func (p *parser) warnf(path string, n *yaml.Node, format string, args ...any) {
	p.add("warning", false, path, n, format, args...)
}

func (p *parser) unsafe(path string, n *yaml.Node, format string, args ...any) {
	p.add("error", true, path, n, format, args...)
}

func (p *parser) errorCount() int {
	n := 0
	for _, i := range p.issues {
		if i.Level == "error" {
			n++
		}
	}
	return n
}

func (p *parser) hasErrors() bool { return p.errorCount() > 0 }

func normKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.NewReplacer("-", "_", " ", "_").Replace(k)
	return k
}

func deref(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 8; i++ {
		n = n.Alias
	}
	return n
}

// ymap is a YAML mapping with normalised keys.
type ymap struct {
	keys []string
	vals map[string]*yaml.Node
	used map[string]bool
}

func (p *parser) asMap(n *yaml.Node, path string) *ymap {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	m := &ymap{vals: map[string]*yaml.Node{}, used: map[string]bool{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := normKey(n.Content[i].Value)
		if _, dup := m.vals[k]; dup {
			p.warnf(join(path, k), n.Content[i], "pole „%s” występuje dwa razy; użyto pierwszej wartości", k)
			continue
		}
		m.keys = append(m.keys, k)
		m.vals[k] = deref(n.Content[i+1])
	}
	return m
}

// get returns the first of the aliases that is present.
func (m *ymap) get(names ...string) (*yaml.Node, string) {
	for _, k := range names {
		if v, ok := m.vals[k]; ok {
			m.used[k] = true
			return v, k
		}
	}
	return nil, ""
}

func (m *ymap) has(names ...string) bool {
	for _, k := range names {
		if _, ok := m.vals[k]; ok {
			return true
		}
	}
	return false
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	if strings.HasPrefix(key, "[") {
		return path + key
	}
	return path + "." + key
}

func isNull(n *yaml.Node) bool {
	return n == nil || n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func (p *parser) str(n *yaml.Node, path string) string {
	if isNull(n) {
		return ""
	}
	if n.Kind != yaml.ScalarNode {
		p.errf(path, n, "oczekiwano tekstu")
		return ""
	}
	return n.Value
}

func (p *parser) strList(n *yaml.Node, path string) []string {
	if isNull(n) {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for i, c := range n.Content {
			c = deref(c)
			if c.Kind != yaml.ScalarNode {
				p.errf(fmt.Sprintf("%s[%d]", path, i), c, "oczekiwano tekstu")
				continue
			}
			out = append(out, c.Value)
		}
		return out
	}
	p.errf(path, n, "oczekiwano tekstu albo listy tekstów")
	return nil
}

func (p *parser) intList(n *yaml.Node, path string) []int {
	var out []int
	for i, s := range p.strList(n, path) {
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			p.errf(fmt.Sprintf("%s[%d]", path, i), n, "„%s” nie jest liczbą całkowitą", s)
			continue
		}
		out = append(out, v)
	}
	return out
}

func (p *parser) number(n *yaml.Node, path string) (float64, bool) {
	if isNull(n) {
		return 0, false
	}
	if n.Kind != yaml.ScalarNode {
		p.errf(path, n, "oczekiwano liczby")
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(n.Value), 64)
	if err != nil {
		p.errf(path, n, "„%s” nie jest liczbą", n.Value)
		return 0, false
	}
	return v, true
}

func (p *parser) boolean(n *yaml.Node, path string) (bool, bool) {
	if isNull(n) {
		return false, false
	}
	if n.Kind == yaml.ScalarNode {
		switch strings.ToLower(strings.TrimSpace(n.Value)) {
		case "true", "yes", "y", "on", "1", "tak":
			return true, true
		case "false", "no", "n", "off", "0", "nie":
			return false, true
		}
	}
	p.errf(path, n, "oczekiwano wartości true albo false")
	return false, false
}

// splitDocuments returns the signature mappings of a YAML text. It accepts a
// single signature, a list of signatures, a mapping with a "signatures" list
// and a multi-document stream.
func (p *parser) splitDocuments(src string) []*yaml.Node {
	if len(src) > MaxYAMLBytes {
		p.errf("", nil, "plik sygnatur jest za duży (limit %d bajtów)", MaxYAMLBytes)
		return nil
	}
	if strings.TrimSpace(src) == "" {
		p.errf("", nil, "pusta sygnatura")
		return nil
	}
	dec := yaml.NewDecoder(strings.NewReader(src))
	var out []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.errf("", nil, "błąd składni YAML: %s", err.Error())
			return nil
		}
		root := deref(&doc)
		if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
			root = deref(root.Content[0])
		}
		switch root.Kind {
		case yaml.SequenceNode:
			out = append(out, root.Content...)
		case yaml.MappingNode:
			if list := mappingValue(root, "signatures"); list != nil && list.Kind == yaml.SequenceNode {
				out = append(out, list.Content...)
			} else {
				out = append(out, root)
			}
		default:
			if !isNull(root) {
				p.errf("", root, "sygnatura musi być mapą YAML (klucz: wartość)")
			}
		}
		if len(out) > MaxSignaturesPerFile {
			p.errf("", nil, "za dużo sygnatur w jednym pliku (limit %d)", MaxSignaturesPerFile)
			return nil
		}
	}
	if len(out) == 0 && !p.hasErrors() {
		p.errf("", nil, "pusta sygnatura")
	}
	return out
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if normKey(n.Content[i].Value) == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
}

var topLevelKeys = []string{"references", "reference", "refs", "severity", "license", "created", "updated", "version_note"}

// parseDef reads one signature mapping. prefix is the YAML path prefix
// ("" for a single signature, "[3]" inside a list).
func (p *parser) parseDef(n *yaml.Node, prefix string) *Def {
	n = deref(n)
	m := p.asMap(n, prefix)
	if m == nil {
		p.errf(prefix, n, "sygnatura musi być mapą YAML (klucz: wartość)")
		return nil
	}
	at := func(k string) string { return join(prefix, k) }
	d := &Def{node: n, MinConfidence: DefaultMinConfidence}

	if v, k := m.get("id", "slug"); v != nil {
		d.ID = strings.TrimSpace(p.str(v, at(k)))
	}
	if v, k := m.get("name"); v != nil {
		d.Name = strings.TrimSpace(p.str(v, at(k)))
	}
	if d.ID == "" && d.Name != "" {
		d.ID = slugify(d.Name)
		p.warnf(at("id"), n, "brak pola id; przyjęto „%s” na podstawie nazwy", d.ID)
	}
	if d.Name == "" && d.ID != "" {
		d.Name = d.ID
		p.warnf(at("name"), n, "brak pola name; przyjęto id „%s”", d.ID)
	}
	if d.ID == "" {
		p.errf(at("id"), n, "brak pola id (krótki identyfikator, np. wordpress)")
	} else if !validSlug(d.ID) {
		p.errf(at("id"), n, "id „%s” jest niepoprawne: dozwolone małe litery, cyfry, „-”, „_” i „.”, do 64 znaków", d.ID)
	}
	if len(d.Name) > 120 {
		p.errf(at("name"), n, "nazwa jest za długa (limit 120 znaków)")
	}

	if v, k := m.get("category"); v != nil {
		d.Category = normKey(p.str(v, at(k)))
		d.Category = strings.ReplaceAll(d.Category, "_", "-")
	}
	if d.Category == "" {
		d.Category = model.CatOther
	} else if !validCategories[d.Category] {
		p.warnf(at("category"), n, "nieznana kategoria „%s”; przyjęto „other”. Dozwolone: %s", d.Category, strings.Join(sortedKeys(validCategories), ", "))
		d.Category = model.CatOther
	}
	if v, k := m.get("description", "desc", "info"); v != nil {
		d.Description = strings.TrimSpace(p.str(v, at(k)))
	}
	if v, k := m.get("author"); v != nil {
		d.Author = p.str(v, at(k))
	}
	if v, k := m.get("cpe"); v != nil {
		d.CPE = strings.TrimSpace(p.str(v, at(k)))
		if d.CPE != "" && !strings.HasPrefix(d.CPE, "cpe:") {
			p.warnf(at(k), v, "cpe powinno zaczynać się od „cpe:”")
		}
	}
	if v, k := m.get("tags"); v != nil {
		d.Tags = cleanList(p.strList(v, at(k)))
	}
	if v, k := m.get("implies"); v != nil {
		d.Implies = cleanList(p.strList(v, at(k)))
	}
	if v, k := m.get("aliases", "alias"); v != nil {
		d.Aliases = cleanList(p.strList(v, at(k)))
	}
	if v, k := m.get("classes", "class"); v != nil {
		for i, c := range cleanList(p.strList(v, at(k))) {
			c = strings.ReplaceAll(normKey(c), "_", "-")
			if !validClasses[c] {
				p.warnf(fmt.Sprintf("%s[%d]", at(k), i), v, "nieznana klasa „%s” została pominięta. Dozwolone: %s", c, strings.Join(sortedKeys(validClasses), ", "))
				continue
			}
			d.Classes = append(d.Classes, c)
		}
	}
	if v, k := m.get("interest", "priority"); v != nil {
		if f, ok := p.number(v, at(k)); ok {
			if f < 0 || f > 100 {
				p.errf(at(k), v, "interest musi być liczbą od 0 do 100")
			} else {
				d.Interest = int(f)
			}
		}
	}
	if v, k := m.get("technology", "tech"); v != nil {
		if v.Kind == yaml.ScalarNode && v.Tag == "!!bool" {
			b, _ := p.boolean(v, at(k))
			d.NoTech = !b
		} else {
			d.Technology = strings.TrimSpace(p.str(v, at(k)))
		}
	}
	if v, k := m.get("enabled"); v != nil {
		if b, ok := p.boolean(v, at(k)); ok {
			d.Disabled = !b
		}
	}
	m.get(topLevelKeys...)
	for _, k := range topLevelKeys {
		m.used[k] = true
	}

	// Extra requests.
	if v, k := m.get("requests", "request", "paths"); v != nil {
		d.Requests = p.parseRequests(v, at(k))
	}

	// Rules: match.rules, match as a list, top-level rules, and the short form.
	if v, k := m.get("match", "matchers", "rules"); v != nil {
		switch v.Kind {
		case yaml.SequenceNode:
			d.Rules = append(d.Rules, p.parseRuleList(v, at(k), "")...)
		case yaml.MappingNode:
			mm := p.asMap(v, at(k))
			p.parseMatchOptions(mm, at(k), d)
			if rv, rk := mm.get("rules", "matchers", "any", "all"); rv != nil {
				if rk == "all" {
					d.All = true
				}
				d.Rules = append(d.Rules, p.parseRuleList(rv, join(at(k), rk), "")...)
			}
			p.unknownKeys(mm, at(k))
		default:
			p.errf(at(k), v, "pole match musi być mapą (condition, min_confidence, rules) albo listą reguł")
		}
	}
	p.parseMatchOptions(m, prefix, d)
	for _, k := range m.keys {
		if m.used[k] {
			continue
		}
		typ, ok := canonType(k)
		if !ok {
			continue
		}
		m.used[k] = true
		d.Rules = append(d.Rules, p.parseShort(m.vals[k], at(k), typ, k)...)
	}

	if v, k := m.get("version", "versions"); v != nil {
		d.Version = p.parseRuleList(v, at(k), "")
		for i := range d.Version {
			if d.Version[i].VersionGroup == 0 {
				d.Version[i].VersionGroup = 1
			}
		}
	}
	p.unknownKeys(m, prefix)
	return d
}

func (p *parser) parseMatchOptions(m *ymap, path string, d *Def) {
	if v, k := m.get("condition", "mode", "operator"); v != nil {
		switch strings.ToLower(strings.TrimSpace(p.str(v, join(path, k)))) {
		case "any", "or", "":
			d.All = false
		case "all", "and":
			d.All = true
		default:
			p.errf(join(path, k), v, "condition musi mieć wartość any albo all")
		}
	}
	if v, k := m.get("min_confidence", "threshold"); v != nil {
		if f, ok := p.number(v, join(path, k)); ok {
			if f < 0 || f > 1 {
				p.errf(join(path, k), v, "min_confidence musi być liczbą od 0 do 1")
			} else {
				d.MinConfidence = f
			}
		}
	}
}

func (p *parser) unknownKeys(m *ymap, path string) {
	for _, k := range m.keys {
		if !m.used[k] {
			p.warnf(join(path, k), m.vals[k], "nieznane pole „%s” zostało pominięte", k)
		}
	}
}

// forbiddenRequestKeys are request features that are not passive detection.
var forbiddenRequestKeys = map[string]string{
	"body": "treść żądania", "data": "treść żądania", "payload": "treść żądania", "json": "treść żądania",
	"form": "treść żądania", "raw": "surowe żądanie", "headers": "własne nagłówki", "header": "własne nagłówki",
	"cookies": "własne ciasteczka", "cookie": "własne ciasteczka", "auth": "dane logowania",
	"username": "dane logowania", "user": "dane logowania", "password": "dane logowania",
	"authorization": "dane logowania", "token": "dane logowania", "credentials": "dane logowania",
	"follow_redirects": "podążanie za przekierowaniami", "redirects": "podążanie za przekierowaniami",
	"url": "pełny adres URL", "host": "inny host", "port": "inny port", "scheme": "inny protokół",
	"params": "parametry żądania", "query": "parametry żądania", "fuzz": "fuzzing", "attack": "atak",
	"payloads": "ładunki", "threads": "równoległość", "race": "wyścig żądań", "iterate": "iteracja ładunków",
}

func (p *parser) parseRequests(n *yaml.Node, path string) []string {
	var items []*yaml.Node
	switch n.Kind {
	case yaml.SequenceNode:
		items = n.Content
	case yaml.ScalarNode, yaml.MappingNode:
		items = []*yaml.Node{n}
	default:
		p.errf(path, n, "requests musi być listą ścieżek")
		return nil
	}
	var out []string
	for i, it := range items {
		it = deref(it)
		ip := fmt.Sprintf("%s[%d]", path, i)
		switch it.Kind {
		case yaml.ScalarNode:
			out = append(out, strings.TrimSpace(it.Value))
		case yaml.MappingNode:
			rm := p.asMap(it, ip)
			if v, k := rm.get("method"); v != nil {
				meth := strings.ToUpper(strings.TrimSpace(p.str(v, join(ip, k))))
				if meth != "GET" && meth != "HEAD" {
					p.unsafe(join(ip, k), v, "metoda %s jest zabroniona: tryb bezpieczny dopuszcza tylko GET i HEAD", meth)
				}
			}
			pv, pk := rm.get("path")
			if pv == nil {
				p.errf(ip, it, "żądanie musi mieć pole path")
			} else {
				out = append(out, strings.TrimSpace(p.str(pv, join(ip, pk))))
			}
			for _, k := range rm.keys {
				if rm.used[k] {
					continue
				}
				if what, bad := forbiddenRequestKeys[k]; bad {
					p.unsafe(join(ip, k), rm.vals[k], "pole „%s” (%s) jest zabronione: sygnatura może wysłać tylko GET lub HEAD bez treści, nagłówków i danych logowania", k, what)
				} else {
					p.unsafe(join(ip, k), rm.vals[k], "nieznane pole żądania „%s”: dozwolone są tylko path i method", k)
				}
			}
		default:
			p.errf(ip, it, "żądanie musi być ścieżką albo mapą z polem path")
		}
	}
	return out
}

func (p *parser) parseRuleList(n *yaml.Node, path, typ string) []RuleDef {
	n = deref(n)
	var items []*yaml.Node
	switch n.Kind {
	case yaml.SequenceNode:
		items = n.Content
	case yaml.MappingNode:
		items = []*yaml.Node{n}
	default:
		p.errf(path, n, "oczekiwano listy reguł")
		return nil
	}
	var out []RuleDef
	for i, it := range items {
		ip := path
		if n.Kind == yaml.SequenceNode {
			ip = fmt.Sprintf("%s[%d]", path, i)
		}
		if r, ok := p.parseRule(deref(it), ip, typ); ok {
			out = append(out, r)
		}
	}
	return out
}

// ruleKeys are the fields a rule mapping can have. They tell a rule mapping
// from a Wappalyzer-style "name: pattern" mapping in the short form.
var ruleKeys = []string{
	"type", "name", "name_regex", "field", "part", "in", "path", "status", "contains", "contains_all",
	"regex", "equals", "exists", "absent", "mmh3", "sha256", "secure", "http_only", "httponly",
	"same_site", "samesite", "case_sensitive", "not", "required", "weight", "version_group", "group",
	"word", "words", "pattern", "value", "value_regex", "missing", "present", "negative",
}

// parseShort reads a short-form rule: a top-level key named after a rule type.
func (p *parser) parseShort(n *yaml.Node, path, typ, key string) []RuleDef {
	n = deref(n)
	switch n.Kind {
	case yaml.ScalarNode:
		if r, ok := p.shortScalar(n, path, typ); ok {
			return []RuleDef{r}
		}
		return nil
	case yaml.SequenceNode:
		var out []RuleDef
		for i, it := range n.Content {
			out = append(out, p.parseShort(it, fmt.Sprintf("%s[%d]", path, i), typ, key)...)
		}
		return out
	case yaml.MappingNode:
		m := p.asMap(n, path)
		if m.has(ruleKeys...) {
			if r, ok := p.parseRule(n, path, typ); ok {
				return []RuleDef{r}
			}
			return nil
		}
		// "headers: {Server: '^nginx'}": every entry is name → pattern ("" means: exists).
		if typ != TypeHeader && typ != TypeCookie && typ != TypeMeta {
			p.errf(path, n, "reguła „%s” nie ma żadnego znanego pola (contains, regex, equals ...)", key)
			return nil
		}
		var out []RuleDef
		for _, k := range m.keys {
			v := m.vals[k]
			r := RuleDef{Type: typ, ypath: join(path, k), line: v.Line}
			// Header and cookie names keep their spelling from the YAML node.
			r.Name = originalKey(n, k)
			if pat := strings.TrimSpace(p.str(v, join(path, k))); pat != "" {
				r.Regex = []string{pat}
				r.VersionGroup = -1 // use group 1 as the version when the pattern has one
			} else {
				r.Exists = true
			}
			out = append(out, r)
		}
		return out
	}
	p.errf(path, n, "niepoprawna reguła „%s”", key)
	return nil
}

func originalKey(n *yaml.Node, norm string) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if normKey(n.Content[i].Value) == norm {
			return strings.TrimSpace(n.Content[i].Value)
		}
	}
	return norm
}

// shortScalar turns "body: wp-content/" and friends into a rule.
func (p *parser) shortScalar(n *yaml.Node, path, typ string) (RuleDef, bool) {
	r := RuleDef{Type: typ, ypath: path, line: n.Line}
	v := strings.TrimSpace(n.Value)
	if v == "" {
		p.errf(path, n, "pusta reguła")
		return r, false
	}
	switch typ {
	case TypeHeader:
		// "Server: nginx" → header Server contains nginx; "X-Jenkins" → header exists.
		if name, val, ok := strings.Cut(v, ":"); ok && strings.TrimSpace(val) != "" {
			r.Name, r.Contains = strings.TrimSpace(name), []string{strings.TrimSpace(val)}
		} else {
			r.Name, r.Exists = strings.TrimSuffix(v, ":"), true
		}
	case TypeCookie:
		r.Name, r.Exists = v, true
	case TypeFavicon:
		if i, err := strconv.ParseInt(v, 10, 32); err == nil {
			r.MMH3 = []int32{int32(i)}
		} else {
			r.SHA256 = []string{v}
		}
	case TypeStatus:
		i, err := strconv.Atoi(v)
		if err != nil {
			p.errf(path, n, "status musi być liczbą")
			return r, false
		}
		r.Status = []int{i}
	case TypePath:
		r.Path, r.Status = v, []int{200}
	case TypeMeta:
		r.Name, r.Contains = "generator", []string{v}
	default:
		r.Contains = []string{v}
	}
	return r, true
}

func (p *parser) parseRule(n *yaml.Node, path, typ string) (RuleDef, bool) {
	r := RuleDef{ypath: path}
	if n != nil {
		r.line = n.Line
	}
	if n != nil && n.Kind == yaml.ScalarNode && typ != "" {
		return p.shortScalar(n, path, typ)
	}
	m := p.asMap(n, path)
	if m == nil {
		p.errf(path, n, "reguła musi być mapą, np. {type: body, contains: 'tekst'}")
		return r, false
	}
	at := func(k string) string { return join(path, k) }

	if v, k := m.get("type"); v != nil {
		t, ok := canonType(p.str(v, at(k)))
		if !ok {
			p.errf(at(k), v, "nieznany typ reguły „%s”. Dozwolone: %s", v.Value, strings.Join(sortedKeys(defaultWeights), ", "))
			return r, false
		}
		typ = t
	}
	if typ == "" {
		// A rule without a type that names a path is a path rule; one that names a header is a header rule.
		switch {
		case m.has("path"):
			typ = TypePath
		case m.has("mmh3", "sha256"):
			typ = TypeFavicon
		default:
			p.errf(at("type"), n, "reguła nie ma pola type")
			return r, false
		}
	}
	r.Type = typ

	if v, k := m.get("name", "header", "cookie", "key"); v != nil {
		r.Name = strings.TrimSpace(p.str(v, at(k)))
	}
	if v, k := m.get("name_regex"); v != nil {
		r.NameRegex = p.str(v, at(k))
	}
	if v, k := m.get("field", "part", "in"); v != nil {
		r.Field = normKey(p.str(v, at(k)))
	}
	if v, k := m.get("path"); v != nil {
		r.Path = strings.TrimSpace(p.str(v, at(k)))
	}
	if v, k := m.get("status", "status_code", "code"); v != nil {
		r.Status = p.intList(v, at(k))
	}
	if v, k := m.get("contains", "word", "words", "text"); v != nil {
		r.Contains = p.strList(v, at(k))
	}
	if v, k := m.get("contains_all"); v != nil {
		r.ContainsAll = p.strList(v, at(k))
	}
	if v, k := m.get("regex", "pattern", "value_regex", "matches", "re"); v != nil {
		r.Regex = p.strList(v, at(k))
	}
	if v, k := m.get("equals", "value", "is", "eq"); v != nil {
		r.Equals = p.strList(v, at(k))
	}
	if v, k := m.get("exists", "present"); v != nil {
		b, ok := p.boolean(v, at(k))
		if ok && b {
			r.Exists = true
		} else if ok {
			r.Absent = true
		}
	}
	if v, k := m.get("absent", "missing"); v != nil {
		if b, ok := p.boolean(v, at(k)); ok && b {
			r.Absent = true
		}
	}
	if v, k := m.get("mmh3", "hash"); v != nil {
		for _, s := range p.strList(v, at(k)) {
			i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
			if err != nil {
				p.errf(at(k), v, "mmh3 „%s” nie jest 32-bitową liczbą ze znakiem", s)
				continue
			}
			r.MMH3 = append(r.MMH3, int32(i))
		}
	}
	if v, k := m.get("sha256"); v != nil {
		r.SHA256 = p.strList(v, at(k))
	}
	if v, k := m.get("secure"); v != nil {
		if b, ok := p.boolean(v, at(k)); ok {
			r.Secure = &b
		}
	}
	if v, k := m.get("http_only", "httponly"); v != nil {
		if b, ok := p.boolean(v, at(k)); ok {
			r.HTTPOnly = &b
		}
	}
	if v, k := m.get("same_site", "samesite"); v != nil {
		s := strings.ToLower(strings.TrimSpace(p.str(v, at(k))))
		r.SameSite = &s
	}
	if v, k := m.get("case_sensitive"); v != nil {
		r.CaseSensitive, _ = p.boolean(v, at(k))
	}
	if v, k := m.get("not", "negative", "negate"); v != nil {
		r.Not, _ = p.boolean(v, at(k))
	}
	if v, k := m.get("required", "must"); v != nil {
		r.Required, _ = p.boolean(v, at(k))
	}
	if v, k := m.get("weight", "confidence", "score"); v != nil {
		if f, ok := p.number(v, at(k)); ok {
			if f <= 0 || f > 1 {
				p.errf(at(k), v, "weight musi być liczbą większą od 0 i nie większą niż 1")
			} else {
				r.Weight = f
			}
		}
	}
	if v, k := m.get("version_group", "group"); v != nil {
		if f, ok := p.number(v, at(k)); ok {
			if f < 1 || f > 20 {
				p.errf(at(k), v, "version_group musi być numerem grupy od 1 do 20")
			} else {
				r.VersionGroup = int(f)
			}
		}
	}
	p.unknownKeys(m, path)
	return r, true
}

func cleanList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func validSlug(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_' || c == '.')
		if !ok {
			return false
		}
	}
	return true
}

func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = strings.Trim(out[:64], "-")
	}
	return out
}
