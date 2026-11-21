package sig

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
)

// This file makes the loader forgiving about the shape of a signature file:
// JSON or YAML, one signature, a list, a wrapper key or a map keyed by name,
// and the conventions of Wappalyzer technology files. The nuclei converter is
// in nuclei.go. Whatever the input shape, every signature goes through the
// same compiler and the same safe-mode checks.

// wrapperKeys are top-level keys that hold the signatures of a file.
var wrapperKeys = []string{"signatures", "sigs", "fingerprints", "technologies", "apps", "templates", "items", "entries", "definitions"}

// signatureKeys tell one signature mapping from a map keyed by name.
var signatureKeys = []string{"id", "slug", "name", "match", "matchers", "rules", "info", "http", "requests", "version"}

// unwrap returns the signature nodes of a top-level mapping.
func (p *parser) unwrap(root *yaml.Node) []*yaml.Node {
	for _, k := range wrapperKeys {
		v := mappingValue(root, k)
		if v == nil {
			continue
		}
		switch v.Kind {
		case yaml.SequenceNode:
			return v.Content
		case yaml.MappingNode:
			if nodes := p.keyed(v); nodes != nil {
				return nodes
			}
		}
	}
	// {"rules": [{"id": ..., "matchers": [...]}, ...]}: a list of whole signatures under "rules".
	if v := mappingValue(root, "rules"); v != nil && v.Kind == yaml.SequenceNode && len(v.Content) > 0 &&
		mappingValue(root, "id") == nil && mappingValue(root, "name") == nil && mappingValue(root, "slug") == nil {
		if first := deref(v.Content[0]); first.Kind == yaml.MappingNode &&
			(mappingValue(first, "id") != nil || mappingValue(first, "name") != nil || mappingValue(first, "slug") != nil) {
			return v.Content
		}
	}
	if nodes := p.keyed(root); nodes != nil {
		return nodes
	}
	return []*yaml.Node{root}
}

// keyed reads a map keyed by signature name ({"WordPress": {...}, "Drupal":
// {...}}) and returns one node per entry with the name put inside. It
// returns nil when the mapping is one signature.
func (p *parser) keyed(n *yaml.Node) []*yaml.Node {
	if len(n.Content) < 2 {
		return nil
	}
	allTypes := true
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := normKey(n.Content[i].Value)
		if deref(n.Content[i+1]).Kind != yaml.MappingNode {
			return nil
		}
		for _, k := range signatureKeys {
			if key == k {
				return nil
			}
		}
		if _, ok := canonType(key); !ok {
			allTypes = false
		}
	}
	if allTypes {
		return nil // {headers: {...}, cookies: {...}}: the short form of one signature
	}
	if p.origin == nil {
		p.origin = map[*yaml.Node]string{}
	}
	var out []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		val := deref(n.Content[i+1])
		nn := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Line: val.Line}
		if mappingValue(val, "name") == nil {
			nn.Content = append(nn.Content, strNode("name"), strNode(n.Content[i].Value))
		}
		nn.Content = append(nn.Content, val.Content...)
		p.origin[nn] = "keyed"
		out = append(out, nn)
	}
	return out
}

// ---------- Wappalyzer conventions ----------

// wappCategories maps the Wappalyzer category numbers that matter here.
var wappCategories = map[int]string{
	1: model.CatCMS, 2: model.CatCMS, 6: model.CatCMS, 8: model.CatCMS, 11: model.CatCMS, 21: model.CatCMS, 30: model.CatCMS,
	9: model.CatPanel, 3: model.CatPanel, 34: model.CatDatabase, 18: model.CatFramework, 12: model.CatLibrary, 59: model.CatLibrary,
	22: model.CatWebServer, 27: model.CatLanguage, 28: model.CatOS, 64: model.CatProxy, 31: model.CatProxy, 16: model.CatSecurity,
	39: model.CatIoT, 40: model.CatIoT, 46: model.CatIoT, 37: model.CatIoT, 38: model.CatIoT, 47: model.CatDevOps, 60: model.CatDevOps,
	44: model.CatDevOps, 13: model.CatDevOps,
}

// wappalyzer reads the fields that only Wappalyzer technology files have.
func (p *parser) wappalyzer(m *ymap, prefix string, d *Def) {
	if v, k := m.get("cats"); v != nil && d.Category == model.CatOther {
		for _, c := range p.intList(v, join(prefix, k)) {
			if cat, ok := wappCategories[c]; ok {
				d.Category = cat
				break
			}
		}
	}
	// Fields that are not detection rules.
	m.get("icon")
	for _, k := range []string{"icon", "website", "oss", "saas", "pricing", "excludes", "requires", "requirescategory"} {
		m.used[k] = true
	}
	// Fields that need a browser or another protocol.
	var skipped []string
	for _, k := range []string{"js", "dom", "dns", "xhr", "css", "robots", "probe"} {
		if m.has(k) {
			m.used[k] = true
			skipped = append(skipped, k)
		}
	}
	if len(skipped) > 0 {
		p.warnf(prefix, nil, "pola %s zostały pominięte: wymagają przeglądarki albo innego protokołu", strings.Join(skipped, ", "))
	}
	if v, k := m.get("scriptsrc", "script_src", "scripts"); v != nil {
		for i, pat := range p.strList(v, join(prefix, k)) {
			d.Rules = append(d.Rules, RuleDef{Type: TypeBody, Regex: []string{pat}, ypath: join(prefix, k) + "[" + strconv.Itoa(i) + "]", line: v.Line})
		}
	}
	if v, k := m.get("certissuer"); v != nil {
		d.Rules = append(d.Rules, RuleDef{Type: TypeTLS, Field: "issuer", Contains: []string{p.str(v, join(prefix, k))}, ypath: join(prefix, k), line: v.Line})
	}
	for i := range d.Implies {
		d.Implies[i], _, _ = wappPattern(d.Implies[i])
	}
}

var wappVersionRe = regexp.MustCompile(`\\([0-9])`)

// wappPattern splits a Wappalyzer pattern "regex\;version:\1\;confidence:50"
// into the pattern, the version group (0: none) and the weight (0: default).
func wappPattern(s string) (pattern string, group int, weight float64) {
	parts := strings.Split(s, `\;`)
	pattern = parts[0]
	for _, tag := range parts[1:] {
		name, val, _ := strings.Cut(tag, ":")
		switch name {
		case "version":
			if m := wappVersionRe.FindStringSubmatch(val); m != nil {
				group, _ = strconv.Atoi(m[1])
			}
		case "confidence":
			if f, err := strconv.ParseFloat(val, 64); err == nil && f > 0 && f <= 100 {
				weight = f / 100
			}
		}
	}
	return pattern, group, weight
}

// wappRules applies the Wappalyzer conventions to the parsed rules: every
// pattern is a regular expression and may carry version and confidence tags.
func wappRules(d *Def) {
	for i := range d.Rules {
		r := &d.Rules[i]
		if r.Type == TypeBody || r.Type == TypeURL || r.Type == TypeTitle || r.Type == TypeMeta {
			r.Regex, r.Contains = append(r.Regex, r.Contains...), nil
		}
		for j, pat := range r.Regex {
			clean, group, weight := wappPattern(pat)
			r.Regex[j] = clean
			if group > 0 {
				r.VersionGroup = group
			}
			if weight > 0 {
				r.Weight = weight
			}
		}
		// An empty pattern means: the thing exists.
		var kept []string
		for _, pat := range r.Regex {
			if pat != "" {
				kept = append(kept, pat)
			}
		}
		if r.Regex = kept; len(kept) == 0 && len(r.Contains)+len(r.ContainsAll)+len(r.Equals) == 0 && (r.Type == TypeHeader || r.Type == TypeCookie || r.Type == TypeMeta) {
			r.Exists = true
			r.VersionGroup = 0
		}
	}
}

// ---------- Canonical YAML ----------

func strNode(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	// Quote what YAML would read as another type or as syntax.
	if s == "" || strings.ContainsAny(s, ":#{}[],&*!|>'\"%@`\\\n") || strings.TrimSpace(s) != s || s[0] == '-' || s[0] == '?' {
		n.Style = yaml.SingleQuotedStyle
		if strings.ContainsAny(s, "\n\t\r") {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	return n
}

func intNode(i int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(i)}
}

func boolNode(b bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(b)}
}

func floatNode(f float64) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: strconv.FormatFloat(f, 'f', -1, 64)}
}

func listNode(items []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, s := range items {
		n.Content = append(n.Content, strNode(s))
	}
	return n
}

type mapBuilder struct{ n *yaml.Node }

func newMap(flow bool) *mapBuilder {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if flow {
		n.Style = yaml.FlowStyle
	}
	return &mapBuilder{n}
}

func (b *mapBuilder) add(key string, v *yaml.Node) {
	b.n.Content = append(b.n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func (b *mapBuilder) str(key, v string) {
	if v != "" {
		b.add(key, strNode(v))
	}
}

func (b *mapBuilder) list(key string, v []string) {
	if len(v) > 0 {
		b.add(key, listNode(v))
	}
}

// oneOrList writes one text as a scalar and several as a list.
func (b *mapBuilder) oneOrList(key string, v []string) {
	switch len(v) {
	case 0:
	case 1:
		b.add(key, strNode(v[0]))
	default:
		b.add(key, listNode(v))
	}
}

func ruleNode(r *RuleDef, versionRule bool) *yaml.Node {
	b := newMap(true)
	b.str("type", r.Type)
	b.str("name", r.Name)
	b.str("name_regex", r.NameRegex)
	b.str("field", r.Field)
	b.str("path", r.Path)
	if len(r.Status) > 0 {
		st := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, s := range r.Status {
			st.Content = append(st.Content, intNode(s))
		}
		b.add("status", st)
	}
	b.oneOrList("contains", r.Contains)
	b.list("contains_all", r.ContainsAll)
	b.oneOrList("regex", r.Regex)
	b.oneOrList("equals", r.Equals)
	if r.Exists {
		b.add("exists", boolNode(true))
	}
	if r.Absent {
		b.add("absent", boolNode(true))
	}
	if len(r.MMH3) > 0 {
		h := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, v := range r.MMH3 {
			h.Content = append(h.Content, intNode(int(v)))
		}
		b.add("mmh3", h)
	}
	b.list("sha256", r.SHA256)
	if r.Secure != nil {
		b.add("secure", boolNode(*r.Secure))
	}
	if r.HTTPOnly != nil {
		b.add("http_only", boolNode(*r.HTTPOnly))
	}
	if r.SameSite != nil {
		b.add("same_site", strNode(*r.SameSite))
	}
	if r.CaseSensitive {
		b.add("case_sensitive", boolNode(true))
	}
	if r.Not {
		b.add("not", boolNode(true))
	}
	if r.Required {
		b.add("required", boolNode(true))
	}
	if r.Weight > 0 {
		b.add("weight", floatNode(r.Weight))
	}
	switch {
	case r.VersionGroup > 1 || r.VersionGroup == 1 && !versionRule:
		b.add("version_group", intNode(r.VersionGroup))
	case r.VersionGroup == -1 && len(r.Regex) > 0:
		// Short form: the first group is the version when the pattern has one.
		if re, err := regexp.Compile(r.Regex[0]); err == nil && re.NumSubexp() >= 1 {
			b.add("version_group", intNode(1))
		}
	}
	return b.n
}

// YAML writes the signature in the canonical Czujka form. Parsing the text
// again gives the same signature. It is what a converted foreign signature
// is stored as.
func (d *Def) YAML() string {
	b := newMap(false)
	b.str("id", d.ID)
	b.str("name", d.Name)
	b.str("category", d.Category)
	b.str("description", d.Description)
	b.str("author", d.Author)
	b.str("cpe", d.CPE)
	b.list("tags", d.Tags)
	b.list("implies", d.Implies)
	b.list("aliases", d.Aliases)
	b.list("classes", d.Classes)
	if d.Interest != 0 {
		b.add("interest", intNode(d.Interest))
	}
	switch {
	case d.NoTech:
		b.add("technology", boolNode(false))
	case d.Technology != "":
		b.add("technology", strNode(d.Technology))
	}
	if d.Disabled {
		b.add("enabled", boolNode(false))
	}
	b.list("requests", d.Requests)
	mm := newMap(false)
	if d.All {
		mm.add("condition", strNode("all"))
	}
	if d.MinConfidence != DefaultMinConfidence {
		mm.add("min_confidence", floatNode(d.MinConfidence))
	}
	rules := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := range d.Rules {
		rules.Content = append(rules.Content, ruleNode(&d.Rules[i], false))
	}
	mm.add("rules", rules)
	b.add("match", mm.n)
	if len(d.Version) > 0 {
		vs := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := range d.Version {
			vs.Content = append(vs.Content, ruleNode(&d.Version[i], true))
		}
		b.add("version", vs)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(b.n); err != nil {
		return ""
	}
	_ = enc.Close()
	return buf.String()
}

// Convert reads signatures in any accepted format (Czujka YAML, JSON, a map
// keyed by name, Wappalyzer conventions, a passive nuclei HTTP template) and
// returns them as canonical Czujka YAML, several signatures separated by
// "---". The safe-mode validator is the final gate: the converted text is
// validated again, and a signature with an error is not in the output.
func Convert(src string) (string, model.SignatureValidation) {
	sigs, val := Parse(src)
	var b strings.Builder
	for i, s := range sigs {
		if i > 0 {
			b.WriteString("---\n")
		}
		b.WriteString(s.Def.YAML())
	}
	out := b.String()
	if len(sigs) > 0 {
		if again, v2 := Parse(out); !v2.OK || len(again) != len(sigs) {
			val.OK = false
			for _, is := range v2.Issues {
				if is.Level == "error" {
					is.Message = "po konwersji: " + is.Message
					val.Issues = append(val.Issues, is)
				}
			}
			return "", val
		}
	}
	return out, val
}
