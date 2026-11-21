// Package rules implements Czujka's exposure rules ("attack surface as code").
//
// Discovery tells what exists. A rule tells what must never exist (expect:
// absent) or what must always exist (expect: present). Rules are small YAML
// documents in the spirit of the signature DSL (docs/REGULY.md). They are
// evaluated over the stored inventory only: evaluation never sends a packet.
//
// The package has two layers. The pure layer (this file, cond.go, eval.go)
// parses, validates and evaluates rules over in-memory records and is unit
// tested without a database. The store layer (service.go, http.go) keeps the
// rules in their own table, evaluates them over the inventory after every
// analysed run and import, stores violations as model.Finding records of type
// "policy-violation", and serves the REST routes.
package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
)

// FindingType is the model.Finding.Type of a rule violation.
const FindingType = "policy-violation"

// Subjects and expectations.
const (
	SubjectService = "service"
	SubjectHost    = "host"
	ExpectAbsent   = "absent"
	ExpectPresent  = "present"
	PerHost        = "host"
	PerScope       = "scope"
)

// Rule is one parsed and validated exposure rule.
type Rule struct {
	ID          string
	Name        string
	Severity    model.Severity
	Description string
	Remediation string
	Tags        []string
	Enabled     bool
	Subject     string // service (default) | host
	Expect      string // absent (default) | present
	Per         string // present only: host (default) | scope
	Where       Where
	Match       Cond // never nil; an empty match is always true
	YAML        string

	matchHasState bool
	matchHasSvc   bool
}

// Where selects the part of the inventory a rule looks at.
type Where struct {
	Scopes     []string // scope names or scope tags, case-insensitive
	CIDRs      []netip.Prefix
	NotCIDRs   []netip.Prefix
	Tags       []string // host or service has one of them
	NotTags    []string // neither host nor service has any of them
	States     []string // service states; default [open] unless match names a state
	HostStatus []string
}

// Issue is one problem found by the validator. It reuses the shape of the
// signature validator so that the UI shows both the same way.
type Issue = model.SignatureIssue

// Validation is the answer of the validator.
type Validation struct {
	OK     bool    `json:"ok"`
	Issues []Issue `json:"issues"`
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,79}$`)

type parser struct {
	issues []Issue
}

func line(n *yaml.Node) string {
	if n == nil || n.Line == 0 {
		return ""
	}
	return fmt.Sprintf(" (wiersz %d)", n.Line)
}

func (p *parser) errf(path string, n *yaml.Node, format string, args ...any) {
	p.issues = append(p.issues, Issue{Level: "error", Path: path, Message: fmt.Sprintf(format, args...) + line(n)})
}

func (p *parser) warnf(path string, n *yaml.Node, format string, args ...any) {
	p.issues = append(p.issues, Issue{Level: "warning", Path: path, Message: fmt.Sprintf(format, args...) + line(n)})
}

func (p *parser) failed() bool {
	for _, is := range p.issues {
		if is.Level == "error" {
			return true
		}
	}
	return false
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func idx(path string, i int) string { return fmt.Sprintf("%s[%d]", path, i) }

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return deref(n.Content[0])
	}
	return n
}

type kv struct {
	key  string
	knod *yaml.Node
	val  *yaml.Node
}

func (p *parser) mapping(n *yaml.Node, path string) ([]kv, bool) {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		p.errf(path, n, "oczekiwano mapy (klucz: wartość)")
		return nil, false
	}
	out := make([]kv, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, kv{strings.ToLower(strings.TrimSpace(n.Content[i].Value)), n.Content[i], deref(n.Content[i+1])})
	}
	return out, true
}

func (p *parser) str(n *yaml.Node, path string) string {
	n = deref(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		p.errf(path, n, "oczekiwano tekstu")
		return ""
	}
	return strings.TrimSpace(n.Value)
}

func (p *parser) strList(n *yaml.Node, path string) []string {
	n = deref(n)
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		if v := strings.TrimSpace(n.Value); v != "" {
			return []string{v}
		}
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		p.errf(path, n, "oczekiwano tekstu albo listy tekstów")
		return nil
	}
	var out []string
	for i, c := range n.Content {
		c = deref(c)
		if c.Kind != yaml.ScalarNode {
			p.errf(idx(path, i), c, "oczekiwano tekstu")
			continue
		}
		if v := strings.TrimSpace(c.Value); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (p *parser) boolean(n *yaml.Node, path string) (bool, bool) {
	n = deref(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		p.errf(path, n, "oczekiwano wartości true albo false")
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(n.Value)) {
	case "true", "yes", "tak", "on":
		return true, true
	case "false", "no", "nie", "off":
		return false, true
	}
	p.errf(path, n, "oczekiwano wartości true albo false, jest „%s”", n.Value)
	return false, false
}

func (p *parser) integer(n *yaml.Node, path string, lo, hi int) (int, bool) {
	n = deref(n)
	var v int
	if n == nil || n.Kind != yaml.ScalarNode {
		p.errf(path, n, "oczekiwano liczby całkowitej")
		return 0, false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(n.Value), "%d", &v); err != nil || fmt.Sprint(v) != strings.TrimSpace(n.Value) {
		p.errf(path, n, "oczekiwano liczby całkowitej, jest „%s”", n.Value)
		return 0, false
	}
	if v < lo || v > hi {
		p.errf(path, n, "liczba %d jest poza zakresem %d–%d", v, lo, hi)
		return 0, false
	}
	return v, true
}

// regex compiles an RE2 expression. Matching is case-insensitive unless the
// expression sets its own flags.
func (p *parser) regex(n *yaml.Node, path string) *regexp.Regexp {
	src := p.str(n, path)
	if src == "" {
		p.errf(path, n, "puste wyrażenie regularne")
		return nil
	}
	if len(src) > 500 {
		p.errf(path, n, "wyrażenie regularne jest dłuższe niż 500 znaków")
		return nil
	}
	if !strings.HasPrefix(src, "(?") {
		src = "(?i)" + src
	}
	re, err := regexp.Compile(src)
	if err != nil {
		p.errf(path, n, "błędne wyrażenie regularne (składnia RE2, bez odwołań wstecznych i asercji): %v", err)
		return nil
	}
	return re
}

func (p *parser) prefixes(n *yaml.Node, path string) []netip.Prefix {
	var out []netip.Prefix
	for i, s := range p.strList(n, path) {
		pp := idx(path, i)
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				p.errf(pp, n, "„%s” nie jest adresem IP ani siecią CIDR", s)
				continue
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		pr, err := netip.ParsePrefix(s)
		if err != nil {
			p.errf(pp, n, "„%s” nie jest poprawną siecią CIDR", s)
			continue
		}
		out = append(out, pr.Masked())
	}
	return out
}

var severities = map[string]model.Severity{"info": model.SevInfo, "low": model.SevLow, "medium": model.SevMedium, "high": model.SevHigh}

// Parse reads one rule. The rule is nil when the validator found an error.
func Parse(src string) (*Rule, Validation) {
	p := &parser{}
	r := p.parse(src)
	val := Validation{OK: !p.failed(), Issues: p.issues}
	if val.Issues == nil {
		val.Issues = []Issue{}
	}
	if !val.OK {
		return nil, val
	}
	return r, val
}

// ParseMany reads a YAML list of rules or several documents (built-in pack).
func ParseMany(src string) ([]*Rule, Validation) {
	var docs []string
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err == nil {
		if n := deref(&root); n != nil && n.Kind == yaml.SequenceNode {
			for _, c := range n.Content {
				b, _ := yaml.Marshal(c)
				docs = append(docs, string(b))
			}
		}
	}
	if docs == nil {
		docs = strings.Split(src, "\n---")
	}
	var out []*Rule
	all := Validation{OK: true, Issues: []Issue{}}
	for i, d := range docs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		r, v := Parse(d)
		for _, is := range v.Issues {
			is.Path = idx("", i) + "." + is.Path
			all.Issues = append(all.Issues, is)
		}
		if r == nil {
			all.OK = false
			continue
		}
		out = append(out, r)
	}
	return out, all
}

func (p *parser) parse(src string) *Rule {
	if strings.TrimSpace(src) == "" {
		p.errf("", nil, "pusta reguła")
		return nil
	}
	if len(src) > 64<<10 {
		p.errf("", nil, "reguła jest dłuższa niż 64 KiB")
		return nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		p.errf("", nil, "błąd składni YAML: %v", err)
		return nil
	}
	fields, ok := p.mapping(&root, "")
	if !ok {
		return nil
	}
	r := &Rule{Enabled: true, Subject: SubjectService, Expect: ExpectAbsent, Severity: model.SevMedium, YAML: src}
	var matchNode, whereNode, idNode *yaml.Node
	for _, f := range fields {
		switch f.key {
		case "id", "slug":
			r.ID, idNode = p.str(f.val, f.key), f.val
		case "name", "nazwa":
			r.Name = p.str(f.val, f.key)
		case "severity", "waga":
			s := strings.ToLower(p.str(f.val, f.key))
			sev, ok := severities[s]
			if !ok {
				p.errf(f.key, f.val, "nieznana waga „%s”: dozwolone info, low, medium, high", s)
			}
			r.Severity = sev
		case "description", "opis":
			r.Description = p.str(f.val, f.key)
		case "remediation", "zalecenie":
			r.Remediation = p.str(f.val, f.key)
		case "tags":
			r.Tags = p.strList(f.val, f.key)
		case "enabled":
			r.Enabled, _ = p.boolean(f.val, f.key)
		case "subject":
			s := strings.ToLower(p.str(f.val, f.key))
			if s != SubjectService && s != SubjectHost {
				p.errf(f.key, f.val, "nieznany podmiot „%s”: dozwolone service albo host", s)
			}
			r.Subject = s
		case "expect":
			s := strings.ToLower(p.str(f.val, f.key))
			if s != ExpectAbsent && s != ExpectPresent {
				p.errf(f.key, f.val, "nieznane oczekiwanie „%s”: dozwolone absent (każde dopasowanie to naruszenie) albo present (brak dopasowania to naruszenie)", s)
			}
			r.Expect = s
		case "per":
			s := strings.ToLower(p.str(f.val, f.key))
			if s != PerHost && s != PerScope {
				p.errf(f.key, f.val, "nieznana wartość „%s”: dozwolone host albo scope", s)
			}
			r.Per = s
		case "where", "gdzie":
			whereNode = f.val
		case "match", "warunek":
			matchNode = f.val
		default:
			p.warnf(f.key, f.knod, "nieznane pole „%s” zostało pominięte", f.key)
		}
	}
	if r.ID == "" {
		r.ID = slugify(r.Name)
	}
	if r.ID == "" {
		p.errf("id", nil, "brak pola id (albo name, z którego powstanie id)")
	} else if !slugRe.MatchString(r.ID) {
		p.errf("id", idNode, "id „%s” może mieć tylko małe litery, cyfry, „-”, „_” i „.” (najwyżej 80 znaków)", r.ID)
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if r.Per != "" && r.Expect != ExpectPresent {
		p.warnf("per", nil, "pole per działa tylko z expect: present")
	}
	if r.Expect == ExpectPresent && r.Per == "" {
		r.Per = PerHost
	}
	if whereNode != nil {
		r.Where = p.parseWhere(whereNode, "where")
	}
	if matchNode == nil {
		if r.Expect == ExpectAbsent {
			p.errf("match", nil, "brak warunku match: reguła expect: absent bez warunku zgłosiłaby każdą usługę")
		}
		r.Match = allCond{}
	} else {
		info := &condInfo{}
		r.Match = p.parseCond(matchNode, "match", info)
		r.matchHasState, r.matchHasSvc = info.state, info.svc
	}
	if r.Match == nil {
		r.Match = allCond{}
	}
	if len(r.Where.States) == 0 && !r.matchHasState {
		r.Where.States = []string{string(model.ServiceOpen)}
	}
	return r
}

func (p *parser) parseWhere(n *yaml.Node, path string) Where {
	var w Where
	fields, ok := p.mapping(n, path)
	if !ok {
		return w
	}
	for _, f := range fields {
		fp := join(path, f.key)
		switch f.key {
		case "scope", "scopes":
			w.Scopes = p.strList(f.val, fp)
		case "cidr":
			w.CIDRs = p.prefixes(f.val, fp)
		case "not_cidr":
			w.NotCIDRs = p.prefixes(f.val, fp)
		case "tags", "tag":
			w.Tags = p.strList(f.val, fp)
		case "not_tags", "not_tag":
			w.NotTags = p.strList(f.val, fp)
		case "state", "states":
			w.States = p.states(f.val, fp)
		case "host_status":
			w.HostStatus = p.hostStatuses(f.val, fp)
		default:
			p.errf(fp, f.knod, "nieznane pole „%s” w where: dozwolone scope, cidr, not_cidr, tags, not_tags, state, host_status", f.key)
		}
	}
	return w
}

var serviceStates = []string{"open", "gone", "unknown", "filtered"}
var hostStatuses = []string{"up", "unstable", "down", "expected-offline", "unknown"}

func (p *parser) oneOfList(n *yaml.Node, path string, allowed []string, what string) []string {
	vals := p.strList(n, path)
	for i, v := range vals {
		v = strings.ToLower(v)
		vals[i] = v
		found := false
		for _, a := range allowed {
			if a == v {
				found = true
			}
		}
		if !found {
			p.errf(path, n, "nieznany %s „%s”: dozwolone %s", what, v, strings.Join(allowed, ", "))
		}
	}
	return vals
}

func (p *parser) states(n *yaml.Node, path string) []string {
	return p.oneOfList(n, path, serviceStates, "stan usługi")
}

func (p *parser) hostStatuses(n *yaml.Node, path string) []string {
	return p.oneOfList(n, path, hostStatuses, "stan hosta")
}

func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if r2, ok := plFold[r]; ok {
				b.WriteRune(r2)
				dash = false
			} else if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 80 {
		out = strings.Trim(out[:80], "-")
	}
	return out
}

var plFold = map[rune]rune{'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z'}
