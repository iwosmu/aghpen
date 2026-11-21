package sig

import (
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Sig is one compiled signature.
type Sig struct {
	Def
	Slug    string
	Builtin bool
	Enabled bool
	YAML    string

	rules    []*rule
	version  []*rule
	paths    []string // extra paths this signature asks for
	classes  []string
	techName string
	isTech   bool
	needHTTP bool // every positive rule reads HTTP data
	maxConf  float64
}

// Paths returns the extra request paths of the signature.
func (s *Sig) Paths() []string { return append([]string(nil), s.paths...) }

func (s *Sig) clone() *Sig {
	cp := *s
	cp.rules = cloneRules(s.rules)
	cp.version = cloneRules(s.version)
	return &cp
}

func cloneRules(in []*rule) []*rule {
	out := make([]*rule, len(in))
	for i, r := range in {
		cp := *r
		cp.contains = append([]lit(nil), r.contains...)
		cp.containsAll = append([]lit(nil), r.containsAll...)
		cp.regex = append([]rx(nil), r.regex...)
		out[i] = &cp
	}
	return out
}

// lit is a literal a text must contain.
type lit struct {
	exact string
	low   string
	id    int32 // id in the body automaton, -1 when not in it
}

// rx is a compiled pattern with an optional literal every match must contain.
type rx struct {
	re *regexp.Regexp
	// need is a set of lower-case literals; every match of re contains at
	// least one of them. ids are their numbers in the automaton of a set.
	need []string
	ids  []int32
}

type rule struct {
	typ         string
	name        string // lower case
	nameShown   string
	nameRe      *regexp.Regexp
	field       string
	path        string
	status      []int
	contains    []lit
	containsAll []lit
	regex       []rx
	equals      []string
	hasText     bool
	exists      bool
	absent      bool
	mmh3        []int32
	sha256      []string
	secure      *bool
	httpOnly    *bool
	sameSite    *string
	cs          bool
	not         bool
	required    bool
	weight      float64
	vgroup      int
}

var (
	serviceFields = map[string]bool{"": true, "any": true, "name": true, "product": true, "version": true, "extrainfo": true, "extra_info": true, "cpe": true}
	tlsFields     = map[string]bool{"": true, "any": true, "subject": true, "cn": true, "subject_cn": true, "issuer": true, "san": true, "sans": true, "org": true, "subject_org": true, "version": true, "cipher": true}
	pathFields    = map[string]bool{"": true, "body": true, "title": true, "header": true, "location": true, "status": true}
	cookieFields  = map[string]bool{"": true, "value": true, "name": true}
)

// compile checks the meaning of a parsed signature and prepares it for
// matching. Problems go to the parser's issue list; the result is nil when
// the signature has an error.
func (p *parser) compile(d *Def, prefix string) *Sig {
	if d == nil {
		return nil
	}
	before := len(p.issues)
	s := &Sig{Def: *d, Slug: d.ID, Enabled: !d.Disabled}
	s.techName = d.Technology
	if s.techName == "" {
		s.techName = d.Name
	}
	s.isTech = !d.NoTech && d.Category != model.CatHeader && d.Category != model.CatCookie && d.Category != model.CatEnvironment
	if d.Technology != "" {
		s.isTech = true
	}

	classes := map[string]bool{}
	for _, c := range d.Classes {
		classes[c] = true
	}
	switch d.Category {
	case model.CatIoT:
		classes[model.ClassIoT] = true
	case model.CatDatabase:
		classes[model.ClassDatabase] = true
	}
	s.classes = sortedKeys(classes)

	if len(d.Rules) == 0 {
		p.errf(join(prefix, "match"), d.node, "sygnatura nie ma żadnej reguły (pole match.rules albo forma skrócona, np. body: 'tekst')")
	}
	if len(d.Rules)+len(d.Version) > MaxRulesPerSignature {
		p.errf(join(prefix, "match"), d.node, "za dużo reguł w sygnaturze (limit %d)", MaxRulesPerSignature)
	}

	pathSet := map[string]bool{}
	addPath := func(path, ypath string) {
		if path == "" || pathSet[path] {
			return
		}
		if reason := CheckPath(path); reason != "" {
			p.unsafe(ypath, nil, "niebezpieczna ścieżka „%s”: %s", clip(path, 80), reason)
			return
		}
		pathSet[path] = true
		s.paths = append(s.paths, path)
	}
	for i, path := range d.Requests {
		addPath(path, fmt.Sprintf("%s[%d]", join(prefix, "requests"), i))
	}
	requested := map[string]bool{}
	for k := range pathSet {
		requested[k] = true
	}

	prod := 1.0
	positives := 0
	s.needHTTP = true
	usedPaths := map[string]bool{}
	for i := range d.Rules {
		rd := &d.Rules[i]
		r := p.compileRule(rd, false)
		if r == nil {
			continue
		}
		if r.typ == TypePath {
			addPath(r.path, join(rd.ypath, "path"))
			usedPaths[r.path] = true
		}
		s.rules = append(s.rules, r)
		if !r.not {
			positives++
			prod *= 1 - r.weight
			switch r.typ {
			case TypeBanner, TypeService, TypeTLS, TypeHostname:
				s.needHTTP = false
			}
		}
	}
	for i := range d.Version {
		rd := &d.Version[i]
		r := p.compileRule(rd, true)
		if r == nil {
			continue
		}
		if r.typ == TypePath {
			addPath(r.path, join(rd.ypath, "path"))
			usedPaths[r.path] = true
		}
		s.version = append(s.version, r)
	}
	if len(s.paths) > MaxRequestsPerSignature {
		p.unsafe(join(prefix, "requests"), d.node, "sygnatura prosi o %d ścieżek; limit to %d dodatkowych żądań na sygnaturę", len(s.paths), MaxRequestsPerSignature)
	}
	for path := range requested {
		if !usedPaths[path] {
			p.warnf(join(prefix, "requests"), d.node, "ścieżka „%s” byłaby pobierana, ale żadna reguła typu path jej nie używa", path)
		}
	}
	if len(d.Rules) > 0 && positives == 0 && len(p.issues) == before {
		p.errf(join(prefix, "match"), d.node, "sygnatura ma tylko reguły negatywne (not: true); potrzebna jest co najmniej jedna reguła pozytywna")
	}
	s.maxConf = 1 - prod
	if positives > 0 && s.maxConf+1e-9 < d.MinConfidence {
		p.warnf(join(prefix, "match.min_confidence"), d.node, "sygnatura nigdy nie zadziała: największa możliwa pewność %.2f jest mniejsza niż min_confidence %.2f", s.maxConf, d.MinConfidence)
	}
	sort.Strings(s.paths)
	for _, is := range p.issues[before:] {
		if is.Level == "error" {
			return nil
		}
	}
	return s
}

func (p *parser) compileRule(rd *RuleDef, versionRule bool) *rule {
	before := len(p.issues)
	at := func(k string) string { return join(rd.ypath, k) }
	bad := func(format string, args ...any) {
		p.issues = append(p.issues, model.SignatureIssue{Level: "error", Path: rd.ypath, Message: withLine(fmt.Sprintf(format, args...), rd.line)})
	}
	r := &rule{
		typ: rd.Type, field: rd.Field, path: rd.Path, status: rd.Status, exists: rd.Exists, absent: rd.Absent,
		mmh3: rd.MMH3, secure: rd.Secure, httpOnly: rd.HTTPOnly, sameSite: rd.SameSite,
		cs: rd.CaseSensitive, not: rd.Not, required: rd.Required, weight: rd.Weight,
		nameShown: rd.Name, name: strings.ToLower(rd.Name),
	}
	if r.weight == 0 {
		r.weight = defaultWeights[rd.Type]
	}
	if r.exists && r.absent {
		bad("reguła nie może mieć jednocześnie exists i absent")
	}

	checkLit := func(key string, vals []string) []lit {
		var out []lit
		for i, v := range vals {
			switch {
			case v == "":
				p.issues = append(p.issues, model.SignatureIssue{Level: "error", Path: fmt.Sprintf("%s[%d]", at(key), i), Message: withLine("pusty tekst do dopasowania", rd.line)})
			case len(v) > MaxLiteralLen:
				p.issues = append(p.issues, model.SignatureIssue{Level: "error", Path: fmt.Sprintf("%s[%d]", at(key), i), Message: withLine(fmt.Sprintf("tekst do dopasowania jest za długi (limit %d znaków)", MaxLiteralLen), rd.line)})
			default:
				out = append(out, lit{exact: v, low: strings.ToLower(v), id: -1})
			}
		}
		return out
	}
	r.contains = checkLit("contains", rd.Contains)
	r.containsAll = checkLit("contains_all", rd.ContainsAll)
	for _, e := range rd.Equals {
		if len(e) > MaxLiteralLen {
			bad("wartość equals jest za długa (limit %d znaków)", MaxLiteralLen)
			continue
		}
		r.equals = append(r.equals, strings.TrimSpace(e))
	}
	minGroups := math.MaxInt
	for i, pat := range rd.Regex {
		re, need, msg, safety := compileRegex(pat, rd.CaseSensitive)
		if msg != "" {
			p.issues = append(p.issues, model.SignatureIssue{Level: "error", Path: fmt.Sprintf("%s[%d]", at("regex"), i), Message: withLine(msg, rd.line), Safety: safety})
			continue
		}
		r.regex = append(r.regex, rx{re: re, need: need})
		minGroups = min(minGroups, re.NumSubexp())
	}
	if rd.NameRegex != "" {
		re, _, msg, safety := compileRegex(rd.NameRegex, false)
		if msg != "" {
			p.issues = append(p.issues, model.SignatureIssue{Level: "error", Path: at("name_regex"), Message: withLine(msg, rd.line), Safety: safety})
		}
		r.nameRe = re
	}
	// A matcher that failed to compile still counts as "given", so one mistake gives one message.
	r.hasText = len(rd.Contains)+len(rd.ContainsAll)+len(rd.Regex)+len(rd.Equals) > 0

	switch {
	case rd.VersionGroup == -1: // short form: the first group is the version when there is one
		if len(r.regex) > 0 && minGroups >= 1 {
			r.vgroup = 1
		}
	case rd.VersionGroup > 0:
		if len(r.regex) == 0 {
			bad("version_group wymaga pola regex z grupą w nawiasach")
		} else if rd.VersionGroup > minGroups {
			bad("version_group %d: wyrażenie ma tylko %d grup w nawiasach", rd.VersionGroup, minGroups)
		} else {
			r.vgroup = rd.VersionGroup
		}
	}
	if versionRule {
		if len(r.regex) == 0 || r.vgroup == 0 {
			bad("reguła wersji musi mieć pole regex z grupą w nawiasach, np. 'WordPress ([0-9.]+)'")
		}
		if r.not || r.absent {
			bad("reguła wersji nie może być negatywna")
		}
	}

	hasFlags := r.secure != nil || r.httpOnly != nil || r.sameSite != nil
	switch rd.Type {
	case TypeHeader:
		if r.name == "" && r.nameRe == nil && !r.hasText {
			bad("reguła header potrzebuje nazwy nagłówka (name) albo dopasowania (contains, regex, equals)")
		}
	case TypeCookie:
		if !cookieFields[r.field] {
			bad("nieznane pole field „%s” w regule cookie (dozwolone: value, name)", r.field)
		}
		if r.name == "" && r.nameRe == nil && !r.hasText && !hasFlags {
			bad("reguła cookie potrzebuje nazwy (name, name_regex), dopasowania wartości albo flag (secure, http_only)")
		}
		if r.sameSite != nil {
			switch *r.sameSite {
			case "lax", "strict", "none", "":
			default:
				bad("same_site musi mieć wartość lax, strict, none albo pusty tekst")
			}
		}
	case TypeMeta:
		if r.name == "" {
			r.name, r.nameShown = "generator", "generator"
		}
	case TypeFavicon:
		for _, h := range rd.SHA256 {
			h = strings.ToLower(strings.TrimSpace(h))
			if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
				bad("sha256 ikony musi mieć 64 znaki szesnastkowe")
				continue
			}
			r.sha256 = append(r.sha256, h)
		}
		if len(r.mmh3) == 0 && len(r.sha256) == 0 && !r.exists && !r.absent {
			bad("reguła favicon potrzebuje pola mmh3 albo sha256")
		}
		if r.hasText {
			bad("reguła favicon nie obsługuje contains, regex ani equals; użyj mmh3 albo sha256")
		}
	case TypePath:
		if r.path == "" {
			bad("reguła path potrzebuje pola path")
		}
		if !pathFields[r.field] {
			bad("nieznane pole field „%s” w regule path (dozwolone: body, title, header, location)", r.field)
		}
		if r.field == "header" && r.name == "" && !r.hasText {
			bad("reguła path z field: header potrzebuje nazwy nagłówka (name) albo dopasowania")
		}
		if !r.hasText && !r.not && !r.absent && !versionRule {
			p.issues = append(p.issues, model.SignatureIssue{Level: "warning", Path: rd.ypath, Message: withLine("reguła path bez dopasowania treści (contains, regex): serwer, który na każdą ścieżkę odpowiada 200, da fałszywe trafienie", rd.line)})
		}
	case TypeStatus:
		if len(r.status) == 0 {
			bad("reguła status potrzebuje pola status z kodem HTTP")
		}
	case TypeService:
		if !serviceFields[r.field] {
			bad("nieznane pole field „%s” w regule service (dozwolone: name, product, version, extrainfo, cpe)", r.field)
		}
		if !r.hasText {
			bad("reguła service potrzebuje dopasowania (contains, regex, equals)")
		}
	case TypeTLS:
		if !tlsFields[r.field] {
			bad("nieznane pole field „%s” w regule tls (dozwolone: subject, issuer, san, org)", r.field)
		}
		if !r.hasText && !r.exists && !r.absent {
			bad("reguła tls potrzebuje dopasowania (contains, regex, equals) albo exists")
		}
	case TypeBody, TypeTitle, TypeBanner, TypeURL, TypeRedirect, TypeHostname:
		if !r.hasText && !r.exists && !r.absent {
			bad("reguła %s potrzebuje dopasowania (contains, regex, equals) albo exists/absent", rd.Type)
		}
	}
	for _, st := range r.status {
		if st < 100 || st > 599 {
			bad("kod statusu %d jest poza zakresem 100–599", st)
		}
	}
	if len(r.status) > 0 && rd.Type != TypeStatus && rd.Type != TypePath {
		bad("pole status działa tylko w regułach status i path")
	}
	for _, is := range p.issues[before:] {
		if is.Level == "error" {
			return nil
		}
	}
	return r
}

func withLine(msg string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s (wiersz %d)", msg, line)
	}
	return msg
}

// compileRegex compiles a pattern with Go's RE2 engine. RE2 runs in time
// linear in the input, so a signature cannot cause catastrophic backtracking
// (ReDoS). The length limit bounds the compiled program.
func compileRegex(pat string, caseSensitive bool) (re *regexp.Regexp, need []string, msg string, safety bool) {
	if pat == "" {
		return nil, nil, "puste wyrażenie regularne", false
	}
	if len(pat) > MaxRegexLen {
		return nil, nil, fmt.Sprintf("wyrażenie regularne jest za długie (%d znaków, limit %d)", len(pat), MaxRegexLen), true
	}
	src := pat
	if !caseSensitive {
		src = "(?i)" + pat
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, nil, "niepoprawne wyrażenie regularne (składnia RE2, bez odwołań wstecznych i lookaround): " + strings.TrimPrefix(err.Error(), "error parsing regexp: "), false
	}
	if tree, err := syntax.Parse(src, syntax.Perl); err == nil {
		need = requiredLiterals(tree.Simplify())
	}
	return re, need, "", false
}

// maxNeedSet bounds the literal set of one pattern.
const maxNeedSet = 24

// requiredLiterals returns a set of lower-case literals such that every match
// of the pattern contains at least one of them, or nil when no such set is
// certain. The engine uses it as a cheap filter: one Aho-Corasick pass over
// the body tells which patterns can match at all, so most never run.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= 0x80 {
				return nil // exotic case folding: do not filter
			}
		}
		if len(re.Rune) < 2 {
			return nil // a single letter filters nothing
		}
		return []string{strings.ToLower(string(re.Rune))}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
	case syntax.OpConcat:
		// Every part is needed: keep the most selective set.
		var best []string
		for _, sub := range re.Sub {
			if set := requiredLiterals(sub); set != nil && (best == nil || moreSelective(set, best)) {
				best = set
			}
		}
		return best
	case syntax.OpAlternate:
		// One branch is enough for a match: every branch must give a set.
		seen := map[string]bool{}
		var out []string
		for _, sub := range re.Sub {
			set := requiredLiterals(sub)
			if set == nil {
				return nil
			}
			for _, l := range set {
				if !seen[l] {
					seen[l] = true
					out = append(out, l)
				}
			}
		}
		if len(out) > maxNeedSet {
			return nil
		}
		return out
	}
	return nil
}

// moreSelective reports whether literal set a filters better than b: its
// shortest literal is longer, or as long with fewer literals.
func moreSelective(a, b []string) bool {
	ma, mb := shortest(a), shortest(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func shortest(set []string) int {
	n := len(set[0])
	for _, l := range set[1:] {
		n = min(n, len(l))
	}
	return n
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "")), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}
