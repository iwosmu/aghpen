package sig

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/signatures"
)

// set is an immutable compiled signature set. Match reads it without locks;
// a reload swaps the whole set.
type set struct {
	sigs    []*Sig // all, in load order
	enabled []*Sig
	bySlug  map[string]*Sig
	ac      *ac
	paths   []string
	canon   map[string]string // lower-case technology name or alias → display name
	cats    map[string]string // display name → category
	cpes    map[string]string
}

// Engine implements model.SignatureEngine. It is safe for concurrent use:
// Match and ExtraPaths never block, Load and SetEnabled swap the set atomically.
type Engine struct {
	cur atomic.Pointer[set]
	mu  sync.Mutex // serialises writers
}

var _ model.SignatureEngine = (*Engine)(nil)

// Rejected is a signature that Load refused.
type Rejected struct {
	Slug   string                 `json:"slug"`
	Issues []model.SignatureIssue `json:"issues"`
}

// LoadReport says what a Load call did.
type LoadReport struct {
	Loaded   int        `json:"loaded"`
	Enabled  int        `json:"enabled"`
	Rejected []Rejected `json:"rejected"`
}

// NewEngine returns an engine without signatures.
func NewEngine() *Engine {
	e := &Engine{}
	e.cur.Store(buildSet(nil))
	return e
}

// NewBuiltinEngine returns an engine with the embedded signature library.
func NewBuiltinEngine() (*Engine, error) {
	sigs, err := Builtin()
	if err != nil {
		return nil, err
	}
	e := NewEngine()
	if rep := e.Load(sigs); len(rep.Rejected) > 0 {
		r := rep.Rejected[0]
		return nil, fmt.Errorf("sig: built-in signature %q is invalid: %s: %s", r.Slug, r.Issues[0].Path, r.Issues[0].Message)
	}
	return e, nil
}

var (
	builtinOnce sync.Once
	builtinSigs []model.Signature
	builtinErr  error
)

// Builtin returns the embedded signature library as model records, one per
// signature, each with its own YAML text. The store seeds its table from it.
func Builtin() ([]model.Signature, error) {
	builtinOnce.Do(func() { builtinSigs, builtinErr = loadFS(signatures.FS) })
	if builtinErr != nil {
		return nil, builtinErr
	}
	return append([]model.Signature(nil), builtinSigs...), nil
}

func loadFS(fsys fs.FS) ([]model.Signature, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	// Imported corpora come after the hand-written library (cmd/sigimport
	// already dropped every import that names one of our technologies).
	community, err := fs.Glob(fsys, "community/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(community)
	files = append(files, community...)
	var out []model.Signature
	seen := map[string]string{}
	for _, name := range files {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		parsed, val := Parse(string(data))
		for _, is := range val.Issues {
			if is.Level == "error" {
				return nil, fmt.Errorf("sig: %s: %s: %s", name, is.Path, is.Message)
			}
		}
		for _, s := range parsed {
			if prev, dup := seen[s.Slug]; dup {
				return nil, fmt.Errorf("sig: %s: duplicate signature id %q (also in %s)", name, s.Slug, prev)
			}
			seen[s.Slug] = name
			s.Builtin = true
			m := s.Model()
			m.Author = orDefault(m.Author, "Czujka")
			out = append(out, m)
		}
	}
	return out, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Model returns the signature as a model record.
func (s *Sig) Model() model.Signature {
	return model.Signature{
		Slug: s.Slug, Name: s.Name, Category: s.Category, Description: s.Description, YAML: s.YAML,
		Enabled: s.Enabled, Builtin: s.Builtin, Author: s.Author, Tags: append([]string{}, s.Tags...), Interest: s.Interest,
	}
}

// Parse reads and validates a YAML text with one or more signatures and
// returns the compiled, safe ones together with the validation result.
func Parse(src string) ([]*Sig, model.SignatureValidation) {
	p := &parser{}
	nodes := p.splitDocuments(src)
	trimmed := strings.TrimSpace(src)
	jsonText := strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	var out []*Sig
	pathSet := map[string]bool{}
	ids := map[string]bool{}
	for i, n := range nodes {
		prefix := ""
		if len(nodes) > 1 {
			prefix = fmt.Sprintf("[%d]", i)
		}
		before := p.errorCount()
		var d *Def
		// A converted signature is stored as canonical Czujka YAML.
		foreign := p.origin[n] != "" || jsonText
		if isNuclei(n) {
			d, foreign = p.convertNuclei(n, prefix), true
		} else {
			d = p.parseDef(n, prefix)
		}
		s := p.compile(d, prefix)
		if d != nil && d.ID != "" {
			if ids[d.ID] {
				p.errf(join(prefix, "id"), n, "id „%s” występuje w pliku więcej niż raz", d.ID)
				continue
			}
			ids[d.ID] = true
		}
		// A signature with any error, a safety error included, is never
		// compiled: an unsafe request must not reach the collector.
		if s == nil || p.errorCount() != before {
			continue
		}
		switch {
		case foreign:
			s.YAML = s.Def.YAML()
		case len(nodes) == 1:
			s.YAML = src
		default:
			if b, err := yaml.Marshal(n); err == nil {
				s.YAML = string(b)
			}
		}
		for _, path := range s.paths {
			pathSet[path] = true
		}
		out = append(out, s)
	}
	val := model.SignatureValidation{Issues: p.issues, Paths: sortedKeys(pathSet)}
	if val.Issues == nil {
		val.Issues = []model.SignatureIssue{}
	}
	val.OK = !p.hasErrors()
	if !val.OK {
		// One bad signature in a text makes the text invalid, but the good ones stay usable for built-in loading.
		val.Paths = sortedKeys(pathSet)
	}
	return out, val
}

// Validate is the safe-mode validator. It accepts a signature only when it is
// passive detection: GET or HEAD without a body, headers or credentials, a
// safe path, a bounded number of requests and linear-time patterns.
func Validate(src string) model.SignatureValidation {
	_, val := Parse(src)
	return val
}

// Load replaces the signature set (hot reload). Records with invalid or
// unsafe YAML are rejected and reported; the others are active at once.
// A later record with the same slug replaces an earlier one, so custom
// signatures can override built-in ones.
func (e *Engine) Load(records []model.Signature) LoadReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	var rep LoadReport
	var sigs []*Sig
	index := map[string]int{}
	for _, rec := range records {
		parsed, val := Parse(rec.YAML)
		if !val.OK || len(parsed) == 0 {
			slug := rec.Slug
			if slug == "" && len(parsed) > 0 {
				slug = parsed[0].Slug
			}
			rep.Rejected = append(rep.Rejected, Rejected{Slug: slug, Issues: errorsOnly(val.Issues)})
			continue
		}
		for _, s := range parsed {
			if rec.Slug != "" && len(parsed) == 1 {
				s.Slug = rec.Slug
			}
			s.Builtin = rec.Builtin
			s.Enabled = rec.Enabled
			if rec.Author != "" {
				s.Author = rec.Author
			}
			if i, dup := index[s.Slug]; dup {
				sigs[i] = s
				continue
			}
			index[s.Slug] = len(sigs)
			sigs = append(sigs, s)
		}
	}
	st := buildSet(sigs)
	e.cur.Store(st)
	rep.Loaded, rep.Enabled = len(st.sigs), len(st.enabled)
	return rep
}

func errorsOnly(in []model.SignatureIssue) []model.SignatureIssue {
	var out []model.SignatureIssue
	for _, i := range in {
		if i.Level == "error" {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		out = append(out, model.SignatureIssue{Level: "error", Message: "pusta sygnatura"})
	}
	return out
}

// SetEnabled turns one signature on or off. It reports whether the slug exists.
func (e *Engine) SetEnabled(slug string, enabled bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.cur.Load()
	if _, ok := old.bySlug[slug]; !ok {
		return false
	}
	sigs := make([]*Sig, len(old.sigs))
	for i, s := range old.sigs {
		if s.Slug == slug {
			cp := *s
			cp.Enabled = enabled
			s = &cp
		}
		sigs[i] = s
	}
	e.cur.Store(buildSet(sigs))
	return true
}

// Signatures lists the loaded signatures as model records.
func (e *Engine) Signatures() []model.Signature {
	st := e.cur.Load()
	out := make([]model.Signature, len(st.sigs))
	for i, s := range st.sigs {
		out[i] = s.Model()
	}
	return out
}

// Count returns the number of loaded and of enabled signatures.
func (e *Engine) Count() (total, enabled int) {
	st := e.cur.Load()
	return len(st.sigs), len(st.enabled)
}

// buildSet prepares a signature set for matching: the body automaton, the
// technology alias table and the ordered list of extra paths.
func buildSet(sigs []*Sig) *set {
	// Literal ids belong to one set. Rules are copied so that a set that is
	// still in use by a running Match is never written to.
	cloned := make([]*Sig, len(sigs))
	for i, s := range sigs {
		cloned[i] = s.clone()
	}
	sigs = cloned
	st := &set{sigs: sigs, bySlug: map[string]*Sig{}, canon: map[string]string{}, cats: map[string]string{}, cpes: map[string]string{}}
	litID := map[string]int32{}
	var lits []string
	idOf := func(low string) int32 {
		if low == "" {
			return -1
		}
		id, ok := litID[low]
		if !ok {
			id = int32(len(lits))
			litID[low] = id
			lits = append(lits, low)
		}
		return id
	}
	pathScore := map[string]float64{}
	for _, s := range sigs {
		st.bySlug[s.Slug] = s
		if !s.Enabled {
			continue
		}
		st.enabled = append(st.enabled, s)
		if s.isTech {
			key := strings.ToLower(s.techName)
			if _, ok := st.canon[key]; !ok {
				st.canon[key] = s.techName
			}
			for _, a := range s.Aliases {
				if _, ok := st.canon[strings.ToLower(a)]; !ok {
					st.canon[strings.ToLower(a)] = s.techName
				}
			}
			if _, ok := st.cats[s.techName]; !ok {
				st.cats[s.techName] = s.Category
			}
			if s.CPE != "" && st.cpes[s.techName] == "" {
				st.cpes[s.techName] = s.CPE
			}
		}
		// The rule structs are private to the signature, so the ids can be written in place.
		for _, r := range append(append([]*rule{}, s.rules...), s.version...) {
			if r.typ != TypeBody {
				continue
			}
			for i := range r.contains {
				r.contains[i].id = idOf(r.contains[i].low)
			}
			for i := range r.containsAll {
				r.containsAll[i].id = idOf(r.containsAll[i].low)
			}
			for i := range r.regex {
				x := &r.regex[i]
				x.ids = make([]int32, len(x.need))
				for j, l := range x.need {
					x.ids[j] = idOf(l)
				}
			}
		}
		// A path is worth more when a strong rule of an interesting signature needs it.
		best := map[string]float64{}
		for _, r := range s.rules {
			if r.typ == TypePath && !r.not {
				best[r.path] = max(best[r.path], r.weight)
			}
		}
		for _, path := range s.paths {
			w := best[path]
			if w == 0 {
				w = 0.3 // version-only or request-only path
			}
			pathScore[path] += w * (1 + float64(s.Interest)/100)
		}
	}
	if len(lits) > 0 {
		st.ac = buildAC(lits)
	}
	st.paths = sortedKeys(pathScore)
	sort.SliceStable(st.paths, func(i, j int) bool { return pathScore[st.paths[i]] > pathScore[st.paths[j]] })
	return st
}

// ExtraPaths returns the safe paths that enabled signatures need, most useful
// first, without duplicates.
func (e *Engine) ExtraPaths() []string {
	return append([]string{}, e.cur.Load().paths...)
}

// PathsFor returns the extra paths worth fetching for one service whose root
// page is already known, best first, at most limit (0: no limit). Paths of
// signatures that the root page already supports come first, so a small
// per-host budget is spent where it confirms or dates a technology. Paths of
// custom signatures come next: the analyst asked for them, so the budget
// must not go to the generic paths of the built-in library first.
func (e *Engine) PathsFor(svc *model.ServiceResult, limit int) []string {
	st := e.cur.Load()
	if svc == nil {
		return nil
	}
	v := newView(svc, st, nil)
	score := map[string]float64{}
	for i, path := range st.paths {
		score[path] = 1 / float64(i+2) // keep the global order as a tie-break
	}
	for _, s := range st.enabled {
		if len(s.paths) == 0 {
			continue
		}
		if !s.Builtin {
			for _, path := range s.paths {
				score[path] += 5
			}
		}
		support := 0.0
		for _, r := range s.rules {
			if r.typ == TypePath || r.not || r.absent {
				continue
			}
			if ok, _, _ := v.eval(r); ok {
				support = max(support, r.weight)
			}
		}
		if support == 0 {
			continue
		}
		for _, path := range s.paths {
			score[path] += 10 * support
		}
	}
	out := sortedKeys(score)
	sort.SliceStable(out, func(i, j int) bool { return score[out[i]] > score[out[j]] })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Match evaluates the enabled signatures against one service.
func (e *Engine) Match(svc *model.ServiceResult) ([]model.SigMatch, []model.Technology, []string) {
	return e.MatchHost(svc)
}

// MatchHost is Match with the host names of the address (reverse DNS, the
// target domain). Hostname rules and the staging heuristics use them.
func (e *Engine) MatchHost(svc *model.ServiceResult, hostnames ...string) ([]model.SigMatch, []model.Technology, []string) {
	matches, techs, classes := []model.SigMatch{}, []model.Technology{}, []string{}
	if svc == nil {
		return matches, techs, classes
	}
	st := e.cur.Load()
	v := newView(svc, st, hostnames)
	var hit []*Sig
	for _, s := range st.enabled {
		if m, ok := v.evalSig(s); ok {
			matches = append(matches, m)
			hit = append(hit, s)
		}
	}
	techs = mergeTechnologies(st, svc, matches, hit)
	techs = addSelfDescribed(svc, techs)
	classSet := map[string]bool{}
	for _, m := range matches {
		for _, c := range m.Classes {
			classSet[c] = true
		}
	}
	for _, c := range classify(v) {
		classSet[c] = true
	}
	// An unfinished installer asks for the new administrator's password (Nextcloud, Matomo, Joomla, WordPress):
	// that form makes it an install page, not a login page.
	if classSet[model.ClassInstallPage] {
		delete(classSet, model.ClassLogin)
	}
	classes = sortedKeys(classSet)
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].Signature < matches[j].Signature
	})
	return matches, techs, classes
}

// techAcc collects the evidence for one technology.
type techAcc struct {
	name     string
	category string
	cpe      string
	prod     float64 // Π(1 - confidence) over the evidence
	sources  []string
	versions map[string]float64 // version → Π(1 - confidence)
	order    []string
}

func (t *techAcc) add(conf float64, source, version string) {
	if conf <= 0 {
		return
	}
	conf = min(conf, 0.99)
	t.prod *= 1 - conf
	for _, s := range t.sources {
		if s == source {
			source = ""
			break
		}
	}
	if source != "" {
		t.sources = append(t.sources, source)
	}
	if version != "" {
		if _, ok := t.versions[version]; !ok {
			t.versions[version] = 1
			t.order = append(t.order, version)
		}
		t.versions[version] *= 1 - conf
	}
}

// versionConflictPenalty lowers the confidence of a technology whose
// evidence disagrees about the version.
const versionConflictPenalty = 0.85

// compatible reports whether one version is a more precise form of the other
// ("2.4" and "2.4.57").
func compatible(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	return a == b || strings.HasPrefix(b, a) && (b[len(a)] == '.' || b[len(a)] == '-' || b[len(a)] == '_' || b[len(a)] == '+')
}

// mergeTechnologies builds one Technology per name. The confidence is the
// noisy-OR over every signature and the nmap product that name it.
func mergeTechnologies(st *set, svc *model.ServiceResult, matches []model.SigMatch, hit []*Sig) []model.Technology {
	acc := map[string]*techAcc{}
	var order []string
	get := func(name, category string) *techAcc {
		key := strings.ToLower(name)
		if canon, ok := st.canon[key]; ok {
			name, key = canon, strings.ToLower(canon)
		}
		t, ok := acc[key]
		if !ok {
			t = &techAcc{name: name, prod: 1, versions: map[string]float64{}}
			t.category = st.cats[name]
			if t.category == "" {
				t.category = category
			}
			t.cpe = st.cpes[name]
			acc[key] = t
			order = append(order, key)
		}
		return t
	}
	for i, m := range matches {
		s := hit[i]
		if !s.isTech {
			continue
		}
		t := get(s.techName, s.Category)
		t.add(m.Confidence, s.Slug, m.Version)
		if t.cpe == "" {
			t.cpe = s.CPE
		}
		for _, imp := range s.Implies {
			get(imp, model.CatOther).add(m.Confidence*0.9, "implied:"+s.Slug, "")
		}
	}
	if product := strings.TrimSpace(svc.Product); product != "" {
		conf := svc.Confidence
		if conf <= 0 || conf > 1 {
			conf = 0.7
		}
		t := get(nmapProductName(product, func(name string) bool {
			key := strings.ToLower(name)
			if canon, ok := st.canon[key]; ok {
				key = strings.ToLower(canon)
			}
			_, ok := acc[key]
			return ok
		}), nmapCategory(svc.Name))
		t.add(conf, "nmap", cleanVersion(firstField(svc.Version)))
		if t.cpe == "" {
			for _, c := range svc.CPE {
				if strings.HasPrefix(c, "cpe:/a:") || strings.HasPrefix(c, "cpe:2.3:a:") {
					t.cpe = c
					break
				}
			}
		}
	}

	out := make([]model.Technology, 0, len(order))
	for _, key := range order {
		t := acc[key]
		conf := 1 - t.prod
		// Fold versions that are prefixes of a more precise one into it.
		best, bestConf := "", -1.0
		conflict := false
		for _, ver := range t.order {
			c := 1 - t.versions[ver]
			for _, other := range t.order {
				if other != ver && len(other) < len(ver) && compatible(other, ver) {
					c = 1 - (1-c)*t.versions[other]
				}
			}
			if c > bestConf+1e-9 || (c > bestConf-1e-9 && len(ver) > len(best)) {
				best, bestConf = ver, c
			}
		}
		for _, ver := range t.order {
			if !compatible(ver, best) {
				conflict = true
				t.sources = append(t.sources, "version-conflict:"+ver)
			}
		}
		if conflict {
			conf *= versionConflictPenalty
		}
		cpe := t.cpe
		if best != "" && strings.HasPrefix(cpe, "cpe:2.3:") && strings.Count(cpe, ":") == 4 {
			cpe += ":" + strings.ToLower(best)
		}
		out = append(out, model.Technology{
			Name: t.name, Category: t.category, Version: best, Confidence: round3(conf), Sources: t.sources, CPE: cpe,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// nmapServerWords are words nmap appends to a product name ("Grafana http",
// "Jenkins httpd", "Gitea web server") that are not part of the product.
var nmapServerWords = []string{" http server", " httpd", " http", " web server", " web interface", " web ui", " web admin", " server"}

// nmapProductName returns the name under which an nmap product joins the
// technologies of a service. When the product is "<name> http" (or another
// server word) and a signature already named <name>, the nmap evidence
// joins that technology instead of creating a second one.
func nmapProductName(product string, known func(string) bool) string {
	if known(product) {
		return product
	}
	lower := strings.ToLower(product)
	for _, w := range nmapServerWords {
		if strings.HasSuffix(lower, w) {
			if base := strings.TrimSpace(product[:len(product)-len(w)]); base != "" && known(base) {
				return base
			}
		}
	}
	return product
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func nmapCategory(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "http"):
		return model.CatWebServer
	case databaseServices[n]:
		return model.CatDatabase
	}
	return model.CatOther
}
