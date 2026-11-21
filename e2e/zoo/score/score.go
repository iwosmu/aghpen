package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// Row is one line of e2e/zoo/truth.tsv: what a careful analyst says about one published port.
type Row struct {
	Batch, Proto, Category, Image string
	Port                          int
	Service, Product, Version     string
	Techs, Classes, OK            []string
	Finding, Ready                string
}

// ReadTruth parses the truth table (tab-separated, 13 columns, # comments).
func ReadTruth(r io.Reader) ([]Row, error) {
	var rows []Row
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 13 {
			return nil, fmt.Errorf("truth line %d: %d columns, want 13", n, len(f))
		}
		port, err := strconv.Atoi(f[1])
		if err != nil {
			return nil, fmt.Errorf("truth line %d: port %q", n, f[1])
		}
		rows = append(rows, Row{Batch: f[0], Port: port, Proto: f[2], Category: f[3], Image: f[4], Service: f[5], Product: f[6],
			Version: f[7], Techs: list(f[8]), Classes: list(f[9]), Finding: f[10], OK: list(f[11]), Ready: f[12]})
	}
	return rows, sc.Err()
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Platform: runtimes, web servers and front-end libraries that a page or header shows on many products. Reported
// next to a product they are not counted as false positives; RESULTS.md lists the ones checked by hand.
var Platform = []string{"^Go$", "^Node\\.js$", "^Express$", "^Apache HTTP Server$", "^PHP$", "^Java$", "^jQuery$", "^Bootstrap$",
	"^Vue\\.js$", "^React$", "^Angular", "^nginx$", "^OpenResty$", "^Python$", "^Jetty$", "^Font Awesome$"}

func re(expr string) *regexp.Regexp { return regexp.MustCompile("(?i)" + expr) }

// Result is the score of one tool on one truth row. Version, Techs, Classes and Finding are nil when the row does not
// ask for them (not counted).
type Result struct {
	Found, Named, Product            bool
	Version, Techs, Classes, Finding *bool
	Said                             string   // what the tool said: name, product, version, technologies
	Missing                          []string // expected technologies or classes not reported
	Wrong                            []string // technologies or classes reported that the row does not allow
}

func ptr(b bool) *bool { return &b }

// Score checks one service against one row. svc is nil when the tool did not report the port open.
func Score(row Row, svc *model.ServiceResult, findings []model.Finding) Result {
	var r Result
	if svc == nil || svc.State != "open" {
		if row.Version != "" {
			r.Version = ptr(false)
		}
		if len(row.Techs) > 0 {
			r.Techs = ptr(false)
		}
		if len(row.Classes) > 0 {
			r.Classes = ptr(false)
		}
		if row.Finding != "" {
			r.Finding = ptr(false)
		}
		return r
	}
	r.Found = true
	r.Named = re("^(" + row.Service + ")$").MatchString(svc.Name)
	names := techNames(svc)
	r.Said = said(svc)

	prod := re(row.Product)
	versions := []string{}
	for _, t := range svc.Technologies {
		if prod.MatchString(t.Name) {
			r.Product = true
			versions = append(versions, t.Version)
		}
	}
	if svc.Product != "" && prod.MatchString(svc.Product) {
		r.Product = true
		versions = append(versions, svc.Version)
	}
	if row.Version != "" {
		ok := false
		for _, v := range versions {
			if versionMatch(row.Version, v) {
				ok = true
			}
		}
		r.Version = ptr(ok)
	}
	if len(row.Techs) > 0 {
		all := true
		for _, want := range row.Techs {
			if !anyMatch(re(want), names) {
				all = false
				r.Missing = append(r.Missing, want)
			}
		}
		r.Techs = ptr(all)
	}
	if len(row.Classes) > 0 {
		all := true
		for _, c := range row.Classes {
			if !contains(svc.Classes, c) {
				all = false
				r.Missing = append(r.Missing, "class:"+c)
			}
		}
		r.Classes = ptr(all)
	}
	if row.Finding != "" {
		ok := false
		for _, f := range findings {
			if f.Port == row.Port && (strings.Contains(strings.ToLower(f.Title), strings.ToLower(row.Finding)) || f.Type == row.Finding || f.Signature == row.Finding) {
				ok = true
			}
		}
		r.Finding = ptr(ok)
	}
	allowed := append([]string{row.Product}, row.Techs...)
	allowed = append(allowed, row.OK...)
	allowed = append(allowed, Platform...)
	for _, t := range svc.Technologies {
		// nmap's own product shown as a technology is nmap's statement, scored as such, not a signature's.
		if svc.Product != "" && strings.EqualFold(t.Name, svc.Product) {
			continue
		}
		if !anyRe(allowed, t.Name) {
			r.Wrong = append(r.Wrong, t.Name)
		}
	}
	for _, c := range svc.Classes {
		if !contains(row.Classes, c) && !anyRe(row.OK, "class:"+c) {
			r.Wrong = append(r.Wrong, "class:"+c)
		}
	}
	return r
}

// versionMatch: the reported version starts with the expected one at a component boundary ("11.6" matches "11.6.16",
// not "11.60").
func versionMatch(want, got string) bool {
	got = strings.TrimPrefix(strings.TrimSpace(got), "v")
	if got == "" || !strings.HasPrefix(got, want) {
		return false
	}
	if len(got) == len(want) {
		return true
	}
	c := got[len(want)]
	return c < '0' || c > '9'
}

func techNames(svc *model.ServiceResult) []string {
	out := []string{}
	for _, t := range svc.Technologies {
		out = append(out, t.Name)
	}
	if svc.Product != "" {
		out = append(out, svc.Product)
	}
	return out
}

func said(svc *model.ServiceResult) string {
	parts := []string{svc.Name}
	if svc.Product != "" {
		parts = append(parts, strings.TrimSpace(svc.Product+" "+svc.Version))
	}
	var ts []string
	for _, t := range svc.Technologies {
		ts = append(ts, strings.TrimSpace(t.Name+" "+t.Version))
	}
	sort.Strings(ts)
	if len(ts) > 0 {
		parts = append(parts, "["+strings.Join(ts, ", ")+"]")
	}
	if len(svc.Classes) > 0 {
		parts = append(parts, "{"+strings.Join(svc.Classes, ",")+"}")
	}
	return strings.Join(parts, " ")
}

func anyMatch(r *regexp.Regexp, names []string) bool {
	for _, n := range names {
		if r.MatchString(n) {
			return true
		}
	}
	return false
}

func anyRe(exprs []string, s string) bool {
	for _, e := range exprs {
		if re(e).MatchString(s) {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Find returns the service of the given port and protocol in a scan result (any host), or nil.
func Find(hosts []model.HostResult, port int, proto string) *model.ServiceResult {
	for i := range hosts {
		for j := range hosts[i].Services {
			s := &hosts[i].Services[j]
			if s.Port == port && s.Proto == proto && s.State == "open" && !s.Carried {
				return s
			}
		}
	}
	return nil
}

// Tally counts results per category: [hits, asked] for each check.
type Tally struct {
	Rows                                                int
	Found, Named, Product                               int
	Version, VersionN, Techs, TechsN, Classes, ClassesN int
	Wrong                                               int
}

func (t *Tally) Add(r Result) {
	t.Rows++
	t.Found += b2i(r.Found)
	t.Named += b2i(r.Named)
	t.Product += b2i(r.Product)
	add := func(p *bool, hit, n *int) {
		if p != nil {
			*n++
			*hit += b2i(*p)
		}
	}
	add(r.Version, &t.Version, &t.VersionN)
	add(r.Techs, &t.Techs, &t.TechsN)
	add(r.Classes, &t.Classes, &t.ClassesN)
	t.Wrong += len(r.Wrong)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
