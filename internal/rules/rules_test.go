package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, src string) *Rule {
	t.Helper()
	r, val := Parse(src)
	if r == nil {
		t.Fatalf("parse failed: %+v", val.Issues)
	}
	return r
}

func hasIssue(val Validation, path, fragment string) bool {
	for _, is := range val.Issues {
		if is.Path == path && strings.Contains(is.Message, fragment) {
			return true
		}
	}
	return false
}

func TestValidatorPolishMessagesAndPaths(t *testing.T) {
	cases := []struct{ src, path, frag string }{
		{"id: x\nseverity: critical\nmatch: {class: login}", "severity", "nieznana waga"},
		{"id: x\nmatch: {title: '(a'}", "match.title", "RE2"},
		{"id: x\nmatch: {title: '(?=a)b'}", "match.title", "RE2"},
		{"id: x\nmatch: {port: 70000}", "match.port[0]", "nie jest portem"},
		{"id: x\nmatch: {colour: red}", "match.colour", "nieznany warunek"},
		{"id: x\nwhere: {cidr: [10.0.0.0/33]}\nmatch: {class: login}", "where.cidr[0]", "CIDR"},
		{"id: x\nmatch: {all: []}", "match.all", "niepustej listy"},
		{"id: x\nmatch: {any: [{tls: {expird: true}}]}", "match.any[0].tls.expird", "nieznane pole"},
		{"id: x\nmatch: {tech: 'WordPress <<< 6'}", "match.tech", "technologii"},
		{"id: Zle ID\nmatch: {class: login}", "id", "małe litery"},
		{"id: x", "match", "brak warunku"},
		{"id: x\nexpect: maybe\nmatch: {class: login}", "expect", "nieznane oczekiwanie"},
		{"id: x\nmatch: [class: login]", "match", "all: [...]"},
	}
	for _, c := range cases {
		r, val := Parse(c.src)
		if r != nil || val.OK {
			t.Errorf("%q: expected an error", c.src)
			continue
		}
		if !hasIssue(val, c.path, c.frag) {
			t.Errorf("%q: no issue at %s with %q: %+v", c.src, c.path, c.frag, val.Issues)
		}
	}
	// Line numbers are in the message.
	_, val := Parse("id: x\nseverity: high\nmatch:\n  port: abc\n")
	if len(val.Issues) == 0 || !strings.Contains(val.Issues[0].Message, "wiersz 4") {
		t.Fatalf("no line number: %+v", val.Issues)
	}
	// Unknown top-level field is a warning, not an error.
	r, val := Parse("id: x\nfoo: 1\nmatch: {class: login}")
	if r == nil || len(val.Issues) != 1 || val.Issues[0].Level != "warning" {
		t.Fatalf("want one warning: %+v", val.Issues)
	}
}

func TestBuiltinPackIsValid(t *testing.T) {
	pack, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(pack) < 12 {
		t.Fatalf("starter pack has %d rules, want at least 12", len(pack))
	}
	seen := map[string]bool{}
	enabled := 0
	for _, r := range pack {
		if seen[r.ID] {
			t.Fatalf("duplicate id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Enabled {
			enabled++
		}
		// The stored text of each rule parses on its own.
		r2, val := Parse(r.YAML)
		if r2 == nil || len(val.Issues) > 0 {
			t.Fatalf("%s: stored text does not parse cleanly: %+v", r.ID, val.Issues)
		}
	}
	if enabled == len(pack) || enabled == 0 {
		t.Fatalf("expected a mix of enabled and disabled rules, got %d of %d enabled", enabled, len(pack))
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"6.4.3", "6.5", -1}, {"6.10", "6.9", 1}, {"6", "6.0.0", 0}, {"v2.4.57", "2.4.57", 0}, {"5.9-beta", "6", -1}, {"10.1", "9.99", 1}}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// ---------- fixtures ----------

func web(id int64, port int, scheme, title string, classes ...string) *SvcRec {
	return &SvcRec{Service: model.Service{ID: id, Port: port, Proto: "tcp", State: model.ServiceOpen, Name: "http", Title: title,
		URL: scheme + "://x/", HTTPStatus: 200, Classes: classes, FirstSeen: now.Add(-30 * 24 * time.Hour)},
		Result: &model.ServiceResult{Port: port, HTTP: &model.HTTPFingerprint{Scheme: scheme, Status: 200, Title: title,
			Headers: map[string][]string{"Server": {"nginx/1.18.0"}}}}}
}

func host(id int64, ip string, svcs ...*SvcRec) *HostRec {
	return &HostRec{Host: model.Host{ID: id, IP: ip, Status: model.HostUp, FirstSeen: now.Add(-60 * 24 * time.Hour)}, Services: svcs}
}

func run(t *testing.T, src string, hosts ...*HostRec) []Violation {
	t.Helper()
	r := mustParse(t, src)
	e := NewEvaluator([]*Rule{r}, now)
	for _, h := range hosts {
		e.Host(h)
	}
	return e.Finish()
}

func TestLeaves(t *testing.T) {
	admin := web(1, 8080, "http", "Panel administracyjny", model.ClassAdminPanel, model.ClassLogin)
	plain := web(2, 80, "http", "Strona")
	secure := web(3, 443, "https", "Logowanie", model.ClassLogin)
	secure.Result.TLS = &model.TLSInfo{SubjectCN: "a.test", NotAfter: now.Add(5 * 24 * time.Hour), SelfSigned: true}
	expired := web(4, 8443, "https", "Stary")
	expired.Result.TLS = &model.TLSInfo{SubjectCN: "old.test", NotAfter: now.Add(-24 * time.Hour)}
	redirect := web(5, 81, "http", "Login", model.ClassLogin)
	redirect.Result.HTTP.Redirects = []model.Redirect{{From: "http://x/", To: "https://x/", Status: 301}}
	db := &SvcRec{Service: model.Service{ID: 6, Port: 5432, Proto: "tcp", State: model.ServiceOpen, Name: "postgresql", FirstSeen: now.Add(-time.Hour)}}
	gone := &SvcRec{Service: model.Service{ID: 7, Port: 23, Proto: "tcp", State: model.ServiceGone, Name: "telnet"}}
	wp := web(8, 8081, "http", "Blog")
	wp.Service.Technologies = []model.Technology{{Name: "WordPress", Version: "5.8.1"}}
	wpNew := web(9, 8082, "http", "Blog 2")
	wpNew.Service.Technologies = []model.Technology{{Name: "WordPress", Version: "6.6"}}
	wpNoVer := web(10, 8083, "http", "Blog 3")
	wpNoVer.Service.Technologies = []model.Technology{{Name: "WordPress"}}
	ck := web(11, 8084, "https", "App")
	ck.Result.HTTP.Cookies = []model.Cookie{{Name: "sessionid", Secure: false, HTTPOnly: true}}
	ck.Service.Tags = []string{"approved"}

	h1 := host(1, "10.66.1.10", admin, plain, secure, expired, redirect, db, gone, wp, wpNew, wpNoVer, ck)
	h2 := host(2, "10.66.10.5", web(20, 8080, "http", "Admin", model.ClassAdminPanel))
	h2.Host.Tags = []string{"mgmt"}

	ids := func(vs []Violation) []int {
		var out []int
		for _, v := range vs {
			out = append(out, v.Port)
		}
		return out
	}
	cases := []struct {
		name string
		src  string
		want []int
	}{
		{"class", "id: a\nmatch: {class: admin-panel}", []int{8080, 8080}},
		{"not_cidr", "id: a\nwhere: {not_cidr: [10.66.10.0/24]}\nmatch: {class: admin-panel}", []int{8080}},
		{"not_tags", "id: a\nwhere: {not_tags: [mgmt]}\nmatch: {class: admin-panel}", []int{8080}},
		{"login over http", "id: a\nmatch: {all: [{class: login}, {scheme: http}, {redirects_to_https: false}]}", []int{8080}},
		{"tls expired", "id: a\nmatch: {tls: {expired: true}}", []int{8443}},
		{"tls expiring", "id: a\nmatch: {tls: {expired: false, days_left_below: 14}}", []int{443}},
		{"tls self-signed", "id: a\nmatch: {tls: {self_signed: true}}", []int{443}},
		{"no tls on web", "id: a\nmatch: {all: [{tls: {present: false}}, {http_status: [2xx]}, {port: 80}]}", []int{80}},
		{"db port", "id: a\nmatch: {any: [{service: [postgresql, mysql]}, {port: 3306}]}", []int{5432}},
		{"state default open", "id: a\nmatch: {port: 23}", nil},
		{"state explicit", "id: a\nmatch: {port: 23, state: gone}", []int{23}},
		{"tech version", "id: a\nmatch: {tech: 'WordPress < 6'}", []int{8081}},
		{"tech map", "id: a\nmatch: {tech: {name: wordpress, version: '>= 6.5'}}", []int{8082}},
		{"tech any version", "id: a\nmatch: {tech: WordPress}", []int{8081, 8082, 8083}},
		{"header regex", "id: a\nmatch: {header: {name: server, regex: 'nginx/1\\.1[0-8]'}, port: 80}", []int{80}},
		{"header absent", "id: a\nmatch: {header: {name: Strict-Transport-Security, present: false}, scheme: https}", []int{443, 8443, 8084}},
		{"cookie flags", "id: a\nmatch: {cookie: {name_regex: '^session', secure: false}}", []int{8084}},
		{"title", "id: a\nmatch: {title: '^panel'}", []int{8080}},
		{"new within", "id: a\nmatch: {new_within_days: 1}", []int{5432}},
		{"not tagged", "id: a\nmatch: {all: [{scheme: https}, {not: {tags: [approved]}}]}", []int{443, 8443}},
		{"port range", "id: a\nmatch: {port: '8080-8082'}", []int{8080, 8081, 8082, 8080}},
		{"cidr", "id: a\nwhere: {cidr: [10.66.10.5]}\nmatch: {port: 8080}", []int{8080}},
	}
	for _, c := range cases {
		got := ids(run(t, c.src, h1, h2))
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: got ports %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEvidenceNamesMatchedFields(t *testing.T) {
	s := web(1, 8080, "http", "Panel", model.ClassAdminPanel)
	vs := run(t, "id: adm\nseverity: high\nmatch: {all: [{class: admin-panel}, {port: 8080}, {not: {tags: [approved]}}]}", host(7, "10.0.0.7", s))
	if len(vs) != 1 {
		t.Fatalf("want 1 violation, got %d", len(vs))
	}
	v := vs[0]
	if v.Key != "policy-violation|adm|10.0.0.7|8080/tcp" || v.HostID != 7 || v.ServiceID == nil || *v.ServiceID != 1 || v.Severity != model.SevHigh {
		t.Fatalf("bad violation: %+v", v)
	}
	var where []string
	for _, e := range v.Evidence {
		where = append(where, e.Where+"="+e.Snippet)
	}
	joined := strings.Join(where, ";")
	for _, want := range []string{"rule=adm", "class=admin-panel", "port=8080/tcp", "not=nie zachodzi: etykieta approved"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence %q lacks %q", joined, want)
		}
	}
	r := mustParse(t, "id: adm\nseverity: high\nremediation: Zamknij.\nmatch: {class: admin-panel}")
	f := v.Finding(r, 42, now)
	if f.Type != FindingType || f.Key != v.Key || f.LastRunID != 42 || f.Signature != "policy:adm" || !strings.Contains(f.Description, "Zamknij.") || f.Interest < 80 {
		t.Fatalf("bad finding: %+v", f)
	}
}

func TestPresentPerHostAndScope(t *testing.T) {
	a := host(1, "10.66.1.1", web(1, 443, "https", "A"))
	b := host(2, "10.66.1.2", web(2, 80, "http", "B"))
	down := host(3, "10.66.1.3")
	down.Host.Status = model.HostDown
	vs := run(t, "id: must-443\nexpect: present\nwhere: {cidr: [10.66.1.0/24]}\nmatch: {port: 443}", a, b, down)
	if len(vs) != 1 || vs[0].IP != "10.66.1.2" || vs[0].Subject != SubjectHost || vs[0].Key != "policy-violation|must-443|10.66.1.2" {
		t.Fatalf("per host: %+v", vs)
	}
	vs = run(t, "id: any-https\nexpect: present\nper: scope\nwhere: {cidr: [10.66.1.0/24]}\nmatch: {scheme: https}", a, b)
	if len(vs) != 0 {
		t.Fatalf("scope satisfied, got %+v", vs)
	}
	vs = run(t, "id: any-ssh\nexpect: present\nper: scope\nwhere: {cidr: [10.66.1.0/24]}\nmatch: {port: 22}", a, b)
	if len(vs) != 1 || vs[0].Subject != PerScope || !vs[0].Storable || vs[0].HostID != 1 {
		t.Fatalf("scope violated: %+v", vs)
	}
	vs = run(t, "id: any-ssh\nexpect: present\nper: scope\nwhere: {cidr: [192.0.2.0/24]}\nmatch: {port: 22}", a, b)
	if len(vs) != 1 || vs[0].Storable {
		t.Fatalf("empty scope must give one unstorable violation: %+v", vs)
	}
}

func TestHostSubjectAndScopes(t *testing.T) {
	a := host(1, "10.66.1.1", web(1, 23, "http", "x"))
	a.Scopes = []string{"kampus", "www"}
	b := host(2, "10.66.1.2")
	b.Host.Status = model.HostUnstable
	vs := run(t, "id: flappy\nsubject: host\nmatch: {host_status: unstable}", a, b)
	if len(vs) != 1 || vs[0].IP != "10.66.1.2" || vs[0].Subject != SubjectHost {
		t.Fatalf("host status: %+v", vs)
	}
	vs = run(t, "id: s\nwhere: {scope: [Kampus]}\nmatch: {port: 23}", a, b)
	if len(vs) != 1 || vs[0].IP != "10.66.1.1" {
		t.Fatalf("scope where: %+v", vs)
	}
	vs = run(t, "id: s\nsubject: host\nmatch: {port: 23}", a, b)
	if len(vs) != 1 || vs[0].Key != "policy-violation|s|10.66.1.1" {
		t.Fatalf("host subject with service condition: %+v", vs)
	}
}

func TestNoDataIsNotAbsence(t *testing.T) {
	raw := &SvcRec{Service: model.Service{ID: 1, Port: 22, Proto: "tcp", State: model.ServiceOpen, Name: "ssh"}}
	for _, src := range []string{
		"id: a\nmatch: {header: {name: X-Frame-Options, present: false}}",
		"id: a\nmatch: {redirects_to_https: false}",
		"id: a\nmatch: {tls: {present: false}}",
	} {
		if vs := run(t, src, host(1, "10.0.0.1", raw)); len(vs) != 0 {
			t.Errorf("%s: a service without HTTP data must not match: %+v", src, vs)
		}
	}
}

func TestDryRunMessage(t *testing.T) {
	r := mustParse(t, "id: a\nmatch: {class: login}")
	for n, want := range map[int]string{1: "1 naruszenie", 3: "3 naruszenia", 7: "7 naruszeń", 12: "12 naruszeń", 22: "22 naruszenia"} {
		if got := DryRunMessage(r, n, 10, 20); !strings.Contains(got, "zgłosiłaby dziś "+want) {
			t.Errorf("%d: %s", n, got)
		}
	}
}
