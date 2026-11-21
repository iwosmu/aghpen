package sig

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func rec(slug, yaml string, enabled bool) model.Signature {
	return model.Signature{Slug: slug, YAML: yaml, Enabled: enabled}
}

func techByName(techs []model.Technology, name string) *model.Technology {
	for i := range techs {
		if techs[i].Name == name {
			return &techs[i]
		}
	}
	return nil
}

func slugs(ms []model.SigMatch) []string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.Signature)
	}
	return out
}

const sigNginx = `
id: nginx
name: nginx
category: web-server
cpe: cpe:2.3:a:f5:nginx
match:
  rules:
    - {type: header, name: Server, regex: '^nginx(?:/([0-9.]+))?', weight: 0.9, version_group: 1}
`

const sigWP = `
id: wordpress
name: WordPress
category: cms
cpe: cpe:2.3:a:wordpress:wordpress
implies: [PHP]
classes: [login]
interest: 10
tags: [php]
requests: [/wp-login.php]
match:
  min_confidence: 0.5
  rules:
    - {type: meta, name: generator, regex: '^WordPress(?: ([0-9.]+))?', weight: 0.9, version_group: 1}
    - {type: body, contains: 'wp-content/', weight: 0.5}
    - {type: path, path: /wp-login.php, status: 200, contains: 'user_login', weight: 0.9}
`

const sigPHP = `
id: php
name: PHP
category: language
cpe: cpe:2.3:a:php:php
match:
  rules:
    - {type: header, name: X-Powered-By, regex: '^PHP(?:/([0-9.]+))?', weight: 0.9, version_group: 1}
`

const sigFinding = `
id: header-version-server
name: Wersja oprogramowania w Server
category: header
interest: 15
match:
  rules:
    - {type: header, name: Server, regex: '/[0-9]+\.[0-9]+', weight: 0.9}
`

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine()
	rep := e.Load([]model.Signature{rec("nginx", sigNginx, true), rec("wordpress", sigWP, true), rec("php", sigPHP, true), rec("header-version-server", sigFinding, true)})
	if rep.Loaded != 4 || rep.Enabled != 4 || len(rep.Rejected) != 0 {
		t.Fatalf("load report = %+v", rep)
	}
	return e
}

func TestMatchReturnsMatchesTechnologiesAndClasses(t *testing.T) {
	e := testEngine(t)
	svc := sample()
	matches, techs, classes := e.Match(svc)
	if got := slugs(matches); !reflect.DeepEqual(got, []string{"wordpress", "header-version-server", "nginx", "php"}) {
		t.Errorf("matches (best first, then by slug) = %v", got)
	}
	wp := techByName(techs, "WordPress")
	if wp == nil || wp.Version != "6.5.3" || wp.Category != model.CatCMS || wp.CPE != "cpe:2.3:a:wordpress:wordpress:6.5.3" {
		t.Fatalf("WordPress technology = %+v", wp)
	}
	// meta 0.9, body 0.5, path 0.9 → 1 - 0.1*0.5*0.1 = 0.995; the technology keeps at most 0.99 per source.
	if matches[0].Confidence != 0.995 || wp.Confidence != 0.99 {
		t.Errorf("WordPress confidence: match %v, technology %v", matches[0].Confidence, wp.Confidence)
	}
	// PHP: its own signature (0.9) and "implied by WordPress" (0.995 capped 0.99, ×0.9) → 1 - 0.1*(1-0.891).
	php := techByName(techs, "PHP")
	if php == nil || php.Version != "8.2.7" || math.Abs(php.Confidence-0.989) > 0.0011 {
		t.Fatalf("PHP technology = %+v", php)
	}
	if !reflect.DeepEqual(php.Sources, []string{"implied:wordpress", "php"}) {
		t.Errorf("PHP sources = %v", php.Sources)
	}
	// nginx: the signature (0.9) and the nmap product (confidence 1 → 0.99), same version.
	ng := techByName(techs, "nginx")
	if ng == nil || ng.Version != "1.24.0" || math.Abs(ng.Confidence-0.999) > 0.0011 || !reflect.DeepEqual(ng.Sources, []string{"nginx", "nmap"}) {
		t.Fatalf("nginx technology = %+v", ng)
	}
	// A finding (category header) is a match but not a technology.
	if techByName(techs, "Wersja oprogramowania w Server") != nil {
		t.Error("a header finding must not become a technology")
	}
	if len(techs) != 3 {
		t.Errorf("technologies = %+v", techs)
	}
	// Classes: "login" from the signature and from the password field; "staging" from the dev. host name and certificate.
	if !reflect.DeepEqual(classes, []string{model.ClassLogin, model.ClassStaging}) {
		t.Errorf("classes = %v", classes)
	}
	// Match must not write to its input.
	if svc.Matches != nil || svc.Technologies != nil || svc.Classes != nil {
		t.Error("Match must not modify the service")
	}
}

func TestMatchNilAndEmpty(t *testing.T) {
	e := testEngine(t)
	m, tech, cl := e.Match(nil)
	if m == nil || tech == nil || cl == nil || len(m)+len(tech)+len(cl) != 0 {
		t.Error("nil service: want empty, non-nil slices")
	}
	m, tech, cl = e.Match(&model.ServiceResult{Port: 9, State: "open"})
	if m == nil || tech == nil || cl == nil || len(m)+len(tech)+len(cl) != 0 {
		t.Errorf("empty service: %v %v %v", m, tech, cl)
	}
}

func TestTechnologyMergeWithNmap(t *testing.T) {
	e := testEngine(t)
	base := func() *model.ServiceResult {
		return &model.ServiceResult{Name: "http", HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"nginx/1.24.0"}}}}
	}

	t.Run("signature only", func(t *testing.T) {
		_, techs, _ := e.Match(base())
		ng := techByName(techs, "nginx")
		if ng == nil || ng.Confidence != 0.9 || ng.Version != "1.24.0" || !reflect.DeepEqual(ng.Sources, []string{"nginx"}) {
			t.Fatalf("nginx = %+v", ng)
		}
	})
	t.Run("nmap agrees: confidence goes up", func(t *testing.T) {
		svc := base()
		svc.Product, svc.Version, svc.Confidence = "nginx", "1.24.0", 0.8
		_, techs, _ := e.Match(svc)
		ng := techByName(techs, "nginx")
		// 1 - (1-0.9)(1-0.8) = 0.98
		if ng == nil || ng.Confidence != 0.98 || ng.Version != "1.24.0" {
			t.Fatalf("nginx = %+v", ng)
		}
		for _, s := range ng.Sources {
			if strings.HasPrefix(s, "version-conflict") {
				t.Errorf("no conflict expected: %v", ng.Sources)
			}
		}
	})
	t.Run("nmap gives a less precise version: no conflict, the precise one stays", func(t *testing.T) {
		svc := base()
		svc.Product, svc.Version, svc.Confidence = "nginx", "1.24", 0.8
		_, techs, _ := e.Match(svc)
		ng := techByName(techs, "nginx")
		if ng == nil || ng.Confidence != 0.98 || ng.Version != "1.24.0" {
			t.Fatalf("nginx = %+v", ng)
		}
	})
	t.Run("nmap disagrees about the version: confidence goes down", func(t *testing.T) {
		svc := base()
		svc.Product, svc.Version, svc.Confidence = "nginx", "1.18.0", 0.8
		_, techs, _ := e.Match(svc)
		ng := techByName(techs, "nginx")
		// 0.98 × 0.85 = 0.833; the version with the stronger evidence (signature 0.9 > nmap 0.8) wins.
		if ng == nil || math.Abs(ng.Confidence-0.833) > 0.0011 || ng.Version != "1.24.0" {
			t.Fatalf("nginx = %+v", ng)
		}
		if !reflect.DeepEqual(ng.Sources, []string{"nginx", "nmap", "version-conflict:1.18.0"}) {
			t.Errorf("sources = %v", ng.Sources)
		}
		if ng.Confidence >= 0.9 {
			t.Error("a version conflict must lower the confidence below the single-source value")
		}
	})
	t.Run("nmap is the stronger source: its version wins", func(t *testing.T) {
		svc := base()
		svc.Product, svc.Version, svc.Confidence = "nginx", "1.18.0", 1
		_, techs, _ := e.Match(svc)
		ng := techByName(techs, "nginx")
		if ng == nil || ng.Version != "1.18.0" || !reflect.DeepEqual(ng.Sources, []string{"nginx", "nmap", "version-conflict:1.24.0"}) {
			t.Fatalf("nginx = %+v", ng)
		}
	})
	t.Run("nmap product without a signature", func(t *testing.T) {
		svc := &model.ServiceResult{Port: 3306, Name: "mysql", Product: "MySQL", Version: "8.0.36-0ubuntu0.22.04.1", Confidence: 1, CPE: []string{"cpe:/a:mysql:mysql:8.0.36"}}
		_, techs, _ := e.Match(svc)
		my := techByName(techs, "MySQL")
		if my == nil || my.Category != model.CatDatabase || my.Version != "8.0.36-0ubuntu0.22.04.1" || my.CPE != "cpe:/a:mysql:mysql:8.0.36" || !reflect.DeepEqual(my.Sources, []string{"nmap"}) {
			t.Fatalf("MySQL = %+v", my)
		}
	})
	t.Run("nmap product name in another case and an alias", func(t *testing.T) {
		e2 := NewEngine()
		e2.Load([]model.Signature{rec("apache", "id: apache\nname: Apache HTTP Server\ncategory: web-server\naliases: ['Apache httpd', Apache]\nheader: {name: Server, regex: '^Apache(?:/([0-9.]+))?'}\n", true)})
		svc := &model.ServiceResult{Name: "http", Product: "Apache httpd", Version: "2.4.57 ((Debian))", Confidence: 1,
			HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"Apache/2.4.57 (Debian)"}}}}
		_, techs, _ := e2.Match(svc)
		if len(techs) != 1 || techs[0].Name != "Apache HTTP Server" || techs[0].Version != "2.4.57" || !reflect.DeepEqual(techs[0].Sources, []string{"apache", "nmap"}) {
			t.Fatalf("technologies = %+v", techs)
		}
	})
}

func TestTwoSignaturesOneTechnology(t *testing.T) {
	e := NewEngine()
	e.Load([]model.Signature{
		rec("jenkins", "id: jenkins\nname: Jenkins\ncategory: devops\nheader: {name: X-Jenkins, regex: '^([0-9.]+)', weight: 0.9, version_group: 1}\n", true),
		rec("jenkins-open", "id: jenkins-open\nname: Jenkins bez logowania\ntechnology: Jenkins\ncategory: devops\ninterest: 90\nclasses: [dev-tool]\ntitle: {regex: 'Dashboard \\[Jenkins\\]', weight: 0.8}\n", true),
		rec("debug", "id: debug\nname: Tryb debug\ntechnology: false\ncategory: devops\nbody: {contains: DEBUG, weight: 0.8}\n", true),
	})
	svc := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Title: "Dashboard [Jenkins]", BodyExcerpt: "DEBUG", Headers: map[string][]string{"X-Jenkins": {"2.440.1"}}}}
	matches, techs, classes := e.Match(svc)
	if len(matches) != 3 {
		t.Fatalf("matches = %v", slugs(matches))
	}
	// 1 - 0.1*0.2 = 0.98, one technology for both signatures; "technology: false" gives none.
	if len(techs) != 1 || techs[0].Name != "Jenkins" || techs[0].Confidence != 0.98 || techs[0].Version != "2.440.1" {
		t.Fatalf("technologies = %+v", techs)
	}
	if !reflect.DeepEqual(classes, []string{model.ClassDevTool}) {
		t.Errorf("classes = %v", classes)
	}
}

func TestCategoryGivesClasses(t *testing.T) {
	e := NewEngine()
	e.Load([]model.Signature{
		rec("cam", "id: cam\nname: Kamera\ncategory: iot\ntitle: {contains: 'ip camera', weight: 0.8}\n", true),
		rec("db", "id: db\nname: CouchDB\ncategory: database\nbody: {contains: '\"couchdb\":\"Welcome\"', weight: 0.9}\n", true),
	})
	_, _, classes := e.Match(&model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Title: "IP Camera", BodyExcerpt: `{"couchdb":"Welcome"}`}})
	if !reflect.DeepEqual(classes, []string{model.ClassDatabase, model.ClassIoT}) {
		t.Errorf("classes = %v", classes)
	}
}

func TestHotReloadEnableDisable(t *testing.T) {
	e := testEngine(t)
	svc := sample()
	if total, enabled := e.Count(); total != 4 || enabled != 4 {
		t.Fatalf("count = %d/%d", total, enabled)
	}
	if !e.SetEnabled("wordpress", false) {
		t.Fatal("SetEnabled must find the signature")
	}
	if e.SetEnabled("nope", false) {
		t.Error("SetEnabled must report an unknown slug")
	}
	matches, techs, _ := e.Match(svc)
	if got := slugs(matches); !reflect.DeepEqual(got, []string{"header-version-server", "nginx", "php"}) {
		t.Errorf("after disable: %v", got)
	}
	if techByName(techs, "WordPress") != nil {
		t.Error("a disabled signature must not give a technology")
	}
	if len(e.ExtraPaths()) != 0 {
		t.Errorf("paths of a disabled signature must not be requested: %v", e.ExtraPaths())
	}
	for _, s := range e.Signatures() {
		if s.Slug == "wordpress" && s.Enabled {
			t.Error("Signatures() must show the signature as disabled")
		}
	}
	e.SetEnabled("wordpress", true)
	if m, _, _ := e.Match(svc); len(m) != 4 {
		t.Errorf("after enable: %v", slugs(m))
	}

	// Hot reload: a new set replaces the old one at once.
	custom := "id: portal\nname: Portal AGH\ncategory: cms\nauthor: analityk\nmeta: {name: 'og:site_name', equals: 'Portal AGH', weight: 0.9}\n"
	rep := e.Load([]model.Signature{rec("nginx", sigNginx, true), rec("portal", custom, true), rec("php", sigPHP, false)})
	if rep.Loaded != 3 || rep.Enabled != 2 {
		t.Fatalf("report = %+v", rep)
	}
	matches, _, _ = e.Match(svc)
	if got := slugs(matches); !reflect.DeepEqual(got, []string{"nginx", "portal"}) {
		t.Errorf("after reload: %v", got)
	}
	// A custom record with the slug of a built-in one replaces it.
	override := strings.Replace(sigNginx, "weight: 0.9", "weight: 0.4", 1)
	e.Load([]model.Signature{{Slug: "nginx", YAML: sigNginx, Enabled: true, Builtin: true}, {Slug: "nginx", YAML: override, Enabled: true}})
	matches, _, _ = e.Match(svc)
	if len(matches) != 1 || matches[0].Confidence != 0.4 {
		t.Errorf("override: %+v", matches)
	}
	if list := e.Signatures(); len(list) != 1 || list[0].Builtin {
		t.Errorf("override must replace the built-in record: %+v", list)
	}
}

func TestLoadRejectsBadSignaturesAndKeepsGoodOnes(t *testing.T) {
	e := NewEngine()
	rep := e.Load([]model.Signature{
		rec("nginx", sigNginx, true),
		rec("evil", "id: evil\nname: Evil\nrequests:\n  - {path: /login, method: POST, body: 'user=admin&password=admin'}\nmatch:\n  rules:\n    - {type: path, path: /login, contains: welcome}\n", true),
		rec("traversal", "id: traversal\nname: T\nmatch:\n  rules:\n    - {type: path, path: '/../../etc/passwd', contains: 'root:'}\n", true),
		rec("broken", "id: broken\nname: [", true),
	})
	if rep.Loaded != 1 || len(rep.Rejected) != 3 {
		t.Fatalf("report = %+v", rep)
	}
	for _, r := range rep.Rejected {
		if len(r.Issues) == 0 || r.Slug == "" {
			t.Errorf("a rejected signature needs its slug and issues: %+v", r)
		}
		for _, is := range r.Issues {
			if is.Level != "error" {
				t.Errorf("only errors belong in the report: %+v", is)
			}
		}
	}
	if !rep.Rejected[0].Issues[0].Safety || !rep.Rejected[1].Issues[0].Safety {
		t.Errorf("the unsafe signatures must be marked as safety problems: %+v", rep.Rejected)
	}
	if paths := e.ExtraPaths(); len(paths) != 0 {
		t.Fatalf("a rejected signature must never add a request path: %v", paths)
	}
	if m, _, _ := e.Match(sample()); len(m) != 1 || m[0].Signature != "nginx" {
		t.Errorf("the good signature must still work: %v", slugs(m))
	}
}

func TestExtraPathsOrderedAndDeduplicated(t *testing.T) {
	mk := func(id string, interest int, paths ...string) model.Signature {
		var b strings.Builder
		fmt.Fprintf(&b, "id: %s\nname: %s\ninterest: %d\nmatch:\n  rules:\n", id, id, interest)
		for _, p := range paths {
			fmt.Fprintf(&b, "    - {type: path, path: '%s', status: [200], contains: x}\n", p)
		}
		return rec(id, b.String(), true)
	}
	e := NewEngine()
	e.Load([]model.Signature{
		mk("a", 10, "/common", "/only-a"),
		mk("b", 90, "/common", "/only-b"),
		mk("c", 50, "/common", "/only-c"),
		mk("d", 99, "/only-d"),
		func() model.Signature { s := mk("off", 100, "/disabled"); s.Enabled = false; return s }(),
	})
	got := e.ExtraPaths()
	// Shared by three signatures first; then by the interest of the signature; no path twice; nothing from a disabled signature.
	want := []string{"/common", "/only-d", "/only-b", "/only-c", "/only-a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExtraPaths = %v, want %v", got, want)
	}
	got[0] = "/changed"
	if e.ExtraPaths()[0] != "/common" {
		t.Error("ExtraPaths must return a copy")
	}
	for _, p := range e.ExtraPaths() {
		if reason := CheckPath(p); reason != "" {
			t.Errorf("unsafe path %q in ExtraPaths: %s", p, reason)
		}
	}
}

func TestPathsForPutsSupportedSignaturesFirst(t *testing.T) {
	e := NewEngine()
	e.Load([]model.Signature{
		rec("a", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, contains: alpha, weight: 0.6}\n    - {type: path, path: /a-version, contains: x}\n", true),
		rec("b", "id: b\nname: B\nmatch:\n  rules:\n    - {type: body, contains: beta, weight: 0.6}\n    - {type: path, path: /b-version, contains: x}\n", true),
		rec("c", "id: c\nname: C\ninterest: 100\nmatch:\n  rules:\n    - {type: path, path: /c-blind, contains: x}\n", true),
	})
	svc := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, BodyExcerpt: "this is beta software"}}
	got := e.PathsFor(svc, 0)
	if len(got) != 3 || got[0] != "/b-version" {
		t.Errorf("PathsFor = %v, want /b-version first", got)
	}
	if got := e.PathsFor(svc, 1); !reflect.DeepEqual(got, []string{"/b-version"}) {
		t.Errorf("PathsFor with limit 1 = %v", got)
	}
}

func TestMatchIsSafeDuringReload(t *testing.T) {
	e := testEngine(t)
	svc := sample()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				matches, techs, _ := e.Match(svc)
				for _, m := range matches {
					if m.Signature == "" || m.Confidence <= 0 || m.Confidence > 1 {
						t.Errorf("bad match during reload: %+v", m)
						return
					}
				}
				if techByName(techs, "nginx") == nil {
					t.Error("nginx is in every set and must always be found")
					return
				}
				e.ExtraPaths()
			}
		}()
	}
	sets := [][]model.Signature{
		{rec("nginx", sigNginx, true), rec("wordpress", sigWP, true), rec("php", sigPHP, true)},
		{rec("php", sigPHP, true), rec("nginx", sigNginx, true)},
		{rec("header-version-server", sigFinding, true), rec("wordpress", sigWP, true), rec("nginx", sigNginx, true)},
	}
	for i := 0; i < 300; i++ {
		e.Load(sets[i%len(sets)])
		e.SetEnabled("wordpress", i%2 == 0)
	}
	close(stop)
	wg.Wait()
}

func TestAhoCorasick(t *testing.T) {
	lits := []string{"he", "she", "his", "hers", "wp-content/", "ółć", "a"}
	a := buildAC(lits)
	hits := make([]uint64, a.words())
	a.scan("ushers and żółć", hits)
	want := map[string]bool{"he": true, "she": true, "hers": true, "ółć": true, "a": true}
	for i, l := range lits {
		if got := bit(hits, int32(i)); got != want[l] {
			t.Errorf("literal %q: found = %v, want %v", l, got, want[l])
		}
	}
	empty := buildAC(nil)
	empty.scan("anything", make([]uint64, empty.words()))
}
