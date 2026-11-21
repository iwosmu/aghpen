package sig

import (
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/signatures"
)

// The samples below are written by hand in the shapes that signature sets
// usually have. None of them is a Czujka file.

// jsonList: a JSON array, "matchers" with a matcher kind in "type" and the target in "part".
const jsonList = `[
  {
    "id": "acme-portal",
    "name": "ACME Portal",
    "category": "cms",
    "severity": "medium",
    "tags": "portal, php",
    "matchers": [
      {"type": "word", "part": "body", "words": ["acme-portal.css", "ACME Portal"]},
      {"type": "regex", "part": "header", "pattern": "X-Powered-By: ACME/([0-9.]+)", "group": 1},
      {"type": "word", "part": "title", "value": "ACME"}
    ],
    "version_regex": "ACME Portal v([0-9.]+)"
  },
  {
    "name": "Router Admin",
    "category": "iot",
    "favicon_hash": 116323821,
    "cookies": {"router_sid": ""},
    "headers": {"Server": "^RouterOS httpd"}
  }
]`

// jsonKeyed: a JSON object keyed by technology name, in the Wappalyzer style.
const jsonKeyed = `{
  "technologies": {
    "Example CMS": {
      "cats": [1],
      "description": "Example CMS is a content management system.",
      "headers": {"X-Generator": "Example CMS(?: ([\\d.]+))?\\;version:\\1"},
      "cookies": {"examplecms_session": ""},
      "meta": {"generator": "^Example CMS ([\\d.]+)\\;version:\\1"},
      "html": ["<link[^>]+/examplecms/assets/", "<!-- Example CMS -->\\;confidence:50"],
      "scriptSrc": "examplecms(?:\\.min)?\\.js",
      "implies": ["PHP\\;confidence:80", "MySQL"],
      "icon": "ExampleCMS.svg",
      "website": "https://example.org",
      "cpe": "cpe:2.3:a:example:cms:*:*:*:*:*:*:*:*",
      "js": {"ExampleCMS.version": "([\\d.]+)\\;version:\\1"}
    },
    "BrowserOnly": {
      "cats": [59],
      "js": {"BrowserOnly": ""}
    }
  }
}`

// yamlSynonyms: YAML with other field names, a wrapper key and a top-level endpoint.
const yamlSynonyms = `
fingerprints:
  - slug: campus-login
    label: Campus Login
    kind: panel
    endpoint: /login
    detect:
      - {part: body, contains: 'name="campus_password"'}
      - {part: title, pattern: '^Campus (Login|Sign in)'}
      - {status_code: 200}
    operator: and
  - identifier: Old Printer UI
    product: Old Printer UI
    group: iot
    rules:
      - {header: Server, value: 'PrintServer'}
      - {cookie: PRNSESSID}
      - {url: /status.htm, word: 'Toner level'}
      - {favicon: [-1234567, 7654321]}
      - {keyword: 'Printer Web Interface'}
`

func mustConvert(t *testing.T, src string, want int) ([]*Sig, model.SignatureValidation) {
	t.Helper()
	sigs, val := Parse(src)
	for _, is := range val.Issues {
		if is.Level == "error" && want >= 0 && val.OK {
			t.Errorf("unexpected error: %+v", is)
		}
	}
	if want >= 0 && len(sigs) != want {
		t.Fatalf("got %d signatures, want %d; issues: %+v", len(sigs), want, val.Issues)
	}
	for _, s := range sigs {
		s.Enabled = true
	}
	return sigs, val
}

func evalOne(s *Sig, svc *model.ServiceResult) (model.SigMatch, bool) {
	st := buildSet([]*Sig{s})
	return newView(svc, st, nil).evalSig(st.enabled[0])
}

func TestJSONListWithForeignMatchers(t *testing.T) {
	sigs, val := mustConvert(t, jsonList, 2)
	if !val.OK {
		t.Fatalf("issues: %+v", val.Issues)
	}
	a := sigs[0]
	if a.Slug != "acme-portal" || a.Name != "ACME Portal" || a.Category != model.CatCMS || a.Interest != 50 || !reflect.DeepEqual(a.Tags, []string{"portal", "php"}) {
		t.Errorf("acme = %+v", a.Def)
	}
	svc := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Title: "Welcome to ACME", BodyExcerpt: `<link href="/static/acme-portal.css"> ACME Portal v4.2.1`,
		Headers: map[string][]string{"X-Powered-By": {"ACME/4.2"}}}}
	m, ok := evalOne(a, svc)
	if !ok || len(m.Evidence) < 3 || m.Version != "4.2" {
		t.Fatalf("match = %+v ok=%v", m, ok)
	}
	// Without the header the version comes from version_regex.
	delete(svc.HTTP.Headers, "X-Powered-By")
	if m, ok = evalOne(a, svc); !ok || m.Version != "4.2.1" {
		t.Errorf("version_regex: %+v", m)
	}
	if _, ok = evalOne(a, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Title: "Other", BodyExcerpt: "nothing"}}); ok {
		t.Error("an unrelated page must not match")
	}

	b := sigs[1]
	if b.Slug != "router-admin" || b.Category != model.CatIoT || len(b.rules) != 3 {
		t.Fatalf("router = %+v (%d rules)", b.Def, len(b.rules))
	}
	hash := int32(116323821)
	if _, ok := evalOne(b, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FaviconMMH3: &hash}}); !ok {
		t.Error("favicon_hash must match")
	}
	if _, ok := evalOne(b, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Cookies: []model.Cookie{{Name: "router_sid", ValueLen: 8}}}}); !ok {
		t.Error("cookie map must match")
	}
	// The stored text of a converted signature is canonical Czujka YAML.
	if !strings.HasPrefix(a.YAML, "id: acme-portal\n") || strings.Contains(a.YAML, "matchers") {
		t.Errorf("stored YAML = %s", a.YAML)
	}
}

func TestMapKeyedByNameWappalyzerStyle(t *testing.T) {
	sigs, val := Parse(jsonKeyed)
	// "BrowserOnly" has only a JavaScript check: it has no rule Czujka can run and is refused, alone.
	if len(sigs) != 1 || val.OK {
		t.Fatalf("got %d signatures, ok=%v, issues %+v", len(sigs), val.OK, val.Issues)
	}
	if !hasIssue(val, "error", false, "[1].match", "żadnej reguły") || !hasIssue(val, "warning", false, "[0]", "przeglądarki") {
		t.Errorf("issues = %+v", val.Issues)
	}
	s := sigs[0]
	s.Enabled = true
	if s.Slug != "example-cms" || s.Name != "Example CMS" || s.Category != model.CatCMS || s.CPE != "cpe:2.3:a:example:cms:*:*:*:*:*:*:*:*" ||
		!reflect.DeepEqual(s.Implies, []string{"PHP", "MySQL"}) {
		t.Errorf("def = %+v", s.Def)
	}
	cases := []struct {
		name    string
		http    model.HTTPFingerprint
		version string
		conf    float64
	}{
		{"header with version", model.HTTPFingerprint{Headers: map[string][]string{"X-Generator": {"Example CMS 3.2.1"}}}, "3.2.1", 0.6},
		{"header without version", model.HTTPFingerprint{Headers: map[string][]string{"X-Generator": {"Example CMS"}}}, "", 0.6},
		{"cookie exists", model.HTTPFingerprint{Cookies: []model.Cookie{{Name: "examplecms_session", ValueLen: 5}}}, "", 0.6},
		{"meta generator", model.HTTPFingerprint{BodyExcerpt: `<meta name="generator" content="Example CMS 2.0">`}, "2.0", 0.8},
		{"html regex", model.HTTPFingerprint{BodyExcerpt: `<link rel="stylesheet" href="/examplecms/assets/a.css">`}, "", 0.4},
		{"html with confidence 50", model.HTTPFingerprint{BodyExcerpt: "<!-- Example CMS -->"}, "", 0.5},
		{"script source", model.HTTPFingerprint{BodyExcerpt: `<script src="/js/examplecms.min.js"></script>`}, "", 0.4},
	}
	for _, tc := range cases {
		h := tc.http
		h.Status = 200
		m, ok := evalOne(s, &model.ServiceResult{HTTP: &h})
		if !ok || m.Version != tc.version || m.Confidence != tc.conf {
			t.Errorf("%s: ok=%v version=%q confidence=%v", tc.name, ok, m.Version, m.Confidence)
		}
	}
}

func TestYAMLWithSynonyms(t *testing.T) {
	sigs, val := mustConvert(t, yamlSynonyms, 2)
	if !val.OK {
		t.Fatalf("issues: %+v", val.Issues)
	}
	login := sigs[0]
	if login.Slug != "campus-login" || login.Name != "Campus Login" || login.Category != model.CatPanel || !login.All {
		t.Errorf("def = %+v", login.Def)
	}
	// "endpoint: /login" moves the body, title and status rules to that path.
	if !reflect.DeepEqual(login.paths, []string{"/login"}) || len(login.rules) != 3 {
		t.Fatalf("paths = %v, rules = %d", login.paths, len(login.rules))
	}
	for _, r := range login.rules {
		if r.typ != TypePath || r.path != "/login" {
			t.Errorf("rule = %+v", r)
		}
	}
	page := func(status int, title, body string) *model.ServiceResult {
		return &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, BodyExcerpt: "root page", Paths: []model.PathProbe{
			{Path: "/login", Status: status, Title: title, BodySHA256: "x", Excerpt: body}}}}
	}
	if _, ok := evalOne(login, page(200, "Campus Login", `<input name="campus_password">`)); !ok {
		t.Error("the login page must match")
	}
	if _, ok := evalOne(login, page(404, "Campus Login", `<input name="campus_password">`)); ok {
		t.Error("operator: and — a 404 must not match")
	}
	if _, ok := evalOne(login, page(200, "Other", `<input name="campus_password">`)); ok {
		t.Error("operator: and — a wrong title must not match")
	}

	printer := sigs[1]
	if printer.Slug != "old-printer-ui" || printer.Name != "Old Printer UI" || printer.Category != model.CatIoT || len(printer.rules) != 5 {
		t.Fatalf("def = %+v (%d rules)", printer.Def, len(printer.rules))
	}
	types := []string{}
	for _, r := range printer.rules {
		types = append(types, r.typ)
	}
	if !reflect.DeepEqual(types, []string{TypeHeader, TypeCookie, TypePath, TypeFavicon, TypeBody}) {
		t.Errorf("rule types = %v", types)
	}
	if _, ok := evalOne(printer, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"PrintServer/1.0"}}}}); !ok {
		t.Error("{header: Server, value: PrintServer} must match as contains")
	}
	h := int32(7654321)
	if _, ok := evalOne(printer, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FaviconMMH3: &h}}); !ok {
		t.Error("{favicon: [..]} must match")
	}
}

func TestOtherShapes(t *testing.T) {
	cases := map[string]struct {
		src  string
		want []string
	}{
		"json single":          {`{"id": "one", "name": "One", "body": "hello one"}`, []string{"one"}},
		"json wrapper list":    {`{"signatures": [{"id": "a", "name": "A", "title": "A"}, {"id": "b", "name": "B", "title": "B"}]}`, []string{"a", "b"}},
		"json rules of sigs":   {`{"rules": [{"name": "Alpha", "matchers": [{"type": "word", "words": ["alpha"]}]}, {"name": "Beta", "html": "beta"}]}`, []string{"alpha", "beta"}},
		"yaml keyed":           {"Alpha:\n  html: 'alpha-app'\nBeta:\n  headers: {X-Beta: ''}\n", []string{"alpha", "beta"}},
		"free-form id":         {"id: My App (v2)\nbody: 'my app'\n", []string{"my-app-v2"}},
		"technology as name":   {"technology: Gamma Server\nheader: 'Server: gamma'\n", []string{"gamma-server"}},
		"matchers-condition":   {"id: mc\nname: MC\nmatchers-condition: and\nmatchers:\n  - {type: word, words: [a1, b2], condition: and}\n  - {type: status, status: [200]}\n", []string{"mc"}},
		"percent confidence":   {"id: pc\nname: PC\nmatchers:\n  - {type: word, words: [zzz], confidence: 80}\n", []string{"pc"}},
		"version pattern list": {"id: vp\nname: VP\nbody: vp\nversion: ['VP/([0-9.]+)']\n", []string{"vp"}},
		"version number":       {"id: vn\nname: VN\nbody: vn\nversion: 1.2\n", []string{"vn"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sigs, val := Parse(tc.src)
			var got []string
			for _, s := range sigs {
				got = append(got, s.Slug)
			}
			if !val.OK || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("slugs = %v, want %v; issues %+v", got, tc.want, val.Issues)
			}
		})
	}
	// condition: and inside a matcher means: every word.
	s := mustParse(t, cases["matchers-condition"].src)
	if !s.All || len(s.rules[0].containsAll) != 2 {
		t.Errorf("rule = %+v", s.rules[0])
	}
	if s := mustParse(t, cases["percent confidence"].src); s.rules[0].weight != 0.8 {
		t.Errorf("weight = %v", s.rules[0].weight)
	}
	// A forgiving loader is still a safe loader.
	for name, src := range map[string]string{
		"json POST":       `{"id": "x", "name": "X", "requests": [{"path": "/login", "method": "POST", "body": "a=b"}], "body": "x"}`,
		"keyed traversal": `{"Evil": {"matchers": [{"path": "/../../etc/passwd", "word": "root:"}]}, "Evil2": {"endpoint": "/.env", "matchers": [{"word": "DB_PASSWORD"}]}}`,
	} {
		sigs, val := Parse(src)
		safety := false
		for _, is := range val.Issues {
			safety = safety || is.Safety
		}
		if val.OK || len(sigs) != 0 || !safety {
			t.Errorf("%s: must be refused as unsafe: ok=%v sigs=%d issues=%+v", name, val.OK, len(sigs), val.Issues)
		}
	}
}

// ---------- nuclei ----------

const nucleiTech = `id: acme-gateway-detect

info:
  name: ACME Gateway - Detect
  author: jkowalski,anowak
  severity: info
  description: ACME Gateway login panel was detected.
  classification:
    cpe: cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*
  metadata:
    max-request: 2
    shodan-query: http.title:"ACME Gateway"
  tags: panel,acme,detect

http:
  - method: GET
    path:
      - "{{BaseURL}}/gateway/login"
      - "{{BaseURL}}/login"

    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "<title>ACME Gateway</title>"
          - "acme-gateway-login"
        condition: and

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - 'Gateway version ([0-9.]+)'
`

const nucleiRoot = `id: example-server-detect
info:
  name: Example Server Detect
  author: test
  severity: info
  tags: tech,example
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: regex
        part: header
        regex:
          - '(?i)Server: ExampleServer(/[0-9.]+)?'
      - type: word
        words:
          - "Powered by ExampleServer"
        case-insensitive: true
      - type: dsl
        dsl:
          - "status_code==200 && (\"-1840324437\" == mmh3(base64_py(body)))"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - 'ExampleServer/([0-9.]+)'
      - type: kval
        kval:
          - server
`

func TestNucleiPassiveTemplates(t *testing.T) {
	sigs, val := mustConvert(t, nucleiTech, 1)
	if !val.OK {
		t.Fatalf("issues: %+v", val.Issues)
	}
	s := sigs[0]
	if s.Slug != "acme-gateway-detect" || s.Name != "ACME Gateway - Detect" || s.Author != "jkowalski, anowak" || s.Interest != 10 ||
		s.Category != model.CatPanel || !reflect.DeepEqual(s.classes, []string{model.ClassLogin}) || s.CPE != "cpe:2.3:a:acme:gateway" {
		t.Errorf("def = %+v classes=%v", s.Def, s.classes)
	}
	// Two paths, one folded rule each: path + status + every word.
	if !reflect.DeepEqual(s.paths, []string{"/gateway/login", "/login"}) || len(s.rules) != 2 || len(s.version) != 2 {
		t.Fatalf("paths = %v, rules = %d, version rules = %d", s.paths, len(s.rules), len(s.version))
	}
	for _, r := range s.rules {
		if r.typ != TypePath || len(r.containsAll) != 2 || !reflect.DeepEqual(r.status, []int{200}) || !r.cs || r.required {
			t.Errorf("rule = %+v", r)
		}
	}
	page := func(path string, status int, body string) *model.ServiceResult {
		return &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, BodyExcerpt: "root", Paths: []model.PathProbe{{Path: path, Status: status, BodySHA256: "p", Excerpt: body}}}}
	}
	good := `<html><title>ACME Gateway</title><div class="acme-gateway-login">Gateway version 7.4.2</div>`
	m, ok := evalOne(s, page("/login", 200, good))
	if !ok || m.Version != "7.4.2" || m.Confidence != 0.9 {
		t.Errorf("match = %+v ok=%v", m, ok)
	}
	if _, ok := evalOne(s, page("/gateway/login", 200, good)); !ok {
		t.Error("the other path must match too")
	}
	if _, ok := evalOne(s, page("/login", 403, good)); ok {
		t.Error("status 403 must not match")
	}
	if _, ok := evalOne(s, page("/login", 200, "<title>ACME Gateway</title>")); ok {
		t.Error("condition: and — one word is not enough")
	}
	// The stored text is Czujka YAML, and it parses to the same signature.
	again := mustParse(t, s.YAML)
	if strings.Contains(s.YAML, "BaseURL") || again.Slug != s.Slug || len(again.rules) != 2 || !reflect.DeepEqual(again.paths, s.paths) {
		t.Errorf("stored YAML:\n%s", s.YAML)
	}

	sigs, val = mustConvert(t, nucleiRoot, 1)
	if !val.OK || !hasIssue(val, "warning", false, "extractors[1]", "kval") {
		t.Fatalf("issues: %+v", val.Issues)
	}
	r := sigs[0]
	if len(r.paths) != 0 || len(r.rules) != 3 || r.rules[0].typ != TypeFavicon || r.rules[1].typ != TypeHeader || r.rules[2].typ != TypeBody || r.rules[2].cs {
		t.Fatalf("rules = %+v %+v %+v", r.rules[0], r.rules[1], r.rules[2])
	}
	m, ok = evalOne(r, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"ExampleServer/2.5.1"}}}})
	if !ok || m.Version != "2.5.1" {
		t.Errorf("header match = %+v ok=%v", m, ok)
	}
	if _, ok = evalOne(r, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, BodyExcerpt: "powered by exampleserver"}}); !ok {
		t.Error("case-insensitive word must match")
	}
	hash := int32(-1840324437)
	if _, ok = evalOne(r, &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FaviconMMH3: &hash}}); !ok {
		t.Error("the favicon hash idiom must become a favicon rule")
	}
}

func TestNucleiActiveTemplatesAreRefused(t *testing.T) {
	head := "id: bad\ninfo:\n  name: Bad\n  author: x\n  severity: high\n"
	cases := []struct{ name, body, path, msg string }{
		{"POST login", "http:\n  - method: POST\n    path: ['{{BaseURL}}/login']\n    body: 'username=admin&password=admin'\n    matchers:\n      - {type: word, words: [Welcome]}\n", "http[0].method", "POST"},
		{"request body", "http:\n  - method: POST\n    path: ['{{BaseURL}}/login']\n    body: 'username=admin&password=admin'\n    matchers:\n      - {type: word, words: [Welcome]}\n", "http[0].body", "treść żądania"},
		{"raw request", "http:\n  - raw:\n      - |\n        GET /admin HTTP/1.1\n        Host: {{Hostname}}\n    matchers:\n      - {type: status, status: [200]}\n", "http[0].raw", "surowe żądania"},
		{"payloads and attack", "http:\n  - method: GET\n    path: ['{{BaseURL}}/?user={{user}}']\n    payloads:\n      user: [admin, root]\n    attack: clusterbomb\n    matchers:\n      - {type: word, words: [ok]}\n", "http[0].payloads", "ładunki"},
		{"fuzzing", "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n    fuzzing:\n      - {part: query, type: postfix, fuzz: [\"'\"]}\n    matchers:\n      - {type: word, words: [SQL]}\n", "http[0].fuzzing", "fuzzing"},
		{"custom headers", "http:\n  - method: GET\n    path: ['{{BaseURL}}/api']\n    headers:\n      Authorization: Basic YWRtaW46YWRtaW4=\n    matchers:\n      - {type: status, status: [200]}\n", "http[0].headers", "własne nagłówki"},
		{"template variable in the path", "http:\n  - method: GET\n    path: ['{{BaseURL}}/{{randstr}}.php']\n    matchers:\n      - {type: status, status: [200]}\n", "http[0].path[0]", "zmiennych"},
		{"interactsh in the path", "http:\n  - method: GET\n    path: ['{{BaseURL}}/?url=http://{{interactsh-url}}']\n    matchers:\n      - {type: word, part: interactsh_protocol, words: [http]}\n", "http[0].path[0]", "zmiennych"},
		{"other host", "http:\n  - method: GET\n    path: ['https://evil.example.org/x']\n    matchers:\n      - {type: status, status: [200]}\n", "http[0].path[0]", "{{BaseURL}}"},
		{"dsl helper", "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - {type: dsl, dsl: ['contains(tolower(body), \"x\") && len(body) > 100']}\n", "matchers[0].dsl", "DSL"},
		{"helper in a word", "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - {type: word, words: ['{{md5(\"a\")}}']}\n", "matchers[0].words", "funkcji pomocniczych"},
		{"dns protocol", "dns:\n  - name: '{{FQDN}}'\n    type: A\n    matchers:\n      - {type: word, words: [IN]}\n", "dns", "protoko"},
		{"tcp protocol", "tcp:\n  - inputs: [{data: 'INFO\\r\\n'}]\n    host: ['{{Hostname}}']\n    matchers:\n      - {type: word, words: [redis_version]}\n", "tcp", "protoko"},
		{"headless", "headless:\n  - steps: [{action: navigate, args: {url: '{{BaseURL}}'}}]\n", "headless", "protoko"},
		{"unsafe path after conversion", "http:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - {type: word, words: ['[core]']}\n", "path", ".git"},
		{"secret file", "http:\n  - method: GET\n    path: ['{{BaseURL}}/backup.sql']\n    matchers:\n      - {type: word, words: ['INSERT INTO']}\n", "path", ".sql"},
		{"state change", "http:\n  - method: GET\n    path: ['{{BaseURL}}/actuator/shutdown']\n    matchers:\n      - {type: status, status: [200]}\n", "path", "shutdown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, val := Convert(head + tc.body)
			if val.OK || out != "" {
				t.Fatalf("must be refused; output:\n%s", out)
			}
			if !hasIssue(val, "error", true, tc.path, tc.msg) {
				t.Errorf("want a safety error at %q mentioning %q, got %+v", tc.path, tc.msg, val.Issues)
			}
			if sigs, _ := Parse(head + tc.body); len(sigs) != 0 {
				t.Error("a refused template must not compile")
			}
		})
	}
	// Unsupported but harmless features are plain errors, not safety errors.
	_, val := Convert(head + "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - {type: binary, binary: ['504B0304']}\n")
	if val.OK || !hasIssue(val, "error", false, "matchers[0].type", "binary") {
		t.Errorf("binary matcher: %+v", val.Issues)
	}
}

func TestFaviconDSL(t *testing.T) {
	for expr, want := range map[string][]int32{
		`"-1840324437" == mmh3(base64_py(body))`:                                             {-1840324437},
		`status_code==200 && ("116323821" == mmh3(base64_py(body)))`:                         {116323821},
		`status_code==200 && ("1" == mmh3(base64_py(body)) || "2" == mmh3(base64_py(body)))`: {1, 2},
		`mmh3(base64_py(body)) == '-5'`:                                                      {-5},
	} {
		got, ok := faviconDSL(expr)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("faviconDSL(%s) = %v %v", expr, got, ok)
		}
	}
	for _, expr := range []string{`contains(body, "x")`, `"1" == mmh3(base64_py(body)) && contains(body, "admin")`, `len(body) > 5`, `"1" == md5(body)`} {
		if _, ok := faviconDSL(expr); ok {
			t.Errorf("faviconDSL(%s) must be refused", expr)
		}
	}
}

// TestCanonicalYAMLRoundTrip writes every built-in signature in the canonical
// form and parses it again: the result must be the same signature.
func TestCanonicalYAMLRoundTrip(t *testing.T) {
	files, _ := fs.Glob(signatures.FS, "*.yaml")
	n := 0
	for _, name := range files {
		data, _ := fs.ReadFile(signatures.FS, name)
		sigs, _ := Parse(string(data))
		for _, s := range sigs {
			n++
			text := s.Def.YAML()
			again, val := Parse(text)
			if !val.OK || len(again) != 1 {
				t.Errorf("%s: canonical YAML does not parse: %+v\n%s", s.Slug, val.Issues, text)
				continue
			}
			a := again[0]
			same := a.Slug == s.Slug && a.Name == s.Name && a.Category == s.Category && a.Description == s.Description && a.CPE == s.CPE &&
				a.Interest == s.Interest && a.All == s.All && a.MinConfidence == s.MinConfidence && a.techName == s.techName && a.isTech == s.isTech &&
				reflect.DeepEqual(a.paths, s.paths) && reflect.DeepEqual(a.classes, s.classes) && reflect.DeepEqual(a.Tags, s.Tags) &&
				reflect.DeepEqual(a.Implies, s.Implies) && reflect.DeepEqual(a.Aliases, s.Aliases) && len(a.rules) == len(s.rules) && len(a.version) == len(s.version) &&
				a.maxConf == s.maxConf
			if !same {
				t.Errorf("%s: the canonical YAML is a different signature:\n%s", s.Slug, text)
				continue
			}
			for i := range s.rules {
				x, y := s.rules[i], a.rules[i]
				if x.typ != y.typ || x.name != y.name || x.field != y.field || x.path != y.path || x.weight != y.weight || x.vgroup != y.vgroup || x.not != y.not ||
					x.required != y.required || x.absent != y.absent || x.exists != y.exists || x.cs != y.cs || len(x.regex) != len(y.regex) ||
					len(x.contains) != len(y.contains) || len(x.containsAll) != len(y.containsAll) || !reflect.DeepEqual(x.equals, y.equals) ||
					!reflect.DeepEqual(x.status, y.status) || !reflect.DeepEqual(x.mmh3, y.mmh3) {
					t.Errorf("%s: rule %d differs after the round trip:\n%+v\n%+v", s.Slug, i, x, y)
				}
				for j := range x.regex {
					if x.regex[j].re.String() != y.regex[j].re.String() {
						t.Errorf("%s: rule %d regex differs: %q vs %q", s.Slug, i, x.regex[j].re, y.regex[j].re)
					}
				}
				for j := range x.contains {
					if x.contains[j].exact != y.contains[j].exact {
						t.Errorf("%s: rule %d literal differs: %q vs %q", s.Slug, i, x.contains[j].exact, y.contains[j].exact)
					}
				}
			}
		}
	}
	if n < 150 {
		t.Fatalf("only %d signatures checked", n)
	}
}

// TestDocsWalkthroughExamples reads the seven examples of the "2 minutes"
// walkthrough from docs/SIGNATURES.md. Each one must pass the validator
// without a warning, detect its feature and stay quiet on another page.
func TestDocsWalkthroughExamples(t *testing.T) {
	data, err := os.ReadFile("../../docs/SIGNATURES.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	start := strings.Index(doc, "## 13. Jak napisać własną sygnaturę w 2 minuty")
	end := strings.Index(doc, "## 14. ")
	if start < 0 || end < start {
		t.Fatal("the walkthrough section is missing")
	}
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(doc[start:end], -1)
	if len(blocks) != 7 {
		t.Fatalf("got %d examples, want the seven of the brief", len(blocks))
	}
	hash := int32(116323821)
	target := &model.ServiceResult{HTTP: &model.HTTPFingerprint{
		Status:  200,
		Headers: map[string][]string{"X-Powered-By": {"AplikacjaX/2.1"}, "X-Generator": {"KampusCMS"}},
		Cookies: []model.Cookie{{Name: "APLIKACJAX_SESSION", ValueLen: 32}, {Name: "kampuscms_sid", ValueLen: 16}},
		BodyExcerpt: `<html><head><meta name="generator" content="KampusCMS 5.2"><link href="/kampuscms/assets/site.css"></head>
<body><div id="aplikacjax-root"></div><footer>Powered by AplikacjaX v2.1.4</footer></body></html>`,
		FaviconMMH3: &hash,
		Paths: []model.PathProbe{
			{Path: "/login", Status: 200, BodySHA256: "a", Excerpt: `<form><input type="password" name="aplikacjax_password"></form>`},
			{Path: "/kampuscms/admin/", Status: 302, BodySHA256: "b", Excerpt: "KampusCMS"},
		},
	}}
	other := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, Headers: map[string][]string{"Server": {"nginx"}}, BodyExcerpt: "<html><body>Witaj</body></html>",
		Paths: []model.PathProbe{{Path: "/login", Status: 404, BodySHA256: "c", Excerpt: "Not Found"}}}}
	versions := map[string]string{"aplikacjax-wersja": "2.1.4", "kampuscms": "5.2"}
	for i, b := range blocks {
		sigs, val := Parse(b[1])
		if !val.OK || len(sigs) != 1 || len(val.Issues) != 0 {
			t.Errorf("example %d: ok=%v issues=%+v", i+1, val.OK, val.Issues)
			continue
		}
		s := sigs[0]
		s.Enabled = true
		m, ok := evalOne(s, target)
		if !ok {
			t.Errorf("example %d (%s) does not detect its feature", i+1, s.Slug)
		}
		if want, has := versions[s.Slug]; has && m.Version != want {
			t.Errorf("example %d (%s): version %q, want %q", i+1, s.Slug, m.Version, want)
		}
		if _, ok := evalOne(s, other); ok {
			t.Errorf("example %d (%s) matches an unrelated page", i+1, s.Slug)
		}
	}
}
