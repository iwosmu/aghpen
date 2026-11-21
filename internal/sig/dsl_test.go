package sig

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// briefExample is the signature from the task brief, verbatim.
const briefExample = `
id: wordpress
name: WordPress
category: cms            # model.Cat* values
description: System CMS
tags: [php]
interest: 10             # 0..100 weight for the analyst interest score
classes: []              # model.Class* values, e.g. [admin-panel]
cpe: cpe:2.3:a:wordpress:wordpress
requests:                # optional extra safe GETs
  - path: /wp-login.php
match:
  condition: any         # any | all
  min_confidence: 0.5
  rules:
    - {type: meta, name: generator, regex: '^WordPress', weight: 0.9}
    - {type: body, contains: 'wp-content/', weight: 0.5}
    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}
    - {type: path, path: /wp-login.php, status: 200, contains: 'user_login', weight: 0.9}
    - {type: favicon, mmh3: [-235701012], weight: 0.9}
version:
  - {type: meta, name: generator, regex: 'WordPress ([0-9.]+)'}
`

func mustParse(t *testing.T, src string) *Sig {
	t.Helper()
	sigs, val := Parse(src)
	if !val.OK || len(sigs) != 1 {
		t.Fatalf("signature must be valid, got %d signatures and issues %+v\n%s", len(sigs), val.Issues, src)
	}
	sigs[0].Enabled = true
	return sigs[0]
}

// matchOne evaluates one signature text against one service.
func matchOne(t *testing.T, src string, svc *model.ServiceResult, hostnames ...string) (model.SigMatch, bool) {
	t.Helper()
	st := buildSet([]*Sig{mustParse(t, src)})
	return newView(svc, st, hostnames).evalSig(st.enabled[0])
}

func hasIssue(val model.SignatureValidation, level string, safety bool, pathPart, msgPart string) bool {
	for _, is := range val.Issues {
		if is.Level == level && is.Safety == safety && strings.Contains(is.Path, pathPart) && strings.Contains(is.Message, msgPart) {
			return true
		}
	}
	return false
}

func TestBriefExampleIsValid(t *testing.T) {
	val := Validate(briefExample)
	if !val.OK || len(val.Issues) != 0 {
		t.Fatalf("the example of the brief must validate cleanly: %+v", val.Issues)
	}
	if len(val.Paths) != 1 || val.Paths[0] != "/wp-login.php" {
		t.Errorf("paths = %v", val.Paths)
	}
	s := mustParse(t, briefExample)
	if s.Slug != "wordpress" || s.Category != model.CatCMS || s.Interest != 10 || s.MinConfidence != 0.5 || s.All || len(s.rules) != 5 || len(s.version) != 1 {
		t.Errorf("parsed = %+v", s.Def)
	}
}

func TestShortForms(t *testing.T) {
	for name, src := range map[string]string{
		"scalar body":      "id: a\nname: A\nbody: 'Powered by Foo'\n",
		"header exists":    "id: a\nname: A\nheader: X-Foo\n",
		"header value":     "id: a\nname: A\nheader: 'Server: foo'\n",
		"list of rules":    "id: a\nname: A\nbody: ['foo', 'bar']\ntitle: Foo\n",
		"rule mapping":     "id: a\nname: A\nheader: {name: Server, regex: '^foo/([0-9.]+)'}\n",
		"wappalyzer maps":  "id: a\nname: A\nheaders: {Server: '^foo/([0-9.]+)', X-Foo: ''}\ncookies: {foo_session: ''}\nmeta: {generator: '^Foo'}\n",
		"favicon number":   "id: a\nname: A\nfavicon: -235701012\n",
		"top-level rules":  "id: a\nname: A\nrules:\n  - {type: title, contains: foo}\n",
		"match as a list":  "id: a\nname: A\nmatch:\n  - {type: title, contains: foo}\n",
		"aliases of keys":  "id: a\nname: A\nmatchers:\n  - {type: html, words: [foo], confidence: 0.6}\n",
		"id from the name": "name: My Fancy App 2\ntitle: foo\n",
		"status and path":  "id: a\nname: A\nstatus: 401\npath: /login\n",
	} {
		t.Run(name, func(t *testing.T) {
			sigs, val := Parse(src)
			if !val.OK || len(sigs) != 1 {
				t.Fatalf("issues: %+v", val.Issues)
			}
		})
	}
	s := mustParse(t, "name: My Fancy App 2\ntitle: foo\n")
	if s.Slug != "my-fancy-app-2" {
		t.Errorf("derived id = %q", s.Slug)
	}
	s = mustParse(t, "id: a\nname: A\nheaders: {Server: '^foo/([0-9.]+)', X-Foo: ''}\n")
	if len(s.rules) != 2 || s.rules[0].vgroup != 1 || !s.rules[1].exists || s.rules[1].nameShown != "X-Foo" {
		t.Errorf("wappalyzer-style headers: %+v %+v", s.rules[0], s.rules[1])
	}
	svc := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Headers: map[string][]string{"Server": {"foo/2.1"}}}}
	m, ok := matchOne(t, "id: a\nname: A\nheaders: {Server: '^foo/([0-9.]+)'}\n", svc)
	if !ok || m.Version != "2.1" {
		t.Errorf("short form version: ok=%v version=%q", ok, m.Version)
	}
}

func TestMultipleSignaturesInOneText(t *testing.T) {
	list := "- {id: a, name: A, body: foo}\n- {id: b, name: B, title: bar}\n"
	wrapped := "signatures:\n  - {id: a, name: A, body: foo}\n  - {id: b, name: B, title: bar}\n"
	stream := "id: a\nname: A\nbody: foo\n---\nid: b\nname: B\ntitle: bar\n"
	for name, src := range map[string]string{"list": list, "wrapped": wrapped, "stream": stream} {
		sigs, val := Parse(src)
		if !val.OK || len(sigs) != 2 || sigs[0].Slug != "a" || sigs[1].Slug != "b" {
			t.Errorf("%s: %d signatures, issues %+v", name, len(sigs), val.Issues)
		}
		for _, s := range sigs {
			if _, v := Parse(s.YAML); !v.OK {
				t.Errorf("%s: the YAML kept for %q does not parse again: %+v", name, s.Slug, v.Issues)
			}
		}
	}
	_, val := Parse("- {id: a, name: A, body: foo}\n- {id: a, name: A2, body: bar}\n")
	if val.OK || !hasIssue(val, "error", false, "[1].id", "więcej niż raz") {
		t.Errorf("duplicate id must be an error: %+v", val.Issues)
	}
	// One bad signature gets a path with its index.
	_, val = Parse("- {id: a, name: A, body: foo}\n- {id: b, name: B, body: {regex: '('}}\n")
	if val.OK || !hasIssue(val, "error", false, "[1].body.regex[0]", "wyrażenie regularne") {
		t.Errorf("issue path must name the signature and the field: %+v", val.Issues)
	}
}

func TestValidatorRejectsUnsafeSignatures(t *testing.T) {
	head := "id: bad\nname: Bad\n"
	rule := "match:\n  rules:\n    - {type: path, path: %s, contains: x}\n"
	cases := []struct {
		name, src, path, msg string
	}{
		{"POST", head + "requests:\n  - {path: /login, method: POST}\nbody: x\n", "requests[0].method", "POST"},
		{"PUT", head + "requests:\n  - {path: /a, method: put}\nbody: x\n", "requests[0].method", "PUT"},
		{"DELETE", head + "requests:\n  - {path: /a, method: DELETE}\nbody: x\n", "requests[0].method", "DELETE"},
		{"request body", head + "requests:\n  - {path: /login, body: 'user=admin&pass=admin'}\nbody: x\n", "requests[0].body", "treść żądania"},
		{"request data", head + "requests:\n  - {path: /login, data: {a: b}}\nbody: x\n", "requests[0].data", "zabronione"},
		{"request headers", head + "requests:\n  - {path: /a, headers: {Authorization: 'Basic YWRtaW46YWRtaW4='}}\nbody: x\n", "requests[0].headers", "nagłówki"},
		{"request cookies", head + "requests:\n  - {path: /a, cookies: {sid: x}}\nbody: x\n", "requests[0].cookies", "ciasteczka"},
		{"credentials", head + "requests:\n  - {path: /a, username: admin, password: admin}\nbody: x\n", "requests[0].password", "dane logowania"},
		{"auth block", head + "requests:\n  - {path: /a, auth: {user: admin}}\nbody: x\n", "requests[0].auth", "dane logowania"},
		{"unknown request key", head + "requests:\n  - {path: /a, retries: 50}\nbody: x\n", "requests[0].retries", "nieznane pole żądania"},
		{"payload list", head + "requests:\n  - {path: /a, payloads: [a, b]}\nbody: x\n", "requests[0].payloads", "zabronione"},
		{"userinfo", head + "requests: ['/a@evil.example.org/']\nbody: x\n", "requests[0]", "@"},
		{"absolute URL", head + "requests: ['http://10.0.0.1/admin']\nbody: x\n", "requests[0]", "inne hosty"},
		{"scheme-relative URL", head + "requests: ['//evil.example.org/x']\nbody: x\n", "requests[0]", "inne hosty"},
		{"no leading slash", head + "requests: ['admin/index.php']\nbody: x\n", "requests[0]", "zaczynać"},
		{"traversal", head + "requests: ['/static/../../etc/hosts']\nbody: x\n", "requests[0]", "przejście katalogów"},
		{"encoded traversal", head + "requests: ['/static/%2e%2e/%2e%2e/x']\nbody: x\n", "requests[0]", "kodowanie procentowe"},
		{"null byte", head + "requests: ['/index.php%00.jpg']\nbody: x\n", "requests[0]", "kodowanie procentowe"},
		{"bad characters", head + "requests: ['/a;cat x']\nbody: x\n", "requests[0]", "niedozwolony"},
		{"script in query", head + "requests: ['/s?q=<script>']\nbody: x\n", "requests[0]", "niedozwolony"},
		{"too long", head + "requests: ['/" + strings.Repeat("a", 300) + "']\nbody: x\n", "requests[0]", "za długa"},
		{"logout", head + fmt.Sprintf(rule, "/user/logout"), "rules[0].path", "logout"},
		{"delete", head + fmt.Sprintf(rule, "'/api/users?action=delete'"), "rules[0].path", "delete"},
		{"shutdown", head + fmt.Sprintf(rule, "/actuator/shutdown"), "rules[0].path", "shutdown"},
		{"reboot", head + fmt.Sprintf(rule, "/cgi-bin/reboot.cgi"), "rules[0].path", "reboot"},
		{"reset token", head + fmt.Sprintf(rule, "/factory/reset"), "rules[0].path", "factory"},
		{"dotenv", head + fmt.Sprintf(rule, "/.env"), "rules[0].path", ".env"},
		{"git config", head + fmt.Sprintf(rule, "/.git/config"), "rules[0].path", ".git"},
		{"backup file", head + fmt.Sprintf(rule, "/db.sql"), "rules[0].path", ".sql"},
		{"backup archive", head + fmt.Sprintf(rule, "/www.tar.gz"), "rules[0].path", ".tar"},
		{"backup word", head + fmt.Sprintf(rule, "/backup/"), "rules[0].path", "backup"},
		{"private key", head + fmt.Sprintf(rule, "/id_rsa"), "rules[0].path", "id_rsa"},
		{"key file", head + fmt.Sprintf(rule, "/server.key"), "rules[0].path", ".key"},
		{"wp-config", head + fmt.Sprintf(rule, "/wp-config.php.old"), "rules[0].path", "wp-config"},
		{"actuator env", head + fmt.Sprintf(rule, "/actuator/env"), "rules[0].path", "actuator/env"},
		{"heap dump", head + fmt.Sprintf(rule, "/actuator/heapdump"), "rules[0].path", "heapdump"},
		{"command", head + fmt.Sprintf(rule, "'/cgi-bin/test?cmd=id'"), "rules[0].path", "cmd"},
		{"editor backup", head + fmt.Sprintf(rule, "/index.php~"), "rules[0].path", "~"},
		{"yaml config", head + fmt.Sprintf(rule, "/config/app.yml"), "rules[0].path", "YAML"},
		{"version rule path", head + "body: x\nversion:\n  - {type: path, path: /.env, regex: 'V=([0-9]+)'}\n", "version[0].path", ".env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val := Validate(tc.src)
			if val.OK {
				t.Fatalf("must be rejected:\n%s", tc.src)
			}
			if !hasIssue(val, "error", true, tc.path, tc.msg) {
				t.Errorf("want a safety error at %q mentioning %q, got %+v", tc.path, tc.msg, val.Issues)
			}
			if sigs, _ := Parse(tc.src); len(sigs) != 0 {
				t.Errorf("an unsafe signature must not compile")
			}
		})
	}

	// Too many requests in one signature.
	var b strings.Builder
	b.WriteString(head + "requests:\n")
	for i := 0; i <= MaxRequestsPerSignature; i++ {
		fmt.Fprintf(&b, "  - /p%d\n", i)
	}
	b.WriteString("body: x\n")
	if val := Validate(b.String()); val.OK || !hasIssue(val, "error", true, "requests", "limit") {
		t.Errorf("request limit not enforced: %+v", val.Issues)
	}
	// A regex that is too long is a safety issue; RE2 has no backtracking.
	long := head + "body: {regex: '" + strings.Repeat("(a|b)", 200) + "'}\n"
	if val := Validate(long); val.OK || !hasIssue(val, "error", true, "body.regex[0]", "za długie") {
		t.Errorf("regex length limit not enforced: %+v", val.Issues)
	}
	// The classic ReDoS pattern is fine for RE2 (linear time) and is accepted.
	if val := Validate(head + "body: {regex: '^(a+)+$'}\n"); !val.OK {
		t.Errorf("RE2 handles nested quantifiers in linear time: %+v", val.Issues)
	}
	// Backreferences and lookaround do not exist in RE2.
	for _, pat := range []string{`(a)\1`, `foo(?=bar)`, `(?<!x)y`} {
		if val := Validate(head + "body: {regex: '" + pat + "'}\n"); val.OK || !hasIssue(val, "error", false, "regex[0]", "RE2") {
			t.Errorf("pattern %q must be rejected: %+v", pat, val.Issues)
		}
	}
}

func TestValidatorStructureErrors(t *testing.T) {
	cases := []struct{ name, src, path, msg string }{
		{"empty", "", "", "pusta"},
		{"not yaml", "id: [unclosed\n", "", "YAML"},
		{"scalar", "just text\n", "", "mapą"},
		{"no id and no name", "body: x\n", "id", "brak pola id"},
		{"bad id", "id: '!!!'\nname: x\nbody: x\n", "id", "niepoprawne"},
		{"no rules", "id: a\nname: A\n", "match", "żadnej reguły"},
		{"unknown rule type", "id: a\nname: A\nmatch:\n  rules:\n    - {type: exploit, contains: x}\n", "match.rules[0].type", "nieznany typ"},
		{"rule without type", "id: a\nname: A\nmatch:\n  rules:\n    - {weight: 0.5}\n", "match.rules[0].type", "nie ma pola type"},
		{"body without matcher", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body}\n", "match.rules[0]", "potrzebuje dopasowania"},
		{"weight out of range", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, contains: x, weight: 1.5}\n", "rules[0].weight", "weight"},
		{"bad condition", "id: a\nname: A\nmatch:\n  condition: some\n  rules:\n    - {type: body, contains: x}\n", "match.condition", "any albo all"},
		{"bad min_confidence", "id: a\nname: A\nmatch:\n  min_confidence: 3\n  rules:\n    - {type: body, contains: x}\n", "match.min_confidence", "od 0 do 1"},
		{"bad interest", "id: a\nname: A\ninterest: 500\nbody: x\n", "interest", "od 0 do 100"},
		{"bad status", "id: a\nname: A\nstatus: 999\n", "status", "100–599"},
		{"favicon sha", "id: a\nname: A\nfavicon: {sha256: [abc]}\n", "favicon", "64 znaki"},
		{"favicon mmh3", "id: a\nname: A\nfavicon: {mmh3: [99999999999]}\n", "favicon.mmh3", "32-bitową"},
		{"version without group", "id: a\nname: A\nbody: x\nversion:\n  - {type: body, regex: 'v[0-9]+'}\n", "version[0]", "grup"},
		{"version_group too high", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, regex: 'v([0-9]+)', version_group: 2}\n", "rules[0]", "tylko 1 grup"},
		{"only negative rules", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, contains: x, not: true}\n", "match", "negatywne"},
		{"exists and absent", "id: a\nname: A\nmatch:\n  rules:\n    - {type: header, name: X, exists: true, absent: true}\n", "rules[0]", "jednocześnie"},
		{"path without path", "id: a\nname: A\nmatch:\n  rules:\n    - {type: path, contains: x}\n", "rules[0]", "pola path"},
		{"service field", "id: a\nname: A\nmatch:\n  rules:\n    - {type: service, field: nope, contains: x}\n", "rules[0]", "field"},
		{"empty literal", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, contains: ['']}\n", "rules[0].contains[0]", "pusty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val := Validate(tc.src)
			if val.OK || !hasIssue(val, "error", false, tc.path, tc.msg) {
				t.Errorf("want an error at %q mentioning %q, got ok=%v %+v", tc.path, tc.msg, val.OK, val.Issues)
			}
		})
	}
	// Every issue of a located problem names its line.
	val := Validate("id: a\nname: A\nmatch:\n  rules:\n    - {type: body, regex: '('}\n")
	if len(val.Issues) != 1 || !strings.Contains(val.Issues[0].Message, "(wiersz 5)") {
		t.Errorf("one mistake must give one issue with its line: %+v", val.Issues)
	}
}

func TestValidatorWarnings(t *testing.T) {
	cases := []struct{ name, src, path, msg string }{
		{"unknown top-level field", "id: a\nname: A\nbody: x\nfrobnicate: 1\n", "frobnicate", "nieznane pole"},
		{"unknown rule field", "id: a\nname: A\nmatch:\n  rules:\n    - {type: body, contains: x, fuzzy: true}\n", "rules[0].fuzzy", "nieznane pole"},
		{"unknown category", "id: a\nname: A\ncategory: gadget\nbody: x\n", "category", "nieznana kategoria"},
		{"unknown class", "id: a\nname: A\nclasses: [shiny]\nbody: x\n", "classes[0]", "nieznana klasa"},
		{"unreachable threshold", "id: a\nname: A\nmatch:\n  min_confidence: 0.9\n  rules:\n    - {type: body, contains: x, weight: 0.2}\n", "min_confidence", "nigdy nie zadziała"},
		{"path rule without content", "id: a\nname: A\nmatch:\n  rules:\n    - {type: path, path: /login}\n", "rules[0]", "fałszywe trafienie"},
		{"request nobody uses", "id: a\nname: A\nrequests: [/unused]\nbody: x\n", "requests", "żadna reguła"},
		{"duplicate key", "id: a\nname: A\nbody: x\nBody: y\n", "body", "dwa razy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val := Validate(tc.src)
			if !val.OK {
				t.Fatalf("a warning must not reject the signature: %+v", val.Issues)
			}
			if !hasIssue(val, "warning", false, tc.path, tc.msg) {
				t.Errorf("want a warning at %q mentioning %q, got %+v", tc.path, tc.msg, val.Issues)
			}
		})
	}
	s := mustParse(t, "id: a\nname: A\ncategory: gadget\nbody: x\n")
	if s.Category != model.CatOther {
		t.Errorf("unknown category must fall back to other, got %q", s.Category)
	}
}

func TestCheckPath(t *testing.T) {
	good := []string{
		"/", "/wp-login.php", "/administrator/", "/api/v1/status/buildinfo", "/actuator", "/actuator/health",
		"/.well-known/security.txt", "/robots.txt", "/xmldata?item=all", "/index.php?option=com_users&view=login",
		"/manager/html", "/v2/", "/~jkowalski/", "/swagger-ui/index.html", "/openapi.yaml", "/phpinfo.php",
		"/server-status", "/console/login/LoginForm.jsp", "/core/install.php", "/preset/list", "/settings",
	}
	for _, p := range good {
		if reason := CheckPath(p); reason != "" {
			t.Errorf("CheckPath(%q) = %q, want allowed", p, reason)
		}
	}
	bad := []string{
		"", "x", "//host/x", "http://host/", "/a/../b", "/..", "/%2e%2e/", "/a%00", "/a b", "/a\tb", "/a\r\n", "/a;b",
		"/a#b", "/a\\b", "/user:pass@host/", "/a//b", "/a?b=c?d", "/a?x=<y>", "/a?x=%27", "/.env", "/.git/HEAD",
		"/.htpasswd", "/.ssh/id_rsa", "/.aws/credentials", "/logout", "/Logout.aspx", "/doLogout", "/signout",
		"/api/shutdown", "/admin/delete/1", "/users/destroy", "/restart", "/reboot.cgi", "/backup.zip",
		"/site-backup/", "/dump.sql", "/db.sqlite", "/cert.pem", "/server.key", "/keystore.jks", "/web.config",
		"/config.php.bak", "/wp-config.php", "/etc/passwd", "/proc/self/environ", "/actuator/heapdump",
		"/actuator/env", "/a?cmd=ls", "/exec", "/cgi-bin/sh", "/api/token", "/secrets", "/private/key",
		"/a/reset", "/a/update", "/a/upload", "/save", "/factory", "/index.php~", "/config.yml", "/app.ini",
		"/debug.log", "/a?" + strings.Repeat("x=1&", 30),
		// L3 of the security review: word parts of camelCase and compounds.
		"/api/resetPassword", "/cache/flushAll", "/cache/flushall", "/api/v1/DeleteUser", "/admin/doExecute",
		"/redis/flushdb", "/user/resetpassword", "/XMLExport",
	}
	for _, p := range bad {
		if reason := CheckPath(p); reason == "" {
			t.Errorf("CheckPath(%q) allowed, want refused", p)
		}
	}
}

func TestRequiredLiteral(t *testing.T) {
	// The value is the sorted literal set, joined with "|"; "" means: no filter.
	cases := map[string]string{
		`wp-content/`:                       "wp-content/",
		`/wp-(?:content|includes)/`:         "content|includes",
		`Joomla!(?: ([0-9.]+))?`:            "joomla!",
		`^nginx(?:/([0-9.]+))?`:             "nginx",
		`foo|bar`:                           "bar|foo",
		`kontroler\.php\?_action=|USOSweb`:  "kontroler.php?_action=|usosweb",
		`(?:abc)+def`:                       "abc",
		`[0-9]+\.[0-9]+`:                    "",
		`x*`:                                "",
		`foo|[0-9]+`:                        "",
		`foo|x?`:                            "",
		`Powered by (Gitea|Forgejo) v`:      "powered by ",
		`(?:a|b)longerliteral[0-9]{2,}tail`: "longerliteral",
		`<input\b[^>]{0,400}\btype\s*=\s*["']?password`: "password",
		`(alpha|beta)(gamma-delta|epsilon-zeta)`:        "epsilon-zeta|gamma-delta",
	}
	for pat, want := range cases {
		_, need, msg, _ := compileRegex(pat, false)
		if msg != "" {
			t.Fatalf("%q: %s", pat, msg)
		}
		sort.Strings(need)
		if got := strings.Join(need, "|"); got != want {
			t.Errorf("requiredLiterals(%q) = %q, want %q", pat, got, want)
		}
	}
}
