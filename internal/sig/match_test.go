package sig

import (
	"math"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func i32(v int32) *int32 { return &v }

// sample is a service with every field a rule can read.
func sample() *model.ServiceResult {
	return &model.ServiceResult{
		Port: 443, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.24.0", ExtraInfo: "Ubuntu",
		CPE: []string{"cpe:/a:igor_sysoev:nginx:1.24.0"}, Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", Tunnel: "ssl", Confidence: 1,
		TLS: &model.TLSInfo{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", SubjectCN: "dev.portal.example.edu", SubjectOrg: "Example University",
			Issuer: "Example Test CA", SANs: []string{"dev.portal.example.edu", "portal.example.edu"}},
		HTTP: &model.HTTPFingerprint{
			Scheme: "https", URL: "https://10.0.0.5:443/", FinalURL: "https://10.0.0.5:443/wp-login.php", Host: "dev.portal.example.edu", Status: 200,
			Title: "Log In ‹ Portal — WordPress",
			Headers: map[string][]string{
				"Server":       {"nginx/1.24.0 (Ubuntu)"},
				"X-Powered-By": {"PHP/8.2.7"},
				"Content-Type": {"text/html; charset=UTF-8"},
				"Link":         {"<https://x/wp-json/>; rel=\"https://api.w.org/\""},
			},
			Cookies: []model.Cookie{
				{Name: "wordpress_test_cookie", Value: "WP+Cookie+check", ValueLen: 15, Secure: true, Path: "/"},
				{Name: "PHPSESSID", Value: "abcdef0123456789", ValueLen: 16, HTTPOnly: false, Secure: false, SameSite: "None"},
			},
			Redirects:     []model.Redirect{{From: "https://10.0.0.5:443/", To: "https://10.0.0.5:443/wp-login.php", Status: 302}},
			Server:        "nginx/1.24.0 (Ubuntu)",
			PoweredBy:     "PHP/8.2.7",
			MetaGenerator: "WordPress 6.5.3",
			BodyExcerpt: `<!DOCTYPE html><html><head><title>Log In</title>
<meta name="generator" content="WordPress 6.5.3" />
<meta property="og:site_name" content='Portal AGH'>
<link rel="stylesheet" href="/wp-content/themes/x/style.css?ver=6.5.3">
</head><body class="login"><form><input type="text" name="log" id="user_login"><input type="password" name="pwd"></form>
Powered by ExampleApp v3.14.1-beta</body></html>`,
			BodySHA256:    "rootsha",
			FaviconMMH3:   i32(-235701012),
			FaviconSHA256: strings.Repeat("ab", 32),
			Paths: []model.PathProbe{
				{Path: "/wp-login.php", Status: 200, Title: "Log In", BodySHA256: "p1", Excerpt: `<input name="log" id="user_login">`, Headers: map[string][]string{"X-Frame-Options": {"SAMEORIGIN"}}},
				{Path: "/readme.html", Status: 200, Title: "WordPress › ReadMe", BodySHA256: "p2", Excerpt: "<h1>WordPress</h1> Version 6.5.3"},
				{Path: "/admin", Status: 302, Location: "/admin/login"},
				{Path: "/missing", Status: 404, Excerpt: "Not Found"},
			},
		},
	}
}

func rules(body string) string {
	return "id: t\nname: T\nmatch:\n  rules:\n" + body
}

// TestEveryRuleType has at least one positive and one negative case for each rule type and each matcher.
func TestEveryRuleType(t *testing.T) {
	cases := []struct {
		name, rule string
		want       bool
		where      string
		snippet    string
	}{
		// header
		{"header exists", `{type: header, name: X-Powered-By}`, true, "header:X-Powered-By", "PHP/8.2.7"},
		{"header exists, other case", `{type: header, name: x-powered-by, exists: true}`, true, "header:x-powered-by", ""},
		{"header missing", `{type: header, name: X-Nope}`, false, "", ""},
		{"header absent", `{type: header, name: Strict-Transport-Security, absent: true}`, true, "header:Strict-Transport-Security", "brak"},
		{"header absent but present", `{type: header, name: Server, absent: true}`, false, "", ""},
		{"header contains", `{type: header, name: Server, contains: NGINX}`, true, "header:Server", "nginx/1.24.0"},
		{"header contains, case sensitive", `{type: header, name: Server, contains: NGINX, case_sensitive: true}`, false, "", ""},
		{"header equals", `{type: header, name: X-Powered-By, equals: php/8.2.7}`, true, "", ""},
		{"header equals is not contains", `{type: header, name: X-Powered-By, equals: php}`, false, "", ""},
		{"header regex", `{type: header, name: Server, regex: '^nginx/[0-9.]+'}`, true, "", ""},
		{"header regex no match", `{type: header, name: Server, regex: '^apache'}`, false, "", ""},
		{"header name_regex", `{type: header, name_regex: '^x-powered', contains: php}`, true, "header:X-Powered-By", ""},
		{"header without a name", `{type: header, regex: '^Server: nginx'}`, true, "header:Server", ""},
		// cookie
		{"cookie by name", `{type: cookie, name: PHPSESSID}`, true, "cookie:PHPSESSID", "PHPSESSID (16 B; Secure=false; HttpOnly=false; SameSite=None)"},
		{"cookie name, other case", `{type: cookie, name: phpsessid}`, true, "cookie:PHPSESSID", ""},
		{"cookie name_regex", `{type: cookie, name_regex: '^wordpress_'}`, true, "cookie:wordpress_test_cookie", ""},
		{"cookie missing", `{type: cookie, name: JSESSIONID}`, false, "", ""},
		{"cookie absent", `{type: cookie, name: JSESSIONID, absent: true}`, true, "", "brak"},
		{"cookie value regex", `{type: cookie, name: wordpress_test_cookie, regex: '^WP\+Cookie'}`, true, "", ""},
		{"cookie value no match", `{type: cookie, name: wordpress_test_cookie, equals: other}`, false, "", ""},
		{"cookie not secure", `{type: cookie, name_regex: 'SESS', secure: false}`, true, "cookie:PHPSESSID", ""},
		{"cookie secure flag filters", `{type: cookie, name: PHPSESSID, secure: true}`, false, "", ""},
		{"cookie http_only false", `{type: cookie, name: PHPSESSID, http_only: false}`, true, "", ""},
		{"cookie same_site", `{type: cookie, same_site: none, secure: false}`, true, "cookie:PHPSESSID", ""},
		// body
		{"body contains", `{type: body, contains: 'WP-CONTENT/'}`, true, "body", "wp-content/"},
		{"body contains any of a list", `{type: body, contains: ['nope', 'user_login']}`, true, "body", ""},
		{"body contains none", `{type: body, contains: ['nope', 'neither']}`, false, "", ""},
		{"body contains_all", `{type: body, contains_all: ['wp-content/', 'user_login']}`, true, "", ""},
		{"body contains_all, one missing", `{type: body, contains_all: ['wp-content/', 'nope']}`, false, "", ""},
		{"body regex", `{type: body, regex: 'themes/[a-z]+/style\.css'}`, true, "", ""},
		{"body regex case sensitive", `{type: body, regex: 'THEMES/', case_sensitive: true}`, false, "", ""},
		{"body regex, literal prefilter present but no match", `{type: body, regex: 'wp-content/plugins/[a-z]+'}`, false, "", ""},
		{"body absent", `{type: body, contains: 'joomla', absent: true}`, true, "", "brak"},
		// title
		{"title contains", `{type: title, contains: wordpress}`, true, "title", ""},
		{"title equals", `{type: title, equals: 'log in ‹ portal — wordpress'}`, true, "", ""},
		{"title regex anchored", `{type: title, regex: '^Log In'}`, true, "", ""},
		{"title no match", `{type: title, contains: drupal}`, false, "", ""},
		// meta
		{"meta generator", `{type: meta, name: generator, regex: '^WordPress'}`, true, "meta:generator", "WordPress"},
		{"meta default name is generator", `{type: meta, contains: wordpress}`, true, "", ""},
		{"meta other name, single quotes, property", `{type: meta, name: 'og:site_name', equals: 'Portal AGH'}`, true, "meta:og:site_name", ""},
		{"meta missing", `{type: meta, name: description, exists: true}`, false, "", ""},
		// favicon
		{"favicon mmh3", `{type: favicon, mmh3: [1, -235701012]}`, true, "favicon", "mmh3 -235701012"},
		{"favicon mmh3 other", `{type: favicon, mmh3: [12345]}`, false, "", ""},
		{"favicon sha256", "{type: favicon, sha256: [" + strings.Repeat("AB", 32) + "]}", true, "favicon", "sha256"},
		{"favicon sha256 other", "{type: favicon, sha256: [" + strings.Repeat("cd", 32) + "]}", false, "", ""},
		// path
		{"path status only", `{type: path, path: /wp-login.php, status: 200}`, true, "path:/wp-login.php", "HTTP 200"},
		{"path content", `{type: path, path: /wp-login.php, status: [200], contains: user_login}`, true, "", ""},
		{"path content no match", `{type: path, path: /wp-login.php, contains: joomla}`, false, "", ""},
		{"path wrong status", `{type: path, path: /missing, status: [200], contains: 'not found'}`, false, "", ""},
		{"path 404 expected", `{type: path, path: /missing, status: [404]}`, true, "", "HTTP 404"},
		{"path without status needs 200", `{type: path, path: /admin}`, false, "", ""},
		{"path redirect location", `{type: path, path: /admin, status: [301, 302], field: location, contains: /admin/login}`, true, "", ""},
		{"path title", `{type: path, path: /readme.html, field: title, contains: readme}`, true, "", ""},
		{"path header", `{type: path, path: /wp-login.php, field: header, name: X-Frame-Options, equals: sameorigin}`, true, "", ""},
		{"path never fetched", `{type: path, path: /nope, status: [200]}`, false, "", ""},
		{"path never fetched is not absent", `{type: path, path: /nope, contains: x, absent: true}`, false, "", ""},
		// status
		{"status", `{type: status, status: [200, 401]}`, true, "status", "HTTP 200"},
		{"status other", `{type: status, status: 403}`, false, "", ""},
		// banner
		{"banner regex", `{type: banner, regex: '^SSH-2\.0-OpenSSH'}`, true, "banner", ""},
		{"banner contains", `{type: banner, contains: dropbear}`, false, "", ""},
		// service
		{"service product", `{type: service, field: product, equals: NGINX}`, true, "service:product", ""},
		{"service name", `{type: service, field: name, regex: '^https?$'}`, true, "service:name", ""},
		{"service version", `{type: service, field: version, regex: '^1\.2'}`, true, "", ""},
		{"service cpe", `{type: service, field: cpe, contains: 'igor_sysoev:nginx'}`, true, "", ""},
		{"service extra info", `{type: service, field: extra_info, contains: ubuntu}`, true, "", ""},
		{"service any field", `{type: service, contains: 'nginx 1.24.0'}`, true, "service", ""},
		{"service no match", `{type: service, field: product, contains: apache}`, false, "", ""},
		// tls
		{"tls subject", `{type: tls, field: subject, regex: '^dev\.'}`, true, "tls:subject", ""},
		{"tls issuer", `{type: tls, field: issuer, contains: 'test ca'}`, true, "tls:issuer", ""},
		{"tls san", `{type: tls, field: san, equals: portal.example.edu}`, true, "", ""},
		{"tls org", `{type: tls, field: org, contains: university}`, true, "", ""},
		{"tls version", `{type: tls, field: version, equals: 'TLS 1.3'}`, true, "", ""},
		{"tls any field", `{type: tls, contains: 'example test ca'}`, true, "tls", ""},
		{"tls no match", `{type: tls, field: issuer, contains: "let's encrypt"}`, false, "", ""},
		// url and redirect
		{"url final", `{type: url, contains: /wp-login.php}`, true, "url", ""},
		{"url scheme", `{type: url, regex: '^https://'}`, true, "", ""},
		{"url no match", `{type: url, regex: '^http://'}`, false, "", ""},
		{"redirect target", `{type: redirect, regex: '/wp-login\.php$'}`, true, "redirect", ""},
		{"redirect no match", `{type: redirect, contains: /cas/login}`, false, "", ""},
		// hostname
		{"hostname from Host", `{type: hostname, regex: '^dev\.'}`, true, "hostname", "dev.portal.example.edu"},
		{"hostname no match", `{type: hostname, contains: staging}`, false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := matchOne(t, rules("    - "+tc.rule+"\n"), sample())
			if ok != tc.want {
				t.Fatalf("matched = %v, want %v (rule %s)", ok, tc.want, tc.rule)
			}
			if !ok {
				return
			}
			if len(m.Evidence) != 1 {
				t.Fatalf("evidence = %+v", m.Evidence)
			}
			ev := m.Evidence[0]
			if tc.where != "" && ev.Where != tc.where {
				t.Errorf("where = %q, want %q", ev.Where, tc.where)
			}
			if tc.snippet != "" && !strings.Contains(strings.ToLower(ev.Snippet), strings.ToLower(tc.snippet)) {
				t.Errorf("snippet = %q, want it to contain %q", ev.Snippet, tc.snippet)
			}
		})
	}
}

func TestHostnameRuleUsesGivenNames(t *testing.T) {
	svc := &model.ServiceResult{Port: 22, Name: "ssh"}
	src := rules("    - {type: hostname, regex: '(^|\\.)staging[0-9]*\\.'}\n")
	if _, ok := matchOne(t, src, svc); ok {
		t.Error("no host name known: the rule must not match")
	}
	if _, ok := matchOne(t, src, svc, "Staging2.Example.EDU."); !ok {
		t.Error("the rule must match a given host name (case and trailing dot ignored)")
	}
	if _, ok := matchOne(t, src, svc, "10.0.0.1"); ok {
		t.Error("an IP address is not a host name")
	}
}

func TestRulesWithoutHTTPData(t *testing.T) {
	svc := &model.ServiceResult{Port: 22, Name: "ssh", Banner: "SSH-2.0-dropbear_2022.83"}
	// absent on a service that has no HTTP data is not a match: nothing was observed.
	if _, ok := matchOne(t, rules("    - {type: header, name: X-Frame-Options, absent: true}\n"), svc); ok {
		t.Error("a header cannot be 'absent' on a non-HTTP service")
	}
	m, ok := matchOne(t, rules("    - {type: banner, regex: 'dropbear_([0-9.]+)', version_group: 1}\n"), svc)
	if !ok || m.Version != "2022.83" {
		t.Errorf("banner match on a non-HTTP service: ok=%v version=%q", ok, m.Version)
	}
}

func TestCookieEvidenceHidesTheValue(t *testing.T) {
	svc := sample()
	svc.HTTP.Cookies = []model.Cookie{{Name: "session", Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2VjcmV0c2ln", ValueLen: 53}}
	m, ok := matchOne(t, rules("    - {type: cookie, regex: '^eyJ[A-Za-z0-9_-]+\\.eyJ'}\n"), svc)
	if !ok {
		t.Fatal("JWT cookie must match")
	}
	for _, ev := range m.Evidence {
		if strings.Contains(ev.Snippet, "eyJ") || strings.Contains(ev.Where, "eyJ") {
			t.Errorf("evidence leaks the cookie value: %+v", ev)
		}
	}
	if m.Evidence[0].Where != "cookie:session" || !strings.Contains(m.Evidence[0].Snippet, "53 B") {
		t.Errorf("evidence = %+v", m.Evidence[0])
	}
}

func TestConfidenceIsNoisyOR(t *testing.T) {
	svc := sample()
	approx := func(a, b float64) bool { return math.Abs(a-b) < 0.0011 }
	cases := []struct {
		name  string
		src   string
		match bool
		conf  float64
		nEv   int
	}{
		{"one rule", rules("    - {type: body, contains: 'wp-content/', weight: 0.5}\n"), true, 0.5, 1},
		{"two rules: 1-(0.5)(0.3)", rules("    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}\n"), true, 0.85, 2},
		{"three rules: 1-(0.5)(0.3)(0.1)", rules("    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}\n    - {type: meta, name: generator, regex: '^WordPress', weight: 0.9}\n"), true, 0.985, 3},
		{"a rule that does not match adds nothing", rules("    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: body, contains: 'joomla', weight: 0.9}\n"), true, 0.5, 1},
		{"default weight of a header rule", rules("    - {type: header, name: X-Powered-By}\n"), true, defaultWeights[TypeHeader], 1},
		{"below the default threshold 0.3", rules("    - {type: body, contains: 'wp-content/', weight: 0.2}\n"), false, 0, 0},
		{"two weak rules pass together: 1-(0.8)(0.8)", rules("    - {type: body, contains: 'wp-content/', weight: 0.2}\n    - {type: title, contains: 'log in', weight: 0.2}\n"), true, 0.36, 2},
		{"min_confidence 0.9 not reached", "id: t\nname: T\nmatch:\n  min_confidence: 0.9\n  rules:\n    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}\n    - {type: body, contains: joomla, weight: 0.9}\n", false, 0, 0},
		{"min_confidence equal to the result", "id: t\nname: T\nmatch:\n  min_confidence: 0.85\n  rules:\n    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: cookie, name_regex: '^wordpress_', weight: 0.7}\n", true, 0.85, 2},
		{"weight 1 is certain", rules("    - {type: body, contains: 'wp-content/', weight: 1}\n"), true, 1, 1},
		{"condition all: every rule matches", "id: t\nname: T\nmatch:\n  condition: all\n  rules:\n    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: title, contains: 'log in', weight: 0.5}\n", true, 0.75, 2},
		{"condition all: one rule fails", "id: t\nname: T\nmatch:\n  condition: all\n  rules:\n    - {type: body, contains: 'wp-content/', weight: 0.9}\n    - {type: title, contains: drupal, weight: 0.5}\n", false, 0, 0},
		{"required rule matches", rules("    - {type: body, contains: 'wp-content/', weight: 0.5, required: true}\n    - {type: title, contains: drupal, weight: 0.5}\n"), true, 0.5, 1},
		{"required rule fails", rules("    - {type: body, contains: 'joomla', weight: 0.5, required: true}\n    - {type: title, contains: 'log in', weight: 0.9}\n"), false, 0, 0},
		{"not: a veto that does not fire", rules("    - {type: body, contains: 'wp-content/', weight: 0.5}\n    - {type: header, name: X-Drupal-Cache, not: true}\n"), true, 0.5, 1},
		{"not: a veto that fires", rules("    - {type: body, contains: 'wp-content/', weight: 0.9}\n    - {type: header, name: Server, contains: nginx, not: true}\n"), false, 0, 0},
		{"absent rule counts as evidence", rules("    - {type: header, name: Content-Security-Policy, absent: true, weight: 0.4}\n"), true, 0.4, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := matchOne(t, tc.src, svc)
			if ok != tc.match {
				t.Fatalf("matched = %v, want %v", ok, tc.match)
			}
			if !ok {
				return
			}
			if !approx(m.Confidence, tc.conf) {
				t.Errorf("confidence = %v, want %v", m.Confidence, tc.conf)
			}
			if len(m.Evidence) != tc.nEv {
				t.Errorf("evidence count = %d, want %d: %+v", len(m.Evidence), tc.nEv, m.Evidence)
			}
		})
	}
}

func TestVersionExtraction(t *testing.T) {
	svc := sample()
	cases := []struct{ name, src, want string }{
		{"version list, meta", "id: t\nname: T\nbody: 'wp-content/'\nversion:\n  - {type: meta, name: generator, regex: 'WordPress ([0-9.]+)'}\n", "6.5.3"},
		{"version list, first that matches wins", "id: t\nname: T\nbody: 'wp-content/'\nversion:\n  - {type: header, name: X-Nope, regex: '([0-9.]+)'}\n  - {type: body, regex: 'style\\.css\\?ver=([0-9.]+)'}\n  - {type: meta, name: generator, regex: 'WordPress ([0-9])'}\n", "6.5.3"},
		{"version from a path", "id: t\nname: T\nbody: 'wp-content/'\nversion:\n  - {type: path, path: /readme.html, regex: 'Version ([0-9.]+)'}\n", "6.5.3"},
		{"version_group on a match rule", rules("    - {type: header, name: Server, regex: '^nginx/([0-9.]+)', version_group: 1}\n"), "1.24.0"},
		{"a match rule gives no version without version_group", rules("    - {type: header, name: X-Powered-By, regex: '^PHP/([0-9.]+)'}\n"), ""},
		{"second group", rules("    - {type: header, name: Server, regex: '^(nginx|apache)/([0-9.]+)', version_group: 2}\n"), "1.24.0"},
		{"non-capturing groups do not count", rules("    - {type: header, name: Server, regex: '^(?:nginx|apache)/([0-9.]+)', version_group: 1}\n"), "1.24.0"},
		{"version with a suffix", rules("    - {type: body, regex: 'ExampleApp v([0-9a-z.\\-]+)', version_group: 1}\n"), "3.14.1-beta"},
		{"version from the banner", rules("    - {type: banner, regex: 'OpenSSH_([0-9.]+p[0-9]+)', version_group: 1}\n"), "9.6p1"},
		{"version from the nmap fields", "id: t\nname: T\nservice: {field: product, equals: nginx}\nversion:\n  - {type: service, field: version, regex: '^([0-9.]+)'}\n", "1.24.0"},
		{"optional group that is empty", rules("    - {type: header, name: Server, regex: '^nginx(?:-plus/([0-9.]+))?'}\n"), ""},
		{"a match rule version wins over the version list", "id: t\nname: T\nheader: {name: Server, regex: '^nginx/([0-9.]+)', version_group: 1}\nversion:\n  - {type: meta, name: generator, regex: 'WordPress ([0-9.]+)'}\n", "1.24.0"},
		{"garbage is not a version", rules("    - {type: body, regex: 'name=\"(log)\"', version_group: 1}\n"), ""},
		{"no version rule", rules("    - {type: body, contains: 'wp-content/'}\n"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := matchOne(t, tc.src, svc)
			if !ok {
				t.Fatal("signature must match")
			}
			if m.Version != tc.want {
				t.Errorf("version = %q, want %q", m.Version, tc.want)
			}
		})
	}
	// A version found by the version list is added to the evidence.
	m, _ := matchOne(t, cases[0].src, svc)
	if len(m.Evidence) != 2 || !strings.HasPrefix(m.Evidence[1].Snippet, "wersja: ") || m.Evidence[1].Where != "meta:generator" {
		t.Errorf("version evidence = %+v", m.Evidence)
	}
}

func TestCleanVersion(t *testing.T) {
	for in, want := range map[string]string{
		"6.5.3": "6.5.3", " 2.4.57 ": "2.4.57", "9.6p1": "9.6p1", "1.0.0-rc.1": "1.0.0-rc.1", "v2": "v2", "10.1.62.": "10.1.62",
		"": "", "beta": "", "1.0 (Ubuntu)": "", "<script>": "", strings.Repeat("1", 60): "",
	} {
		if got := cleanVersion(in); got != want {
			t.Errorf("cleanVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSoftNotFoundPagesDoNotMatchPathRules(t *testing.T) {
	src := rules("    - {type: path, path: /phpmyadmin/, status: [200], contains: phpMyAdmin, weight: 0.9}\n")
	real := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FinalURL: "http://10.0.0.1/", BodySHA256: "root", Paths: []model.PathProbe{
		{Path: "/phpmyadmin/", Status: 200, BodySHA256: "pma", Excerpt: "<title>phpMyAdmin</title>"},
		{Path: "/a", Status: 404}, {Path: "/b", Status: 404},
	}}}
	if _, ok := matchOne(t, src, real); !ok {
		t.Error("a real page must match")
	}
	// A wiki that answers every path with the same "page phpMyAdmin does not exist" body.
	catchAll := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FinalURL: "http://10.0.0.1/", BodySHA256: "root", Paths: []model.PathProbe{
		{Path: "/phpmyadmin/", Status: 200, BodySHA256: "same", Excerpt: "This topic does not exist: phpMyAdmin"},
		{Path: "/a", Status: 200, BodySHA256: "same"}, {Path: "/b", Status: 200, BodySHA256: "same"},
	}}}
	if _, ok := matchOne(t, src, catchAll); ok {
		t.Error("a catch-all answer must not match a path rule")
	}
	// A single-page app that serves the root document for every path.
	spa := &model.ServiceResult{HTTP: &model.HTTPFingerprint{Status: 200, FinalURL: "http://10.0.0.1/", BodySHA256: "root", BodyExcerpt: "<div id=app>phpMyAdmin</div>", Paths: []model.PathProbe{
		{Path: "/phpmyadmin/", Status: 200, BodySHA256: "root", Excerpt: "<div id=app>phpMyAdmin</div>"},
	}}}
	if _, ok := matchOne(t, src, spa); ok {
		t.Error("the root document served for another path must not match a path rule")
	}
}

func TestClassifier(t *testing.T) {
	has := func(list []string, c string) bool {
		for _, x := range list {
			if x == c {
				return true
			}
		}
		return false
	}
	html := func(status int, title, body string) *model.ServiceResult {
		return &model.ServiceResult{Name: "http", HTTP: &model.HTTPFingerprint{Status: status, Title: title, BodyExcerpt: body, URL: "http://10.0.0.1/", FinalURL: "http://10.0.0.1/",
			Headers: map[string][]string{"Content-Type": {"text/html"}}}}
	}
	e := NewEngine()
	cases := []struct {
		name  string
		svc   *model.ServiceResult
		hosts []string
		want  []string
		not   []string
	}{
		{"login form", html(200, "Portal", `<form><input type="password" name="p"></form>`), nil, []string{model.ClassLogin}, []string{model.ClassAdminPanel}},
		{"login form, unquoted attribute", html(200, "Portal", `<input name=p type=password>`), nil, []string{model.ClassLogin}, nil},
		{"basic auth", func() *model.ServiceResult {
			s := html(401, "401 Unauthorized", "")
			s.HTTP.Headers["Www-Authenticate"] = []string{`Basic realm="router"`}
			return s
		}(), nil, []string{model.ClassLogin}, []string{model.ClassErrorPage}},
		{"admin title", html(200, "Panel administracyjny", "x"), nil, []string{model.ClassAdminPanel}, nil},
		{"admin path after a redirect", func() *model.ServiceResult {
			s := html(200, "Sign in", "x")
			s.HTTP.FinalURL = "http://10.0.0.1/admin/login"
			return s
		}(), nil, []string{model.ClassAdminPanel}, nil},
		{"plain page", html(200, "Wydział Informatyki", "<p>Aktualności administracji wydziału</p>"), nil, nil, []string{model.ClassAdminPanel, model.ClassLogin, model.ClassStaging, model.ClassAPI, model.ClassErrorPage}},
		{"staging host name", html(200, "Portal", "x"), []string{"staging.portal.example.edu"}, []string{model.ClassStaging}, nil},
		{"dev host name with a number", html(200, "Portal", "x"), []string{"dev2.example.edu"}, []string{model.ClassStaging}, nil},
		{"word inside a name is not a marker", html(200, "Portal", "x"), []string{"devices.example.edu", "contest.example.edu", "latest.example.edu"}, nil, []string{model.ClassStaging}},
		{"staging title", html(200, "Portal [TEST]", "x"), nil, []string{model.ClassStaging}, nil},
		{"staging title in Polish", html(200, "USOSweb – środowisko testowe", "x"), nil, []string{model.ClassStaging}, nil},
		{"staging header", func() *model.ServiceResult {
			s := html(200, "Portal", "x")
			s.HTTP.Headers["X-Environment"] = []string{"staging"}
			return s
		}(), nil, []string{model.ClassStaging}, nil},
		{"production header", func() *model.ServiceResult {
			s := html(200, "Portal", "x")
			s.HTTP.Headers["X-Environment"] = []string{"production"}
			return s
		}(), nil, nil, []string{model.ClassStaging}},
		{"staging certificate", func() *model.ServiceResult {
			s := html(200, "Portal", "x")
			s.TLS = &model.TLSInfo{SubjectCN: "uat.portal.example.edu"}
			return s
		}(), nil, []string{model.ClassStaging}, nil},
		{"directory listing", html(200, "Index of /", `<h1>Index of /</h1><a href="../">Parent Directory</a>`), nil, []string{model.ClassDirListing}, nil},
		{"json api", func() *model.ServiceResult {
			s := html(200, "", `{"status":"ok"}`)
			s.HTTP.Headers["Content-Type"] = []string{"application/json; charset=utf-8"}
			return s
		}(), nil, []string{model.ClassAPI}, nil},
		{"swagger", html(200, "Swagger UI", `<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js">`), nil, []string{model.ClassAPI}, nil},
		{"server error", html(500, "Internal Server Error", "boom"), nil, []string{model.ClassErrorPage}, nil},
		{"404 page", html(404, "404 Not Found", "<h1>Not Found</h1>"), nil, []string{model.ClassErrorPage}, nil},
		{"mysql port", &model.ServiceResult{Port: 3306, Name: "mysql"}, nil, []string{model.ClassDatabase}, []string{model.ClassRemoteAccess}},
		{"ssh port", &model.ServiceResult{Port: 22, Name: "ssh"}, nil, []string{model.ClassRemoteAccess}, []string{model.ClassDatabase}},
		{"rdp over tls", &model.ServiceResult{Port: 3389, Name: "ssl/ms-wbt-server"}, nil, []string{model.ClassRemoteAccess}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, classes := e.MatchHost(tc.svc, tc.hosts...)
			for _, c := range tc.want {
				if !has(classes, c) {
					t.Errorf("classes = %v, want %q", classes, c)
				}
			}
			for _, c := range tc.not {
				if has(classes, c) {
					t.Errorf("classes = %v, must not have %q", classes, c)
				}
			}
		})
	}
}
