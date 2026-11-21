package sig

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/signatures"
)

// TestBuiltinLibraryIsValid loads every built-in signature file and fails on
// any validator error. It also holds the library to the rules of the brief.
func TestBuiltinLibraryIsValid(t *testing.T) {
	files, err := fs.Glob(signatures.FS, "*.yaml")
	if err != nil || len(files) < 5 {
		t.Fatalf("signature files: %v %v", files, err)
	}
	seen := map[string]string{}
	total := 0
	for _, name := range files {
		data, err := fs.ReadFile(signatures.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		sigs, val := Parse(string(data))
		for _, is := range val.Issues {
			// Warnings fail too: the built-in library must be clean.
			t.Errorf("%s: %s: %s: %s", name, is.Level, is.Path, is.Message)
		}
		if !val.OK {
			t.Errorf("%s: validator rejected the file", name)
		}
		for _, s := range sigs {
			total++
			if prev, dup := seen[s.Slug]; dup {
				t.Errorf("%s: id %q is also in %s", name, s.Slug, prev)
			}
			seen[s.Slug] = name
			if s.Name == "" || s.Description == "" {
				t.Errorf("%s: %s: name and description are required in the built-in library", name, s.Slug)
			}
			if !validCategory(s.Category) {
				t.Errorf("%s: %s: unknown category %q", name, s.Slug, s.Category)
			}
			if s.Interest < 0 || s.Interest > 100 {
				t.Errorf("%s: %s: interest %d", name, s.Slug, s.Interest)
			}
			if len(s.paths) > MaxRequestsPerSignature {
				t.Errorf("%s: %s: %d requests", name, s.Slug, len(s.paths))
			}
			for _, p := range s.paths {
				if reason := CheckPath(p); reason != "" {
					t.Errorf("%s: %s: unsafe path %q: %s", name, s.Slug, p, reason)
				}
			}
			// Each signature is valid on its own text too: the store keeps one YAML per signature.
			if again, v := Parse(s.YAML); !v.OK || len(again) != 1 || again[0].Slug != s.Slug {
				t.Errorf("%s: %s: the single-signature YAML does not parse again: %+v", name, s.Slug, v.Issues)
			}
		}
	}
	if total < 150 {
		t.Errorf("the library has %d signatures, the brief asks for at least 150", total)
	}
	t.Logf("%d built-in signatures in %d files", total, len(files))

	// University software named in the brief must be covered.
	for _, slug := range []string{"moodle", "usosweb", "dspace", "ojs", "ezproxy", "zimbra", "bigbluebutton", "jupyterhub", "koha"} {
		if _, ok := seen[slug]; !ok {
			t.Errorf("signature %q is missing", slug)
		}
	}
}

func validCategory(c string) bool {
	switch c {
	case model.CatCMS, model.CatFramework, model.CatAppServer, model.CatWebServer, model.CatIoT, model.CatPanel, model.CatDatabase,
		model.CatDevOps, model.CatLanguage, model.CatProxy, model.CatSecurity, model.CatOS, model.CatLibrary, model.CatEnvironment,
		model.CatHeader, model.CatCookie, model.CatOther:
		return true
	}
	return false
}

func TestBuiltinEngine(t *testing.T) {
	e, err := NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	total, enabled := e.Count()
	if total < 150 || enabled != total {
		t.Fatalf("count = %d, enabled = %d", total, enabled)
	}
	recs, err := Builtin()
	if err != nil || len(recs) != total {
		t.Fatalf("Builtin() = %d records, %v", len(recs), err)
	}
	for _, r := range recs {
		if !r.Builtin || !r.Enabled || r.Slug == "" || r.YAML == "" || r.Author == "" {
			t.Fatalf("built-in record = %+v", r)
		}
	}
	paths := e.ExtraPaths()
	if len(paths) == 0 || len(paths) > 80 {
		t.Errorf("the library asks for %d extra paths; the scanner budget is small, keep it under 80", len(paths))
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			t.Errorf("path %q twice in ExtraPaths", p)
		}
		seen[p] = true
	}
}

// TestBuiltinDetections runs the real library against recorded responses.
// The WordPress, Jenkins, Grafana and JupyterHub data come from the docker lab
// in cmd/fpprobe/testlab; the others follow the vendors' documented responses.
func TestBuiltinDetections(t *testing.T) {
	e, err := NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	http := func(status int, title, body string, headers map[string][]string) *model.HTTPFingerprint {
		if headers == nil {
			headers = map[string][]string{}
		}
		return &model.HTTPFingerprint{Scheme: "http", URL: "http://10.0.0.9/", FinalURL: "http://10.0.0.9/", Status: status, Title: title, BodyExcerpt: body, Headers: headers}
	}
	cases := []struct {
		name    string
		svc     *model.ServiceResult
		hosts   []string
		tech    string
		version string
		classes []string
		sigs    []string
		absent  []string // technologies that must not be reported
	}{
		{name: "WordPress", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "CzujkaLab", `<meta name="generator" content="WordPress 6.9.4" /><link rel='stylesheet' href='http://x/wp-includes/css/dist/block-library/style.min.css?ver=6.9.4'><script src="/wp-content/themes/t/a.js"></script>`,
				map[string][]string{"Server": {"Apache/2.4.67 (Debian)"}, "X-Powered-By": {"PHP/8.3.31"}, "Link": {`<http://x/index.php?rest_route=/>; rel="https://api.w.org/"`}})
			h.MetaGenerator = "WordPress 6.9.4"
			return h
		}()}, tech: "WordPress", version: "6.9.4", sigs: []string{"wordpress", "apache", "php", "header-version-powered-by"}, absent: []string{"Drupal", "Joomla"}},
		{name: "PHP from WordPress headers", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "x", "x", map[string][]string{"X-Powered-By": {"PHP/8.3.31"}})}, tech: "PHP", version: "8.3.31"},
		{name: "Jenkins", svc: &model.ServiceResult{Name: "http", HTTP: http(403, "", `<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/></head><body>Authentication required</body></html>`,
			map[string][]string{"X-Jenkins": {"2.580.2"}, "X-Hudson": {"1.395"}, "Server": {"Jetty(12.1.14)"}})}, tech: "Jenkins", version: "2.580.2", classes: []string{model.ClassDevTool}},
		{name: "Grafana", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Grafana", `<body class="theme-dark app-grafana"><script>window.grafanaBootData = {settings: {"buildInfo":{"version":"13.0.2"}}}</script>`, nil)
			h.FinalURL = "http://10.0.0.9/login"
			return h
		}()}, tech: "Grafana", classes: []string{model.ClassLogin}},
		{name: "JupyterHub", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "JupyterHub", "<form action=\"/hub/login\"><input type=\"password\"></form>",
			map[string][]string{"X-Jupyterhub-Version": {"6.2.0"}, "Server": {"TornadoServer/6.6.1"}})}, tech: "JupyterHub", version: "6.2.0", classes: []string{model.ClassLogin, model.ClassDevTool}},
		{name: "Moodle", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Home | New Site", `<script>M.cfg = {"wwwroot":"http://x","sesskey":"abc","themerev":"1"};</script><link href="/theme/yui_combo.php?rollup/3.18.1/yui-moodlesimple-min.css">`, nil)
			h.Cookies = []model.Cookie{{Name: "MoodleSession", ValueLen: 26, HTTPOnly: true}}
			return h
		}()}, tech: "Moodle"},
		{name: "USOSweb", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "Aktualności - USOSweb - Akademia", `<a href="kontroler.php?_action=logowaniecas/index">zaloguj się</a> <footer>USOSweb 7.1.2.0-4</footer>`, nil)}, tech: "USOSweb", version: "7.1.2.0-4", classes: []string{model.ClassLogin}},
		{name: "DSpace", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Repozytorium", `<meta name="Generator" content="DSpace 7.6.1"><ds-app></ds-app>`, nil)
			h.MetaGenerator = "DSpace 7.6.1"
			return h
		}()}, tech: "DSpace", version: "7.6.1"},
		{name: "OJS", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Czasopismo", `<meta name="generator" content="Open Journal Systems 3.4.0.5"><div class="pkp_structure_page">`, nil)
			h.MetaGenerator = "Open Journal Systems 3.4.0.5"
			return h
		}()}, tech: "Open Journal Systems", version: "3.4.0.5"},
		{name: "EZproxy", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "Database Menu", "EZproxy login", map[string][]string{"Server": {"EZproxy"}})}, tech: "EZproxy", classes: []string{model.ClassLogin}},
		{name: "Koha", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Katalog biblioteki", `<meta name="generator" content="Koha 23.1105000"><link href="/opac-tmpl/bootstrap/css/opac.css">`, nil)
			h.MetaGenerator = "Koha 23.1105000"
			return h
		}()}, tech: "Koha", version: "23.1105000"},
		{name: "BigBlueButton API", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Welcome", "<html>nginx</html>", nil)
			h.Paths = []model.PathProbe{{Path: "/bigbluebutton/api", Status: 200, BodySHA256: "bbb", Excerpt: "<response><returncode>SUCCESS</returncode><version>2.0</version><apiVersion>2.0</apiVersion><bbbVersion>2.7.4</bbbVersion></response>"}}
			return h
		}()}, tech: "BigBlueButton", version: "2.7.4"},
		{name: "Zimbra", svc: &model.ServiceResult{Name: "http", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "Zimbra Web Client Sign In", `<form name="loginForm"><input type="password" name="password"></form><script src="/js/zimbraMail/"></script>`, nil)
			h.Cookies = []model.Cookie{{Name: "ZM_TEST", ValueLen: 4}}
			return h
		}()}, tech: "Zimbra Collaboration", classes: []string{model.ClassLogin}},
		{name: "Tomcat default page", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "Apache Tomcat/10.1.62", "<h1>Apache Tomcat/10.1.62</h1> If you're seeing this, you've successfully installed Tomcat. Congratulations!", nil)},
			tech: "Apache Tomcat", version: "10.1.62", classes: []string{model.ClassDefaultPage}},
		{name: "nginx with nmap", svc: &model.ServiceResult{Name: "http", Product: "nginx", Version: "1.30.7", Confidence: 1,
			HTTP: http(200, "Welcome to nginx!", "<h1>Welcome to nginx!</h1>", map[string][]string{"Server": {"nginx/1.30.7"}})}, tech: "nginx", version: "1.30.7", classes: []string{model.ClassDefaultPage}},
		{name: "Django debug page", svc: &model.ServiceResult{Name: "http", HTTP: http(404, "Page not found at /x", "<p>Using the URLconf defined in <code>app.urls</code>, Django tried these URL patterns</p> You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.", nil)},
			tech: "Django", classes: []string{model.ClassStaging, model.ClassErrorPage}, sigs: []string{"django-debug"}},
		{name: "phpinfo", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "PHP 8.2.7 - phpinfo()", "<h1>PHP Version 8.2.7</h1><td>System</td><td>Configure Command</td>", nil)}, tech: "PHP", version: "8.2.7", sigs: []string{"phpinfo"}},
		{name: "staging host", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "Portal", "<p>hello</p>", nil)}, hosts: []string{"staging.portal.example.edu"}, classes: []string{model.ClassStaging}, sigs: []string{"staging-hostname"}},
		{name: "OpenSSH banner", svc: &model.ServiceResult{Port: 22, Name: "ssh", Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}, tech: "OpenSSH", version: "9.6p1", classes: []string{model.ClassRemoteAccess}},
		{name: "Dropbear banner", svc: &model.ServiceResult{Port: 22, Name: "ssh", Banner: "SSH-2.0-dropbear_2022.83"}, tech: "Dropbear SSH", version: "2022.83", classes: []string{model.ClassRemoteAccess, model.ClassIoT}},
		{name: "MariaDB from nmap", svc: &model.ServiceResult{Port: 3306, Name: "mysql", Product: "MariaDB", Version: "10.11.6", Confidence: 1}, tech: "MariaDB", version: "10.11.6", classes: []string{model.ClassDatabase}},
		{name: "Mosquitto from the nmap service name", svc: &model.ServiceResult{Port: 1883, Name: "mosquitto version 2.0.23", Confidence: 1}, tech: "Mosquitto", version: "2.0.23", classes: []string{model.ClassIoT}},
		{name: "RabbitMQ AMQP from nmap", svc: &model.ServiceResult{Port: 5672, Name: "amqp", Product: "RabbitMQ", Version: "4.3.8", Confidence: 1}, tech: "RabbitMQ", version: "4.3.8"},
		{name: "Redis from nmap", svc: &model.ServiceResult{Port: 6379, Name: "redis", Product: "Redis key-value store", Version: "7.2.4", Confidence: 1}, tech: "Redis", version: "7.2.4", classes: []string{model.ClassDatabase}},
		{name: "JWT cookie without flags over HTTPS", svc: &model.ServiceResult{Name: "http", Tunnel: "ssl", HTTP: func() *model.HTTPFingerprint {
			h := http(200, "App", "x", nil)
			h.Scheme, h.URL, h.FinalURL = "https", "https://10.0.0.9/", "https://10.0.0.9/"
			h.Cookies = []model.Cookie{{Name: "session", Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2ln", ValueLen: 45}}
			return h
		}()}, sigs: []string{"cookie-jwt", "cookie-session-no-secure", "cookie-session-no-httponly"}},
		{name: "plain page gives no technology", svc: &model.ServiceResult{Name: "http", HTTP: http(200, "Wydział Informatyki AGH", "<h1>Aktualności</h1><p>Zapraszamy na dzień otwarty. Kontakt: dziekanat.</p>", map[string][]string{"Content-Type": {"text/html; charset=utf-8"}})},
			absent: []string{"WordPress", "Moodle", "PHP", "nginx", "Apache HTTP Server", "Jenkins", "phpMyAdmin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, techs, classes := e.MatchHost(tc.svc, tc.hosts...)
			if tc.tech != "" {
				tech := techByName(techs, tc.tech)
				if tech == nil {
					t.Fatalf("technology %q not found; technologies = %+v; matches = %v", tc.tech, techs, slugs(matches))
				}
				if tc.version != "" && tech.Version != tc.version {
					t.Errorf("version = %q, want %q", tech.Version, tc.version)
				}
				if tech.Confidence < 0.5 {
					t.Errorf("confidence = %v", tech.Confidence)
				}
			}
			for _, c := range tc.classes {
				if !strings.Contains(","+strings.Join(classes, ",")+",", ","+c+",") {
					t.Errorf("classes = %v, want %q", classes, c)
				}
			}
			for _, s := range tc.sigs {
				if !strings.Contains(","+strings.Join(slugs(matches), ",")+",", ","+s+",") {
					t.Errorf("matches = %v, want %q", slugs(matches), s)
				}
			}
			for _, name := range tc.absent {
				if techByName(techs, name) != nil {
					t.Errorf("false positive: %q in %+v", name, techs)
				}
			}
			if tc.name == "plain page gives no technology" && len(techs) != 0 {
				t.Errorf("a plain page must give no technology: %+v (matches %v)", techs, slugs(matches))
			}
		})
	}
}

func TestStagingLabelIgnoresLab(t *testing.T) {
	for name, want := range map[string]bool{
		"pg.lab.czujka.test":        false,
		"lab212.agh.edu.pl":         false,
		"staging-portal.example.pl": true,
		"api.dev.example.pl":        true,
	} {
		if got := stagingLabelRe.MatchString(firstLabels(name)); got != want {
			t.Errorf("%s: staging = %v, want %v", name, got, want)
		}
	}
}
