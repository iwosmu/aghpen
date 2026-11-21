package signatures_test

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

// Responses in testdata/labtools were read with GET from the services of the organisers' template (lab/jury) on 2026-11-21.

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "labtools", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var titleRe = regexp.MustCompile(`(?is)<title>\s*(.*?)\s*</title>`)

// page builds what the HTTP collector stores for a page: status, decoded title, body excerpt and final URL.
func page(t *testing.T, status int, file, finalURL string) *model.HTTPFingerprint {
	body := fixture(t, file)
	title := ""
	if m := titleRe.FindStringSubmatch(body); m != nil {
		title = html.UnescapeString(m[1])
	}
	return &model.HTTPFingerprint{Scheme: "http", Status: status, Title: title, BodyExcerpt: body, BodyLength: len(body), URL: finalURL, FinalURL: finalURL}
}

type want struct {
	slug, tech, version, class string
}

func check(t *testing.T, eng *sig.Engine, svc *model.ServiceResult, w want) {
	t.Helper()
	matches, techs, classes := eng.Match(svc)
	found := false
	for _, m := range matches {
		if m.Signature == w.slug {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: no match; matches %+v", w.slug, matches)
	}
	if w.tech != "" {
		ok := false
		for _, tc := range techs {
			if tc.Name == w.tech && (w.version == "" || tc.Version == w.version) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: technology %q %q missing; technologies %+v", w.slug, w.tech, w.version, techs)
		}
	}
	if w.class != "" && !slices.Contains(classes, w.class) {
		t.Errorf("%s: class %q missing; classes %v", w.slug, w.class, classes)
	}
}

func TestLabtoolsSignatures(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	base := "http://host.docker.internal"

	// Toxiproxy 2.12.0, modern-proxy :8474. The root is Go's 404; /version answers.
	toxi := &model.ServiceResult{Port: 8474, Proto: "tcp", State: "open", Name: "http", Product: "Golang net/http server",
		HTTP: page(t, 404, "toxiproxy-root.txt", base+":8474/")}
	toxi.HTTP.Paths = []model.PathProbe{{Path: "/version", Status: 200, Excerpt: fixture(t, "toxiproxy-version.json")}}
	check(t, eng, toxi, want{"toxiproxy-api", "Toxiproxy", "2.12.0", model.ClassUnauthControlAPI})

	// Traefik v3.1 with api.insecure, modern-proxy :8086 over plain HTTP.
	tr := &model.ServiceResult{Port: 8086, Proto: "tcp", State: "open", Name: "http", Product: "Golang net/http server",
		HTTP: page(t, 200, "traefik-dashboard.html", base+":8086/dashboard/")}
	tr.HTTP.Paths = []model.PathProbe{{Path: "/api/version", Status: 200, Excerpt: fixture(t, "traefik-api-version.json")}}
	check(t, eng, tr, want{"traefik-api-insecure", "Traefik", "3.1.7", model.ClassUnauthControlAPI})

	// Nginx Proxy Manager, modern :80 (default site) and :81 (admin; already in panels.yaml).
	npm := &model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "OpenResty web app server",
		HTTP: page(t, 200, "npm-default-site.html", base+"/")}
	check(t, eng, npm, want{"nginx-proxy-manager-default-site", "Nginx Proxy Manager", "", model.ClassDefaultPage})
	npmAdmin := &model.ServiceResult{Port: 81, Proto: "tcp", State: "open", Name: "http", HTTP: page(t, 200, "npm-admin.html", base+":81/")}
	check(t, eng, npmAdmin, want{"nginx-proxy-manager", "Nginx Proxy Manager", "", model.ClassAdminPanel})

	// DVWA 1.10, vulnerable :8090 (redirect to login.php).
	dvwa := &model.ServiceResult{Port: 8090, Proto: "tcp", State: "open", Name: "http", Product: "Apache httpd", Version: "2.4.25",
		HTTP: page(t, 200, "dvwa-login.html", base+":8090/login.php")}
	check(t, eng, dvwa, want{"dvwa", "DVWA (Damn Vulnerable Web Application)", "1.10", model.ClassStaging})

	// httpbin 0.9.2, custom-network :8888 (nmap says tcpwrapped; the page still identifies it).
	hb := &model.ServiceResult{Port: 8888, Proto: "tcp", State: "open", Name: "tcpwrapped", HTTP: page(t, 200, "httpbin.html", base+":8888/")}
	check(t, eng, hb, want{"httpbin", "httpbin", "0.9.2", model.ClassDevTool})

	// WordPress install pages: 4.7.5 (vulnerable :8088, image wordpress:4.7) and 7.1.5 (modern :8080, wordpress:latest).
	wp47 := &model.ServiceResult{Port: 8088, Proto: "tcp", State: "open", Name: "http", Product: "Apache httpd", Version: "2.4.10",
		HTTP: page(t, 200, "wordpress-47-install.html", base+":8088/wp-admin/install.php")}
	check(t, eng, wp47, want{"wordpress-installer", "WordPress", "4.7.5", model.ClassInstallPage})
	wp := &model.ServiceResult{Port: 8080, Proto: "tcp", State: "open", Name: "http", Product: "Apache httpd", Version: "2.4.71",
		HTTP: page(t, 200, "wordpress-latest-install.html", base+":8080/wp-admin/install.php")}
	check(t, eng, wp, want{"wordpress-installer", "WordPress", "7.1.5", model.ClassInstallPage})

	// Adminer, phpMyAdmin, Gitea and RabbitMQ Management are in panels.yaml already; Adminer is checked on its real page.
	adm := &model.ServiceResult{Port: 8089, Proto: "tcp", State: "open", Name: "http", HTTP: page(t, 200, "adminer.html", base+":8089/")}
	check(t, eng, adm, want{"adminer", "Adminer", "", model.ClassAdminPanel})

	// Redis 7 without a password: nmap read the version from INFO.
	redis := &model.ServiceResult{Port: 6379, Proto: "tcp", State: "open", Name: "redis", Product: "Redis key-value store", Version: "7.4.12"}
	check(t, eng, redis, want{"redis-no-auth", "", "", model.ClassDatabase})
}

func TestLabtoolsNoFalseMatch(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	ours := []string{"toxiproxy-api", "traefik-api-insecure", "nginx-proxy-manager-default-site", "dvwa", "httpbin", "wordpress-installer", "redis-no-auth"}
	cases := map[string]*model.ServiceResult{
		// Redis with requirepass: nmap gets NOAUTH and no version.
		"redis with a password": {Port: 6379, Proto: "tcp", State: "open", Name: "redis", Product: "Redis key-value store"},
		// A finished WordPress site, not the installer.
		"wordpress site": {Port: 80, Proto: "tcp", State: "open", Name: "http", HTTP: &model.HTTPFingerprint{Status: 200, Title: "Blog",
			BodyExcerpt: `<link rel='stylesheet' href='/wp-includes/css/dist/block-library/style.min.css?ver=7.1.5'>`, FinalURL: "http://x/"}},
		// Another Go service with a 404 root and no Toxiproxy /version.
		"go 404": {Port: 8080, Proto: "tcp", State: "open", Name: "http", Product: "Golang net/http server",
			HTTP: &model.HTTPFingerprint{Status: 404, BodyExcerpt: "404 page not found\n", Paths: []model.PathProbe{{Path: "/version", Status: 404, Excerpt: "404 page not found\n"}}}},
		// The plain nginx welcome page of the custom-network stack (:8787).
		"nginx default": {Port: 8787, Proto: "tcp", State: "open", Name: "http", Product: "nginx", HTTP: &model.HTTPFingerprint{Status: 200, Title: "Welcome to nginx!",
			BodyExcerpt: "<h1>Welcome to nginx!</h1>"}},
	}
	for name, svc := range cases {
		matches, _, _ := eng.Match(svc)
		for _, m := range matches {
			if slices.Contains(ours, m.Signature) {
				t.Errorf("%s: unexpected match %s", name, m.Signature)
			}
		}
	}
}
