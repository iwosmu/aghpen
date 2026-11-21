package signatures_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

// Responses in testdata/zoo were read with GET by Czujka (HTTP collector, default profile) from real instances of the
// images named in each case, run in the zoo machine (e2e/zoo) on 2026-11-21.

func zooFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "zoo", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// zooPage builds what the HTTP collector stores for a page from a zoo fixture.
func zooPage(t *testing.T, status int, file, title, finalURL string) *model.HTTPFingerprint {
	body := zooFixture(t, file)
	return &model.HTTPFingerprint{Scheme: "http", Status: status, Title: title, BodyExcerpt: body, BodyLength: len(body), URL: finalURL, FinalURL: finalURL}
}

func httpSvc(port int, product, version string, h *model.HTTPFingerprint) *model.ServiceResult {
	return &model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", Product: product, Version: version, HTTP: h}
}

func noClass(t *testing.T, eng *sig.Engine, svc *model.ServiceResult, class string) {
	t.Helper()
	if _, _, classes := eng.Match(svc); slices.Contains(classes, class) {
		t.Errorf("port %d: class %q set; classes %v", svc.Port, class, classes)
	}
}

func noMatch(t *testing.T, eng *sig.Engine, svc *model.ServiceResult, slug string) {
	t.Helper()
	matches, _, _ := eng.Match(svc)
	for _, m := range matches {
		if m.Signature == slug {
			t.Errorf("port %d: %s matched; it should not", svc.Port, slug)
		}
	}
}

func TestZooCMSInstallers(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	b := "http://localhost"

	// mediawiki:1.46.2 without LocalSettings.php.
	mw := httpSvc(33080, "Apache httpd", "2.4.71", zooPage(t, 200, "mediawiki-1.46-not-configured.html", "MediaWiki 1.46.2", b+":33080/"))
	check(t, eng, mw, want{"mediawiki-not-configured", "MediaWiki", "1.46.2", model.ClassInstallPage})

	// nextcloud:35.0.3-apache first run; /status.php says installed:false.
	nc := httpSvc(80, "Apache httpd", "2.4.71", zooPage(t, 200, "nextcloud-35-install.html", "Nextcloud", b+"/"))
	nc.HTTP.Paths = []model.PathProbe{{Path: "/status.php", Status: 200, Excerpt: `{"installed":false,"maintenance":false,"needsDbUpgrade":false,"version":"35.0.3.2","versionstring":"35.0.3","edition":"","productname":"Nextcloud","extendedSupport":false}`}}
	check(t, eng, nc, want{"nextcloud-installer", "Nextcloud", "35.0.3", model.ClassInstallPage})
	noClass(t, eng, nc, model.ClassLogin)
	noMatch(t, eng, nc, "nextcloud")

	// matomo:5.14.3-apache installer: the version is in the title.
	mt := httpSvc(41080, "Apache httpd", "2.4.71", zooPage(t, 200, "matomo-5.14-install.html", "Matomo 5.14.3 › Installation", b+":41080/"))
	mt.HTTP.Cookies = []model.Cookie{{Name: "MATOMO_SESSID"}}
	check(t, eng, mt, want{"matomo-installer", "Matomo", "5.14.3", model.ClassInstallPage})
	noClass(t, eng, mt, model.ClassLogin)
	noMatch(t, eng, mt, "matomo")

	// joomla:3.10.12 ("Joomla! Web Installer") and joomla:6.2.0 ("Joomla Installer").
	j3 := httpSvc(8082, "Apache httpd", "2.4.56", zooPage(t, 200, "joomla-3.10-install.html", "Joomla! Web Installer", b+":8082/installation/index.php"))
	check(t, eng, j3, want{"joomla-installer", "Joomla", "", model.ClassInstallPage})
	j6 := httpSvc(8083, "Apache httpd", "2.4.71", zooPage(t, 200, "joomla-6.2-install.html", "Joomla Installer", b+":8083/installation/index.php"))
	check(t, eng, j6, want{"joomla-installer", "Joomla", "", model.ClassInstallPage})
	noClass(t, eng, j6, model.ClassLogin)

	// drupal:7.103 redirects to /install.php (Drupal 8+ uses /core/install.php).
	d7 := httpSvc(19080, "Apache httpd", "2.4.62", zooPage(t, 200, "drupal-7-install.html", "Select an installation profile | Drupal", b+":19080/install.php"))
	check(t, eng, d7, want{"drupal-installer", "Drupal", "", model.ClassInstallPage})
}

func TestZooDevTools(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	b := "http://localhost"

	// keycloak/keycloak:26.8.2 start-dev: nmap names port 8080 "rtsp"; the HTTP answer vetoes the RTSP (IoT) finding.
	kc := &model.ServiceResult{Port: 8080, Proto: "tcp", State: "open", Name: "rtsp",
		HTTP: zooPage(t, 200, "keycloak-26.8-admin-console.html", "Keycloak Administration Console", b+":8080/admin/master/console/")}
	check(t, eng, kc, want{"keycloak-admin-console", "Keycloak", "", model.ClassAdminPanel})
	noMatch(t, eng, kc, "rtsp")
	noClass(t, eng, kc, model.ClassIoT)
	// A real RTSP service (no HTTP answer) still matches.
	cam := &model.ServiceResult{Port: 554, Proto: "tcp", State: "open", Name: "rtsp", Banner: "RTSP/1.0 200 OK"}
	check(t, eng, cam, want{"rtsp", "", "", model.ClassIoT})

	// hashicorp/consul:2.1.0 agent -dev: version from the UI's URL-encoded environment; /v1/agent/members without a token.
	cs := httpSvc(18500, "Golang net/http server", "", zooPage(t, 200, "consul-2.1-ui.html", "Consul by HashiCorp", b+":18500/ui/"))
	check(t, eng, cs, want{"consul", "HashiCorp Consul", "2.1.0", model.ClassDevTool})
	noMatch(t, eng, cs, "consul-api-open")
	cs.HTTP.Paths = []model.PathProbe{{Path: "/v1/agent/members", Status: 200,
		Headers: map[string][]string{"X-Consul-Default-Acl-Policy": {"allow"}}, Excerpt: zooFixture(t, "consul-2.1-agent-members.json")}}
	check(t, eng, cs, want{"consul-api-open", "HashiCorp Consul", "2.1.0", model.ClassUnauthControlAPI})

	// axllent/mailpit:v1.34.0: web UI (version in the stylesheet URL) and the SMTP banner nmap read on 1025.
	mp := httpSvc(38025, "Golang net/http server", "", zooPage(t, 200, "mailpit-1.34.html", "Mailpit", b+":38025/"))
	check(t, eng, mp, want{"mailpit", "Mailpit", "1.34.0", model.ClassDevTool})
	noMatch(t, eng, mp, "mailhog")
	smtp := &model.ServiceResult{Port: 1025, Proto: "tcp", State: "open", Name: "smtp", Banner: "220 a6086590296c Mailpit ESMTP Service ready"}
	check(t, eng, smtp, want{"mailpit-smtp", "Mailpit", "", model.ClassDevTool})

	// gogs/gogs:0.14.4 first run.
	gg := httpSvc(3300, "Golang net/http server", "", zooPage(t, 200, "gogs-0.14-install.html", "Installation - Gogs", b+":3300/install"))
	gg.HTTP.Cookies = []model.Cookie{{Name: "i_like_gogs"}, {Name: "_csrf"}, {Name: "lang"}}
	check(t, eng, gg, want{"gogs-installer", "Gogs", "", model.ClassInstallPage})
	noClass(t, eng, gg, model.ClassLogin)

	// registry:3.1.2: /v2/ answers 200 without a token.
	rg := httpSvc(5000, "Docker Registry", "", &model.HTTPFingerprint{Scheme: "http", Status: 200, URL: b + ":5000/", FinalURL: b + ":5000/"})
	rg.HTTP.Paths = []model.PathProbe{{Path: "/v2/", Status: 200, Headers: map[string][]string{"Docker-Distribution-Api-Version": {"registry/2.0"}}, Excerpt: "{}"}}
	check(t, eng, rg, want{"docker-registry-open", "Docker Registry", "", model.ClassUnauthControlAPI})

	// louislam/uptime-kuma:2.5.12 before its first setup redirects to /setup-database.
	uk := httpSvc(3001, "Node.js Express framework", "", &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Uptime Kuma", URL: b + ":3001/", FinalURL: b + ":3001/setup-database"})
	check(t, eng, uk, want{"uptime-kuma-setup", "Uptime Kuma", "", model.ClassInstallPage})
}

func TestZooMonitoring(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	b := "http://localhost"

	// prom/alertmanager:v0.35.0: the version from alertmanager_build_info on /metrics (first 16 KiB, as collected).
	am := httpSvc(9093, "Golang net/http server", "", &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Alertmanager", URL: b + ":9093/", FinalURL: b + ":9093/"})
	am.HTTP.Paths = []model.PathProbe{{Path: "/metrics", Status: 200, Excerpt: zooFixture(t, "alertmanager-0.35-metrics.txt")}}
	check(t, eng, am, want{"alertmanager", "Alertmanager", "0.35.0", model.ClassDevTool})

	// prom/pushgateway:v1.11.5: its own product, not a generic exporter; version from /api/v1/status.
	pg := httpSvc(9091, "Golang net/http server", "", &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Prometheus Pushgateway", URL: b + ":9091/", FinalURL: b + ":9091/"})
	pg.HTTP.Paths = []model.PathProbe{{Path: "/api/v1/status", Status: 200, Excerpt: zooFixture(t, "pushgateway-1.11-status.json")}}
	check(t, eng, pg, want{"pushgateway", "Prometheus Pushgateway", "1.11.5", model.ClassDevTool})
}

func TestZooJava(t *testing.T) {
	eng, err := sig.NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	b := "http://localhost"

	// quay.io/wildfly/wildfly:42.0.0.Final: welcome page on 8080 and the HAL console on the management port 9990.
	wf := httpSvc(28080, "", "", zooPage(t, 200, "wildfly-42-welcome.html", "Welcome to WildFly", b+":28080/"))
	check(t, eng, wf, want{"wildfly-default-page", "WildFly / JBoss", "", model.ClassDefaultPage})
	hal := httpSvc(9990, "", "", zooPage(t, 200, "wildfly-42-hal-console.html", "HAL Management Console", b+":9990/console/index.html"))
	check(t, eng, hal, want{"wildfly-hal-console", "WildFly / JBoss", "", model.ClassAdminPanel})

	// solr:9.11.0 admin UI.
	solr := httpSvc(8983, "Jetty", "", zooPage(t, 200, "solr-9.11-admin.html", "Solr Admin", b+":8983/solr/"))
	check(t, eng, solr, want{"solr", "Apache Solr", "9.11.0", model.ClassAdminPanel})

	// metabase/metabase:v0.65.6.3 before its first setup. The SPA answers every path with its page and echoes the
	// path into it (<meta name="uri" content="/_profiler/">): that is not a Symfony profiler.
	mb := httpSvc(13000, "", "", zooPage(t, 200, "metabase-0.65-setup.html", "Metabase", b+":13000/"))
	mb.HTTP.Cookies = []model.Cookie{{Name: "metabase.DEVICE"}}
	prof := zooFixture(t, "metabase-0.65-profiler-path.html")
	mb.HTTP.Paths = []model.PathProbe{{Path: "/_profiler/", Status: 200, Title: "Metabase", Length: len(prof), Excerpt: prof}}
	check(t, eng, mb, want{"metabase-setup", "Metabase", "0.65.6.3", model.ClassInstallPage})
	check(t, eng, mb, want{"metabase", "Metabase", "0.65.6.3", ""})
	noMatch(t, eng, mb, "symfony-profiler")
	noClass(t, eng, mb, model.ClassStaging)
}
