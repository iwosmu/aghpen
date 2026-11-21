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
