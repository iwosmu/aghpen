package analyze

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

// goldenAt is the time of every golden input.
var goldenAt = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

// goldenServices are services that together produce every finding type and
// every interest reason the analysis writes.
func goldenServices() []FindingService {
	withClass := func(port int, title string, classes ...string) model.ServiceResult {
		s := httpSvc(port, title, 200)
		s.Classes = classes
		return s
	}
	tlsSvc := func(port int, f func(t *model.TLSInfo)) model.ServiceResult {
		s := httpSvc(port, "Portal", 200)
		s.HTTP.Scheme = "https"
		s.TLS = &model.TLSInfo{SubjectCN: "portal.example", Issuer: "R3", NotAfter: goldenAt.Add(400 * 24 * time.Hour), SHA256: "abcdef0123456789abcdef"}
		f(s.TLS)
		return s
	}
	header := httpSvc(8081, "x", 200)
	header.HTTP.Headers["X-Powered-By"] = []string{"PHP/7.4.3"}
	header.HTTP.Headers["Server"] = []string{"nginx/1.24.0"}
	header.Matches = []model.SigMatch{{Signature: "header-version-powered-by", Name: "Wersja oprogramowania w X-Powered-By", Category: model.CatHeader, Confidence: 0.9, Interest: 20,
		Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Powered-By", Snippet: "PHP/7.4.3"}}}}
	cookie := httpSvc(8082, "x", 200)
	cookie.HTTP.Scheme = "https"
	cookie.TLS = &model.TLSInfo{SubjectCN: "c.example", NotAfter: goldenAt.Add(400 * 24 * time.Hour)}
	cookie.HTTP.Cookies = []model.Cookie{{Name: "JSESSIONID", Value: "v"}, {Name: "auth_token", Value: "eyJhbGciOi"}, {Name: "wordpress_logged_in", Value: "v", HTTPOnly: true, Secure: true}}
	cookie.Matches = []model.SigMatch{{Signature: "cookie-laravel", Name: "Ciasteczko sesji Laravel", Category: model.CatCookie, Confidence: 1, Interest: 5,
		Evidence: []model.Evidence{{Matcher: "cookie", Where: "cookie:laravel_session", Snippet: "laravel_session"}}}}
	admin := withClass(8083, "Adminer")
	admin.Matches = []model.SigMatch{{Signature: "adminer", Name: "Adminer", Version: "4.8.1", Confidence: 0.95, Interest: 40, Classes: []string{model.ClassAdminPanel, model.ClassDatabase},
		Evidence: []model.Evidence{{Matcher: "title", Where: "title", Snippet: "Adminer"}}}}
	login := withClass(8084, "Zaloguj się", model.ClassLogin)
	sig := httpSvc(8085, "x", 200)
	sig.Matches = []model.SigMatch{
		{Signature: "acme-footer", Name: "Stopka ACME", Version: "3.1", Confidence: 0.8, Interest: 25, Tags: []string{"custom", "outdated"},
			Evidence: []model.Evidence{{Matcher: "body", Where: "body", Snippet: "Powered by ACME 3.1"}}},
		{Signature: "symfony-profiler", Name: "Symfony – profiler i pasek debugowania", Confidence: 0.9, Interest: 60, Tags: []string{"debug"},
			Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Debug-Token", Snippet: "a1b2c3"}}},
	}
	return []FindingService{
		{Result: admin},
		{Result: login},
		{Result: withClass(8086, "Sklep [staging]", model.ClassStaging)},
		{Result: httpSvc(8087, "phpinfo()", 200)},
		{Result: withClass(8088, "Kamera IP", model.ClassIoT)},
		{Result: withClass(8089, "Gitea", model.ClassDevTool)},
		{Result: model.ServiceResult{Port: 3306, Proto: "tcp", State: "open", Name: "mysql", Product: "MariaDB", Version: "11.4.13"}},
		{Result: model.ServiceResult{Port: 6379, Proto: "tcp", State: "open", Name: "redis"}},
		{Result: model.ServiceResult{Port: 23, Proto: "tcp", State: "open", Name: "telnet"}},
		{Result: model.ServiceResult{Port: 3389, Proto: "tcp", State: "open", Name: "ms-wbt-server"}},
		{Result: model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6"}},
		{Result: tlsSvc(8443, func(t *model.TLSInfo) { t.NotAfter = goldenAt.Add(-24 * time.Hour) })},
		{Result: tlsSvc(8444, func(t *model.TLSInfo) { t.NotAfter = goldenAt.Add(5*24*time.Hour + time.Hour) })},
		{Result: tlsSvc(8445, func(t *model.TLSInfo) { t.NotAfter = goldenAt.Add(1*24*time.Hour + time.Hour) })},
		{Result: tlsSvc(8446, func(t *model.TLSInfo) { t.SelfSigned = true })},
		{Result: tlsSvc(8447, func(t *model.TLSInfo) { t.HostMismatch = true; t.SANs = []string{"other.example", "www.other.example"} })},
		{Result: func() model.ServiceResult {
			s := tlsSvc(8448, func(*model.TLSInfo) {})
			s.Classes = []string{model.ClassLogin}
			return s
		}()},
		{Result: header},
		{Result: cookie},
		{Result: httpSvc(8090, "Index of /backup", 200)},
		{Result: httpSvc(8091, "Welcome to nginx!", 200)},
		{Result: httpSvc(8092, "Nowa", 200), New: true},
		{Result: model.ServiceResult{Port: 9999, Proto: "tcp", State: "open"}, New: true},
		{Result: sig},
	}
}

func goldenFindings() []model.Finding {
	in := findingInput(goldenServices()...)
	in.At = goldenAt
	return DeriveFindings(in)
}

func goldenReasons() []model.InterestReason {
	var all []model.InterestReason
	for i, fs := range goldenServices() {
		in := InterestInput{Service: fs.Result, Hostnames: []string{"ci.example"}, NewExposure: fs.New, Now: goldenAt}
		switch i {
		case 0:
			in.GroupSize, in.TotalServices, in.ScopeCriticality = 1, 87, 5
		case 1:
			in.ScopeCriticality = 4
		}
		_, why := Interest(in)
		all = append(all, why...)
	}
	return all
}

func evidenceLine(ev []model.Evidence) string {
	parts := make([]string, len(ev))
	for i, e := range ev {
		parts[i] = e.Where + "=" + e.Snippet
	}
	return strings.Join(parts, " | ")
}

// checkGolden compares got with testdata/name, or rewrites it with -update.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/" + name
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run Golden -update to write it)", err)
	}
	if string(want) != got {
		wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
		for i := 0; i < len(wl) || i < len(gl); i++ {
			var w, g string
			if i < len(wl) {
				w = wl[i]
			}
			if i < len(gl) {
				g = gl[i]
			}
			if w != g {
				t.Fatalf("%s line %d:\nwant %q\ngot  %q", path, i+1, w, g)
			}
		}
	}
}

// The Polish texts of every finding type and every interest reason. The
// file is the reference: the Polish output must not change.
func TestFindingTextGolden(t *testing.T) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, f := range goldenFindings() {
		seen[f.Type] = true
		fmt.Fprintf(&b, "%s\n  pl.title: %s\n  pl.desc:  %s\n  pl.evidence: %s\n", f.Type, f.Title, f.Description, evidenceLine(f.Evidence))
		if pl := RenderFinding(f, "pl"); pl.Title != f.Title || pl.Description != f.Description || evidenceLine(pl.Evidence) != evidenceLine(f.Evidence) {
			t.Errorf("Polish rendering changed the stored finding: %+v", pl)
		}
		en := RenderFinding(f, "en")
		fmt.Fprintf(&b, "  en.title: %s\n  en.desc:  %s\n  en.evidence: %s\n", en.Title, en.Description, evidenceLine(en.Evidence))
	}
	for typ := range FindingBaseInterest {
		if !seen[typ] {
			t.Errorf("no golden finding of type %s", typ)
		}
	}
	checkGolden(t, "findingtext.golden", b.String())
}

// A new reason code or a new finding title lead needs its English text.
func TestEnglishCoversEveryTypeAndReason(t *testing.T) {
	for _, w := range InterestWeights {
		if _, ok := reasonEN[w.Code]; !ok {
			t.Errorf("reason %s has no English label", w.Code)
		}
	}
	for _, f := range goldenFindings() {
		if en := RenderFinding(f, "en"); en.Title == f.Title || en.Description == f.Description && !strings.Contains(f.Description, ": ") {
			t.Errorf("%s: no English rendering: %q / %q", f.Type, en.Title, en.Description)
		}
	}
	if got := RenderFinding(model.Finding{Type: "manual", Manual: true, Title: "Ręczny wpis"}, "en"); got.Title != "Ręczny wpis" {
		t.Errorf("manual finding changed: %q", got.Title)
	}
}

func TestReasonTextGolden(t *testing.T) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, r := range goldenReasons() {
		seen[r.Code] = true
		fmt.Fprintf(&b, "%s %+d\n  pl: %s\n  en: %s\n", r.Code, r.Points, r.Text, RenderReason(r, "en"))
		if RenderReason(r, "pl") != r.Text {
			t.Errorf("Polish rendering changed the stored reason %q", r.Text)
		}
	}
	for _, w := range InterestWeights {
		if !seen[w.Code] {
			t.Errorf("no golden reason with code %s", w.Code)
		}
	}
	checkGolden(t, "reasontext.golden", b.String())
}
