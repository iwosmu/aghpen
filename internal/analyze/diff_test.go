package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func httpSvc(port int, title string, status int) model.ServiceResult {
	return model.ServiceResult{
		Port: port, Proto: "tcp", State: "open", Name: "http",
		HTTP: &model.HTTPFingerprint{
			Scheme: "http", URL: "http://x/", Status: status, Title: title,
			Headers:     map[string][]string{"Server": {"nginx"}, "Date": {"Mon, 01 Jan 2026 00:00:00 GMT"}, "Content-Type": {"text/html"}},
			BodySimhash: "ffff0000ffff0000", BodySHA256: "aa", BodyLength: 1000,
		},
	}
}

func snap(run int64, hosts ...HostSnapshot) Snapshot {
	return Snapshot{RunID: run, At: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC).Add(time.Duration(run) * time.Hour), Hosts: hosts}
}

func host(ip string, status model.HostStatus, svcs ...model.ServiceResult) HostSnapshot {
	return HostSnapshot{HostID: 1, IP: ip, Up: status == model.HostUp, Status: status, Services: svcs}
}

func kinds(cs []model.Change) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c.Kind)
		if c.Expected {
			out[i] += "(expected)"
		}
	}
	return out
}

func find(cs []model.Change, k model.ChangeKind) *model.Change {
	for i := range cs {
		if cs[i].Kind == k {
			return &cs[i]
		}
	}
	return nil
}

func TestDiffFirstRunHasNoChanges(t *testing.T) {
	cs, sum := Diff(nil, snap(1, host("10.0.0.1", model.HostUp, httpSvc(80, "a", 200))), DiffOptions{})
	if len(cs) != 0 || sum.PrevRunID != nil || sum.HostsNew != 0 {
		t.Fatalf("first run: %v %+v", kinds(cs), sum)
	}
}

func TestDiffHostTransitions(t *testing.T) {
	cases := []struct {
		name     string
		prev     *HostSnapshot
		cur      HostSnapshot
		want     []string
		summary  string
		severity model.Severity
	}{
		{"new host", nil, host("10.66.3.17", model.HostUp, model.ServiceResult{Port: 8080, Proto: "tcp", State: "open", Product: "Jenkins", Version: "2.440"}),
			[]string{"host_new", "service_new"}, "Nowy host 10.66.3.17 (otwarte porty: 8080)", model.SevLow},
		{"gone", ptr(host("10.0.0.2", model.HostUnstable)), host("10.0.0.2", model.HostDown),
			[]string{"host_gone"}, "Host 10.0.0.2 nieaktywny, nie odpowiada w zwykłych godzinach", model.SevMedium},
		{"still down is silent", ptr(host("10.0.0.2", model.HostDown)), host("10.0.0.2", model.HostDown), nil, "", ""},
		{"back", ptr(host("10.0.0.2", model.HostDown)), host("10.0.0.2", model.HostUp),
			[]string{"host_back"}, "Host 10.0.0.2 znów aktywny (był nieaktywny)", model.SevLow},
		{"missing after an answer", ptr(host("10.0.0.2", model.HostUp)), host("10.0.0.2", model.HostUnstable),
			[]string{"host_missing"}, "Host 10.0.0.2 nie odpowiada (niepotwierdzone)", model.SevMedium},
		{"unstable after expected offline", ptr(host("10.0.0.2", model.HostExpectedOffline)), host("10.0.0.2", model.HostUnstable),
			[]string{"host_unstable"}, "Host 10.0.0.2 nie odpowiada w zwykłych godzinach (niepotwierdzone)", model.SevLow},
		{"irregular host misses again", ptr(host("10.0.0.2", model.HostUp)), HostSnapshot{IP: "10.0.0.2", Status: model.HostUnstable, Stability: 0.5, Observations: 40},
			[]string{"host_unstable(expected)"}, "Host 10.0.0.2 niestabilny (aktywny w ok. 50% skanów)", model.SevInfo},
		{"expected offline", ptr(host("10.0.0.2", model.HostUp)), HostSnapshot{IP: "10.0.0.2", Status: model.HostExpectedOffline, Pattern: "zwykle aktywny pn–pt 08–16"},
			[]string{"host_gone(expected)"}, "Host 10.0.0.2 poza godzinami (zwykle aktywny pn–pt 08–16)", model.SevInfo},
		{"expected back", ptr(host("10.0.0.2", model.HostExpectedOffline)), host("10.0.0.2", model.HostUp),
			[]string{"host_back(expected)"}, "Host 10.0.0.2 znów aktywny", model.SevInfo},
		{"back after a short miss", ptr(host("10.0.0.2", model.HostUnstable, httpSvc(80, "a", 200))), host("10.0.0.2", model.HostUp, httpSvc(80, "a", 200)),
			[]string{"host_back"}, "Host 10.0.0.2 znów aktywny", model.SevInfo},
		{"irregular host back is expected", ptr(host("10.0.0.2", model.HostUnstable)), HostSnapshot{IP: "10.0.0.2", Up: true, Status: model.HostUp, Stability: 0.5, Observations: 40},
			[]string{"host_back(expected)"}, "Host 10.0.0.2 znów aktywny", model.SevInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := snap(1)
			if c.prev != nil {
				prev.Hosts = []HostSnapshot{*c.prev}
			}
			cs, sum := Diff(&prev, snap(2, c.cur), DiffOptions{})
			got := kinds(cs)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("kinds = %v, want %v", got, c.want)
			}
			if len(cs) == 0 {
				return
			}
			if !strings.Contains(cs[0].Summary, c.summary) {
				t.Errorf("summary = %q, want it to contain %q", cs[0].Summary, c.summary)
			}
			if cs[0].Severity != c.severity {
				t.Errorf("severity = %s, want %s", cs[0].Severity, c.severity)
			}
			if cs[0].Expected && (sum.HostsGone != 0 || sum.HostsBack != 0 || sum.ByKind["expected"] != 1) {
				t.Errorf("expected changes must stay out of the headline: %+v", sum)
			}
			if cs[0].RunID != 2 || cs[0].PrevRunID == nil || *cs[0].PrevRunID != 1 {
				t.Errorf("run ids: %+v", cs[0])
			}
		})
	}
}

func TestDiffNewServiceSummaryAndSeverity(t *testing.T) {
	base := httpSvc(80, "Intranet", 200)
	jenkins := model.ServiceResult{Port: 8080, Proto: "tcp", State: "open", Name: "http", Product: "Jenkins", Version: "2.440", Classes: []string{model.ClassDevTool}}
	prev := snap(1, host("10.66.3.17", model.HostUp, base))
	cur := snap(2, HostSnapshot{HostID: 5, IP: "10.66.3.17", Up: true, Status: model.HostUp, Services: []model.ServiceResult{base, jenkins}, ServiceIDs: map[string]int64{"8080/tcp": 77}})
	cs, sum := Diff(&prev, cur, DiffOptions{})
	if len(cs) != 1 {
		t.Fatalf("changes: %v", kinds(cs))
	}
	c := cs[0]
	if c.Summary != "Nowa usługa 10.66.3.17:8080 (Jenkins 2.440)" {
		t.Errorf("summary = %q", c.Summary)
	}
	if c.Severity != model.SevMedium || c.Port != 8080 || c.ServiceID == nil || *c.ServiceID != 77 || c.HostID != 5 {
		t.Errorf("change = %+v", c)
	}
	if sum.ServicesNew != 1 || sum.ByKind["service_new"] != 1 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestDiffSilentHostServicesAreUnknownNotGone(t *testing.T) {
	prev := snap(1, host("10.0.0.3", model.HostUp, httpSvc(80, "a", 200), httpSvc(443, "b", 200)))
	// The host did not answer: no services listed, status unstable.
	cs, sum := Diff(&prev, snap(2, host("10.0.0.3", model.HostUnstable)), DiffOptions{})
	if find(cs, model.ChangeServiceGone) != nil || sum.ServicesGone != 0 {
		t.Fatalf("a silent host must not lose its services: %v", kinds(cs))
	}
	// The host answers and port 443 is closed: now it is gone.
	cs, sum = Diff(&prev, snap(2, host("10.0.0.3", model.HostUp, httpSvc(80, "a", 200))), DiffOptions{})
	g := find(cs, model.ChangeServiceGone)
	if g == nil || g.Port != 443 || sum.ServicesGone != 1 || !strings.HasPrefix(g.Summary, "Usługa 10.0.0.3:443 zniknęła") {
		t.Fatalf("want service_gone for 443, got %v", kinds(cs))
	}
	// Port 443 was not in the scope of the newer run: not gone.
	cs, _ = Diff(&prev, snap(2, host("10.0.0.3", model.HostUp, httpSvc(80, "a", 200))), DiffOptions{PortInScope: func(_ string, p int) bool { return p == 80 }})
	if len(cs) != 0 {
		t.Fatalf("out-of-scope port reported: %v", kinds(cs))
	}
	// The host came back from a silent run without a carried baseline: no
	// service noise, only the return of the host itself.
	silent := snap(2, host("10.0.0.3", model.HostUnstable))
	cs, _ = Diff(&silent, snap(3, host("10.0.0.3", model.HostUp, httpSvc(80, "a", 200))), DiffOptions{})
	if strings.Join(kinds(cs), ",") != "host_back" {
		t.Fatalf("no baseline, want only host_back, got %v", kinds(cs))
	}
}

func TestDiffServiceFields(t *testing.T) {
	mod := func(f func(s *model.ServiceResult)) model.ServiceResult {
		s := httpSvc(443, "Portal", 200)
		s.Product, s.Version = "nginx", "1.24.0"
		s.Technologies = []model.Technology{{Name: "WordPress", Version: "6.4", Confidence: 0.9}, {Name: "Guess", Confidence: 0.2}}
		s.TLS = &model.TLSInfo{SHA256: "aaa", SubjectCN: "portal.example", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
		s.HTTP.Cookies = []model.Cookie{{Name: "PHPSESSID", Secure: true, HTTPOnly: true, ValueHash: "1"}}
		if f != nil {
			f(&s)
		}
		return s
	}
	cases := []struct {
		name    string
		change  func(s *model.ServiceResult)
		want    string
		summary string
	}{
		{"nothing", nil, "", ""},
		{"volatile headers and cookie values", func(s *model.ServiceResult) {
			s.HTTP.Headers["Date"] = []string{"Tue"}
			s.HTTP.Headers["Etag"] = []string{"W/123"}
			s.HTTP.Headers["X-Request-Id"] = []string{"abc"}
			s.HTTP.Headers["Set-Cookie"] = []string{"PHPSESSID=zzz"}
			s.HTTP.Cookies[0].ValueHash = "2"
			s.HTTP.BodySimhash = "ffff0000ffff0001" // 1 bit
			s.HTTP.BodySHA256 = "bb"
		}, "", ""},
		{"version", func(s *model.ServiceResult) { s.Version = "1.26.1" }, "service_changed", "Zmiana wersji 10.0.0.9:443: nginx 1.24.0 → nginx 1.26.1"},
		{"product", func(s *model.ServiceResult) { s.Product, s.Version = "Apache httpd", "2.4.58" }, "service_changed", "Zmiana produktu 10.0.0.9:443: nginx 1.24.0 → Apache httpd 2.4.58"},
		{"version missing this time is not a change", func(s *model.ServiceResult) { s.Product, s.Version = "", "" }, "", ""},
		{"tech added", func(s *model.ServiceResult) {
			s.Technologies = append(s.Technologies, model.Technology{Name: "PHP", Version: "8.2", Confidence: 0.8})
		}, "tech_new", "Nowa technologia PHP 8.2 na 10.0.0.9:443"},
		{"tech removed", func(s *model.ServiceResult) { s.Technologies = s.Technologies[1:] }, "tech_gone", "Technologia WordPress 6.4 zniknęła z 10.0.0.9:443"},
		{"tech version", func(s *model.ServiceResult) { s.Technologies[0].Version = "6.5" }, "tech_version", "Zmiana wersji WordPress, 10.0.0.9:443: 6.4 → 6.5"},
		{"weak tech guess ignored", func(s *model.ServiceResult) { s.Technologies = s.Technologies[:1] }, "", ""},
		{"title", func(s *model.ServiceResult) { s.HTTP.Title = "Portal  v2" }, "title_changed", "Zmiana tytułu strony 10.0.0.9:443: „Portal” → „Portal v2”"},
		{"status", func(s *model.ServiceResult) { s.HTTP.Status = 503; s.HTTP.BodySimhash = "0000ffff0000ffff" }, "status_changed", "Zmiana kodu HTTP 10.0.0.9:443: 200 → 503"},
		{"redirect", func(s *model.ServiceResult) {
			s.HTTP.Redirects = []model.Redirect{{From: "https://x/", To: "https://sso.example/login?state=123", Status: 302}}
		}, "redirect_changed", "Zmiana przekierowania 10.0.0.9:443: (brak) → https://sso.example/login"},
		{"cert", func(s *model.ServiceResult) {
			s.TLS = &model.TLSInfo{SHA256: "bbb", SubjectCN: "portal.example", NotAfter: time.Date(2028, 2, 3, 0, 0, 0, 0, time.UTC)}
		}, "cert_changed", "Nowy certyfikat TLS 10.0.0.9:443: portal.example, ważny do 2028-02-03"},
		{"header set", func(s *model.ServiceResult) {
			s.HTTP.Headers["X-Powered-By"] = []string{"PHP/8.2"}
			delete(s.HTTP.Headers, "Content-Type")
		}, "headers_changed", "Zmiana nagłówków 10.0.0.9:443: dodano X-Powered-By; usunięto Content-Type"},
		{"server header value", func(s *model.ServiceResult) { s.HTTP.Headers["Server"] = []string{"Apache"} }, "headers_changed", "Server: nginx → Apache"},
		{"cookie set", func(s *model.ServiceResult) {
			s.HTTP.Cookies = append(s.HTTP.Cookies, model.Cookie{Name: "csrftoken"})
		}, "cookies_changed", "Zmiana ciasteczek 10.0.0.9:443: dodano csrftoken"},
		{"cookie flags", func(s *model.ServiceResult) { s.HTTP.Cookies[0].Secure = false }, "cookies_changed", "PHPSESSID: Secure+HttpOnly → HttpOnly"},
		{"content", func(s *model.ServiceResult) { s.HTTP.BodySimhash = "0000ffff0000ffff" }, "content_changed", "Zmiana treści strony 10.0.0.9:443"},
		{"class", func(s *model.ServiceResult) { s.Classes = []string{model.ClassAdminPanel} }, "class_changed", "Zmiana klas usługi 10.0.0.9:443: dodano panel administracyjny"},
		{"http stage failed this time", func(s *model.ServiceResult) { s.HTTP = nil; s.Technologies = nil }, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := snap(1, host("10.0.0.9", model.HostUp, mod(nil)))
			cs, _ := Diff(&prev, snap(2, host("10.0.0.9", model.HostUp, mod(c.change))), DiffOptions{})
			if c.want == "" {
				if len(cs) != 0 {
					t.Fatalf("want no change, got %v: %q", kinds(cs), cs[0].Summary)
				}
				return
			}
			if len(cs) != 1 || string(cs[0].Kind) != c.want {
				t.Fatalf("kinds = %v, want [%s]", kinds(cs), c.want)
			}
			if !strings.Contains(cs[0].Summary, c.summary) {
				t.Errorf("summary = %q, want it to contain %q", cs[0].Summary, c.summary)
			}
		})
	}
}

func TestDiffIsDeterministicAndSorted(t *testing.T) {
	prev := snap(1)
	cur := snap(2, host("10.0.0.20", model.HostUp), host("10.0.0.3", model.HostUp), host("10.0.0.100", model.HostUp))
	cs, sum := Diff(&prev, cur, DiffOptions{})
	if len(cs) != 3 || cs[0].IP != "10.0.0.3" || cs[1].IP != "10.0.0.20" || cs[2].IP != "10.0.0.100" {
		t.Fatalf("order: %v", cs)
	}
	if sum.HostsNew != 3 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestSimhashDistance(t *testing.T) {
	if d, ok := SimhashDistance("ff", "0f"); !ok || d != 4 {
		t.Errorf("distance = %d %v", d, ok)
	}
	if _, ok := SimhashDistance("", "0f"); ok {
		t.Errorf("empty must not be ok")
	}
	if _, ok := SimhashDistance("zz", "0f"); ok {
		t.Errorf("bad hex must not be ok")
	}
}

func ptr[T any](v T) *T { return &v }

// A full run (version detection on) followed by a discovery-only run and a
// full run again: the field that a run did not measure keeps its value, so
// no change event either way.
func TestDiffDiscoveryRunAfterFullRunIsQuiet(t *testing.T) {
	full := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", CPE: []string{"cpe:/a:openbsd:openssh:9.6p1"}, Confidence: 1,
		Technologies: []model.Technology{{Name: "OpenSSH", Version: "9.6p1", Sources: []string{"nmap"}}}}
	bare := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Confidence: 0.3}
	web := model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.26.2", Confidence: 1,
		Technologies: []model.Technology{{Name: "nginx", Version: "1.26.2", Sources: []string{"nmap", "header:server"}}}}
	webBare := model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http-alt", Confidence: 0.3,
		Technologies: []model.Technology{{Name: "nginx", Sources: []string{"header:server"}}}}
	runs := []Snapshot{
		snap(1, host("10.0.0.5", model.HostUp, full, web)),
		snap(2, host("10.0.0.5", model.HostUp, bare, webBare)),
		snap(3, host("10.0.0.5", model.HostUp, full, web)),
	}
	for i := 1; i < len(runs); i++ {
		changes, _ := Diff(&runs[i-1], runs[i], DiffOptions{})
		if len(changes) != 0 {
			t.Errorf("run %d -> %d: %v", i, i+1, kinds(changes))
		}
	}
	// a real upgrade between two full runs is still a change
	newer := full
	newer.Version = "9.9p1"
	newer.Technologies = []model.Technology{{Name: "OpenSSH", Version: "9.9p1", Sources: []string{"nmap"}}}
	changes, _ := Diff(&runs[2], snap(4, host("10.0.0.5", model.HostUp, newer, web)), DiffOptions{})
	if got := kinds(changes); len(got) == 0 {
		t.Errorf("upgrade 9.6p1 -> 9.9p1 not reported")
	}
}

// A host whose port scan did not finish (nmap host timeout) keeps its
// services: they are unreachable in this run, not gone. Measured on the
// public instance: one such run reported 100 services gone.
func TestDiffPortsUnknownIsNotGone(t *testing.T) {
	svc := func(port int) model.ServiceResult {
		return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http"}
	}
	prev := &Snapshot{RunID: 1, Hosts: []HostSnapshot{{HostID: 1, IP: "10.0.0.1", Up: true, Status: model.HostUp, Services: []model.ServiceResult{svc(22), svc(80)}}}}
	cur := Snapshot{RunID: 2, Hosts: []HostSnapshot{{HostID: 1, IP: "10.0.0.1", Up: true, Status: model.HostUp, PortsUnknown: true, Services: []model.ServiceResult{svc(80)}}}}
	ch, sum := Diff(prev, cur, DiffOptions{})
	for _, c := range ch {
		if c.Kind == model.ChangeServiceGone {
			t.Errorf("unexpected %+v", c)
		}
	}
	if sum.ServicesGone != 0 || sum.ServicesUnreachable != 1 {
		t.Errorf("summary %+v", sum)
	}
	cur.Hosts[0].PortsUnknown = false
	if _, sum = Diff(prev, cur, DiffOptions{}); sum.ServicesGone != 1 {
		t.Errorf("a finished scan reports the service gone: %+v", sum)
	}
}
