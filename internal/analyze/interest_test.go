package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func codes(why []model.InterestReason) string {
	out := make([]string, len(why))
	for i, r := range why {
		out[i] = r.Code
	}
	return strings.Join(out, ",")
}

func TestInterest(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	login := httpSvc(80, "Logowanie", 200)
	login.Classes = []string{model.ClassLogin}

	admin := httpSvc(8080, "Dashboard [Jenkins]", 200)
	admin.Classes = []string{model.ClassAdminPanel}
	admin.TLS = &model.TLSInfo{NotAfter: now.Add(-48 * time.Hour), SelfSigned: true, SubjectCN: "jenkins"}

	cases := []struct {
		name  string
		in    InterestInput
		score int
		codes string
	}{
		{"plain page", InterestInput{Service: httpSvc(80, "Hello", 200)}, 0, ""},
		{"login over plain http without security headers", InterestInput{Service: login}, 30, "login-plain-http,missing-security-headers"},
		{"admin panel, dev tool, expired self-signed cert, new", InterestInput{Service: admin, NewExposure: true, Now: now}, 80, // sum 90, compressed above 70
			"admin-panel,dev-tool,expired-cert,new-exposure,self-signed-cert"},
		{"a large sum stays under 100", InterestInput{Service: func() model.ServiceResult {
			s := admin
			s.Classes = []string{model.ClassAdminPanel, model.ClassStaging, model.ClassIoT, model.ClassDirListing}
			return s
		}(), NewExposure: true, Now: now, ScopeCriticality: 5}, 95, ""}, // sum 165
		{"database", InterestInput{Service: model.ServiceResult{Port: 6379, Name: "redis", Product: "Redis key-value store", Version: "7.4.1", State: "open"}}, 25, "database"},
		{"telnet", InterestInput{Service: model.ServiceResult{Port: 23, Name: "telnet", State: "open"}}, 25, "remote-access-plaintext"},
		{"ssh is only worth 5", InterestInput{Service: model.ServiceResult{Port: 22, Name: "ssh", State: "open"}}, 5, "remote-access"},
		{"rare technology", InterestInput{Service: httpSvc(80, "x", 200), GroupSize: 1, TotalServices: 400}, 10, "rare-tech"},
		{"rare rule needs a big enough network", InterestInput{Service: httpSvc(80, "x", 200), GroupSize: 1, TotalServices: 5}, 0, ""},
		{"signature weight times confidence", InterestInput{Service: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.Matches = []model.SigMatch{{Signature: "custom-footer", Name: "Stopka ACME", Interest: 30, Confidence: 0.5}, {Signature: "nginx", Interest: 0, Confidence: 1}}
			return s
		}()}, 15, "signature"},
		{"cert expiring soon", InterestInput{Service: func() model.ServiceResult {
			s := httpSvc(443, "x", 200)
			s.TLS = &model.TLSInfo{NotAfter: now.Add(10 * 24 * time.Hour)}
			return s
		}(), Now: now}, 5, "cert-expiring"},
		{"scope criticality 4", InterestInput{Service: httpSvc(80, "x", 200), ScopeCriticality: 4}, 5, "scope-criticality"},
		{"sensitive header and weak cookie", InterestInput{Service: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.HTTP.Headers["X-Powered-By"] = []string{"PHP/7.4.3"}
			s.HTTP.Cookies = []model.Cookie{{Name: "PHPSESSID"}}
			return s
		}()}, 10, "sensitive-header,interesting-cookie"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, why := Interest(c.in)
			if score != c.score {
				t.Errorf("score = %d, want %d (%s)", score, c.score, codes(why))
			}
			if c.codes != "" && codes(why) != c.codes {
				t.Errorf("codes = %s, want %s", codes(why), c.codes)
			}
			for i := 1; i < len(why); i++ {
				if why[i].Points > why[i-1].Points {
					t.Errorf("reasons are not sorted by points: %v", why)
				}
			}
			for _, r := range why {
				if r.Text == "" || r.Points <= 0 {
					t.Errorf("bad reason %+v", r)
				}
			}
		})
	}
}

func TestInterestWeightsTableIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range InterestWeights {
		if seen[w.Code] {
			t.Errorf("duplicate code %s", w.Code)
		}
		seen[w.Code] = true
		if w.Points <= 0 || w.Points > 100 || w.Text == "" {
			t.Errorf("bad weight %+v", w)
		}
	}
}

func TestHostInterest(t *testing.T) {
	if got := HostInterest([]int{10, 70, 30}, false); got != 70 {
		t.Errorf("got %d", got)
	}
	if got := HostInterest([]int{98}, true); got != 100 {
		t.Errorf("got %d", got)
	}
	if got := HostInterest(nil, false); got != 0 {
		t.Errorf("got %d", got)
	}
}

func TestEffectiveClassesFallbacks(t *testing.T) {
	cases := []struct {
		name string
		svc  model.ServiceResult
		host []string
		want string
	}{
		{"mysql", model.ServiceResult{Name: "mysql"}, nil, "database"},
		{"rdp", model.ServiceResult{Name: "ms-wbt-server"}, nil, "remote-access"},
		{"dir listing", httpSvc(80, "Index of /backup", 200), nil, "directory-listing"},
		{"default page", httpSvc(80, "Welcome to nginx!", 200), nil, "default-page"},
		{"phpmyadmin", httpSvc(80, "phpMyAdmin", 200), nil, "admin-panel"},
		{"grafana", httpSvc(3000, "Grafana", 200), nil, "dev-tool"},
		{"staging hostname", httpSvc(80, "Sklep", 200), []string{"staging.sklep.example"}, "staging"},
		{"production hostname is not staging", httpSvc(80, "Sklep", 200), []string{"latest-news.example"}, ""},
		{"classes from signature matches", func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.Matches = []model.SigMatch{{Signature: "hikvision", Classes: []string{model.ClassIoT}}}
			return s
		}(), nil, "iot"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := strings.Join(EffectiveClasses(&c.svc, c.host), ","); got != c.want {
				t.Errorf("classes = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCompressInterestKeepsTheTopOrdered(t *testing.T) {
	prev := -1
	for sum := 0; sum <= 300; sum += 5 {
		got := CompressInterest(sum)
		if got < prev || got > 99 {
			t.Fatalf("sum %d -> %d after %d", sum, got, prev)
		}
		if sum <= InterestKnee && got != sum {
			t.Errorf("sum %d -> %d, want the sum below the knee", sum, got)
		}
		prev = got
	}
	// the lab case: phpMyAdmin over HTTP against a blog login page over HTTP
	if a, b := CompressInterest(150), CompressInterest(105); a <= b {
		t.Errorf("150 -> %d, 105 -> %d: the larger sum must rank higher", a, b)
	}
}
