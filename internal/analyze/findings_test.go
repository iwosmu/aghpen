package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func types(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Type
	}
	return out
}

func findingInput(svcs ...FindingService) FindingInput {
	return FindingInput{HostID: 9, IP: "10.66.3.17", Hostnames: []string{"ci.example"}, RunID: 4,
		At: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), Services: svcs}
}

func TestDeriveFindingsTypes(t *testing.T) {
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	withClass := func(title string, classes ...string) model.ServiceResult {
		s := httpSvc(8080, title, 200)
		s.Classes = classes
		return s
	}
	tlsSvc := func(f func(t *model.TLSInfo)) model.ServiceResult {
		s := httpSvc(443, "Portal", 200)
		s.HTTP.Scheme = "https"
		s.HTTP.Headers["Strict-Transport-Security"] = []string{"max-age=1"}
		s.TLS = &model.TLSInfo{SubjectCN: "portal.example", Issuer: "R3", NotAfter: at.Add(400 * 24 * time.Hour), SHA256: "abcdef0123456789abcdef"}
		f(s.TLS)
		return s
	}
	cases := []struct {
		name string
		svc  FindingService
		want []string
		sev  model.Severity
	}{
		{"admin panel", FindingService{Result: withClass("Panel", model.ClassAdminPanel)}, []string{FindingAdminPanel}, model.SevInfo},
		{"login over plain http", FindingService{Result: withClass("Logowanie", model.ClassLogin)}, []string{FindingLoginPlainHTTP}, model.SevLow},
		{"staging", FindingService{Result: withClass("Sklep", model.ClassStaging)}, []string{FindingStaging}, model.SevInfo},
		{"debug page", FindingService{Result: httpSvc(80, "phpinfo()", 200)}, []string{FindingDebugPage}, model.SevLow},
		{"iot", FindingService{Result: withClass("Kamera", model.ClassIoT)}, []string{FindingIoT}, model.SevInfo},
		{"database", FindingService{Result: model.ServiceResult{Port: 5432, Proto: "tcp", State: "open", Name: "postgresql", Product: "PostgreSQL DB", Version: "16.2"}}, []string{FindingDatabase}, model.SevLow},
		{"telnet", FindingService{Result: model.ServiceResult{Port: 23, Proto: "tcp", State: "open", Name: "telnet"}}, []string{FindingRemoteAccess}, model.SevLow},
		{"ssh", FindingService{Result: model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6"}}, []string{FindingRemoteAccess}, model.SevInfo},
		{"expired cert", FindingService{Result: tlsSvc(func(t *model.TLSInfo) { t.NotAfter = at.Add(-24 * time.Hour) })}, []string{FindingExpiredCert}, model.SevLow},
		{"cert expiring", FindingService{Result: tlsSvc(func(t *model.TLSInfo) { t.NotAfter = at.Add(5 * 24 * time.Hour) })}, []string{FindingCertExpiring}, model.SevInfo},
		{"self-signed", FindingService{Result: tlsSvc(func(t *model.TLSInfo) { t.SelfSigned = true })}, []string{FindingSelfSigned}, model.SevInfo},
		{"hostname mismatch", FindingService{Result: tlsSvc(func(t *model.TLSInfo) { t.HostMismatch = true; t.SANs = []string{"other.example"} })}, []string{FindingHostMismatch}, model.SevInfo},
		{"interesting header", FindingService{Result: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.HTTP.Headers["X-Powered-By"] = []string{"PHP/7.4.3"}
			return s
		}()}, []string{FindingHeader}, model.SevInfo},
		{"interesting cookie", FindingService{Result: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.HTTP.Cookies = []model.Cookie{{Name: "JSESSIONID", Value: "SECRET-VALUE"}}
			return s
		}()}, []string{FindingCookie}, model.SevInfo},
		{"directory listing", FindingService{Result: httpSvc(80, "Index of /backup", 200)}, []string{FindingDirListing}, model.SevLow},
		{"default page", FindingService{Result: httpSvc(80, "Welcome to nginx!", 200)}, []string{FindingDefaultPage}, model.SevInfo},
		{"new exposure", FindingService{Result: httpSvc(80, "x", 200), New: true}, []string{FindingNewExposure}, model.SevInfo},
		{"custom signature", FindingService{Result: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.Matches = []model.SigMatch{
				{Signature: "acme-footer", Name: "Stopka ACME", Version: "3.1", Confidence: 0.8, Interest: 25, Tags: []string{"custom"},
					Evidence: []model.Evidence{{Matcher: "body", Where: "body", Snippet: "Powered by ACME 3.1"}}},
				{Signature: "nginx", Name: "nginx", Category: model.CatWebServer, Confidence: 1},
			}
			return s
		}()}, []string{FindingSignature}, model.SevInfo},
		{"header signature", FindingService{Result: func() model.ServiceResult {
			s := httpSvc(80, "x", 200)
			s.Matches = []model.SigMatch{{Signature: "x-internal-node", Name: "X-Internal-Node", Category: model.CatHeader, Confidence: 0.6,
				Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Internal-Node", Snippet: "node-7"}}}}
			return s
		}()}, []string{FindingHeader}, model.SevInfo},
		{"plain page has no finding", FindingService{Result: httpSvc(80, "Hello", 200)}, nil, ""},
		{"closed port has no finding", FindingService{Result: model.ServiceResult{Port: 23, State: "closed", Name: "telnet"}}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := DeriveFindings(findingInput(c.svc))
			if strings.Join(types(fs), ",") != strings.Join(c.want, ",") {
				t.Fatalf("types = %v, want %v", types(fs), c.want)
			}
			for _, f := range fs {
				if f.Severity != c.sev {
					t.Errorf("severity = %s, want %s", f.Severity, c.sev)
				}
				if f.Key == "" || f.Title == "" || f.Description == "" || f.Status != model.FindingNew ||
					f.IP != "10.66.3.17" || f.HostID != 9 || f.FirstRunID != 4 || f.LastRunID != 4 || len(f.Evidence) == 0 {
					t.Errorf("incomplete finding: %+v", f)
				}
				if !strings.HasPrefix(f.Key, f.Type+"/10.66.3.17/tcp-") {
					t.Errorf("key = %q", f.Key)
				}
				for _, e := range f.Evidence {
					if strings.Contains(e.Snippet, "SECRET-VALUE") {
						t.Errorf("a cookie value leaked into the evidence: %+v", e)
					}
				}
			}
		})
	}
}

func TestFindingKeyIsStableAcrossRescans(t *testing.T) {
	svc := httpSvc(8080, "Dashboard [Jenkins]", 200)
	svc.Matches = []model.SigMatch{{Signature: "jenkins", Name: "Jenkins", Version: "2.440", Confidence: 0.9, Classes: []string{model.ClassDevTool, model.ClassAdminPanel},
		Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Jenkins", Snippet: "2.440"}}}}
	first := DeriveFindings(findingInput(FindingService{Result: svc}))

	// The rescan sees a new version, another title, another time and run.
	svc2 := httpSvc(8080, "Dashboard [Jenkins] (3 builds)", 200)
	svc2.Matches = []model.SigMatch{{Signature: "jenkins", Name: "Jenkins", Version: "2.441", Confidence: 0.95, Classes: []string{model.ClassDevTool, model.ClassAdminPanel}}}
	in2 := findingInput(FindingService{Result: svc2})
	in2.RunID, in2.At = 5, in2.At.Add(24*time.Hour)
	second := DeriveFindings(in2)

	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("findings: %v / %v", types(first), types(second))
	}
	for i := range first {
		if first[i].Key != second[i].Key {
			t.Errorf("key changed on rescan: %q -> %q", first[i].Key, second[i].Key)
		}
	}
	if first[0].Key != "admin-panel/10.66.3.17/tcp-8080/jenkins" {
		t.Errorf("key = %q", first[0].Key)
	}
	if first[0].Title != "Panel administracyjny: Jenkins (10.66.3.17:8080)" || first[0].Signature != "jenkins" {
		t.Errorf("finding = %+v", first[0])
	}
	if got := FindingKey("x", "2001:db8::1", 443, "", "A b/C"); got != "x/2001:db8::1/tcp-443/a-b-c" {
		t.Errorf("FindingKey = %q", got)
	}
}

// Inside one finding type the service interest breaks the tie (0..4), and a
// web tool for databases gets the admin-panel finding, not "database open to
// the network".
func TestFindingTieBreakAndWebDatabaseTool(t *testing.T) {
	b := &findingBuilder{fs: &FindingService{Interest: 96}, s: &model.ServiceResult{}, in: &FindingInput{}}
	hi := b.interest(FindingAdminPanel, nil)
	b.fs.Interest = 55
	lo := b.interest(FindingAdminPanel, nil)
	if hi != 79 || lo != 75 {
		t.Errorf("admin panel: %d (service 96), %d (service 55)", hi, lo)
	}
	web := model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Classes: []string{model.ClassDatabase, model.ClassAdminPanel},
		HTTP: &model.HTTPFingerprint{URL: "http://10.0.0.5/", Status: 200, Title: "phpMyAdmin"}}
	db := model.ServiceResult{Port: 5432, Proto: "tcp", State: "open", Name: "postgresql", Classes: []string{model.ClassDatabase}}
	fs := DeriveFindings(FindingInput{IP: "10.0.0.5", Services: []FindingService{{Result: web, Interest: 90}, {Result: db, Interest: 70}}})
	var dbPorts []int
	for _, f := range fs {
		if f.Type == FindingDatabase {
			dbPorts = append(dbPorts, f.Port)
		}
	}
	if len(dbPorts) != 1 || dbPorts[0] != 5432 {
		t.Errorf("database findings on ports %v, want only 5432", dbPorts)
	}
}
