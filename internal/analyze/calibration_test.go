package analyze

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// The DefectDojo login page of the lab (http://127.0.0.1:18080): nginx,
// Django, csrftoken cookie, no CSP, plain HTTP. testdata holds the real
// output of "fpprobe -addr 127.0.0.1:18080 -paths" with the built-in
// signatures (2026-11-21).
//
// Before the calibration: service interest 100; five findings, all with
// interest 100 (login-plain-http, interesting-cookie x2, interesting-header
// x2), because every finding copied the capped service score.
// After: service interest 75 (sum 80, compressed above 70); three findings: login-plain-http 50 (with the
// evidence of the signature "login form over plain HTTP"), headers 11,
// cookies 10.
func TestDojoLoginCalibration(t *testing.T) {
	b, err := os.ReadFile("testdata/dojo-login-service.json")
	if err != nil {
		t.Fatal(err)
	}
	var s model.ServiceResult
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	score, why := Interest(InterestInput{Service: s, ScopeCriticality: 3, Now: time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)})
	for _, w := range why {
		t.Logf("service reason %3d %s %s", w.Points, w.Code, w.Text)
	}
	if score != 75 {
		t.Errorf("service interest %d, want 75 (sum 80)", score)
	}
	fs := DeriveFindings(FindingInput{IP: "127.0.0.1", Services: []FindingService{{Result: s, Interest: score}}})
	got := map[string]model.Finding{}
	for _, f := range fs {
		t.Logf("finding %3d %-20s %s (%d evidence lines)", f.Interest, f.Type, f.Title, len(f.Evidence))
		if _, dup := got[f.Type]; dup {
			t.Errorf("two findings of type %s on one service", f.Type)
		}
		got[f.Type] = f
	}
	if len(fs) != 3 {
		t.Fatalf("%d findings, want 3", len(fs))
	}
	login := got[FindingLoginPlainHTTP]
	// base 50, plus 2 from the service interest (75) as the tie-break
	if login.Interest != 52 || login.Signature == "" {
		t.Errorf("login-plain-http %+v", login)
	}
	hasURL := false
	for _, e := range login.Evidence {
		if e.Where == "url" {
			hasURL = true
		}
	}
	if !hasURL {
		t.Errorf("the evidence of the signature must join the login finding: %+v", login.Evidence)
	}
	if h, c := got[FindingHeader], got[FindingCookie]; h.Interest < 5 || h.Interest > 25 || c.Interest < 5 || c.Interest > 25 {
		t.Errorf("weak findings must stay low: header %d, cookie %d", h.Interest, c.Interest)
	}
	if got[FindingCookie].Key != "interesting-cookie/127.0.0.1/tcp-18080" {
		t.Errorf("merged key %s", got[FindingCookie].Key)
	}
}

func TestWeakSignalsDoNotReachTheTop(t *testing.T) {
	s := model.ServiceResult{Port: 443, Proto: "tcp", State: "open", Name: "https", Tunnel: "ssl",
		HTTP: &model.HTTPFingerprint{Scheme: "https", Status: 200, Headers: map[string][]string{
			"Server": {"Apache/2.4.57"}, "X-Powered-By": {"PHP/8.1"}},
			Cookies: []model.Cookie{{Name: "PHPSESSID", HTTPOnly: false}}},
		TLS: &model.TLSInfo{HostMismatch: true, NotAfter: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
		Matches: []model.SigMatch{
			{Signature: "h1", Category: model.CatHeader, Interest: 20, Confidence: 1},
			{Signature: "h2", Category: model.CatHeader, Interest: 20, Confidence: 1},
			{Signature: "c1", Category: model.CatCookie, Interest: 20, Confidence: 1},
		}}
	score, why := Interest(InterestInput{Service: s, Now: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)})
	if score > WeakSignalsCap {
		t.Errorf("weak signals only: score %d > %d (%+v)", score, WeakSignalsCap, why)
	}
}

func TestFindingInterestOrder(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	admin := model.ServiceResult{Port: 8080, State: "open", Name: "http", Classes: []string{model.ClassAdminPanel},
		HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Admin", Headers: map[string][]string{"X-Powered-By": {"Express"}}}}
	db := model.ServiceResult{Port: 5432, State: "open", Name: "postgresql", Product: "PostgreSQL", Classes: []string{model.ClassDatabase}}
	loginTLS := model.ServiceResult{Port: 443, State: "open", Name: "https", Tunnel: "ssl", Classes: []string{model.ClassLogin},
		HTTP: &model.HTTPFingerprint{Scheme: "https", Status: 200, Title: "Sign in"},
		TLS:  &model.TLSInfo{SubjectCN: "x", NotAfter: now.AddDate(0, 0, -3), Expired: true}}
	plainCert := loginTLS
	plainCert.Classes = nil
	in := FindingInput{IP: "10.0.0.1", At: now, Services: []FindingService{{Result: admin}, {Result: db}, {Result: loginTLS}}}
	fs := DeriveFindings(in)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Interest > fs[j].Interest })
	var order []string
	byType := map[string]int{}
	for _, f := range fs {
		order = append(order, f.Type)
		byType[f.Type+"/"+f.IP] = f.Interest
	}
	t.Logf("order: %s", strings.Join(order, ", "))
	if fs[0].Type != FindingAdminPanel || fs[len(fs)-1].Type != FindingHeader {
		t.Errorf("order %v", order)
	}
	if byType[FindingExpiredCert+"/10.0.0.1"] != 70 {
		t.Errorf("expired certificate on a login page: %d, want 70", byType[FindingExpiredCert+"/10.0.0.1"])
	}
	other := DeriveFindings(FindingInput{IP: "10.0.0.2", At: now, Services: []FindingService{{Result: plainCert}}})
	if len(other) == 0 || other[0].Interest != 40 {
		t.Errorf("expired certificate elsewhere: %+v", other)
	}
	// Scope criticality 5 and a new service raise every finding.
	in.ScopeCriticality = 5
	in.Services = []FindingService{{Result: db, New: true}}
	for _, f := range DeriveFindings(in) {
		if f.Type == FindingDatabase && f.Interest != 90 {
			t.Errorf("database in a critical scope, new: %d, want 90", f.Interest)
		}
	}
}
