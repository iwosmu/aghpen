package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/lab/labcfg"
	"github.com/iwosmu/aghpen/lab/truth"
)

func i32(v int32) *int32 { return &v }

func sampleTruth() *truth.File {
	return &truth.File{State: "t0", Ignore: []string{"10.0.0.254"}, Hosts: []truth.Host{
		{IP: "10.0.0.1", Name: "wp", Services: []truth.Service{{
			Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.67",
			Technologies: []truth.Tech{{Name: "WordPress", Category: "cms", Version: "6.9.4", Aliases: []string{"wordpress"}}, {Name: "PHP", Version: "8.3"}},
			TechOptional: []string{"jQuery"}, Classes: []string{"login"}, ClassOptional: []string{"admin-panel"},
			HTTP:        &truth.HTTP{Status: 200, Title: "Blog&nbsp;A", FaviconMMH3: i32(42), Cookies: []truth.Cookie{{Name: "sid", HTTPOnly: true}}},
			Interesting: []truth.Interesting{{Kind: "header", Name: "X-Powered-By"}, {Kind: "cookie", Name: "sid"}},
			Signatures:  []string{"custom-1"},
		}}},
		{IP: "10.0.0.2", Name: "db", Services: []truth.Service{
			{Port: 3306, Proto: "tcp", Name: "mysql"},
			{Port: 161, Proto: "udp", Name: "snmp", Hard: "udp"},
			{Port: 443, Proto: "tcp", Name: "http", Tunnel: "ssl", TLS: &truth.TLS{SelfSigned: true}},
		}},
		{IP: "10.0.0.3", Name: "missing", Hard: []string{"stealth-firewall"}, Services: []truth.Service{{Port: 22, Proto: "tcp", Name: "ssh", Classes: []string{"remote-access"}}}},
		{IP: "10.0.0.9", Name: "flapper", Availability: &labcfg.Avail{Kind: "schedule", PeriodSec: 100, UpFromSec: 0, UpToSec: 50}, Services: []truth.Service{{Port: 80, Proto: "tcp", Name: "http"}}},
	}}
}

func sampleExport() []model.HostResult {
	return []model.HostResult{
		{IP: "10.0.0.1", Up: true, ObservedAt: time.Unix(1000, 0), Services: []model.ServiceResult{{
			Port: 80, Proto: "tcp", State: "open", Name: "http-alt", Version: "2.4.67",
			Technologies: []model.Technology{{Name: "wordpress", Version: "6.9"}, {Name: "jQuery"}, {Name: "Drupal"}, {Name: "Secure cookie missing", Category: model.CatCookie}, {Name: "LowConf", Confidence: 0.1}},
			Classes:      []string{"login", "admin-panel", "iot"},
			HTTP: &model.HTTPFingerprint{Title: "Blog A", FaviconMMH3: i32(42), Headers: map[string][]string{"x-powered-by": {"PHP/8.3.1"}},
				Cookies: []model.Cookie{{Name: "sid", HTTPOnly: true}}},
			Matches: []model.SigMatch{{Signature: "custom-1"}, {Signature: "hdr", Category: model.CatHeader, Name: "X-Powered-By leak"}},
		}}},
		{IP: "10.0.0.2", Up: true, Services: []model.ServiceResult{
			{Port: 3306, Proto: "tcp", State: "open", Name: "postgresql"},
			{Port: 443, Proto: "tcp", State: "open", Name: "https", TLS: &model.TLSInfo{SelfSigned: true}},
			{Port: 8080, Proto: "tcp", State: "open", Name: "http"},
			{Port: 9999, Proto: "tcp", State: "closed", Name: "x"},
		}},
		{IP: "10.0.0.7", Up: true, Services: []model.ServiceResult{{Port: 80, Proto: "tcp", State: "open"}}},
		{IP: "10.0.0.8", Up: false},
		{IP: "10.0.0.9", Up: true, ObservedAt: time.Unix(1010, 0)},
		{IP: "10.0.0.254", Up: true},
	}
}

func metric(r *Report, name string) Metric {
	for _, m := range r.Metrics {
		if m.Name == name {
			return m
		}
	}
	panic("no metric " + name)
}

func accuracy(r *Report, prefix string) Accuracy {
	for _, a := range r.Accuracies {
		if strings.HasPrefix(a.Name, prefix) {
			return a
		}
	}
	panic("no accuracy " + prefix)
}

func TestScore(t *testing.T) {
	r := Score(sampleTruth(), sampleExport(), Options{MinConfidence: 0.5})
	if m := metric(r, "hosts"); m.TP != 2 || m.FN != 1 || m.FP != 1 || m.Extra[0] != "10.0.0.7" || !strings.Contains(m.Missed[0], "stealth-firewall") {
		t.Errorf("hosts: %+v", m)
	}
	// ports: 80, 3306, 443 found; 22 missed; 161/udp is a hard case; 8080 and the port on the unknown host are extra.
	if m := metric(r, "ports"); m.TP != 3 || m.FN != 1 || m.FP != 2 {
		t.Errorf("ports: %+v", m)
	}
	if len(r.HardMisses) != 1 || !strings.Contains(r.HardMisses[0], "161/udp") {
		t.Errorf("hard misses: %v", r.HardMisses)
	}
	// names: http-alt and https are right, postgresql is wrong, ssh is missed.
	if m := metric(r, "service names"); m.TP != 2 || m.FN != 2 || m.FP != 1 {
		t.Errorf("names: %+v", m)
	}
	// technologies: WordPress found, PHP missed, Drupal extra; jQuery optional, cookie finding and low confidence ignored.
	if m := metric(r, "technologies"); m.TP != 1 || m.FN != 1 || m.FP != 1 || !strings.Contains(m.Extra[0], "Drupal") {
		t.Errorf("technologies: %+v", m)
	}
	// classes: login found, remote-access missed (port missed), iot extra, admin-panel optional.
	if m := metric(r, "classes"); m.TP != 1 || m.FN != 1 || m.FP != 1 {
		t.Errorf("classes: %+v", m)
	}
	if m := metric(r, "hosts"); m.Precision < 0.66 || m.Precision > 0.67 || m.Recall < 0.66 || m.F1 < 0.66 {
		t.Errorf("host rates: %+v", m)
	}
	for prefix, want := range map[string][2]int{
		"service versions": {1, 1}, "technology versions": {1, 1}, "page titles": {1, 1}, "interesting headers and cookies: collected": {2, 2},
		"interesting headers and cookies: flagged": {1, 2}, "cookie flags": {1, 1}, "TLS": {1, 1}, "favicon": {1, 1}, "custom signatures": {1, 1},
	} {
		if a := accuracy(r, prefix); a.Right != want[0] || a.Total != want[1] {
			t.Errorf("%s: %d/%d, want %d/%d (%v)", prefix, a.Right, a.Total, want[0], want[1], a.Wrong)
		}
	}
	if len(r.Unstable) != 1 || !r.Unstable[0].SeenUp || r.Unstable[0].ExpectedUp == nil || !*r.Unstable[0].ExpectedUp {
		t.Errorf("unstable: %+v", r.Unstable)
	}
	strict := Score(sampleTruth(), sampleExport(), Options{Strict: true})
	if m := metric(strict, "ports"); m.FN != 2 {
		t.Errorf("strict mode must count the hard case: %+v", m)
	}
	var buf bytes.Buffer
	printReport(&buf, r, 2)
	for _, want := range []string{"precision", "HARD CASES", "UNSTABLE HOSTS", "10.0.0.7"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report misses %q", want)
		}
	}
}

func TestPerfectExportScoresOne(t *testing.T) {
	tr := sampleTruth()
	var export []model.HostResult
	for _, h := range tr.Hosts {
		e := model.HostResult{IP: h.IP, Up: true}
		for _, s := range h.Services {
			es := model.ServiceResult{Port: s.Port, Proto: s.Proto, State: "open", Name: s.Name, Version: s.Version, Classes: s.Classes}
			for _, tt := range s.Technologies {
				es.Technologies = append(es.Technologies, model.Technology{Name: tt.Name, Version: tt.Version})
			}
			e.Services = append(e.Services, es)
		}
		export = append(export, e)
	}
	r := Score(tr, export, Options{Strict: true})
	for _, m := range r.Metrics {
		if m.F1 != 1 {
			t.Errorf("%s: F1 = %v, want 1 (%v %v)", m.Name, m.F1, m.Missed, m.Extra)
		}
	}
}

func TestHelpers(t *testing.T) {
	for _, c := range []struct {
		want, got string
		ok        bool
	}{
		{"6.9.4", "6.9.4", true}, {"6.9.4", "6.9", true}, {"10", "10.6.22", true}, {"6.9.4", "6.8.1", false}, {"1.2", "1.20", false},
		{"7.9", "7.9p1", true}, {"", "anything", true}, {"1.0", "", false},
	} {
		if versionMatch(c.want, c.got) != c.ok {
			t.Errorf("versionMatch(%q, %q) != %v", c.want, c.got, c.ok)
		}
	}
	svc := truth.Service{Name: "mqtt", NameAlt: []string{"mosquitto*"}}
	if !serviceNameOK(svc, "mosquitto version 2.0.23") || !serviceNameOK(svc, "MQTT") || serviceNameOK(svc, "http") || serviceNameOK(svc, "") {
		t.Error("serviceNameOK is wrong")
	}
	if !serviceNameOK(truth.Service{Name: "http"}, "ssl/https?") || !serviceNameOK(truth.Service{Name: "unknown", NameAlt: []string{"*"}}, "tcpwrapped") {
		t.Error("service name families are wrong")
	}
	if norm("Apache HTTP-Server 2") != "apachehttpserver2" || normTitle(" A&nbsp;&amp;  B\u00a0C ") != "A & B C" {
		t.Error("normalisation is wrong")
	}
}

func TestCompareChanges(t *testing.T) {
	before := &truth.File{State: "t0", Ignore: []string{"10.0.0.254"}, Hosts: []truth.Host{
		{IP: "10.0.0.1", Services: []truth.Service{{Port: 80, Proto: "tcp", Name: "http", Version: "1.24.0", Technologies: []truth.Tech{{Name: "nginx", Version: "1.24.0", Aliases: []string{"nginx httpd"}}},
			HTTP: &truth.HTTP{Title: "Old", Server: "nginx/1.24.0", Headers: map[string]string{"X-Request-Id": ""}}}}},
		{IP: "10.0.0.2", Services: []truth.Service{{Port: 21, Proto: "tcp", Name: "ftp"}}},
		{IP: "10.0.0.9", Availability: &labcfg.Avail{Kind: "flap"}},
	}}
	after := &truth.File{State: "t1", Ignore: []string{"10.0.0.254"}, Hosts: []truth.Host{
		{IP: "10.0.0.1", Services: []truth.Service{{Port: 80, Proto: "tcp", Name: "http", Version: "1.30.7", Classes: []string{"login"}, Technologies: []truth.Tech{{Name: "nginx", Version: "1.30.7", Aliases: []string{"nginx httpd"}}},
			HTTP: &truth.HTTP{Title: "New", Server: "nginx/1.30.7", Headers: map[string]string{"X-Request-Id": ""}}}}},
		{IP: "10.0.0.3", Services: []truth.Service{{Port: 80, Proto: "tcp", Name: "http"}}},
		{IP: "10.0.0.9", Availability: &labcfg.Avail{Kind: "flap"}},
	}}
	cf := &truth.ChangeFile{From: "t0", To: "t1", Changes: truth.Diff(before, after)}
	web := func(version, title, reqID string) model.ServiceResult {
		return model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Version: version,
			HTTP: &model.HTTPFingerprint{Title: title, Headers: map[string][]string{"Server": {"nginx/" + version}, "Date": {reqID}, "X-Request-Id": {reqID}}}}
	}
	from := []model.HostResult{
		{IP: "10.0.0.1", Up: true, Services: []model.ServiceResult{web("1.24.0", "Old", "a")}},
		{IP: "10.0.0.2", Up: true, Services: []model.ServiceResult{{Port: 21, Proto: "tcp", State: "open"}}},
		{IP: "10.0.0.9", Up: true}, {IP: "10.0.0.254", Up: true},
	}
	to := []model.HostResult{
		{IP: "10.0.0.1", Up: true, Services: []model.ServiceResult{web("1.30.7", "New", "b")}},
		{IP: "10.0.0.3", Up: true, Services: []model.ServiceResult{{Port: 80, Proto: "tcp", State: "open"}}},
	}
	r := CompareChanges(cf, before, after, from, to)
	// host_new, host_gone, version, title, Server header are seen. The exports hold no technologies and no classes.
	if r.Metric.TP != 5 || r.Metric.FP != 0 || r.Metric.FN != 0 || len(r.NotChecked) != 2 {
		t.Fatalf("changes: %+v\nnot checked: %v", r.Metric, r.NotChecked)
	}
	// An unexpected change is reported; a missed one too.
	to[0].Services = append(to[0].Services, model.ServiceResult{Port: 8443, Proto: "tcp", State: "open"})
	to[0].Services[0].HTTP.Title = "Old"
	r = CompareChanges(cf, before, after, from, to)
	if r.Metric.FP != 1 || r.Metric.FN != 1 || !strings.Contains(r.Metric.Extra[0], "service_new 10.0.0.1:8443") || !strings.Contains(r.Metric.Missed[0], "title_changed") {
		t.Fatalf("changes: %+v", r.Metric)
	}
	// With technology data in the exports the technology change is checked, by alias.
	from[0].Services[0].Technologies = []model.Technology{{Name: "nginx httpd", Version: "1.24.0"}}
	to[0].Services[0].Technologies = []model.Technology{{Name: "nginx httpd", Version: "1.30.7"}}
	r = CompareChanges(cf, before, after, from, to)
	found := false
	for _, m := range r.Matched {
		if strings.HasPrefix(m, "tech_version 10.0.0.1:80") {
			found = true
		}
	}
	if !found {
		t.Fatalf("technology version change not matched: %v", r.Matched)
	}
	var buf bytes.Buffer
	printChangeReport(&buf, r, 0)
	if !strings.Contains(buf.String(), "observed, not expected") {
		t.Error("change report misses the unexpected list")
	}
}
