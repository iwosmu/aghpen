package truth

import (
	"testing"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

func keys(cs []Change) map[string]bool {
	m := map[string]bool{}
	for _, c := range cs {
		m[c.Key()] = true
	}
	return m
}

func TestDiff(t *testing.T) {
	a := &File{State: "t0", Hosts: []Host{
		{IP: "10.0.0.1", Name: "stays", Services: []Service{
			{Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.24.0",
				Technologies: []Tech{{Name: "nginx", Version: "1.24.0"}},
				HTTP: &HTTP{Status: 200, Title: "Old", Server: "nginx/1.24.0", Headers: map[string]string{"X-A": "1"},
					Cookies: []Cookie{{Name: "sid"}}}},
			{Port: 8000, Proto: "tcp", Name: "http"},
			{Port: 443, Proto: "tcp", Name: "http", TLS: &TLS{SubjectCN: "a", Gen: 0}},
		}},
		{IP: "10.0.0.2", Name: "goes"},
		{IP: "10.0.0.9", Name: "flapper", Availability: &labcfg.Avail{Kind: "flap"}},
	}}
	b := &File{State: "t1", Hosts: []Host{
		{IP: "10.0.0.1", Name: "stays", Services: []Service{
			{Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.30.7", Classes: []string{"login"},
				Technologies: []Tech{{Name: "nginx", Version: "1.30.7"}, {Name: "PHP"}},
				HTTP: &HTTP{Status: 200, Title: "New", Server: "nginx/1.30.7", Headers: map[string]string{"X-A": "1", "X-B": "2"},
					Cookies: []Cookie{{Name: "sid", HTTPOnly: true}}}},
			{Port: 8081, Proto: "tcp", Name: "http"},
			{Port: 443, Proto: "tcp", Name: "http", TLS: &TLS{SubjectCN: "a", Gen: 1}},
		}},
		{IP: "10.0.0.3", Name: "comes"},
	}}
	got := keys(Diff(a, b))
	want := []string{
		"host_new|10.0.0.3|0|", "host_gone|10.0.0.2|0|",
		"service_new|10.0.0.1|8081|", "service_gone|10.0.0.1|8000|",
		"service_changed|10.0.0.1|80|version", "tech_version|10.0.0.1|80|tech:nginx", "tech_new|10.0.0.1|80|tech:PHP",
		"class_changed|10.0.0.1|80|classes", "title_changed|10.0.0.1|80|title",
		"headers_changed|10.0.0.1|80|header:Server", "headers_changed|10.0.0.1|80|header:X-B",
		"cookies_changed|10.0.0.1|80|cookie:sid", "cert_changed|10.0.0.1|443|certificate",
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("missing change %s", k)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d changes, want %d: %v", len(got), len(want), got)
	}
	if got["host_gone|10.0.0.9|0|"] {
		t.Error("an unstable host must not appear in the expected changes")
	}
	if len(Diff(a, a)) != 0 {
		t.Error("a state compared with itself must give no changes")
	}
}

func TestCookieFlags(t *testing.T) {
	if CookieFlags(false, true, true) != "" || CookieFlags(true, false, false) != "set" || CookieFlags(true, true, true) != "set Secure HttpOnly" {
		t.Fatal("unexpected cookie flag text")
	}
}
