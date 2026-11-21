package nmapconv

import (
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

const sample = `<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1795262400">
<host starttime="1795262400" endtime="1795262460"><status state="up" reason="arp-response"/>
<address addr="10.66.50.11" addrtype="ipv4"/><address addr="02:42:0A:42:32:0B" addrtype="mac" vendor="Lab"/>
<hostnames><hostname name="selfsigned.lab.czujka.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx</cpe></service>
<script id="http-title" output="Archiwum dokument\xC3\xB3w"><elem key="title">Archiwum dokument\xC3\xB3w</elem></script>
<script id="http-server-header" output="nginx"><elem>nginx</elem></script>
<script id="http-headers" output="&#xa;  Server: nginx&#xa;  x-powered-by: PHP/8.2.1&#xa;  Set-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax&#xa;  Set-Cookie: lang=pl; Path=/&#xa;  &#xa;  (Request type: GET)&#xa;"/>
<script id="ssl-cert" output="...">
<table key="subject"><elem key="commonName">selfsigned.lab.czujka.test</elem></table>
<table key="issuer"><elem key="commonName">selfsigned.lab.czujka.test</elem></table>
<table key="pubkey"><elem key="type">ec</elem><elem key="bits">256</elem></table>
<table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem><elem key="value">DNS:selfsigned.lab.czujka.test, IP Address:10.66.50.11</elem></table></table>
<table key="validity"><elem key="notBefore">2026-08-01T00:00:00</elem><elem key="notAfter">2026-10-01T00:00:00</elem></table>
</script>
</port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/><service name="http" method="table" conf="3"/></port>
</ports><times srtt="120" rttvar="50" to="100000"/></host>
<host><status state="down" reason="no-response"/><address addr="10.66.50.99" addrtype="ipv4"/></host>
</nmaprun>`

func TestParse(t *testing.T) {
	hosts, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || !hosts[0].Up || hosts[1].Up {
		t.Fatalf("hosts: %+v", hosts)
	}
	h := hosts[0]
	if h.IP != "10.66.50.11" || h.MAC == "" || h.Reason != "arp-response" || h.Hostnames[0] != "selfsigned.lab.czujka.test" || h.RTTMs != 0.12 {
		t.Fatalf("host fields: %+v", h)
	}
	if h.ObservedAt.Unix() != 1795262460 {
		t.Fatalf("observed at %v", h.ObservedAt)
	}
	s := h.Services[0]
	if s.Port != 443 || s.State != "open" || s.Name != "http" || s.Tunnel != "ssl" || s.Product != "nginx" || s.Confidence != 1 || len(s.CPE) != 1 {
		t.Fatalf("service: %+v", s)
	}
	if s.HTTP == nil || s.HTTP.Title != "Archiwum dokumentów" || s.HTTP.Server != "nginx" || s.HTTP.PoweredBy != "PHP/8.2.1" || s.HTTP.Scheme != "https" {
		t.Fatalf("http: %+v", s.HTTP)
	}
	if len(s.HTTP.Cookies) != 2 || !s.HTTP.Cookies[0].Secure || !s.HTTP.Cookies[0].HTTPOnly || s.HTTP.Cookies[0].SameSite != "lax" || s.HTTP.Cookies[1].Secure {
		t.Fatalf("cookies: %+v", s.HTTP.Cookies)
	}
	if s.HTTP.Cookies[0].ValueLen != 6 || s.HTTP.Cookies[0].Value != "" {
		t.Fatal("the raw cookie value must not be kept; only its length and hash")
	}
	if s.TLS == nil || !s.TLS.SelfSigned || !s.TLS.Expired || s.TLS.HostMismatch || s.TLS.SubjectCN != "selfsigned.lab.czujka.test" || len(s.TLS.SANs) != 2 || s.TLS.KeyBits != 256 {
		t.Fatalf("tls: %+v", s.TLS)
	}
	if h.Services[1].State != "closed" {
		t.Fatal("the closed port must keep its state")
	}
	if _, err := Parse(strings.NewReader("<nmaprun")); err == nil {
		t.Fatal("broken XML must fail")
	}
}

func TestUnescapeAndCookie(t *testing.T) {
	if got := Unescape(`Wydzia\xC5\x82 \x zz`); got != "Wydział \\x zz" {
		t.Fatalf("Unescape = %q", got)
	}
	if _, ok := ParseCookie("novalue"); ok {
		t.Fatal("a cookie without = is not a cookie")
	}
	c, ok := ParseCookie("a=b; Domain=x.test; Path=/p; secure")
	if !ok || c.Name != "a" || c.Domain != "x.test" || c.Path != "/p" || !c.Secure || c.HTTPOnly {
		t.Fatalf("cookie: %+v", c)
	}
}

func TestCovers(t *testing.T) {
	tl := &model.TLSInfo{SANs: []string{"*.lab.test", "10.0.0.1"}}
	if !covers(tl, []string{"a.lab.test"}) || !covers(tl, []string{"10.0.0.1"}) || covers(tl, []string{"lab.test", "10.0.0.2"}) {
		t.Fatal("wildcard or IP matching is wrong")
	}
	if !covers(&model.TLSInfo{SubjectCN: "x.test"}, []string{"x.test"}) {
		t.Fatal("the CN is used when there are no SANs")
	}
}

func TestMerge(t *testing.T) {
	sweep := []model.HostResult{{IP: "10.0.0.1", Up: true, Reason: "arp-response"}, {IP: "10.0.0.2", Up: true}}
	tcp := []model.HostResult{{IP: "10.0.0.1", Up: true, Services: []model.ServiceResult{{Port: 80, Proto: "tcp", State: "open", Name: "http"}}}}
	udp := []model.HostResult{{IP: "10.0.0.1", Up: true, Services: []model.ServiceResult{{Port: 53, Proto: "udp", State: "open", Name: "domain"}, {Port: 80, Proto: "tcp", State: "open", Name: "http-alt"}}},
		{IP: "10.0.0.3", Up: false}}
	got := Merge(sweep, tcp, udp)
	if len(got) != 3 || got[0].IP != "10.0.0.1" || len(got[0].Services) != 2 || got[0].Services[0].Port != 53 || got[0].Services[1].Name != "http-alt" {
		t.Fatalf("merge: %+v", got)
	}
	if got[2].Up {
		t.Fatal("a host that no scan saw up must stay down")
	}
}
