package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestServerMovesBetweenStates(t *testing.T) {
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	site := func(title string) *labcfg.Site {
		return &labcfg.Site{Server: "lab/1.0", FaviconSeed: "x",
			Headers: []labcfg.Header{{Name: "X-Env", Value: "test"}},
			Cookies: []labcfg.Cookie{{Name: "sid", Value: "1", HTTPOnly: true}},
			Routes: []labcfg.Route{
				{Path: "/", Body: "<title>" + title + "</title>"},
				{Path: "/go", Location: "/", Status: 301},
				{Path: "/v", Volatile: true, Body: "n={{COUNTER}} r={{RAND}}"},
				{Path: "/secret", BasicRealm: "TEST"},
			}}
	}
	tl := &labcfg.TLS{Mode: "selfsigned", CN: "a.test", SANs: []string{"a.test", "127.0.0.1"}, NotBeforeDays: -1, NotAfterDays: 10}
	tl2 := *tl
	tl2.Gen = 1
	host := &labcfg.Host{Name: "t", States: map[string]labcfg.HostState{
		"t0": {Listeners: []labcfg.Listener{{Port: p1, Kind: "http", Site: site("zero")}, {Port: p2, Kind: "http", Site: site("old port")}, {Port: p3, Kind: "http", TLS: tl, Site: site("tls")}}},
		"t1": {Listeners: []labcfg.Listener{{Port: p1, Kind: "http", Site: site("one")}, {Port: p3, Kind: "http", TLS: &tl2, Site: site("tls")}}},
	}}
	srv := newServer(host)
	if err := srv.apply("t0"); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	base := fmt.Sprintf("http://127.0.0.1:%d", p1)

	resp, body := get(t, c, base+"/")
	if !strings.Contains(body, "zero") || resp.Header.Get("Server") != "lab/1.0" || resp.Header.Get("X-Env") != "test" {
		t.Fatalf("unexpected page: %q %v", body, resp.Header)
	}
	if ck := resp.Header.Get("Set-Cookie"); !strings.Contains(ck, "sid=1") || !strings.Contains(ck, "HttpOnly") {
		t.Fatalf("cookie = %q", ck)
	}
	if resp, _ := get(t, c, base+"/go"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/" {
		t.Fatalf("redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := get(t, c, base+"/secret"); resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "TEST") {
		t.Fatalf("basic auth = %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, base+"/nothing"); resp.StatusCode != 404 {
		t.Fatalf("unknown path = %d", resp.StatusCode)
	}
	_, v1 := get(t, c, base+"/v")
	_, v2 := get(t, c, base+"/v")
	if v1 == v2 {
		t.Fatal("volatile body did not change")
	}
	if resp, icon := get(t, c, base+"/favicon.ico"); resp.StatusCode != 200 || icon != string(labcfg.Favicon("x")) {
		t.Fatal("favicon is wrong")
	}
	post, err := c.Post(base+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", post.StatusCode)
	}
	head, err := c.Head(base + "/")
	if err != nil || head.StatusCode != 200 {
		t.Fatalf("HEAD failed: %v", err)
	}
	head.Body.Close()

	certOf := func() *x509.Certificate {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p3), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}
	before := certOf()

	if err := srv.apply("t1"); err != nil {
		t.Fatal(err)
	}
	if _, body := get(t, c, base+"/"); !strings.Contains(body, "one") {
		t.Fatalf("content did not change: %q", body)
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p2), time.Second); err == nil {
		conn.Close()
		t.Fatal("the port that t1 does not have is still open")
	}
	if after := certOf(); after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("the certificate was not renewed")
	}
	if err := srv.apply("nope"); err == nil {
		t.Fatal("an unknown state must be an error")
	}
	if err := srv.apply("t0"); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p2), time.Second); err != nil {
		t.Fatal("the port did not come back in t0")
	} else {
		conn.Close()
	}
}

func TestMakeCert(t *testing.T) {
	now := time.Now()
	parse := func(spec *labcfg.TLS) (*x509.Certificate, int) {
		c, err := makeCert(spec, now)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf, len(c.Certificate)
	}
	ss, n := parse(&labcfg.TLS{Mode: "selfsigned", CN: "s.test", SANs: []string{"s.test", "10.0.0.1"}, NotBeforeDays: -1, NotAfterDays: 5})
	if n != 1 || ss.Issuer.CommonName != "s.test" || len(ss.IPAddresses) != 1 || ss.DNSNames[0] != "s.test" {
		t.Fatalf("self-signed certificate is wrong: %v", ss.Subject)
	}
	exp, n := parse(&labcfg.TLS{Mode: "ca", CN: "e.test", NotBeforeDays: -400, NotAfterDays: -35, Key: "rsa2048"})
	if n != 2 || !exp.NotAfter.Before(now) || exp.Issuer.CommonName != "Czujka Lab Issuing CA" || exp.Issuer.CommonName == exp.Subject.CommonName {
		t.Fatalf("expired CA-signed certificate is wrong: issuer %q notAfter %v", exp.Issuer.CommonName, exp.NotAfter)
	}
	if _, err := makeCert(&labcfg.TLS{Mode: "other"}, now); err == nil {
		t.Fatal("unknown mode must fail")
	}
}

func TestFirewallRules(t *testing.T) {
	if firewallRules(nil) != nil {
		t.Fatal("no firewall, no rules")
	}
	icmp := firewallRules(&labcfg.Firewall{DropICMP: true})
	if len(icmp) != 1 || strings.Join(icmp[0], " ") != "-A INPUT -p icmp -j DROP" {
		t.Fatalf("icmp rules: %v", icmp)
	}
	st := firewallRules(&labcfg.Firewall{StealthExcept: []int{8888, 31337}})
	if len(st) != 3 || !strings.Contains(strings.Join(st[1], " "), "--dports 8888,31337 -j ACCEPT") || strings.Join(st[2], " ") != "-A INPUT -j DROP" {
		t.Fatalf("stealth rules: %v", st)
	}
}

func TestSmallHelpers(t *testing.T) {
	if gw := parseDefaultGateway("default via 10.66.0.1 dev eth0 \n"); gw != "10.66.0.1" {
		t.Fatalf("gateway = %q", gw)
	}
	if parseDefaultGateway("") != "" {
		t.Fatal("no route, no gateway")
	}
	dir := t.TempDir()
	if readState(filepath.Join(dir, "missing")) != "t0" {
		t.Fatal("a missing state file means t0")
	}
	p := filepath.Join(dir, "current")
	os.WriteFile(p, []byte(" t2\n"), 0o644)
	if readState(p) != "t2" {
		t.Fatal("state file not read")
	}
	if got := cookieHeader(labcfg.Cookie{Name: "a", Value: "b", Secure: true, SameSite: "Lax"}); got != "a=b; Path=/; Secure; SameSite=Lax" {
		t.Fatalf("cookie header = %q", got)
	}
	if renderBody("plain", 1, time.Now()) != "plain" || renderBody("{{COUNTER}}", 7, time.Now()) != "7" {
		t.Fatal("renderBody is wrong")
	}
}

func TestEmbeddedHostConfigsLoad(t *testing.T) {
	entries, err := hostFS.ReadDir("hosts")
	if err != nil || len(entries) < 20 {
		t.Fatalf("embedded host configs: %d, %v", len(entries), err)
	}
	for _, e := range entries {
		h, err := loadHost(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range labcfg.States {
			if _, ok := h.States[st]; !ok {
				t.Errorf("%s has no state %s", h.Name, st)
			}
		}
	}
	if _, err := loadHost("no-such-host"); err == nil {
		t.Fatal("unknown host must fail")
	}
}
