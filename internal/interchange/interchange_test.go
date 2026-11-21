package interchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

var fixedNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// signature is what a round trip must keep: hosts, ports, products, versions.
func signature(hosts []model.HostResult) []string {
	var out []string
	for _, h := range hosts {
		if len(h.Services) == 0 {
			out = append(out, fmt.Sprintf("%s up=%v", h.IP, h.Up))
		}
		for _, s := range h.Services {
			out = append(out, fmt.Sprintf("%s up=%v %d/%s %s name=%s product=%q version=%q", h.IP, h.Up, s.Port, s.Proto, s.State, s.Name, s.Product, s.Version))
		}
	}
	sort.Strings(out)
	return out
}

func mustImport(t *testing.T, data []byte, opts Options) ([]model.HostResult, model.ImportReport) {
	t.Helper()
	if opts.Now.IsZero() {
		opts.Now = fixedNow
	}
	hosts, rep, err := Import(bytes.NewReader(data), opts)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return hosts, rep
}

func TestDetect(t *testing.T) {
	cases := map[string]string{
		"<?xml version=\"1.0\"?><nmaprun>":  FormatNmapXML,
		"\xef\xbb\xbf  \n{\"hosts\":[]}":    FormatJSON,
		"[ {\"ip\":\"10.0.0.1\"} ]":         FormatJSON,
		"ip,port,service\n10.0.0.1,80,http": FormatCSV,
		"   ":                               "",
	}
	for in, want := range cases {
		if got := Detect([]byte(in)); got != want {
			t.Errorf("Detect(%q) = %q, want %q", in, got, want)
		}
	}
}

// Real output of "nmap -sV -Pn --script http-title,banner -p 18181,18182,16379,18999 -oX - 127.0.0.1"
// against three local docker containers (nginx, Apache httpd, Redis).
func TestImportRealNmapXMLLocal(t *testing.T) {
	data, err := os.ReadFile("testdata/nmap-local.xml")
	if err != nil {
		t.Fatal(err)
	}
	hosts, rep := mustImport(t, data, Options{RunID: 12})
	if rep.Format != FormatNmapXML || rep.Hosts != 1 || rep.Services != 4 || len(rep.Invalid) != 0 || rep.RunID == nil || *rep.RunID != 12 {
		t.Fatalf("report = %+v", rep)
	}
	h := hosts[0]
	if h.IP != "127.0.0.1" || !h.Up || h.RunID != 12 || h.ObservedAt.IsZero() || h.ObservedAt.Year() != 2026 {
		t.Fatalf("host = %+v", h)
	}
	by := map[int]model.ServiceResult{}
	for _, s := range h.Services {
		by[s.Port] = s
	}
	ngx := by[18181]
	if ngx.State != "open" || ngx.Name != "http" || ngx.Product != "nginx" || ngx.Version == "" || ngx.Confidence != 1 {
		t.Errorf("nginx = %+v", ngx)
	}
	if ngx.HTTP == nil || ngx.HTTP.Title != "Welcome to nginx!" || !strings.HasPrefix(ngx.HTTP.Server, "nginx/") {
		t.Errorf("nginx http = %+v", ngx.HTTP)
	}
	if len(ngx.CPE) == 0 || !strings.HasPrefix(ngx.CPE[0], "cpe:/a:") || len(ngx.Technologies) != 1 || ngx.Technologies[0].Name != "nginx" {
		t.Errorf("nginx cpe/tech = %v %v", ngx.CPE, ngx.Technologies)
	}
	if len(ngx.Scripts) < 2 {
		t.Errorf("nginx scripts = %v", ngx.Scripts)
	}
	if ap := by[18182]; ap.Product != "Apache httpd" || !strings.HasPrefix(ap.Version, "2.") || ap.ExtraInfo == "" {
		t.Errorf("apache = %+v", ap)
	}
	if rd := by[16379]; rd.Name != "redis" || rd.Product != "Redis key-value store" || rd.Version == "" {
		t.Errorf("redis = %+v", rd)
	}
	if cl := by[18999]; cl.State != "closed" {
		t.Errorf("closed port = %+v", cl)
	}
}

// Real output of nmap run inside a private docker network against four addresses.
func TestImportRealNmapXMLNetwork(t *testing.T) {
	data, err := os.ReadFile("testdata/nmap-net.xml")
	if err != nil {
		t.Fatal(err)
	}
	hosts, rep := mustImport(t, data, Options{})
	if rep.Hosts != 4 || len(hosts) != 4 || rep.Services != 12 {
		t.Fatalf("report = %+v", rep)
	}
	products := map[string]string{}
	for _, h := range hosts {
		if h.Reason != "localhost-response" && (h.MAC == "" || h.RTTMs <= 0) { // .5 is the scanner itself
			t.Errorf("host %s: mac=%q rtt=%v reason=%s", h.IP, h.MAC, h.RTTMs, h.Reason)
		}
		for _, s := range h.Services {
			if s.State == "open" && s.Product != "" {
				products[h.IP] = s.Product
			}
		}
	}
	want := map[string]string{"172.31.250.2": "nginx", "172.31.250.3": "Apache httpd", "172.31.250.4": "Redis key-value store"}
	if !reflect.DeepEqual(products, want) {
		t.Errorf("products = %v, want %v", products, want)
	}
}

// The round trip the jury will test: real nmap XML -> import -> export as
// XML, JSON and CSV -> import again. Hosts, ports, products and versions stay.
func TestRoundTripRealNmap(t *testing.T) {
	for _, file := range []string{"testdata/nmap-local.xml", "testdata/nmap-net.xml"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		orig, _ := mustImport(t, data, Options{})
		want := signature(orig)
		for _, format := range []string{FormatNmapXML, FormatJSON, FormatCSV} {
			t.Run(file+" via "+format, func(t *testing.T) {
				var buf bytes.Buffer
				if err := Export(&buf, format, orig, Meta{GeneratedAt: fixedNow, RunID: 3}); err != nil {
					t.Fatalf("export: %v", err)
				}
				if got := Detect(buf.Bytes()); got != format {
					t.Fatalf("exported %s is detected as %q", format, got)
				}
				back, rep := mustImport(t, buf.Bytes(), Options{})
				if len(rep.Invalid) != 0 {
					t.Fatalf("invalid rows after round trip: %+v", rep.Invalid)
				}
				got := signature(back)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("round trip changed the data\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
				}
				t.Logf("%s -> %s -> import: %d hosts, %d services kept", file, format, rep.Hosts, rep.Services)
				// Titles survive in every format.
				for i, h := range orig {
					for j, s := range h.Services {
						if s.HTTP != nil && s.HTTP.Title != "" {
							b := back[i].Services[j]
							if b.HTTP == nil || b.HTTP.Title != s.HTTP.Title {
								t.Errorf("%s:%d title lost in %s", h.IP, s.Port, format)
							}
						}
					}
				}
			})
		}
	}
}

func fullHost() model.HostResult {
	fav := int32(-123456)
	return model.HostResult{
		RunID: 7, IP: "10.66.3.17", Hostnames: []string{"ci.example", "jenkins.example"}, Up: true, Reason: "syn-ack", RTTMs: 1.25,
		Attempts: 2, MAC: "02:42:AC:11:00:02", Vendor: "ACME", OSGuess: "Linux 6.x", ObservedAt: fixedNow,
		Scripts: []model.ScriptResult{{ID: "smb-os-discovery", Output: "OS: Linux"}},
		Services: []model.ServiceResult{{
			Port: 8443, Proto: "tcp", State: "open", Name: "http", Product: "Jetty", Version: "10.0.18", ExtraInfo: "x",
			CPE: []string{"cpe:/a:eclipse:jetty:10.0.18"}, Banner: "HTTP/1.1 200 OK", Tunnel: "ssl", Confidence: 0.9,
			HTTP: &model.HTTPFingerprint{
				Scheme: "https", URL: "https://10.66.3.17:8443/", FinalURL: "https://10.66.3.17:8443/login", Host: "10.66.3.17", Status: 200,
				Title: "Dashboard [Jenkins] – „zażółć”", Headers: map[string][]string{"X-Jenkins": {"2.440"}, "Server": {"Jetty(10.0.18)"}},
				Cookies:   []model.Cookie{{Name: "JSESSIONID.abc", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", ValueLen: 32, ValueHash: "ab12"}},
				Redirects: []model.Redirect{{From: "https://10.66.3.17:8443/", To: "https://10.66.3.17:8443/login", Status: 302}},
				Server:    "Jetty(10.0.18)", BodyLength: 4321, BodySHA256: "deadbeef", BodySimhash: "a1b2c3d4e5f60718", BodyExcerpt: "<html>",
				FaviconMMH3: &fav, FaviconSHA256: "cafe", ResponseMs: 42,
				Paths: []model.PathProbe{{Path: "/login", Status: 200, Title: "Sign in", Length: 100, Headers: map[string][]string{"A": {"b"}}}},
			},
			TLS: &model.TLSInfo{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", SubjectCN: "ci.example", SANs: []string{"ci.example"},
				Issuer: "ci.example", NotBefore: fixedNow.Add(-time.Hour), NotAfter: fixedNow.Add(240 * time.Hour), Serial: "01", SHA256: "ffee",
				SelfSigned: true, DaysLeft: 10, KeyType: "RSA", KeyBits: 2048},
			Matches: []model.SigMatch{{Signature: "jenkins", Name: "Jenkins", Category: model.CatDevOps, Version: "2.440", Confidence: 0.94, Interest: 30,
				Classes: []string{model.ClassDevTool}, Tags: []string{"ci"}, Evidence: []model.Evidence{{Matcher: "header", Where: "header:X-Jenkins", Snippet: "2.440"}}}},
			Technologies: []model.Technology{{Name: "Jenkins", Category: model.CatDevOps, Version: "2.440", Confidence: 0.94, Sources: []string{"jenkins"}, CPE: "cpe:/a:jenkins:jenkins:2.440"}},
			Classes:      []string{model.ClassDevTool, model.ClassLogin},
			Scripts:      []model.ScriptResult{{ID: "http-title", Output: "Dashboard [Jenkins]"}},
		}, {Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", CPE: []string{}, Matches: []model.SigMatch{}, Technologies: []model.Technology{}, Classes: []string{}}},
	}
}

func TestJSONRoundTripIsLossless(t *testing.T) {
	in := []model.HostResult{fullHost(), {RunID: 7, IP: "10.66.3.18", Up: true, Reason: "echo-reply", Attempts: 1, ObservedAt: fixedNow, Hostnames: []string{}, Services: []model.ServiceResult{}}}
	var buf bytes.Buffer
	if err := Export(&buf, FormatJSON, in, Meta{GeneratedAt: fixedNow, RunID: 7}); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Format  string
		Version int
		Hosts   []json.RawMessage
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil || env.Format != FormatJSON || env.Version != JSONVersion || len(env.Hosts) != 2 {
		t.Fatalf("envelope: %v %+v", err, env)
	}
	out, rep := mustImport(t, buf.Bytes(), Options{})
	if rep.Format != FormatJSON || rep.Hosts != 2 || rep.Services != 2 || len(rep.Invalid) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	a, _ := json.Marshal(in)
	b, _ := json.Marshal(out)
	if !bytes.Equal(a, b) {
		t.Fatalf("JSON round trip is not lossless\n in: %s\nout: %s", a, b)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the structs")
	}
}

func TestImportCSVTolerantColumns(t *testing.T) {
	csv := "\xef\xbb\xbfIP Address;Host;Port;Protocol;State;Service Name;Product;Version;HTTP Title;Status Code;URL;Technologies;Timestamp;Unknown Column\r\n" +
		"10.0.0.5;web01.example;443/tcp;;;https;nginx;1.24.0;Portal;200;https://web01.example/;WordPress:6.4|PHP 8.2;2026-11-20T08:00:00Z;x\r\n" +
		"10.0.0.5;web01.example;22;TCP;open;ssh;OpenSSH;9.6;;;;;;\r\n" +
		";;;;;;;;;;;;;\r\n" +
		"10.0.0.6;;53;udp;open|filtered;domain;;;;;;;;\r\n" +
		"10.0.0.7;printer.example;;;;;;;;;;;;\r\n" +
		"not-an-ip;;80;;;;;;;;;;;\r\n" +
		"10.0.0.8;;99999;;;;;;;;;;;\r\n" +
		"10.0.0.8;;80;icmp;;;;;;;;;;\r\n" +
		"10.0.0.8;;80;tcp;weird;;;;;;;;;\r\n" +
		"10.0.0.8;;80;tcp;open;;;;;abc;;;;\r\n" +
		";only-a-name.example;80;;;;;;;;;;;\r\n"
	hosts, rep := mustImport(t, []byte(csv), Options{})
	if rep.Format != FormatCSV || rep.Hosts != 3 || rep.Services != 3 {
		t.Fatalf("report = %+v", rep)
	}
	wantInvalid := []model.InvalidLine{
		{Line: 7, Value: "not-an-ip", Reason: "niepoprawny adres IP"},
		{Line: 8, Value: "99999", Reason: "niepoprawny numer portu"},
		{Line: 9, Value: "icmp", Reason: "nieznany protokół (dozwolone: tcp, udp, sctp)"},
		{Line: 10, Value: "weird", Reason: "nieznany stan portu (dozwolone: open, closed, filtered)"},
		{Line: 11, Value: "abc", Reason: "niepoprawny kod HTTP"},
		{Line: 12, Value: "only-a-name.example", Reason: "brak adresu IP"},
	}
	if !reflect.DeepEqual(rep.Invalid, wantInvalid) {
		t.Fatalf("invalid = %+v\nwant %+v", rep.Invalid, wantInvalid)
	}
	if rep.Skipped != len(wantInvalid) {
		t.Errorf("skipped = %d", rep.Skipped)
	}
	h := hosts[0]
	if h.IP != "10.0.0.5" || !h.Up || h.Reason != "imported" || !reflect.DeepEqual(h.Hostnames, []string{"web01.example"}) || len(h.Services) != 2 {
		t.Fatalf("host = %+v", h)
	}
	if !h.ObservedAt.Equal(fixedNow) { // the newest row time wins; the ssh row has none and gets "now"
		t.Errorf("observed_at = %v", h.ObservedAt)
	}
	web := h.Services[1]
	if web.Port != 443 || web.Proto != "tcp" || web.State != "open" || web.Product != "nginx" || web.Version != "1.24.0" || web.Tunnel != "ssl" {
		t.Errorf("web = %+v", web)
	}
	if web.HTTP == nil || web.HTTP.Title != "Portal" || web.HTTP.Status != 200 || web.HTTP.Scheme != "https" || web.HTTP.Host != "web01.example" {
		t.Errorf("web http = %+v", web.HTTP)
	}
	if len(web.Technologies) != 2 || web.Technologies[0].Name != "WordPress" || web.Technologies[0].Version != "6.4" || web.Technologies[1].Name != "PHP" || web.Technologies[1].Version != "8.2" {
		t.Errorf("technologies = %+v", web.Technologies)
	}
	if hosts[1].Services[0].Proto != "udp" || hosts[1].Services[0].State != "open|filtered" {
		t.Errorf("udp = %+v", hosts[1].Services[0])
	}
	if hosts[2].IP != "10.0.0.7" || len(hosts[2].Services) != 0 || hosts[2].Hostnames[0] != "printer.example" {
		t.Errorf("host-only row = %+v", hosts[2])
	}
}

func TestImportCSVHostColumnAndStates(t *testing.T) {
	csv := "host,port,status,service\n10.1.1.1,80,up,http\n10.1.1.2,,down,\n10.1.1.3,80,404,http\n"
	hosts, rep := mustImport(t, []byte(csv), Options{})
	if rep.Hosts != 2 || rep.Skipped != 1 { // the down host is skipped by default
		t.Fatalf("report = %+v", rep)
	}
	if hosts[1].Services[0].HTTP == nil || hosts[1].Services[0].HTTP.Status != 404 {
		t.Errorf("http status = %+v", hosts[1].Services[0])
	}
	hosts, rep = mustImport(t, []byte(csv), Options{IncludeDown: true})
	if rep.Hosts != 3 || hosts[1].Up || hosts[1].Reason != "no-response" {
		t.Fatalf("with down hosts: %+v %+v", rep, hosts)
	}
	if _, _, err := Import(strings.NewReader("a,b,c\n1,2,3\n"), Options{}); err == nil || !strings.Contains(err.Error(), "kolumny z adresem") {
		t.Errorf("CSV without an address column: err = %v", err)
	}
}

func TestCSVExportGuardsFormulas(t *testing.T) {
	h := model.HostResult{IP: "10.0.0.1", Up: true, ObservedAt: fixedNow, Services: []model.ServiceResult{{
		Port: 80, Proto: "tcp", State: "open", Name: "http", Banner: "=HYPERLINK(\"http://evil\")",
		HTTP: &model.HTTPFingerprint{Title: "@SUM(1+1), \"quoted\"\nline", Status: 200},
	}}}
	var buf bytes.Buffer
	if err := Export(&buf, FormatCSV, []model.HostResult{h}, Meta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "'=HYPERLINK") || !strings.Contains(buf.String(), "'@SUM") {
		t.Errorf("formula cells are not guarded:\n%s", buf.String())
	}
	back, _ := mustImport(t, buf.Bytes(), Options{})
	s := back[0].Services[0]
	if s.Banner != h.Services[0].Banner || s.HTTP.Title != h.Services[0].HTTP.Title {
		t.Errorf("guard is not removed on import: %+v %+v", s.Banner, s.HTTP)
	}
	head := strings.SplitN(buf.String(), "\n", 2)[0]
	if !strings.HasPrefix(head, "ip,hostname,up,port,proto,state,service,product,version,") {
		t.Errorf("header = %s", head)
	}
}

func TestImportJSONVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
		bad  int
	}{
		{"bare array of host results", `[{"ip":"10.0.0.1","up":true,"services":[{"port":80,"proto":"tcp","state":"open","name":"http","product":"nginx","version":"1.24"}]}]`,
			[]string{`10.0.0.1 up=true 80/tcp open name=http product="nginx" version="1.24"`}, 0},
		{"flat records with other key names", `{"results":[{"IP Address":"10.0.0.2","Port":443,"Protocol":"TCP","Service":"https","Product":"Apache httpd","Version":"2.4.58"},{"address":"10.0.0.2","port":"22","service":"ssh"}]}`,
			[]string{`10.0.0.2 up=true 22/tcp open name=ssh product="" version=""`, `10.0.0.2 up=true 443/tcp open name=https product="Apache httpd" version="2.4.58"`}, 0},
		{"host with nested ports", `[{"ip":"10.0.0.3","hostname":"db.example","ports":[{"port":5432,"service":"postgresql","version":"16.2"},{"port":22}]},{"ip":"10.0.0.4","ports":[80,443]}]`,
			[]string{`10.0.0.3 up=true 22/tcp open name= product="" version=""`, `10.0.0.3 up=true 5432/tcp open name=postgresql product="" version="16.2"`,
				`10.0.0.4 up=true 443/tcp open name= product="" version=""`, `10.0.0.4 up=true 80/tcp open name= product="" version=""`}, 0},
		{"flat record with an up flag keeps its port", `[{"ip":"10.0.0.9","up":true,"port":8080,"service":"http"}]`,
			[]string{`10.0.0.9 up=true 8080/tcp open name=http product="" version=""`}, 0},
		{"json lines", "{\"ip\":\"10.0.0.5\",\"port\":80}\n{\"ip\":\"10.0.0.6\",\"port\":81}\n",
			[]string{`10.0.0.5 up=true 80/tcp open name= product="" version=""`, `10.0.0.6 up=true 81/tcp open name= product="" version=""`}, 0},
		{"invalid records are reported, valid ones are kept", `[{"ip":"999.1.1.1","up":true,"services":[]},{"ip":"10.0.0.7","up":true,"services":[{"port":70000}]},{"ip":"10.0.0.8","up":true,"services":[]},42,{"port":80}]`,
			[]string{"10.0.0.8 up=true"}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hosts, rep := mustImport(t, []byte(c.in), Options{})
			if got := signature(hosts); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %v\nwant %v", got, c.want)
			}
			if len(rep.Invalid) != c.bad {
				t.Errorf("invalid = %+v, want %d", rep.Invalid, c.bad)
			}
			for _, inv := range rep.Invalid {
				if inv.Reason == "" || inv.Line == 0 {
					t.Errorf("invalid row without a reason or a position: %+v", inv)
				}
			}
		})
	}
}

func TestImportErrors(t *testing.T) {
	cases := map[string]string{
		"":                            "pusty",
		"<html><body>x</body></html>": "nmap XML",
		"{\"hosts\": 5":               "JSON",
		"\"just a string\"\n1\n":      "kolumny z adresem",
	}
	for in, want := range cases {
		_, _, err := Import(strings.NewReader(in), Options{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Import(%q): err = %v, want it to contain %q", in, err, want)
		}
	}
	if _, _, err := Import(strings.NewReader("x"), Options{Format: "yaml"}); err == nil {
		t.Errorf("unknown format must fail")
	}
}

func TestNmapXMLDownHostsAndBrokenTail(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap" start="1795262000">
<host><status state="down" reason="no-response"/><address addr="10.9.9.1" addrtype="ipv4"/></host>
<host starttime="1795262001"><status state="up" reason="echo-reply"/><address addr="10.9.9.2" addrtype="ipv4"/><hostnames><hostname name="a.example" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="lighttpd" version="1.4.59" conf="10"><cpe>cpe:/a:lighttpd:lighttpd:1.4.59</cpe></service></port></ports>
<os><osmatch name="Linux 2.6" accuracy="90"/><osmatch name="Linux 5.x" accuracy="97"/></os>
<hostscript><script id="nbstat" output="NetBIOS name: A"/></hostscript></host>
<host><status state="up"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><status state="up"/><address addr="10.9.9.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state sta`
	hosts, rep := mustImport(t, []byte(xml), Options{})
	if len(hosts) != 1 || rep.Hosts != 1 || rep.Skipped != 3 || len(rep.Invalid) != 2 || rep.Invalid[0].Reason != "host bez adresu IP" {
		t.Fatalf("report = %+v hosts=%d", rep, len(hosts))
	}
	h := hosts[0]
	if h.OSGuess != "Linux 5.x" || h.Hostnames[0] != "a.example" || len(h.Scripts) != 1 || h.Scripts[0].ID != "nbstat" || h.Reason != "echo-reply" {
		t.Errorf("host = %+v", h)
	}
	if h.ObservedAt.Unix() != 1795262001 {
		t.Errorf("observed_at = %v", h.ObservedAt)
	}
	all, rep2 := mustImport(t, []byte(xml), Options{IncludeDown: true})
	if len(all) != 2 || all[0].Up || rep2.Skipped != 2 {
		t.Errorf("with down hosts: %d hosts, report %+v", len(all), rep2)
	}
}

func TestXMLExportCarriesCzujkaData(t *testing.T) {
	var buf bytes.Buffer
	if err := Export(&buf, FormatNmapXML, []model.HostResult{fullHost()}, Meta{GeneratedAt: fixedNow, RunID: 7}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`<nmaprun scanner="nmap"`, `start="1795262400"`, `<address addr="10.66.3.17" addrtype="ipv4"/>`, `<port protocol="tcp" portid="8443">`,
		`<state state="open"`, `product="Jetty" version="10.0.18"`, `tunnel="ssl"`, `<cpe>cpe:/a:eclipse:jetty:10.0.18</cpe>`,
		`<script id="czujka-technologies" output="Jenkins:2.440"/>`, `<script id="czujka-classes" output="dev-tool; login"/>`,
		`<hostscript><script id="smb-os-discovery"`, `<hosts up="1" down="0" total="1"/>`, `</nmaprun>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exported XML lacks %s", want)
		}
	}
	back, _ := mustImport(t, buf.Bytes(), Options{})
	s := back[0].Services[0]
	if len(s.Technologies) != 2 || s.Technologies[1].Name != "Jenkins" || s.Technologies[1].Version != "2.440" {
		t.Errorf("technologies after XML round trip = %+v", s.Technologies)
	}
	if !reflect.DeepEqual(s.Classes, []string{"dev-tool", "login"}) || back[0].OSGuess != "Linux 6.x" || back[0].MAC != "02:42:AC:11:00:02" {
		t.Errorf("classes/os/mac after XML round trip = %v %q %q", s.Classes, back[0].OSGuess, back[0].MAC)
	}
}

func TestFieldMappingHasNoDuplicateNames(t *testing.T) {
	seen := map[string]Field{}
	for _, row := range FieldMapping {
		for _, n := range row.Names {
			if prev, dup := seen[normName(n)]; dup {
				t.Errorf("name %q maps to both %s and %s", n, prev, row.Field)
			}
			seen[normName(n)] = row.Field
		}
	}
	if f, ok := LookupField(" HTTP-Status "); !ok || f != FStatus {
		t.Errorf("LookupField = %v %v", f, ok)
	}
}

func TestStreamingWriterRejectsUseAfterClose(t *testing.T) {
	for _, format := range []string{FormatNmapXML, FormatJSON, FormatCSV} {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, format, Meta{GeneratedAt: fixedNow})
		if err != nil {
			t.Fatal(err)
		}
		if buf.Len() == 0 {
			t.Errorf("%s: the header must be written before the first host (streaming)", format)
		}
		before := buf.Len()
		if err := w.WriteHost(fullHost()); err != nil {
			t.Fatal(err)
		}
		if buf.Len() == before {
			t.Errorf("%s: a host must reach the writer at once", format)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteHost(fullHost()); err == nil {
			t.Errorf("%s: WriteHost after Close must fail", format)
		}
	}
	if _, err := NewWriter(&bytes.Buffer{}, "pdf", Meta{}); err == nil {
		t.Errorf("unknown format must fail")
	}
}

// A service the run did not scan is exported as such (CSV column "carried",
// nmap XML port reason czujka-not-scanned) and reads back with Carried set.
func TestCarriedServiceExportRoundTrip(t *testing.T) {
	h := model.HostResult{IP: "10.0.0.5", Up: true, ObservedAt: fixedNow, Services: []model.ServiceResult{
		{Port: 80, Proto: "tcp", State: "open", Name: "http"},
		{Port: 8787, Proto: "tcp", State: "open", Name: "http", Carried: true},
	}}
	for _, format := range []string{FormatCSV, FormatNmapXML, FormatJSON} {
		var buf bytes.Buffer
		if err := Export(&buf, format, []model.HostResult{h}, Meta{GeneratedAt: fixedNow, RunID: 7}); err != nil {
			t.Fatal(err)
		}
		if format == FormatNmapXML && !strings.Contains(buf.String(), `portid="8787"><state state="open" reason="czujka-not-scanned"`) {
			t.Errorf("xml: %s", buf.String())
		}
		back, _ := mustImport(t, buf.Bytes(), Options{})
		got := map[int]bool{}
		for _, s := range back[0].Services {
			got[s.Port] = s.Carried
		}
		if got[80] || !got[8787] {
			t.Errorf("%s round trip: carried %v", format, got)
		}
	}
}
