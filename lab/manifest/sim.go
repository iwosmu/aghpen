package manifest

import (
	"encoding/json"
	"fmt"

	"github.com/iwosmu/aghpen/lab/labcfg"
	"github.com/iwosmu/aghpen/lab/truth"
)

// page builds a small HTML document.
func page(title, body string) string {
	return "<!doctype html>\n<html lang=\"pl\">\n<head>\n<meta charset=\"utf-8\">\n<title>" + title + "</title>\n</head>\n<body>\n" + body + "\n</body>\n</html>\n"
}

func root(body string) labcfg.Route { return labcfg.Route{Path: "/", Body: body} }

func redirect(path, to string, status int) labcfg.Route {
	return labcfg.Route{Path: path, Location: to, Status: status, Body: page("Redirect", "<a href=\""+to+"\">"+to+"</a>")}
}

func hdr(name, value string) labcfg.Header { return labcfg.Header{Name: name, Value: value} }

func clonePorts(in []SimPort) []SimPort {
	raw, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out []SimPort
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

// evolve builds the per-state port lists: t0 is base, every later state starts
// from the state before it and applies its change, so a change stays in force.
func evolve(base []SimPort, changes map[string]func([]SimPort) []SimPort) map[string][]SimPort {
	out := map[string][]SimPort{}
	cur := base
	for _, st := range labcfg.States {
		cur = clonePorts(cur)
		if f := changes[st]; f != nil {
			cur = f(cur)
		}
		out[st] = cur
	}
	return out
}

func portIndex(ports []SimPort, port int) int {
	for i := range ports {
		if ports[i].Port == port {
			return i
		}
	}
	panic(fmt.Sprintf("no port %d", port))
}

func dropPort(ports []SimPort, port int) []SimPort {
	i := portIndex(ports, port)
	return append(ports[:i:i], ports[i+1:]...)
}

func sim(name, ip string, hostnames []string, group, desc string, base []SimPort, changes map[string]func([]SimPort) []SimPort) Container {
	return Container{
		Name: name, IP: ip, Hostnames: hostnames, Group: group, Desc: desc,
		Image: img("labsim", "1"), Build: &Build{Context: ".", Dockerfile: "images/labsim/Dockerfile"},
		Env:    [][2]string{{"LABSIM_HOST", name}},
		MemMB:  48,
		Health: Health{Test: "test -f /tmp/labsim.ready"},
		Sim:    &SimHost{Ports: evolve(base, changes)},
	}
}

var iot = []string{"iot"}

// ---------- IoT imitations ----------

// hikvision imitates the web interface of a Hikvision IP camera (DS-2CD2xxx
// series, firmware 5.5.x). Public fingerprint reproduced: the "App-webs/"
// Server header, the script redirect of "/" to /doc/page/login.asp and the
// login page that loads ../script/login.js. The favicon is lab-made.
func hikvision() []SimPort {
	index := "<!doctype html>\n<html><head><title></title>\n<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" />\n<script>\nwindow.location.href = \"/doc/page/login.asp?_\" + (new Date()).getTime();\n</script>\n</head><body></body></html>\n"
	login := "<!doctype html>\n<html><head><title>Login</title>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n<link href=\"../css/login.css\" rel=\"stylesheet\" type=\"text/css\" />\n<script type=\"text/javascript\" src=\"../script/jquery-1.7.1.min.js\"></script>\n<script type=\"text/javascript\" src=\"../script/login.js\"></script>\n</head><body onload=\"initLogin()\">\n<div class=\"loginbar\"><input type=\"text\" id=\"loginUserName\" maxlength=\"32\" /><input type=\"password\" id=\"loginPassword\" maxlength=\"16\" /></div>\n<div class=\"footer\">&copy;Hikvision Digital Technology Co., Ltd. All Rights Reserved.</div>\n</body></html>\n"
	return []SimPort{{
		Port: 80,
		Site: labcfg.Site{Server: "App-webs/", FaviconSeed: "hikvision", Routes: []labcfg.Route{
			{Path: "/", Body: index}, {Path: "/doc/page/login.asp", Body: login},
		}, Headers: []labcfg.Header{hdr("X-Frame-Options", "SAMEORIGIN")}},
		Product: "Hikvision IP camera httpd", NameAlt: nil,
		Techs:   []truth.Tech{tech("Hikvision IP Camera", "iot", "", "hikvision", "hikvision ip camera httpd", "hikvision web server", "app-webs", "hikvision camera")},
		Classes: iot, ClassOpt: []string{"login", "admin-panel"},
		TechOptional: []string{"jQuery"},
		Interesting:  []truth.Interesting{header("Server", "App-webs/ is the web server of Hikvision cameras")},
	}}
}

// mikrotik imitates the landing page of MikroTik RouterOS 6.49.10 (the page
// before WebFig). Reproduced: the title "RouterOS router configuration page",
// the "RouterOS v6.49.10" heading, the WebFig link and the "mikrotik" footer.
// RouterOS sends no Server header, and neither does the imitation.
func mikrotik() []SimPort {
	body := "<h1>RouterOS v6.49.10</h1>\n<p>You have connected to a router. Administrative access only. If this device is not in your possession, please contact your local network administrator.</p>\n<table><tr><td><a href=\"/webfig/\"><img src=\"/webfig/img/webfig.png\" alt=\"WebFig\"></a></td><td><a href=\"/webfig/\">WebFig</a></td></tr>\n<tr><td><a href=\"/help/license.html\">License</a></td><td><a href=\"/graphs/\">Graphs</a></td></tr></table>\n<div class=\"top\">mikrotik</div>\n<div class=\"footer\">&copy; mikrotik</div>"
	webfig := page("WebFig", "<div id=\"content\"><form name=\"loginForm\"><input name=\"name\"><input type=\"password\" name=\"password\"></form></div>\n<script src=\"/webfig/engine.js\"></script>")
	return []SimPort{{
		Port: 80,
		Site: labcfg.Site{FaviconSeed: "mikrotik", Routes: []labcfg.Route{
			{Path: "/", Body: "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n<title>RouterOS router configuration page</title>\n</head>\n<body>\n" + body + "\n</body>\n</html>\n"},
			{Path: "/webfig/", Body: webfig},
		}},
		Techs:   []truth.Tech{tech("MikroTik RouterOS", "iot", "6.49.10", "mikrotik", "routeros", "mikrotik routeros", "mikrotik router", "mikrotik router config httpd")},
		Classes: iot, ClassOpt: []string{"login", "admin-panel"},
	}}
}

// hpPrinter imitates the Embedded Web Server of an HP LaserJet Pro M404dn.
// Reproduced: the long "HP HTTP Server; <model> - <product number>; Serial
// Number: ...; Built: ... {firmware}" Server header and the title made of
// the model and the address. Ports 80, 443 (self-signed) and 631 (IPP runs over HTTP).
func hpPrinter(ip string) []SimPort {
	server := "HP HTTP Server; HP LaserJet Pro M404dn - W1A53A; Serial Number: PHBLL1Z0XQ; Built: Thu Mar 31, 2022 11:55:49AM {TETONXXXXN002.2212A.00}"
	body := page("HP LaserJet Pro M404dn&nbsp;&nbsp;&nbsp;"+ip, "<div id=\"header\"><span class=\"product-name\">HP LaserJet Pro M404dn</span></div>\n<ul class=\"tabs\"><li><a href=\"/hp/device/DeviceStatus/Index\">Home</a></li><li><a href=\"/hp/device/SuppliesStatus\">Supplies</a></li><li><a href=\"/hp/device/NetworkSummary\">Networking</a></li></ul>\n<div id=\"footer\">&copy; Copyright 2019-2022 HP Development Company, L.P.</div>")
	site := labcfg.Site{Server: server, FaviconSeed: "hp-laserjet", Routes: []labcfg.Route{root(body)}}
	mk := func(port int, t *labcfg.TLS, alt ...string) SimPort {
		return SimPort{
			Port: port, TLS: t, Site: site, NameAlt: alt,
			Techs:   []truth.Tech{tech("HP LaserJet", "iot", "", "hp laserjet", "hp http server", "hp laserjet pro m404dn", "hp embedded web server", "hp printer", "hp laserjet pro")},
			Classes: iot, ClassOpt: []string{"admin-panel"},
			Interesting: []truth.Interesting{header("Server", "leaks the printer model, serial number and firmware build")},
		}
	}
	return []SimPort{
		mk(80, nil),
		mk(443, &labcfg.TLS{Mode: "selfsigned", CN: "HP LaserJet Pro M404dn", Org: "HP Inc.", SANs: []string{ip}, NotBeforeDays: -900, NotAfterDays: 2750, Key: "rsa2048"}),
		mk(631, nil, "ipp"),
	}
}

// synology imitates the DSM 6.2 login page of a Synology DiskStation.
// Reproduced: nginx Server header, the "<name> - Synology DiskStation" title
// and application-name meta, the webman/ and webapi/ asset paths, the
// sds-login-dialog element, port 5000 (HTTP) and 5001 (HTTPS with the default
// "synology.com" certificate), and the redirect from port 80 to 5000.
func synology(ip string) []SimPort {
	body := "<!DOCTYPE html>\n<html class=\"img-no-display\"><head>\n<meta charset=\"utf-8\">\n<title>nas-wimiip&nbsp;-&nbsp;Synology&nbsp;DiskStation</title>\n<meta name=\"application-name\" content=\"nas-wimiip&nbsp;-&nbsp;Synology&nbsp;DiskStation\" />\n<meta name=\"description\" content=\"DiskStation provides a full-featured network attached storage (NAS) solution.\" />\n<link rel=\"stylesheet\" type=\"text/css\" href=\"webman/resources/css/desktop.css?v=1556629596\" />\n<script type=\"text/javascript\" src=\"webapi/entry.cgi?api=SYNO.Core.Desktop.SessionData&version=1&method=getjs&SynoToken=&v=1556629596\"></script>\n</head>\n<body>\n<div id=\"sds-login-dialog\"><form id=\"login-form\"><input type=\"text\" name=\"username\"><input type=\"password\" name=\"passwd\"></form></div>\n<div id=\"sds-login-footer\">Synology DSM 6.2</div>\n</body></html>\n"
	site := labcfg.Site{Server: "nginx", FaviconSeed: "synology-dsm", Routes: []labcfg.Route{{Path: "/", Body: body}, {Path: "/webman/index.cgi", Body: body}},
		Headers: []labcfg.Header{hdr("X-Content-Type-Options", "nosniff"), hdr("X-XSS-Protection", "1; mode=block")}}
	techs := []truth.Tech{tech("Synology DSM", "iot", "6.2", "synology", "synology diskstation", "synology dsm", "diskstation manager", "synology nas", "synology diskstation manager")}
	return []SimPort{
		{Port: 80, Site: labcfg.Site{Server: "nginx", Routes: []labcfg.Route{redirect("/", "http://"+ip+":5000/", 302)}},
			TechOptional: []string{"nginx", "Synology DSM"}, ClassOpt: []string{"iot"}},
		{Port: 5000, Site: site, NameAlt: []string{"upnp"}, Techs: techs, TechOptional: []string{"nginx"}, Classes: []string{"iot", "login"}, ClassOpt: []string{"admin-panel"}},
		{Port: 5001, Site: site, NameAlt: []string{"commplex-link"}, Techs: techs, TechOptional: []string{"nginx"}, Classes: []string{"iot", "login"}, ClassOpt: []string{"admin-panel"},
			TLS: &labcfg.TLS{Mode: "selfsigned", CN: "synology.com", Org: "Synology Inc.", SANs: []string{"synology.com"}, NotBeforeDays: -1200, NotAfterDays: 6000, Key: "rsa2048"}},
	}
}

// ---------- custom-signature target ----------

// infoKiosk is a made-up in-house product. No public signature can know it,
// so only the custom signature in lab/custom-signatures finds it. It shows
// every matcher of the brief: header, cookie, body fragment, favicon hash,
// path and a version in the footer.
func infoKiosk(node, version string) []SimPort {
	body := page("Informator — kiosk "+node, "<!-- InfoKiosk build "+version+" -->\n<main class=\"ik-screen\"><h1>Plan zajęć i komunikaty</h1><p>Dotknij ekranu, aby rozpocząć.</p></main>\n<footer class=\"ik-footer\">InfoKiosk v"+version+" &middot; węzeł "+node+"</footer>")
	status := "{\"product\":\"InfoKiosk\",\"version\":\"" + version + "\",\"node\":\"" + node + "\",\"display\":\"on\"}\n"
	return []SimPort{{
		Port: 80,
		Site: labcfg.Site{
			Server: "ik-httpd", FaviconSeed: "infokiosk",
			Headers: []labcfg.Header{hdr("X-InfoKiosk-Node", node)},
			Cookies: []labcfg.Cookie{{Name: "infokiosk_sid", Value: "9f2c1d7a5b3e4860", HTTPOnly: true}},
			Routes:  []labcfg.Route{root(body), {Path: "/kiosk/status", ContentType: "application/json", Body: status}},
		},
		Techs:       []truth.Tech{tech("InfoKiosk", "other", version, "infokiosk")},
		Signatures:  []string{"lab-infokiosk"},
		Interesting: []truth.Interesting{header("X-InfoKiosk-Node", "unusual custom header; only the custom signature knows it"), cookie("infokiosk_sid", "unusual custom cookie; only the custom signature knows it")},
	}}
}

// A JSON Web Token with harmless claims and a made-up signature.
const labJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnb3NjIiwicm9sZSI6ImFub24iLCJpc3MiOiJsYWIuY3p1amthLnRlc3QifQ.c2lnbmF0dXJlLW5vdC1yZWFsLWxhYi1vbmx5LTAwMDAwMDAw"

func simplePage(port int, server, title, body string) SimPort {
	return SimPort{Port: port, Site: labcfg.Site{Server: server, Routes: []labcfg.Route{root(page(title, body))}}}
}

func manyPorts() []SimPort {
	var ports []int
	for _, p := range []int{81, 82, 88, 591, 2080, 3128, 4567, 9999, 10000, 12345, 20000, 27017, 32768, 49152} {
		ports = append(ports, p)
	}
	for p := 4000; p < 4010; p++ {
		ports = append(ports, p)
	}
	for p := 7000; p < 7020; p++ {
		ports = append(ports, p)
	}
	for p := 8000; p < 8010; p++ {
		ports = append(ports, p)
	}
	for p := 8880; p < 8890; p++ {
		ports = append(ports, p)
	}
	out := make([]SimPort, 0, len(ports))
	for _, p := range ports {
		sp := simplePage(p, "nginx", fmt.Sprintf("Instancja testowa %d", p), fmt.Sprintf("<p>Usługa na porcie %d.</p>", p))
		sp.NameAlt = []string{"*"}
		out = append(out, sp)
	}
	return out
}

func simContainers() []Container {
	loginForm := "<form method=\"get\" action=\"/login\"><label>Login <input name=\"username\"></label> <label>Hasło <input type=\"password\" name=\"password\"></label> <button type=\"submit\">Zaloguj</button></form>"
	apacheOld := "Apache/2.2.15 (CentOS)"

	// --- staging and test ---
	stagingTLS := &labcfg.TLS{Mode: "ca", CN: "staging." + Zone, Org: "AGH Lab", SANs: []string{"staging." + Zone, "10.66.40.10"}, NotBeforeDays: -20, NotAfterDays: 70}
	stagingSite := func(title string) labcfg.Site {
		return labcfg.Site{
			Server:  "nginx/1.26.2",
			Headers: []labcfg.Header{hdr("X-Environment", "staging"), hdr("X-Robots-Tag", "noindex, nofollow"), hdr("X-Build-Commit", "3f9c2ab")},
			Cookies: []labcfg.Cookie{{Name: "stg_session", Value: "b7e2a9c04d1f", Secure: true, HTTPOnly: true, SameSite: "Lax"}},
			Routes:  []labcfg.Route{root(page(title, "<div class=\"env-banner\" style=\"background:#c00;color:#fff\">ŚRODOWISKO TESTOWE (STAGING) — dane nieprodukcyjne</div>\n<h1>Wirtualny Dziekanat</h1>\n"+loginForm))},
		}
	}
	staging := []SimPort{
		{Port: 80, Site: labcfg.Site{Server: "nginx/1.26.2", Routes: []labcfg.Route{redirect("/", "https://10.66.40.10/", 301)}},
			Product: "nginx", Version: "1.26.2", Techs: []truth.Tech{tech("nginx", "web-server", "1.26.2")}, ClassOpt: []string{"staging"}},
		{Port: 443, TLS: stagingTLS, Site: stagingSite("[STAGING] Wirtualny Dziekanat"),
			Product: "nginx", Version: "1.26.2", Techs: []truth.Tech{tech("nginx", "web-server", "1.26.2")},
			Classes:     []string{"staging", "login"},
			Interesting: []truth.Interesting{header("X-Environment", "says the environment is staging"), header("X-Build-Commit", "leaks the build commit"), header("X-Robots-Tag", "hidden from search engines: typical of test sites")}},
	}
	devAPI := []SimPort{{
		Port: 8080,
		Site: labcfg.Site{
			Server: "nginx/1.22.1",
			Headers: []labcfg.Header{hdr("X-Powered-By", "PHP/8.2.12"), hdr("X-Debug-Token", "4f2a1c"), hdr("X-Debug-Token-Link", "http://10.66.40.11:8080/_profiler/4f2a1c"),
				hdr("X-Robots-Tag", "noindex"), hdr("Access-Control-Allow-Origin", "*"), hdr("Access-Control-Allow-Credentials", "true")},
			Routes: []labcfg.Route{{Path: "/", ContentType: "application/json", Body: "{\"service\":\"oceny-api\",\"env\":\"dev\",\"debug\":true,\"version\":\"0.9.3-SNAPSHOT\"}\n"},
				{Path: "/_profiler/4f2a1c", Body: page("Symfony Profiler", "<div id=\"sfwdt\">Symfony Profiler</div>")}},
		},
		Product: "nginx", Version: "1.22.1",
		Techs:        []truth.Tech{tech("nginx", "web-server", "1.22.1"), tech("PHP", "language", "8.2.12", "php")},
		TechOptional: []string{"Symfony"}, Classes: []string{"api", "staging"}, ClassOpt: []string{"dev-tool"},
		Interesting: []truth.Interesting{header("X-Debug-Token", "Symfony profiler is on: a debug build"), header("X-Debug-Token-Link", "link to the profiler"), header("X-Powered-By", "leaks the exact PHP version"),
			header("Access-Control-Allow-Origin", "wildcard CORS"), header("Access-Control-Allow-Credentials", "credentials allowed together with wildcard CORS")},
	}}
	testShop := []SimPort{{
		Port:    80,
		Site:    labcfg.Site{Server: "Apache/2.4.57 (Debian)", Routes: []labcfg.Route{{Path: "*", BasicRealm: "TEST environment - authorized staff only", Body: page("401 Unauthorized", "<h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document requested.</p>")}}},
		Product: "Apache httpd", Version: "2.4.57",
		Techs: []truth.Tech{tech("Apache HTTP Server", "web-server", "2.4.57", "apache", "apache httpd", "apache http server")}, TechOptional: []string{"Debian"},
		Classes: []string{"staging"}, ClassOpt: []string{"login", "error-page"},
		Interesting: []truth.Interesting{header("WWW-Authenticate", "the realm says this is a TEST environment")},
	}}

	// --- TLS zoo and redirects ---
	portalSite := labcfg.Site{
		Server:  "nginx",
		Headers: []labcfg.Header{hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), hdr("X-Content-Type-Options", "nosniff"), hdr("X-Frame-Options", "DENY")},
		Cookies: []labcfg.Cookie{{Name: "portal_session", Value: "0a1b2c3d4e5f6071", Secure: true, HTTPOnly: true, SameSite: "Lax"}},
		Routes:  []labcfg.Route{root(page("Portal Pracowniczy", "<h1>Portal Pracowniczy</h1>\n"+loginForm))},
	}
	tlsValid := []SimPort{
		{Port: 80, Site: labcfg.Site{Server: "nginx", Routes: []labcfg.Route{redirect("/", "https://10.66.50.10/", 301)}}, Product: "nginx", Techs: []truth.Tech{tech("nginx", "web-server", "")}},
		{Port: 443, Site: portalSite, Product: "nginx", Techs: []truth.Tech{tech("nginx", "web-server", "")}, Classes: []string{"login"},
			TLS: &labcfg.TLS{Mode: "ca", CN: "portal." + Zone, Org: "AGH Lab", SANs: []string{"portal." + Zone, "10.66.50.10"}, NotBeforeDays: -335, NotAfterDays: 30, Key: "rsa2048"}},
	}
	tlsPage := func(title string, t *labcfg.TLS) SimPort {
		sp := simplePage(443, "nginx", title, "<h1>"+title+"</h1>")
		sp.TLS = t
		sp.Product = "nginx"
		sp.Techs = []truth.Tech{tech("nginx", "web-server", "")}
		return sp
	}
	selfSigned := &labcfg.TLS{Mode: "selfsigned", CN: "selfsigned." + Zone, SANs: []string{"selfsigned." + Zone, "10.66.50.11"}, NotBeforeDays: -100, NotAfterDays: 265}
	ssAlt := tlsPage("Archiwum dokumentów (kopia)", selfSigned)
	ssAlt.Port = 8443
	ssAlt.NameAlt = []string{"https-alt"}
	expired := &labcfg.TLS{Mode: "ca", CN: "expired." + Zone, SANs: []string{"expired." + Zone, "10.66.50.12"}, NotBeforeDays: -400, NotAfterDays: -35}
	mismatch := &labcfg.TLS{Mode: "ca", CN: "intranet.uczelnia.example", SANs: []string{"intranet.uczelnia.example", "www.intranet.uczelnia.example"}, NotBeforeDays: -30, NotAfterDays: 335}

	redirChain := []SimPort{{
		Port: 80,
		Site: labcfg.Site{Server: "nginx", Routes: []labcfg.Route{
			redirect("/", "/start", 301), redirect("/start", "/pl/", 302), redirect("/pl/", "/pl/home", 307),
			{Path: "/pl/home", Body: page("Biuro Karier — strona główna", "<h1>Biuro Karier</h1><p>Oferty pracy i praktyk.</p>")},
		}},
		Product: "nginx", Techs: []truth.Tech{tech("nginx", "web-server", "")},
	}}
	redirExt := []SimPort{{
		Port:    80,
		Site:    labcfg.Site{Server: "nginx", Routes: []labcfg.Route{redirect("/", "http://10.66.50.10/", 302)}},
		Product: "nginx", Techs: []truth.Tech{tech("nginx", "web-server", "")},
	}}

	// --- headers and cookies ---
	leakySite := func(php string, sessHTTPOnly, tracking bool) labcfg.Site {
		cookies := []labcfg.Cookie{{Name: "PHPSESSID", Value: "q8r2k1m5n7p3s9t4v6w0x2y4z6", HTTPOnly: sessHTTPOnly}, {Name: "lang", Value: "pl", MaxAge: 31536000}}
		if tracking {
			cookies = append(cookies, labcfg.Cookie{Name: "tracking_id", Value: "u-551-20261121", MaxAge: 31536000})
		}
		return labcfg.Site{
			Server: apacheOld,
			Headers: []labcfg.Header{hdr("X-Powered-By", "PHP/"+php), hdr("X-Debug-Mode", "enabled"), hdr("X-Backend-Server", "app-node-03.internal.uczelnia.example"),
				hdr("Via", "1.1 varnish (Varnish/6.0)"), hdr("Access-Control-Allow-Origin", "*")},
			Cookies: cookies,
			Routes:  []labcfg.Route{root(page("System Obsługi Zgłoszeń", "<h1>System Obsługi Zgłoszeń</h1>\n"+loginForm+"\n<p class=\"footer\">HelpDesk 3.1</p>"))},
		}
	}
	leakyInteresting := func(tracking bool) []truth.Interesting {
		out := []truth.Interesting{header("Server", "old Apache 2.2 on CentOS, end of life"), header("X-Powered-By", "leaks the exact PHP version"), header("X-Debug-Mode", "debug mode is on"),
			header("X-Backend-Server", "leaks an internal host name"), header("Via", "names the proxy and its version"), header("Access-Control-Allow-Origin", "wildcard CORS"),
			cookie("PHPSESSID", "session cookie without Secure")}
		if tracking {
			out = append(out, cookie("tracking_id", "new tracking cookie without flags"))
		}
		return out
	}
	leakyPort := func(php string, sessHTTPOnly, tracking bool) SimPort {
		return SimPort{Port: 80, Site: leakySite(php, sessHTTPOnly, tracking), Product: "Apache httpd", Version: "2.2.15",
			Techs:        []truth.Tech{tech("Apache HTTP Server", "web-server", "2.2.15", "apache", "apache httpd", "apache http server"), tech("PHP", "language", php, "php")},
			TechOptional: []string{"Varnish", "CentOS"}, Classes: []string{"login"}, Interesting: leakyInteresting(tracking)}
	}
	oldStatus := simplePage(8000, apacheOld, "Status serwera (stary)", "<pre>uptime: 412 days</pre>")
	oldStatus.Product, oldStatus.Version, oldStatus.NameAlt = "Apache httpd", "2.2.15", []string{"http-alt"}
	oldStatus.TechOptional = []string{"Apache HTTP Server"} // the Server header names it
	newStatus := simplePage(8081, "nginx/1.26.2", "Konsola diagnostyczna", "<h1>Konsola diagnostyczna</h1><pre>queue: 0\nworkers: 4</pre>")
	newStatus.Product, newStatus.Version, newStatus.NameAlt = "nginx", "1.26.2", []string{"blackice-icecap"}
	newStatus.TechOptional = []string{"nginx"} // the Server header names it

	jwtSite := func(fixed bool) labcfg.Site {
		return labcfg.Site{
			Server:  "Microsoft-IIS/8.5",
			Headers: []labcfg.Header{hdr("X-Powered-By", "ASP.NET"), hdr("X-AspNet-Version", "4.0.30319"), hdr("X-AspNetMvc-Version", "5.2")},
			Cookies: []labcfg.Cookie{
				{Name: "access_token", Value: labJWT, Secure: fixed, HTTPOnly: fixed},
				{Name: "ASP.NET_SessionId", Value: "kq1x0w3n5b2m4v6c8z0a1s3d", HTTPOnly: true},
				{Name: "remember_me", Value: "uid=1042&exp=1795000000", MaxAge: 2592000},
			},
			Routes: []labcfg.Route{root(page("e-Dziennik — logowanie", "<h1>e-Dziennik</h1>\n"+loginForm))},
		}
	}
	jwtInteresting := func(fixed bool) []truth.Interesting {
		out := []truth.Interesting{header("X-AspNet-Version", "leaks the .NET version"), header("X-AspNetMvc-Version", "leaks the MVC version"), header("X-Powered-By", "names the platform"),
			header("Server", "IIS 8.5 (Windows Server 2012 R2)"), cookie("ASP.NET_SessionId", "session cookie without Secure on an HTTPS site"), cookie("remember_me", "readable by scripts, no Secure")}
		if fixed {
			return append(out, cookie("access_token", "JWT in a cookie"))
		}
		return append(out, cookie("access_token", "JWT readable by scripts: no HttpOnly, no Secure"))
	}
	jwtPorts := func(fixed bool) []SimPort {
		techs := []truth.Tech{tech("Microsoft IIS", "web-server", "8.5", "iis", "microsoft iis httpd", "microsoft-iis", "internet information services"), tech("ASP.NET", "framework", "4.0.30319", "asp.net", "microsoft asp.net")}
		return []SimPort{
			{Port: 80, Site: jwtSite(fixed), Product: "Microsoft IIS httpd", Version: "8.5", Techs: techs, TechOptional: []string{"Windows Server", "ASP.NET MVC"}, Classes: []string{"login"}, Interesting: jwtInteresting(fixed)},
			{Port: 443, Site: jwtSite(fixed), Product: "Microsoft IIS httpd", Version: "8.5", Techs: techs, TechOptional: []string{"Windows Server", "ASP.NET MVC"}, Classes: []string{"login"}, Interesting: jwtInteresting(fixed),
				TLS: &labcfg.TLS{Mode: "selfsigned", CN: "dziennik." + Zone, SANs: []string{"dziennik." + Zone, "10.66.60.11"}, NotBeforeDays: -200, NotAfterDays: 165, Key: "rsa2048"}},
		}
	}

	// --- site that turns into an admin panel ---
	newsPlain := simplePage(80, "nginx/1.26.2", "Aktualności Koła Naukowego", "<h1>Aktualności</h1><article><h2>Spotkanie organizacyjne</h2><p>Zapraszamy w czwartek o 18:00.</p></article>")
	newsPlain.Product, newsPlain.Version = "nginx", "1.26.2"
	newsPlain.Techs = []truth.Tech{tech("nginx", "web-server", "1.26.2")}
	newsAdmin := simplePage(80, "nginx/1.26.2", "Panel administracyjny — logowanie", "<h1>Panel administracyjny</h1>\n<form method=\"get\" action=\"/admin/login\"><input name=\"admin_user\"><input type=\"password\" name=\"admin_pass\"><button>Zaloguj do panelu</button></form>")
	newsAdmin.Product, newsAdmin.Version = "nginx", "1.26.2"
	newsAdmin.Techs = []truth.Tech{tech("nginx", "web-server", "1.26.2")}
	newsAdmin.Classes = []string{"admin-panel", "login"}
	newsAdmin.Site.Cookies = []labcfg.Cookie{{Name: "admin_session", Value: "c1d2e3f4a5b6", HTTPOnly: true}}
	newsAdmin.Interesting = []truth.Interesting{cookie("admin_session", "admin session cookie without Secure")}

	// --- hard cases ---
	nginxPage := func(port int, title, body string) SimPort {
		sp := simplePage(port, "nginx", title, body)
		sp.Product = "nginx"
		sp.Techs = []truth.Tech{tech("nginx", "web-server", "")}
		return sp
	}
	slow := nginxPage(80, "Archiwum (wolny serwer)", "<p>Ten serwer odpowiada po 4 sekundach.</p>")
	slow.Site.DelayMs = 4000
	slow.Hard = "slow"
	stealthTLS := &labcfg.TLS{Mode: "selfsigned", CN: "serwis.local", SANs: []string{"serwis.local"}, NotBeforeDays: -10, NotAfterDays: 3640}
	s8888 := nginxPage(8888, "Monitoring UPS", "<h1>Monitoring UPS</h1>")
	s8888.NameAlt = []string{"sun-answerbook"}
	s18443 := nginxPage(18443, "Panel serwisowy (TLS)", "<h1>Panel serwisowy</h1>\n"+loginForm)
	s18443.TLS, s18443.Classes, s18443.ClassOpt = stealthTLS, []string{"login"}, []string{"admin-panel"}
	s31337 := nginxPage(31337, "Panel serwisowy", "<h1>Panel serwisowy</h1>\n"+loginForm)
	s31337.NameAlt, s31337.Classes, s31337.ClassOpt = []string{"Elite", "elite"}, []string{"login"}, []string{"admin-panel"}
	volatile := SimPort{
		Port: 80,
		Site: labcfg.Site{Server: "nginx", Routes: []labcfg.Route{{Path: "/", Volatile: true,
			Headers: []labcfg.Header{hdr("X-Request-Id", "{{RAND}}")},
			Body:    page("Tablica ogłoszeń", "<h1>Tablica ogłoszeń</h1>\n<p>Wygenerowano: {{NOW}}</p>\n<p>Odwiedziny: {{COUNTER}}</p>\n<input type=\"hidden\" name=\"csrf\" value=\"{{RAND}}\">\n<div class=\"ad\" data-slot=\"{{RAND}}\">Reklama {{RAND}}</div>")}}},
		Product: "nginx", Techs: []truth.Tech{tech("nginx", "web-server", "")},
	}
	tarpitPort := SimPort{Port: 2222, Kind: "tarpit", Hard: "tarpit", NameAlt: []string{"*"}}

	flapper := sim("flapper", "10.66.70.20", []string{"stacja-pomiarowa"}, "hard", "host niestabilny: osiągalny w pseudolosowych ~50% minut",
		[]SimPort{nginxPage(80, "Stacja pomiarowa", "<h1>Stacja pomiarowa</h1><p>Łącze radiowe, niestabilne.</p>")}, nil)
	flapper.Avail = &labcfg.Avail{Kind: "flap", Seed: "czujka-flapper", SlotSec: 60}
	todOffice := sim("tod-office", "10.66.70.21", []string{"dziekanat-pc"}, "hard", "host „godziny pracy”: 3 minuty włączony, 3 minuty wyłączony",
		[]SimPort{nginxPage(80, "Stanowisko dziekanatu", "<h1>Stanowisko dziekanatu</h1><p>Dostępne w godzinach pracy.</p>")}, nil)
	todOffice.Avail = &labcfg.Avail{Kind: "schedule", PeriodSec: 360, UpFromSec: 0, UpToSec: 180}
	todNight := sim("tod-night", "10.66.70.22", []string{"backup-nocny"}, "hard", "host „nocny”: w cyklu 10 minut wyłączony przez pierwsze 4, włączony przez 6",
		[]SimPort{nginxPage(80, "Serwer kopii zapasowych", "<h1>Kopie zapasowe</h1><p>Włączany na czas okna backupu.</p>")}, nil)
	todNight.Avail = &labcfg.Avail{Kind: "schedule", PeriodSec: 600, UpFromSec: 240, UpToSec: 600}
	for _, c := range []*Container{&flapper, &todOffice, &todNight} {
		c.CapAdd = []string{"NET_ADMIN"}
		c.Hard = []string{"unstable"}
	}

	noICMP := sim("no-icmp", "10.66.70.10", []string{"pliki"}, "hard", "host nie odpowiada na ICMP (iptables DROP icmp)",
		[]SimPort{nginxPage(80, "Serwer plików", "<h1>Serwer plików</h1>")}, nil)
	noICMP.Sim.Firewall = &labcfg.Firewall{DropICMP: true}
	noICMP.CapAdd, noICMP.Hard = []string{"NET_ADMIN"}, []string{"no-icmp-echo"}

	stealth := sim("stealth-high", "10.66.70.11", []string{"serwis"}, "hard", "usługi tylko na nietypowych portach (8888, 18443, 31337); reszta pakietów jest odrzucana po cichu",
		[]SimPort{s8888, s18443, s31337}, map[string]func([]SimPort) []SimPort{
			"t2": func(p []SimPort) []SimPort { return dropPort(p, 31337) },
		})
	stealth.Sim.Firewall = &labcfg.Firewall{StealthExcept: []int{8888, 18443, 31337}}
	stealth.CapAdd, stealth.Hard = []string{"NET_ADMIN"}, []string{"stealth-firewall", "no-icmp-echo", "unusual-ports"}

	slowC := sim("slow", "10.66.70.12", []string{"archiwum"}, "hard", "serwer odpowiadający po 4 s", []SimPort{slow}, nil)
	slowC.Hard = []string{"slow"}
	tarpitC := sim("tarpit", "10.66.70.13", []string{"pulapka"}, "hard", "port 2222 typu tarpit (1 bajt na 10 s) obok zwykłego HTTP",
		[]SimPort{nginxPage(80, "Brama testowa", "<h1>Brama testowa</h1>"), tarpitPort}, nil)
	tarpitC.Hard = []string{"tarpit"}
	many := sim("many-ports", "10.66.70.14", []string{"multi"}, "hard", "host z 64 otwartymi portami HTTP", manyPorts(), nil)
	many.Hard, many.MemMB = []string{"many-ports"}, 96
	volatileC := sim("volatile", "10.66.70.15", []string{"ogloszenia"}, "hard", "treść strony inna przy każdym żądaniu (czas, licznik, losowe tokeny, nagłówek X-Request-Id)", []SimPort{volatile}, nil)
	volatileC.Hard = []string{"volatile-content"}

	edge := func(name, ip, host, title string) Container {
		c := sim(name, ip, []string{host}, "edge", "pojedynczy host na krawędzi bloku ("+ip+")", []SimPort{nginxPage(80, title, "<h1>"+title+"</h1>")}, nil)
		c.Hard = []string{"edge-address"}
		return c
	}

	list := []Container{
		// ---------- web (10.66.2.0/24), next to the real servers ----------
		sim("news-site", "10.66.2.30", []string{"kolo"}, "web", "strona aktualności, która w t1 staje się panelem administracyjnym",
			[]SimPort{newsPlain}, map[string]func([]SimPort) []SimPort{"t1": func([]SimPort) []SimPort { return []SimPort{newsAdmin} }}),

		// ---------- IoT (10.66.30.0/24) ----------
		sim("router-1", "10.66.30.1", []string{"gw-iot"}, "iot", "imitacja MikroTik RouterOS 6.49.10 (pierwszy adres bloku)", mikrotik(), nil),
		sim("cam-1", "10.66.30.10", []string{"kamera-1"}, "iot", "imitacja kamery IP Hikvision", hikvision(), nil),
		sim("cam-2", "10.66.30.11", []string{"kamera-2"}, "iot", "imitacja kamery IP Hikvision (bliźniak cam-1)", hikvision(), nil),
		sim("printer-1", "10.66.30.20", []string{"drukarka-1"}, "iot", "imitacja HP LaserJet Pro M404dn (80, 443, 631)", hpPrinter("10.66.30.20"), nil),
		sim("nas-1", "10.66.30.30", []string{"nas"}, "iot", "imitacja Synology DSM 6.2 (80 → 5000, 5001 TLS)", synology("10.66.30.30"), nil),

		// ---------- staging and test (10.66.40.0/24) ----------
		sim("staging-portal", "10.66.40.10", []string{"staging"}, "staging", "staging: nagłówek X-Environment, baner, certyfikat dla staging."+Zone+"; tytuł zmienia się w t1",
			staging, map[string]func([]SimPort) []SimPort{"t1": func(p []SimPort) []SimPort {
				p[portIndex(p, 443)].Site = stagingSite("[STAGING] Wirtualny Dziekanat 2.0 RC")
				return p
			}}),
		sim("dev-api", "10.66.40.11", []string{"dev-api"}, "staging", "API deweloperskie: X-Debug-Token (profiler Symfony), CORS * z poświadczeniami; w t2 odpowiada 503",
			devAPI, map[string]func([]SimPort) []SimPort{"t2": func(p []SimPort) []SimPort {
				p[0].Site.Routes[0].Status = 503
				p[0].Site.Routes[0].Body = "{\"service\":\"oceny-api\",\"env\":\"dev\",\"status\":\"maintenance\"}\n"
				return p
			}}),
		sim("test-shop", "10.66.40.12", []string{"test"}, "staging", "środowisko TEST za Basic Auth (401, realm „TEST environment”)", testShop, nil),

		// ---------- TLS and redirects (10.66.50.0/24) ----------
		sim("tls-valid", "10.66.50.10", []string{"portal"}, "tls", "poprawny łańcuch (CA laboratorium), HTTP → HTTPS; certyfikat wygasa za 30 dni, odnowiony w t1",
			tlsValid, map[string]func([]SimPort) []SimPort{"t1": func(p []SimPort) []SimPort {
				t := p[portIndex(p, 443)].TLS
				t.NotBeforeDays, t.NotAfterDays, t.Gen = -1, 364, 1
				return p
			}}),
		sim("tls-selfsigned", "10.66.50.11", []string{"selfsigned"}, "tls", "certyfikat self-signed (443 i 8443)",
			[]SimPort{tlsPage("Archiwum dokumentów", selfSigned), ssAlt}, nil),
		sim("tls-expired", "10.66.50.12", []string{"expired"}, "tls", "certyfikat wygasły 35 dni temu; odnowiony w t2",
			[]SimPort{tlsPage("System ankiet", expired)}, map[string]func([]SimPort) []SimPort{"t2": func(p []SimPort) []SimPort {
				t := p[0].TLS
				t.NotBeforeDays, t.NotAfterDays, t.Gen = -1, 89, 1
				return p
			}}),
		sim("tls-mismatch", "10.66.50.13", []string{"mismatch"}, "tls", "certyfikat wystawiony dla innej nazwy (intranet.uczelnia.example)",
			[]SimPort{tlsPage("Intranet wydziału", mismatch)}, nil),
		sim("redir-chain", "10.66.50.20", []string{"kariera"}, "tls", "łańcuch przekierowań: / → /start → /pl/ → /pl/home (301, 302, 307)", redirChain, nil),
		sim("redir-ext", "10.66.50.21", []string{"stary-portal"}, "tls", "przekierowanie na inny host (10.66.50.10); w t2 na 10.66.50.20",
			redirExt, map[string]func([]SimPort) []SimPort{"t2": func(p []SimPort) []SimPort {
				p[0].Site.Routes = []labcfg.Route{redirect("/", "http://10.66.50.20/", 302)}
				return p
			}}),

		// ---------- headers and cookies (10.66.60.0/24) ----------
		sim("hdr-leaky", "10.66.60.10", []string{"helpdesk"}, "headers", "nagłówki zdradzające wersje i debug, CORS *, PHPSESSID bez flag; w t1 zmiana nagłówka, ciasteczek i portów (8000 → 8081)",
			[]SimPort{leakyPort("5.4.16", false, false), oldStatus}, map[string]func([]SimPort) []SimPort{"t1": func([]SimPort) []SimPort {
				return []SimPort{leakyPort("7.4.33", true, true), newStatus}
			}}),
		sim("jwt-app", "10.66.60.11", []string{"dziennik"}, "headers", "ciasteczko-JWT bez HttpOnly/Secure, ASP.NET_SessionId bez Secure, nagłówki IIS/ASP.NET; ciasteczko naprawione w t2",
			jwtPorts(false), map[string]func([]SimPort) []SimPort{"t2": func([]SimPort) []SimPort { return jwtPorts(true) }}),
		sim("kiosk-1", "10.66.60.12", []string{"kiosk-1"}, "headers", "InfoKiosk 4.2.1: cel własnej sygnatury (nagłówek, ciasteczko, fragment HTML, favicon, ścieżka, wersja w stopce); 4.3.0 w t1",
			infoKiosk("k-7f3a", "4.2.1"), map[string]func([]SimPort) []SimPort{"t1": func([]SimPort) []SimPort { return infoKiosk("k-7f3a", "4.3.0") }}),

		// ---------- hard cases (10.66.70.0/24) ----------
		noICMP, stealth, slowC, tarpitC, many, volatileC, flapper, todOffice, todNight,

		// ---------- single hosts far apart and at block edges ----------
		edge("edge-zero", "10.66.99.0", "zero", "Host pod adresem .0"),
		edge("edge-255", "10.66.99.255", "ff", "Host pod adresem .255"),
		sim("router-2", "10.66.128.1", []string{"gw-akademik"}, "edge", "imitacja MikroTik RouterOS 6.49.10, samotny host w 10.66.128.0/24", mikrotik(), nil),
		func() Container {
			c := sim("cam-3", "10.66.130.77", []string{"kamera-3"}, "edge", "nowa kamera Hikvision: pojawia się w t1", hikvision(), nil)
			c.In = []string{"t1", "t2"}
			return c
		}(),
		sim("kiosk-2", "10.66.200.200", []string{"kiosk-2"}, "edge", "InfoKiosk 4.2.1, samotny host w 10.66.200.0/24", infoKiosk("k-c0de", "4.2.1"), nil),
		sim("printer-2", "10.66.255.254", []string{"drukarka-2"}, "edge", "imitacja HP LaserJet na ostatnim adresie sieci", hpPrinter("10.66.255.254"), nil),
	}
	return list
}
