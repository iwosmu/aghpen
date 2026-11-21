package manifest

import (
	"fmt"
	"strings"

	"github.com/iwosmu/aghpen/lab/truth"
)

// Passwords below protect nothing: the lab network is private, holds no real
// data and is destroyed with "down -v". They exist because the software
// refuses to start without them.
const (
	labDBPass    = "lab-db-pass"
	labAdminPass = "Lab-Admin-Pass-2026!"
)

func tech(name, category, version string, aliases ...string) truth.Tech {
	return truth.Tech{Name: name, Category: category, Version: version, Aliases: aliases}
}

func header(name, why string) truth.Interesting {
	return truth.Interesting{Kind: "header", Name: name, Why: why}
}

func cookie(name, why string) truth.Interesting {
	return truth.Interesting{Kind: "cookie", Name: name, Why: why}
}

func custom(name string, args ...[2]string) *Build {
	return &Build{Context: "images/" + name, Args: args}
}

func img(name, tag string) string { return ImageSpace + "/" + name + ":" + tag }

const httpCheck = "wget -q -T 3 -O /dev/null http://127.0.0.1:%d%s || curl -fsS -m 3 -o /dev/null http://127.0.0.1:%d%s"

func httpHealth(port int, path string) Health {
	return Health{Test: fmt.Sprintf(httpCheck, port, path, port, path)}
}

func wordpress(name, ip, host, tag, db, title, desc string, in []string, svc truth.Service) Container {
	return Container{
		Name: name, IP: ip, Hostnames: []string{host}, Group: "cms", Desc: desc, In: in,
		Image: img("wordpress", tag), Build: custom("wordpress", [2]string{"WP_TAG", tag}),
		Env: [][2]string{
			{"WORDPRESS_DB_HOST", "mariadb"}, {"WORDPRESS_DB_USER", "lab"}, {"WORDPRESS_DB_PASSWORD", labDBPass},
			{"WORDPRESS_DB_NAME", db}, {"LAB_URL", "http://" + ip}, {"LAB_TITLE", title},
			{"LAB_ADMIN_PASSWORD", labAdminPass},
			// The lab network has a route out (docker bridge, not internal). Without
			// this, WordPress 5.8.3 updated itself to the newest release one minute
			// after the start (measured 2026-11-21: 7.1.5), and the ground truth was wrong.
			{"WORDPRESS_CONFIG_EXTRA", "define('AUTOMATIC_UPDATER_DISABLED', true); define('WP_AUTO_UPDATE_CORE', false);"},
		},
		MemMB: 256, DependsOn: []string{"mariadb"},
		Health:   Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1/wp-login.php && test -f /tmp/lab-installed", StartPeriod: "120s"},
		Services: []truth.Service{svc},
	}
}

func netsvc(name, ip string, hostnames []string, group, desc, cmd, health string, svcs ...truth.Service) Container {
	return Container{
		Name: name, IP: ip, Hostnames: hostnames, Group: group, Desc: desc,
		Image: img("netsvc", "1"), Build: custom("netsvc"),
		Command: []string{"sh", "-c", cmd}, MemMB: 64, Init: true,
		Health: Health{Test: health}, Services: svcs,
	}
}

func tcp(port int, name string) truth.Service {
	return truth.Service{Port: port, Proto: "tcp", Name: name}
}

// realContainers lists the hosts that run real software.
func realContainers() []Container {
	later := []string{"t1", "t2"}

	apache := func(v string) truth.Tech {
		return tech("Apache HTTP Server", "web-server", v, "apache", "apache httpd", "apache http server")
	}
	nginxT := func(v string) truth.Tech { return tech("nginx", "web-server", v) }

	wpSvc := func(wpVer, apacheVer, phpVer, title string) truth.Service {
		s := tcp(80, "http")
		s.Product, s.Version = "Apache httpd", apacheVer
		s.Technologies = []truth.Tech{tech("WordPress", "cms", wpVer, "wordpress"), tech("PHP", "language", phpVer, "php"), apache(apacheVer)}
		s.TechOptional = []string{"MySQL", "MariaDB", "jQuery", "Debian", "Gutenberg", "RSS", "Twenty Twenty-One", "Twenty Twenty-Five"}
		s.ClassOptional = []string{"login", "admin-panel"}
		s.HTTP = &truth.HTTP{Status: 200, Title: title, Server: "Apache/" + apacheVer + " (Debian)", Headers: map[string]string{"X-Powered-By": "PHP/" + phpVer}}
		s.Interesting = []truth.Interesting{header("X-Powered-By", "leaks the exact PHP version"), header("Link", "WordPress REST API discovery link")}
		return s
	}

	mariadbInit := strings.Join([]string{
		"CREATE DATABASE IF NOT EXISTS wp_main;",
		"CREATE DATABASE IF NOT EXISTS wp_old;",
		"CREATE DATABASE IF NOT EXISTS wp_new;",
		"CREATE DATABASE IF NOT EXISTS joomla;",
		"GRANT ALL PRIVILEGES ON wp_main.* TO 'lab'@'%';",
		"GRANT ALL PRIVILEGES ON wp_old.* TO 'lab'@'%';",
		"GRANT ALL PRIVILEGES ON wp_new.* TO 'lab'@'%';",
		"GRANT ALL PRIVILEGES ON joomla.* TO 'lab'@'%';",
		"FLUSH PRIVILEGES;", "",
	}, "\n")

	vhostConf := `server {
    listen 80 default_server;
    server_name _;
    default_type "text/html; charset=utf-8";
    location / { return 200 '<!doctype html><html lang="pl"><head><title>Hosting wydziałowy — strona domyślna</title></head><body><h1>Hosting wydziałowy</h1><p>Ten serwer obsługuje kilka witryn. Podaj nazwę witryny.</p></body></html>'; }
}
server {
    listen 80;
    server_name rekrutacja.lab.czujka.test;
    default_type "text/html; charset=utf-8";
    location / { return 200 '<!doctype html><html lang="pl"><head><title>Rekrutacja 2026/2027</title><meta name="generator" content="Hugo 0.139.0"></head><body><h1>Rekrutacja 2026/2027</h1><p>Terminy i zasady przyjęć.</p></body></html>'; }
}
server {
    listen 80;
    server_name intranet.lab.czujka.test;
    default_type "text/html; charset=utf-8";
    add_header X-Frame-Options SAMEORIGIN always;
    location / { return 200 '<!doctype html><html lang="pl"><head><title>Intranet — logowanie</title></head><body><h1>Intranet</h1><form method="get" action="/login"><input name="user"><input type="password" name="pass"><button>Zaloguj</button></form></body></html>'; }
}
`

	dnsHealth := "nslookup www." + Zone + " 127.0.0.1 >/dev/null"

	list := []Container{
		// ---------- CMS (10.66.1.0/24) ----------
		wordpress("wp-main", "10.66.1.10", "www", "6.9.4-php8.3-apache", "wp_main", "Wydział Informatyki AGH (lab)",
			"WordPress 6.9.4, zainstalowany, aktualny", nil,
			wpSvc("6.9.4", "2.4.67", "8.3.31", "Wydział Informatyki AGH (lab)")),
		wordpress("wp-old", "10.66.1.11", "blog", "5.8.3-apache", "wp_old", "Blog Koła Naukowego",
			"WordPress 5.8.3 (przestarzały) w t0; w t1 zastąpiony przez 6.9.4 na tym samym adresie", []string{"t0"},
			wpSvc("5.8.3", "2.4.51", "7.4.27", "Blog Koła Naukowego")),
		wordpress("wp-new", "10.66.1.11", "blog", "6.9.4-php8.3-apache", "wp_new", "Blog Koła Naukowego",
			"WordPress 6.9.4 po aktualizacji (t1, t2)", later,
			wpSvc("6.9.4", "2.4.67", "8.3.31", "Blog Koła Naukowego")),
		{
			Name: "joomla", IP: "10.66.1.20", Hostnames: []string{"biblioteka"}, Group: "cms", Desc: "Joomla 5.4.10, zainstalowana",
			Image: "joomla:5.4.10-php8.3-apache",
			Env: [][2]string{
				{"JOOMLA_DB_HOST", "mariadb"}, {"JOOMLA_DB_USER", "lab"}, {"JOOMLA_DB_PASSWORD", labDBPass}, {"JOOMLA_DB_NAME", "joomla"},
				{"JOOMLA_SITE_NAME", "Biblioteka Glowna"}, {"JOOMLA_ADMIN_USER", "Lab Admin"}, {"JOOMLA_ADMIN_USERNAME", "labadmin"},
				{"JOOMLA_ADMIN_PASSWORD", labAdminPass}, {"JOOMLA_ADMIN_EMAIL", "admin@example.com"},
			},
			MemMB: 256, DependsOn: []string{"mariadb"},
			Health: Health{Test: "curl -fsS -m 3 http://127.0.0.1/ | grep -qi joomla", StartPeriod: "180s"},
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.71",
				Technologies:  []truth.Tech{tech("Joomla", "cms", "5", "joomla!", "joomla"), apache("2.4.71")},
				TechOptional:  []string{"PHP", "MySQL", "MariaDB", "Debian", "Bootstrap", "Cassiopeia", "Font Awesome"},
				ClassOptional: []string{"login", "admin-panel"},
				HTTP:          &truth.HTTP{Status: 200, Title: "Home", Server: "Apache/2.4.71 (Debian)"},
			}},
		},
		{
			Name: "drupal", IP: "10.66.1.30", Hostnames: []string{"repozytorium"}, Group: "cms", Desc: "Drupal 10.6.22, zainstalowany (SQLite)",
			Image: img("drupal", "10.6.22"), Build: custom("drupal"), MemMB: 256,
			Health: Health{Test: "curl -fsS -m 5 -o /dev/null http://127.0.0.1/user/login", StartPeriod: "90s"},
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.71",
				Technologies:  []truth.Tech{tech("Drupal", "cms", "10", "drupal"), tech("PHP", "language", "8.3.37", "php"), apache("2.4.71")},
				TechOptional:  []string{"Debian", "SQLite", "Olivero"},
				ClassOptional: []string{"login", "admin-panel"},
				HTTP: &truth.HTTP{Status: 200, Title: "Welcome! | Repozytorium Prac Dyplomowych", Server: "Apache/2.4.71 (Debian)",
					Headers: map[string]string{"X-Generator": "Drupal 10 (https://www.drupal.org)", "X-Powered-By": "PHP/8.3.37"}},
				Interesting: []truth.Interesting{header("X-Generator", "names the CMS and its major version"), header("X-Powered-By", "leaks the exact PHP version")},
			}},
		},
		{
			Name: "dokuwiki", IP: "10.66.1.40", Hostnames: []string{"wiki"}, Group: "cms", Desc: "DokuWiki 2026-07-14c",
			Image: "dokuwiki/dokuwiki:2026-07-14c", MemMB: 192,
			Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1:8080/ || wget -q -T 3 -O /dev/null http://127.0.0.1:8080/", StartPeriod: "60s"},
			Services: []truth.Service{{
				Port: 8080, Proto: "tcp", Name: "http", Product: "Apache httpd",
				Technologies:  []truth.Tech{tech("DokuWiki", "cms", "", "dokuwiki"), tech("PHP", "language", "8.4.28", "php"), apache("")},
				TechOptional:  []string{"jQuery", "Debian", "jQuery UI"},
				ClassOptional: []string{"login"},
				HTTP: &truth.HTTP{Status: 200, Title: "start [DokuWiki]", Server: "Apache", Headers: map[string]string{"X-Powered-By": "PHP/8.4.28"},
					Cookies: []truth.Cookie{{Name: "DokuWiki", HTTPOnly: true, SameSite: "lax"}}},
				Interesting: []truth.Interesting{cookie("DokuWiki", "session cookie without Secure"), header("X-Powered-By", "leaks the exact PHP version")},
			}},
		},

		// ---------- web servers (10.66.2.0/24) ----------
		{
			Name: "nginx-old", IP: "10.66.2.10", Hostnames: []string{"static"}, Group: "web", Desc: "nginx 1.24.0 (strona domyślna) w t0", In: []string{"t0"},
			Image: "nginx:1.24.0-alpine", MemMB: 32, Health: httpHealth(80, "/"),
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.24.0",
				Technologies: []truth.Tech{nginxT("1.24.0")}, Classes: []string{"default-page"},
				HTTP: &truth.HTTP{Status: 200, Title: "Welcome to nginx!", Server: "nginx/1.24.0"},
			}},
		},
		{
			Name: "nginx-new", IP: "10.66.2.10", Hostnames: []string{"static"}, Group: "web", Desc: "nginx 1.30.7 po aktualizacji (t1, t2)", In: later,
			Image: "nginx:1.30.7-alpine", MemMB: 32, Health: httpHealth(80, "/"),
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.30.7",
				Technologies: []truth.Tech{nginxT("1.30.7")}, Classes: []string{"default-page"},
				HTTP: &truth.HTTP{Status: 200, Title: "Welcome to nginx!", Server: "nginx/1.30.7"},
			}},
		},
		{
			Name: "httpd", IP: "10.66.2.11", Hostnames: []string{"www2"}, Group: "web", Desc: "Apache httpd 2.4.71 (strona domyślna „It works!”)",
			Image: "httpd:2.4.71-alpine", MemMB: 48, Health: httpHealth(80, "/"),
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.71",
				Technologies: []truth.Tech{apache("2.4.71")}, Classes: []string{"default-page"},
				HTTP: &truth.HTTP{Status: 200, Title: "It works! Apache httpd", Server: "Apache/2.4.71 (Unix)"},
			}},
		},
		{
			Name: "caddy", IP: "10.66.2.12", Hostnames: []string{"caddy"}, Group: "web", Desc: "Caddy 2.11.9: HTTP → HTTPS, certyfikat z wewnętrznego CA Caddy",
			Image: "caddy:2.11.9-alpine", MemMB: 64,
			Configs: []ConfigFile{{Target: "/etc/caddy/Caddyfile", Content: "{\n\tadmin off\n}\ncaddy." + Zone + ", 10.66.2.12 {\n\ttls internal\n\troot * /usr/share/caddy\n\tfile_server\n}\n"}},
			Health:  Health{Test: "wget -q -T 3 -O /dev/null --no-check-certificate https://127.0.0.1/ || nc -z 127.0.0.1 443"},
			Services: []truth.Service{
				{
					Port: 80, Proto: "tcp", Name: "http", Product: "Caddy httpd",
					Technologies: []truth.Tech{tech("Caddy", "web-server", "", "caddy httpd")},
					HTTP:         &truth.HTTP{Status: 308, Location: "https://10.66.2.12/", Server: "Caddy"},
				},
				{
					Port: 443, Proto: "tcp", Name: "http", Tunnel: "ssl", Product: "Caddy httpd",
					Technologies: []truth.Tech{tech("Caddy", "web-server", "", "caddy httpd")}, Classes: []string{"default-page"},
					HTTP: &truth.HTTP{Status: 200, Title: "Caddy works!", Server: "Caddy"},
					TLS:  &truth.TLS{SubjectCN: "", SANs: []string{"10.66.2.12"}, IssuerCN: "Caddy Local Authority - ECC Intermediate", DaysLeft: 0},
				},
			},
		},
		{
			Name: "vhosts", IP: "10.66.2.20", Hostnames: []string{"hosting", "rekrutacja", "intranet"}, Group: "web",
			Desc:  "nginx 1.30.7 z wirtualnymi hostami: domyślny, rekrutacja, intranet (logowanie)",
			Image: "nginx:1.30.7-alpine", MemMB: 32, Health: httpHealth(80, "/"),
			Configs: []ConfigFile{{Target: "/etc/nginx/conf.d/default.conf", Content: vhostConf}},
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.30.7",
				Technologies: []truth.Tech{nginxT("1.30.7")}, TechOptional: []string{"Hugo"}, ClassOptional: []string{"login"},
				HTTP: &truth.HTTP{Status: 200, Title: "Hosting wydziałowy — strona domyślna", Server: "nginx/1.30.7",
					VHosts: []truth.VHost{{Host: "rekrutacja." + Zone, Title: "Rekrutacja 2026/2027"}, {Host: "intranet." + Zone, Title: "Intranet — logowanie"}}},
			}},
		},

		// ---------- frameworks and app servers (10.66.3.0/24) ----------
		{
			Name: "tomcat", IP: "10.66.3.10", Hostnames: []string{"tomcat"}, Group: "app", Desc: "Apache Tomcat 10.1.62: strona domyślna i /manager/html (401)",
			Image: img("tomcat", "10.1.62"), Build: custom("tomcat"), MemMB: 384, Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1:8080/ || wget -q -T 3 -O /dev/null http://127.0.0.1:8080/", StartPeriod: "90s"},
			Services: []truth.Service{{
				Port: 8080, Proto: "tcp", Name: "http", Product: "Apache Tomcat", Version: "10.1.62",
				Technologies: []truth.Tech{tech("Apache Tomcat", "app-server", "10.1.62", "tomcat", "apache tomcat/coyote jsp engine")},
				TechOptional: []string{"Java"}, Classes: []string{"default-page"}, ClassOptional: []string{"admin-panel", "login"},
				HTTP: &truth.HTTP{Status: 200, Title: "Apache Tomcat/10.1.62"},
			}},
		},
		{
			Name: "spring", IP: "10.66.3.11", Hostnames: []string{"oceny-api"}, Group: "app", Desc: "Spring Boot 3.4 z otwartym Actuatorem (/actuator, /actuator/env)",
			Image: img("spring", "1"), Build: custom("spring"), MemMB: 384,
			Health: Health{Test: "wget -q -T 3 -O /dev/null http://127.0.0.1:8080/actuator/health", StartPeriod: "120s"},
			Services: []truth.Service{{
				Port: 8080, Proto: "tcp", Name: "http", Product: "Apache Tomcat",
				Technologies: []truth.Tech{tech("Spring Boot", "framework", "", "spring", "spring boot actuator", "spring framework")},
				TechOptional: []string{"Java", "Apache Tomcat"}, Classes: []string{"api"}, ClassOptional: []string{"error-page", "dev-tool"},
				HTTP: &truth.HTTP{Status: 404},
			}},
		},
		{
			Name: "django", IP: "10.66.3.12", Hostnames: []string{"dev-django"}, Group: "app", Desc: "Django 5.2 w trybie DEBUG (runserver), /admin/",
			Image: img("pyapps", "1"), Build: custom("pyapps"), MemMB: 128,
			Command: []string{"python", "/app/django/manage.py", "runserver", "0.0.0.0:8000", "--noreload"},
			Health:  httpHealth(8000, "/"),
			Services: []truth.Service{{
				Port: 8000, Proto: "tcp", Name: "http", Product: "WSGIServer", Version: "0.2",
				Technologies: []truth.Tech{tech("Django", "framework", "", "django"), tech("Python", "language", "3.13.18", "python", "cpython")},
				TechOptional: []string{"WSGIServer"}, Classes: []string{"default-page"}, ClassOptional: []string{"staging", "dev-tool", "admin-panel", "login"},
				HTTP:        &truth.HTTP{Status: 200, Title: "The install worked successfully! Congratulations!", Server: "WSGIServer/0.2 CPython/3.13.18"},
				Interesting: []truth.Interesting{header("Server", "development server exposed, with the exact Python version")},
			}},
		},
		{
			Name: "flask", IP: "10.66.3.13", Hostnames: []string{"sale"}, Group: "app", Desc: "Flask 3 za gunicorn 23, ciasteczko sesji o kształcie JWT bez Secure",
			Image: img("pyapps", "1"), Build: custom("pyapps"), MemMB: 128,
			Command: []string{"gunicorn", "--chdir", "/app/flask", "-w", "1", "-b", "0.0.0.0:5000", "app:app"},
			Health:  httpHealth(5000, "/"),
			Services: []truth.Service{{
				Port: 5000, Proto: "tcp", Name: "http", Product: "Gunicorn",
				Technologies: []truth.Tech{tech("gunicorn", "app-server", "", "gunicorn"), tech("Flask", "framework", "", "flask")},
				TechOptional: []string{"Python"}, ClassOptional: []string{"login"},
				HTTP: &truth.HTTP{Status: 200, Title: "Rezerwacja sal — WIMiIP", Server: "gunicorn",
					Cookies: []truth.Cookie{{Name: "session", HTTPOnly: true}}},
				Interesting: []truth.Interesting{cookie("session", "signed Flask session, base64 JSON readable by anyone, no Secure flag")},
			}},
		},
		{
			Name: "express", IP: "10.66.3.14", Hostnames: []string{"status"}, Group: "app", Desc: "Node.js 22 + Express 4, connect.sid, CORS *",
			Image: img("express", "1"), Build: custom("express"), MemMB: 128, Health: httpHealth(3000, "/"),
			Services: []truth.Service{{
				Port: 3000, Proto: "tcp", Name: "http", Product: "Node.js Express framework", NameAlt: []string{"ppp"},
				Technologies:  []truth.Tech{tech("Express", "framework", "", "express", "express.js", "node.js express framework"), tech("Node.js", "language", "", "node", "nodejs")},
				ClassOptional: []string{"api"},
				HTTP: &truth.HTTP{Status: 200, Title: "Status usług — panel publiczny",
					Headers: map[string]string{"X-Powered-By": "Express", "Access-Control-Allow-Origin": "*"},
					Cookies: []truth.Cookie{{Name: "connect.sid", HTTPOnly: true}}},
				Interesting: []truth.Interesting{header("X-Powered-By", "names the framework"), header("Access-Control-Allow-Origin", "wildcard CORS"), cookie("connect.sid", "session cookie without Secure")},
			}},
		},
		{
			Name: "laravel", IP: "10.66.3.15", Hostnames: []string{"rekrutacja-app"}, Group: "app", Desc: "Laravel 12 (APP_DEBUG=true), ciasteczka XSRF-TOKEN i laravel_session",
			Image: img("laravel", "1"), Build: custom("laravel"), MemMB: 192, Health: Health{Test: "wget -q -T 5 -O /dev/null http://127.0.0.1:8000/up", StartPeriod: "60s"},
			Services: []truth.Service{{
				Port: 8000, Proto: "tcp", Name: "http",
				Technologies: []truth.Tech{tech("Laravel", "framework", "", "laravel"), tech("PHP", "language", "8.4.28", "php")},
				TechOptional: []string{"Tailwind CSS", "Vite"}, ClassOptional: []string{"default-page", "staging"},
				HTTP: &truth.HTTP{Status: 200, Title: "Laravel", Headers: map[string]string{"X-Powered-By": "PHP/8.4.28"},
					Cookies: []truth.Cookie{{Name: "XSRF-TOKEN", SameSite: "lax"}, {Name: "laravel_session", HTTPOnly: true, SameSite: "lax"}}},
				Interesting: []truth.Interesting{header("X-Powered-By", "leaks the exact PHP version"), cookie("laravel_session", "names the framework; no Secure flag"), cookie("XSRF-TOKEN", "readable by scripts by design; no Secure flag")},
			}},
		},
		{
			Name: "legacy-php", IP: "10.66.3.16", Hostnames: []string{"rezerwacje"}, Group: "app", In: []string{"t0", "t2"},
			Desc:  "PHP 7.4.33 (koniec wsparcia) na Apache, PHPSESSID bez flag, /info.php; znika w t1, wraca w t2",
			Image: img("legacy-php", "1"), Build: custom("legacy-php"), MemMB: 96, Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1/"},
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.54",
				Technologies: []truth.Tech{tech("PHP", "language", "7.4.33", "php"), apache("2.4.54")},
				TechOptional: []string{"Debian", "RoomBooker"}, ClassOptional: []string{"login"},
				HTTP: &truth.HTTP{Status: 200, Title: "System Rezerwacji Sal", Server: "Apache/2.4.54 (Debian)",
					Headers: map[string]string{"X-Powered-By": "PHP/7.4.33"}, Cookies: []truth.Cookie{{Name: "PHPSESSID"}}},
				Interesting: []truth.Interesting{header("X-Powered-By", "end-of-life PHP version"), cookie("PHPSESSID", "session cookie without Secure and HttpOnly")},
			}},
		},

		// ---------- admin panels and dev tools (10.66.10.0/24) ----------
		{
			Name: "phpmyadmin", IP: "10.66.10.10", Hostnames: []string{"pma"}, Group: "panel", Desc: "phpMyAdmin 5.2.3",
			Image: "phpmyadmin:5.2.3-apache", Env: [][2]string{{"PMA_HOST", "mariadb"}}, MemMB: 192, DependsOn: []string{"mariadb"},
			Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1/"},
			Services: []truth.Service{{
				Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.71",
				Technologies: []truth.Tech{tech("phpMyAdmin", "panel", "5.2.3", "phpmyadmin"), tech("PHP", "language", "8.3.37", "php"), apache("2.4.71")},
				TechOptional: []string{"MySQL", "MariaDB", "Debian", "jQuery", "Bootstrap"}, Classes: []string{"admin-panel", "login"}, ClassOptional: []string{"database"},
				HTTP: &truth.HTTP{Status: 200, Title: "phpMyAdmin", Server: "Apache/2.4.71 (Debian)", Headers: map[string]string{"X-Powered-By": "PHP/8.3.37"},
					Cookies: []truth.Cookie{{Name: "phpMyAdmin", HTTPOnly: true, SameSite: "strict"}, {Name: "pma_lang", HTTPOnly: true, SameSite: "strict"}}},
				Interesting: []truth.Interesting{cookie("phpMyAdmin", "names the admin panel"), header("X-Powered-By", "leaks the exact PHP version")},
			}},
		},
		{
			Name: "adminer", IP: "10.66.10.11", Hostnames: []string{"adminer"}, Group: "panel", Desc: "Adminer 5.5.1",
			Image: "adminer:5.5.1-standalone", MemMB: 96, Health: Health{Test: "php -r 'exit(@file_get_contents(\"http://127.0.0.1:8080/\") === false ? 1 : 0);'"},
			Services: []truth.Service{{
				Port: 8080, Proto: "tcp", Name: "http",
				Technologies: []truth.Tech{tech("Adminer", "panel", "5.5.1", "adminer"), tech("PHP", "language", "8.4.28", "php")},
				Classes:      []string{"admin-panel", "login"}, ClassOptional: []string{"database"},
				HTTP: &truth.HTTP{Status: 200, Title: "Login - Adminer", Headers: map[string]string{"X-Powered-By": "PHP/8.4.28"},
					Cookies: []truth.Cookie{{Name: "adminer_sid", HTTPOnly: true}, {Name: "adminer_key", HTTPOnly: true, SameSite: "lax"}}},
				Interesting: []truth.Interesting{header("X-Powered-By", "leaks the exact PHP version"), cookie("adminer_sid", "names the admin panel")},
			}},
		},
		{
			Name: "shadow-adminer", IP: "10.66.5.5", Group: "shadow", In: []string{"t1"},
			Desc:  "„Shadow IT”: Adminer 4.17.1 postawiony na nowym adresie; pojawia się w t1, znika w t2",
			Image: "adminer:4.17.1-standalone", MemMB: 96, Health: Health{Test: "php -r 'exit(@file_get_contents(\"http://127.0.0.1:8080/\") === false ? 1 : 0);'"},
			Services: []truth.Service{{
				Port: 8080, Proto: "tcp", Name: "http",
				Technologies: []truth.Tech{tech("Adminer", "panel", "4.17.1", "adminer"), tech("PHP", "language", "", "php")},
				Classes:      []string{"admin-panel", "login"}, ClassOptional: []string{"database"},
				HTTP:        &truth.HTTP{Status: 200, Title: "Login - Adminer"},
				Interesting: []truth.Interesting{header("X-Powered-By", "leaks the exact PHP version")},
			}},
		},
		{
			Name: "grafana", IP: "10.66.10.20", Hostnames: []string{"grafana"}, Group: "panel", Desc: "Grafana 12.4.15 (strona logowania)",
			Image: "grafana/grafana:12.4.15", MemMB: 384,
			Env:    [][2]string{{"GF_ANALYTICS_REPORTING_ENABLED", "false"}, {"GF_ANALYTICS_CHECK_FOR_UPDATES", "false"}, {"GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES", "false"}, {"GF_PLUGINS_PREINSTALL_DISABLED", "true"}},
			Health: Health{Test: "wget -q -T 3 -O /dev/null http://127.0.0.1:3000/api/health", StartPeriod: "120s"},
			Services: []truth.Service{{
				Port: 3000, Proto: "tcp", Name: "http", NameAlt: []string{"ppp"}, Product: "Grafana http",
				Technologies: []truth.Tech{tech("Grafana", "panel", "12.4.15", "grafana")},
				TechOptional: []string{"Go", "React"}, Classes: []string{"login"}, ClassOptional: []string{"admin-panel", "dev-tool"},
				HTTP: &truth.HTTP{Status: 302, Location: "/login", Title: "Grafana"},
			}},
		},
		{
			Name: "prometheus", IP: "10.66.10.21", Hostnames: []string{"prometheus"}, Group: "panel", Desc: "Prometheus 3.16.0 bez uwierzytelniania",
			Image: "prom/prometheus:v3.16.0", MemMB: 192, Health: Health{Test: "wget -q -T 3 -O /dev/null http://127.0.0.1:9090/-/healthy"},
			Services: []truth.Service{{
				Port: 9090, Proto: "tcp", Name: "http", NameAlt: []string{"zeus-admin"}, Product: "Golang net/http server",
				Technologies: []truth.Tech{tech("Prometheus", "devops", "", "prometheus", "prometheus time series collection and processing server")},
				TechOptional: []string{"Go", "React", "Mantine"}, ClassOptional: []string{"dev-tool", "admin-panel"},
				HTTP: &truth.HTTP{Status: 302, Location: "/query", Title: "Prometheus Time Series Collection and Processing Server"},
			}},
		},
		{
			Name: "jenkins", IP: "10.66.10.30", Hostnames: []string{"ci"}, Group: "panel", Desc: "Jenkins 2.580.2 LTS bez logowania (kreator wyłączony)",
			Image: "jenkins/jenkins:2.580.2-lts-jdk21", MemMB: 768,
			Env:    [][2]string{{"JAVA_OPTS", "-Xmx384m -Djenkins.install.runSetupWizard=false -Dhudson.model.UpdateCenter.never=true"}},
			Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1:8080/login", StartPeriod: "240s"},
			Services: []truth.Service{
				{
					Port: 8080, Proto: "tcp", Name: "http", Product: "Jetty", Version: "12.1.14",
					Technologies: []truth.Tech{tech("Jenkins", "devops", "2.580.2", "jenkins"), tech("Jetty", "web-server", "12.1.14", "jetty", "eclipse jetty")},
					TechOptional: []string{"Java"}, Classes: []string{"dev-tool"}, ClassOptional: []string{"admin-panel", "login"},
					HTTP:        &truth.HTTP{Status: 200, Title: "Dashboard - Jenkins", Server: "Jetty(12.1.14)", Headers: map[string]string{"X-Jenkins": "2.580.2"}},
					Interesting: []truth.Interesting{header("X-Jenkins", "leaks the exact Jenkins version"), header("X-Jenkins-Session", "Jenkins instance marker")},
				},
				{Port: 50000, Proto: "tcp", Name: "jenkins-agent", NameAlt: []string{"http", "jenkins-listener", "ibm-db2", "unknown"}, Hard: "name-unknown",
					TechOptional: []string{"Jenkins"}, ClassOptional: []string{"dev-tool"}},
			},
		},
		{
			Name: "gitea", IP: "10.66.10.31", Hostnames: []string{"git"}, Group: "panel", Desc: "Gitea 1.27.3 (HTTP 3000, SSH 22)",
			Image: "gitea/gitea:1.27.3", MemMB: 384,
			Env: [][2]string{{"GITEA__security__INSTALL_LOCK", "true"}, {"GITEA__database__DB_TYPE", "sqlite3"}, {"GITEA__server__ROOT_URL", "http://10.66.10.31:3000/"},
				{"GITEA__server__OFFLINE_MODE", "true"}},
			Health: Health{Test: "curl -fsS -m 3 -o /dev/null http://127.0.0.1:3000/api/healthz", StartPeriod: "120s"},
			Services: []truth.Service{
				{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "10.3", Technologies: []truth.Tech{tech("OpenSSH", "other", "10.3", "openssh")}, Classes: []string{"remote-access"}},
				{
					Port: 3000, Proto: "tcp", Name: "http", NameAlt: []string{"ppp"}, Product: "Golang net/http server",
					Technologies: []truth.Tech{tech("Gitea", "devops", "", "gitea")}, TechOptional: []string{"Go", "Vue.js", "Fomantic UI"},
					Classes: []string{"dev-tool"}, ClassOptional: []string{"login"},
					HTTP:        &truth.HTTP{Status: 200, Title: "Gitea: Git with a cup of tea", Cookies: []truth.Cookie{{Name: "i_like_gitea", HTTPOnly: true, SameSite: "lax"}}},
					Interesting: []truth.Interesting{cookie("i_like_gitea", "names the product")},
				},
			},
		},
		{
			Name: "portainer", IP: "10.66.10.40", Hostnames: []string{"portainer"}, Group: "panel", Desc: "Portainer CE 2.39.9 (HTTP 9000, HTTPS 9443 self-signed, 8000)",
			Image: "portainer/portainer-ce:2.39.9-alpine", MemMB: 192,
			Configs: []ConfigFile{{Target: "/run/lab/portainer-pass", Content: labAdminPass}},
			Command: []string{"--admin-password-file", "/run/lab/portainer-pass"},
			Health:  Health{Test: "wget -q -T 3 -O /dev/null http://127.0.0.1:9000/api/system/status", StartPeriod: "90s"},
			Services: []truth.Service{
				{Port: 8000, Proto: "tcp", Name: "unknown", NameAlt: []string{"http", "nagios-nsca"}, Hard: "name-unknown", TechOptional: []string{"Portainer", "Go"}},
				{
					Port: 9000, Proto: "tcp", Name: "http", NameAlt: []string{"cslistener"}, Product: "Golang net/http server",
					Technologies: []truth.Tech{tech("Portainer", "panel", "", "portainer")}, TechOptional: []string{"Go", "AngularJS", "React"},
					Classes: []string{"admin-panel"}, ClassOptional: []string{"login", "dev-tool"},
					HTTP: &truth.HTTP{Status: 200, Title: "Portainer"},
				},
				{
					Port: 9443, Proto: "tcp", Name: "http", Tunnel: "ssl", NameAlt: []string{"tungsten-https"}, Product: "Golang net/http server",
					Technologies: []truth.Tech{tech("Portainer", "panel", "", "portainer")}, TechOptional: []string{"Go", "AngularJS", "React"},
					Classes: []string{"admin-panel"}, ClassOptional: []string{"login", "dev-tool"},
					HTTP: &truth.HTTP{Status: 200, Title: "Portainer"},
					TLS:  &truth.TLS{SelfSigned: true, DaysLeft: 0},
				},
			},
		},
		{
			Name: "rabbitmq", IP: "10.66.10.41", Hostnames: []string{"mq"}, Group: "panel", Desc: "RabbitMQ 4.3.8 z panelem zarządzania (15672)",
			Image: "rabbitmq:4.3.8-management-alpine", MemMB: 512,
			// Not rabbitmq-diagnostics: run as root before the server starts, it creates
			// the Erlang cookie with root ownership and the server then exits with "eacces".
			Health: Health{Test: "wget -q -O /dev/null http://127.0.0.1:15672/ && nc -z 127.0.0.1 5672", StartPeriod: "180s"},
			Services: []truth.Service{
				{Port: 4369, Proto: "tcp", Name: "epmd", Product: "Erlang Port Mapper Daemon"},
				{Port: 5672, Proto: "tcp", Name: "amqp", Product: "RabbitMQ", Version: "4.3.8", Technologies: []truth.Tech{tech("RabbitMQ", "other", "4.3.8", "rabbitmq")}},
				{
					Port: 15672, Proto: "tcp", Name: "http", Product: "Cowboy httpd",
					Technologies: []truth.Tech{tech("RabbitMQ", "panel", "", "rabbitmq", "rabbitmq management")}, TechOptional: []string{"Cowboy", "Erlang"},
					Classes: []string{"admin-panel", "login"},
					HTTP:    &truth.HTTP{Status: 200, Title: "RabbitMQ Management", Server: "Cowboy"},
				},
				{Port: 15692, Proto: "tcp", Name: "http", Product: "Cowboy httpd", NameAlt: []string{"unknown"}, TechOptional: []string{"Cowboy", "RabbitMQ", "Erlang", "Prometheus"}, ClassOptional: []string{"api"}},
				{Port: 25672, Proto: "tcp", Name: "unknown", NameAlt: []string{"erlang-distribution", "rabbitmq"}, Hard: "name-unknown"},
			},
		},
		{
			Name: "pgadmin", IP: "10.66.10.50", Hostnames: []string{"pgadmin"}, Group: "panel", Desc: "pgAdmin 4 9.19 (strona logowania); obraz wystawia też Postfix na porcie 25",
			Image: "dpage/pgadmin4:9.19.0", MemMB: 512,
			Env: [][2]string{{"PGADMIN_DEFAULT_EMAIL", "admin@example.com"}, {"PGADMIN_DEFAULT_PASSWORD", labAdminPass},
				{"PGADMIN_CONFIG_UPGRADE_CHECK_ENABLED", "False"}, {"GUNICORN_THREADS", "4"}},
			Health: Health{Test: "wget -q -T 3 -O /dev/null http://127.0.0.1/misc/ping", StartPeriod: "180s"},
			Services: []truth.Service{
				// The pgAdmin image starts Postfix for password-reset mail and leaves it open on all interfaces.
				{Port: 25, Proto: "tcp", Name: "smtp", Product: "Postfix smtpd", Technologies: []truth.Tech{tech("Postfix", "other", "", "postfix", "postfix smtpd")}},
				{
					Port: 80, Proto: "tcp", Name: "http", Product: "Gunicorn",
					Technologies: []truth.Tech{tech("pgAdmin", "panel", "", "pgadmin", "pgadmin 4", "pgadmin4")}, TechOptional: []string{"gunicorn", "Python", "Flask", "PostgreSQL", "React"},
					Classes: []string{"admin-panel", "login"}, ClassOptional: []string{"database"},
					HTTP:        &truth.HTTP{Status: 302, Location: "/login?next=/", Title: "pgAdmin 4", Server: "gunicorn", Cookies: []truth.Cookie{{Name: "pga4_session", HTTPOnly: true, SameSite: "lax"}}},
					Interesting: []truth.Interesting{cookie("pga4_session", "names the admin panel; no Secure flag")},
				},
			},
		},

		// ---------- non-HTTP services (10.66.20.0/24) ----------
		{
			Name: "mariadb", IP: "10.66.20.10", Hostnames: []string{"db"}, Group: "infra", Desc: "MariaDB 11.4.13 (3306), wspólna baza CMS-ów",
			Image: "mariadb:11.4.13", MemMB: 512,
			Env: [][2]string{{"MARIADB_ROOT_PASSWORD", "lab-root-pass"}, {"MARIADB_USER", "lab"}, {"MARIADB_PASSWORD", labDBPass}},
			// max-connect-errors: service probes close the connection before the handshake. After 100
			// of them MariaDB blocks the scanner address and the version banner disappears.
			Command: []string{"--innodb-buffer-pool-size=96M", "--performance-schema=OFF", "--skip-name-resolve", "--max-connect-errors=4294967295"},
			Configs: []ConfigFile{{Target: "/docker-entrypoint-initdb.d/lab.sql", Content: mariadbInit}},
			Health:  Health{Test: "healthcheck.sh --connect --innodb_initialized", StartPeriod: "120s"},
			Services: []truth.Service{{
				Port: 3306, Proto: "tcp", Name: "mysql", Product: "MariaDB", Version: "11.4.13",
				// MariaDB offers TLS with a self-signed certificate ("MariaDB Server"). nmap reads it
				// in some runs only, so the truth does not require it.
				Technologies: []truth.Tech{tech("MariaDB", "database", "11.4.13", "mariadb", "mysql")}, Classes: []string{"database"},
			}},
		},
		{
			Name: "postgres", IP: "10.66.20.11", Hostnames: []string{"pg"}, Group: "infra", Desc: "PostgreSQL 17.12 (5432)",
			Image: "postgres:17.12-alpine", MemMB: 192, Env: [][2]string{{"POSTGRES_PASSWORD", labDBPass}},
			Health: Health{Test: "pg_isready -U postgres -h 127.0.0.1"},
			Services: []truth.Service{{
				Port: 5432, Proto: "tcp", Name: "postgresql", Product: "PostgreSQL DB",
				Technologies: []truth.Tech{tech("PostgreSQL", "database", "", "postgresql", "postgresql db", "postgres")}, Classes: []string{"database"},
			}},
		},
		{
			Name: "redis", IP: "10.66.20.12", Hostnames: []string{"cache"}, Group: "infra", Desc: "Redis 7.4.12 bez hasła (6379)",
			Image: "redis:7.4.12-alpine", MemMB: 64, Command: []string{"redis-server", "--protected-mode", "no", "--save", ""},
			Health: Health{Test: "redis-cli ping | grep -q PONG"},
			Services: []truth.Service{{
				Port: 6379, Proto: "tcp", Name: "redis", Product: "Redis key-value store", Version: "7.4.12",
				Technologies: []truth.Tech{tech("Redis", "database", "7.4.12", "redis", "redis key-value store")}, Classes: []string{"database"},
			}},
		},
		{
			Name: "memcached", IP: "10.66.20.13", Hostnames: []string{"memcache"}, Group: "infra", Desc: "memcached 1.6.45 (11211)",
			Image: "memcached:1.6.45-alpine", MemMB: 64, Command: []string{"memcached", "-m", "16"},
			Health: Health{Test: "echo version | nc -w 2 127.0.0.1 11211 | grep -q VERSION"},
			Services: []truth.Service{{
				Port: 11211, Proto: "tcp", Name: "memcached", NameAlt: []string{"memcache"}, Product: "Memcached", Version: "1.6.45",
				Technologies: []truth.Tech{tech("Memcached", "database", "1.6.45", "memcached", "memcache")}, Classes: []string{"database"},
			}},
		},
		func() Container {
			c := netsvc("ftp", "10.66.20.20", []string{"ftp"}, "infra", "vsftpd (21), dostęp anonimowy; znika w t1",
				"exec vsftpd /etc/vsftpd/lab.conf", "nc -z 127.0.0.1 21",
				truth.Service{Port: 21, Proto: "tcp", Name: "ftp", Product: "vsftpd", Version: "3.0.5", Technologies: []truth.Tech{tech("vsftpd", "other", "3.0.5", "vsftpd")}, ClassOptional: []string{"remote-access"}})
			c.In = []string{"t0"}
			return c
		}(),
		netsvc("smtp", "10.66.20.21", []string{"mail"}, "infra", "Postfix (25)",
			"postfix start-fg", "nc -z 127.0.0.1 25",
			truth.Service{Port: 25, Proto: "tcp", Name: "smtp", Product: "Postfix smtpd", Technologies: []truth.Tech{tech("Postfix", "other", "", "postfix", "postfix smtpd")}}),
		{
			Name: "mqtt", IP: "10.66.20.22", Hostnames: []string{"mqtt"}, Group: "infra", Desc: "Eclipse Mosquitto 2.0.23 (1883), dostęp anonimowy",
			Image: "eclipse-mosquitto:2.0.23", MemMB: 32,
			Configs: []ConfigFile{{Target: "/mosquitto/config/mosquitto.conf", Content: "listener 1883 0.0.0.0\nallow_anonymous true\npersistence false\n"}},
			Health:  Health{Test: "mosquitto_sub -h 127.0.0.1 -t '$SYS/broker/version' -C 1 -W 3 >/dev/null"},
			Services: []truth.Service{{
				Port: 1883, Proto: "tcp", Name: "mqtt", NameAlt: []string{"mosquitto*"}, Technologies: []truth.Tech{tech("Mosquitto", "other", "2.0.23", "mosquitto", "eclipse mosquitto")},
			}},
		},
		netsvc("dns", DNSIP, []string{"ns1"}, "infra", "dnsmasq: strefa "+Zone+" (53/tcp, 53/udp)",
			"exec dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq-lab.conf", dnsHealth,
			truth.Service{Port: 53, Proto: "tcp", Name: "domain", Product: "dnsmasq", Version: "2.92rel2", Technologies: []truth.Tech{tech("dnsmasq", "other", "2.92", "dnsmasq")}},
			truth.Service{Port: 53, Proto: "udp", Name: "domain", Product: "dnsmasq", Version: "2.92rel2", Hard: "udp", Technologies: []truth.Tech{tech("dnsmasq", "other", "2.92", "dnsmasq")}}),
		netsvc("ssh-new", "10.66.20.30", []string{"bastion"}, "infra", "OpenSSH 10.3 (Alpine 3.24), port 22",
			"ssh-keygen -A >/dev/null && exec /usr/sbin/sshd -D -e", "nc -z 127.0.0.1 22",
			truth.Service{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "10.3", Technologies: []truth.Tech{tech("OpenSSH", "other", "10.3", "openssh")}, Classes: []string{"remote-access"}}),
		{
			Name: "ssh-old", IP: "10.66.20.31", Hostnames: []string{"stary-serwer"}, Group: "infra", Desc: "OpenSSH 7.9 (Alpine 3.9, przestarzały), port 22",
			Image: img("ssh-old", "1"), Build: custom("ssh-old"), MemMB: 32, Health: Health{Test: "nc -z 127.0.0.1 22"},
			Services: []truth.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "7.9",
				Technologies: []truth.Tech{tech("OpenSSH", "other", "7.9", "openssh")}, Classes: []string{"remote-access"}}},
		},
		netsvc("snmp", "10.66.20.40", []string{"ups"}, "infra", "net-snmp (161/udp): host tylko z usługą UDP",
			"exec snmpd -f -Lo -C -c /etc/snmp/lab-snmpd.conf", "snmpget -v2c -c public -t 2 127.0.0.1 1.3.6.1.2.1.1.5.0 >/dev/null",
			truth.Service{Port: 161, Proto: "udp", Name: "snmp", Product: "SNMPv1 server; net-snmp SNMPv3 server", Hard: "udp", Technologies: []truth.Tech{tech("Net-SNMP", "other", "", "net-snmp", "snmp")}, TechOptional: []string{"APC"}}),
		netsvc("ntp", "10.66.20.41", []string{"ntp"}, "infra", "chrony (123/udp): host tylko z usługą UDP",
			"exec chronyd -d -x -u root -f /etc/chrony/lab-chrony.conf", "pidof chronyd >/dev/null",
			truth.Service{Port: 123, Proto: "udp", Name: "ntp", Product: "NTP", Version: "v4", Hard: "udp", TechOptional: []string{"chrony", "NTP"}}),
		{
			Name: "vnc", IP: "10.66.20.50", Hostnames: []string{"pracownia-vnc"}, Group: "infra", Desc: "TigerVNC (5900), wymaga hasła",
			Image: img("vnc", "1"), Build: custom("vnc"), MemMB: 128, Health: Health{Test: "nc -z 127.0.0.1 5900"},
			Services: []truth.Service{
				{Port: 5900, Proto: "tcp", Name: "vnc", Product: "VNC", Technologies: []truth.Tech{tech("VNC", "other", "", "vnc", "tigervnc")}, Classes: []string{"remote-access"}},
			},
		},

		// ---------- tooling ----------
		{
			Name: "scanner-box", IP: ScannerIP, Group: "tools", Desc: "skrzynka skanera: nmap, curl, dig (nie jest hostem laboratorium)",
			Image: img("scanner-box", "1"), Build: &Build{Context: "scanner-box"}, Command: []string{"sleep", "infinity"},
			CapAdd: []string{"NET_RAW", "NET_ADMIN"}, MemMB: 512, DNS: DNSIP, StateRW: true, NotAHost: true,
			Health: Health{Test: "nmap --version >/dev/null"},
		},
	}
	// dnsmasq needs the zone; it is filled in by the generator (see Lab.DNSConfig).
	return list
}
