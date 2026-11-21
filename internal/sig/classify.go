package sig

import (
	"regexp"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// The classifier adds service classes from generic heuristics. Signatures add
// classes too (their "classes" field); Match returns the union.

var (
	passwordInputRe = regexp.MustCompile(`(?i)<input\b[^>]{0,400}\btype\s*=\s*["']?password`)
	adminTitleRe    = regexp.MustCompile(`(?i)\b(admin|administrator|administration|administracja|administracyjny|administratora|control panel|management console|management interface|web console|panel sterowania|panel zarz[aą]dzania|webadmin|sysadmin)\b`)
	adminPathRe     = regexp.MustCompile(`(?i)/(admin|administrator|administration|wp-admin|manage|manager|management|console|cpanel|webadmin|controlpanel|adminpanel|admin-console|sysadmin|backend|backoffice)(/|\.php|\.aspx?|\.jsp|\.do|$|\?)`)
	stagingLabelRe  = regexp.MustCompile(`(?i)(^|[.\-_])(dev|devel|develop|development|test|tst|testing|tests|stage|staging|stg|uat|qa|preprod|pre-prod|preproduction|sandbox|sbx|demo|beta|alpha|acc|acceptance|integration|canary|nightly)[0-9]{0,2}([.\-_]|$)`)
	// "lab" is not a staging marker: at a university it names a laboratory
	// (lab.agh.edu.pl, lab-212). Measured on the lab: with it, every service
	// under *.lab.czujka.test was classed staging (119 false positives).
	stagingTitleRe = regexp.MustCompile(`(?i)(\b(staging|pre-?prod(uction)?|sandbox|uat)\b|\b(test|dev|development|demo|qa)\s+(environment|server|instance|system|site)\b|\[(test|dev|staging|uat|demo)\]|[śs]rodowisko\s+(testowe|deweloperskie|rozwojowe|demonstracyjne)\b|\bwersja\s+(testowa|demonstracyjna)\b|\bserwer\s+testowy\b)`)
	stagingValueRe = regexp.MustCompile(`(?i)^(dev|devel|development|test|testing|stage|staging|stg|uat|qa|preprod|pre-prod|sandbox|demo|local|debug)[0-9]{0,2}$`)
	dirListingRe   = regexp.MustCompile(`(?i)(<title>\s*index of /|<h1>\s*index of /|<title>\s*directory listing for /|\[to parent directory\]|<h1>\s*directory listing for /|<title>[^<]{0,80} - /</title>\s*</head>\s*<body>\s*<h1>[^<]{0,80} - /</h1>)`)
	errorTitleRe   = regexp.MustCompile(`(?i)^\s*((error\s*)?(400|401|403|404|405|500|501|502|503|504)\b|not found|forbidden|bad gateway|bad request|service (temporarily )?unavailable|internal server error|gateway time-?out|access denied|unauthorized|http status \d{3}|server error|page not found|b[łl][aą]d\b|nie znaleziono)`)
	swaggerRe      = regexp.MustCompile(`(?i)(swagger-ui|"swagger"\s*:\s*"2\.|"openapi"\s*:\s*"3\.|redoc-container|<redoc\b|graphiql|graphql playground)`)
)

var stagingHeaders = []string{"x-environment", "x-env", "x-app-env", "x-app-environment", "x-stage", "x-deploy-env", "x-deployment-environment", "x-environment-name"}

var databaseServices = map[string]bool{
	"mysql": true, "postgresql": true, "postgres": true, "mongodb": true, "mongod": true, "redis": true,
	"ms-sql-s": true, "ms-sql-m": true, "oracle-tns": true, "oracle": true, "memcached": true, "memcache": true,
	"cassandra": true, "couchdb": true, "influxdb": true, "elasticsearch": true, "db2": true, "sybase": true,
	"neo4j": true, "rethinkdb": true, "riak": true, "hbase": true, "clickhouse": true, "firebird": true,
	"mariadb": true, "cockroachdb": true, "etcd": true, "zookeeper": true, "ldap": true, "ldaps": true,
}

var remoteAccessServices = map[string]bool{
	"ssh": true, "telnet": true, "ms-wbt-server": true, "rdp": true, "vnc": true, "vnc-http": true,
	"x11": true, "rlogin": true, "rsh": true, "shell": true, "login": true, "exec": true, "winrm": true,
	"wsman": true, "pcanywhere": true, "teamviewer": true, "radmin": true, "ard": true, "nx": true,
	"citrix": true, "ica": true, "telnets": true, "ipmi": true, "rfb": true,
}

// classify returns the classes that the generic heuristics find.
func classify(v *view) []string {
	out := map[string]bool{}
	name := strings.ToLower(strings.TrimPrefix(strings.ToLower(v.svc.Name), "ssl/"))
	if databaseServices[name] {
		out[model.ClassDatabase] = true
	}
	if remoteAccessServices[name] {
		out[model.ClassRemoteAccess] = true
	}

	// Staging, test and development markers in names.
	for _, h := range v.hostnames {
		if stagingLabelRe.MatchString(firstLabels(h)) {
			out[model.ClassStaging] = true
		}
	}
	if v.tls != nil {
		names := []string{v.tls.SubjectCN}
		if len(v.tls.SANs) <= 3 { // a certificate for many hosts says little about this one
			names = append(names, v.tls.SANs...)
		}
		for _, n := range names {
			if net := strings.TrimPrefix(strings.ToLower(n), "*."); net != "" && strings.Contains(net, ".") && stagingLabelRe.MatchString(firstLabels(net)) {
				out[model.ClassStaging] = true
			}
		}
	}
	if v.http == nil {
		return sortedKeys(out)
	}

	h := v.http
	body := v.body.orig
	title := h.Title
	for _, name := range stagingHeaders {
		for _, val := range v.headers[name] {
			if stagingValueRe.MatchString(strings.TrimSpace(val)) {
				out[model.ClassStaging] = true
			}
		}
	}
	if stagingTitleRe.MatchString(title) {
		out[model.ClassStaging] = true
	}

	// The patterns are slow on a large body; a literal check first skips most pages.
	low := v.body.lower()
	hasPassword := strings.Contains(low, "password") && passwordInputRe.MatchString(body)
	if hasPassword {
		out[model.ClassLogin] = true
	}
	for _, val := range v.headers["www-authenticate"] {
		if val != "" {
			out[model.ClassLogin] = true
		}
	}
	adminWord := adminTitleRe.MatchString(title)
	adminPath := adminPathRe.MatchString(pathOf(h.FinalURL))
	for _, rd := range h.Redirects {
		if adminPathRe.MatchString(pathOf(rd.To)) {
			adminPath = true
		}
	}
	if adminWord || adminPath {
		out[model.ClassAdminPanel] = true
	}

	if containsAny(low, "index of /", "directory listing for /", "parent directory", " - /</title>") && dirListingRe.MatchString(body) || strings.HasPrefix(strings.ToLower(title), "index of /") || strings.HasPrefix(strings.ToLower(title), "directory listing for ") {
		out[model.ClassDirListing] = true
	}

	ct := strings.ToLower(strings.Join(v.headers["content-type"], ";"))
	trimmed := strings.TrimSpace(body)
	jsonRoot := strings.Contains(ct, "json") && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "["))
	if jsonRoot || strings.Contains(ct, "application/problem+") || strings.Contains(ct, "application/hal+") ||
		strings.Contains(ct, "application/vnd.api+") || strings.Contains(ct, "application/soap+xml") ||
		containsAny(low, "swagger", "openapi", "redoc", "graphiql", "graphql playground") && swaggerRe.MatchString(body) {
		out[model.ClassAPI] = true
	}
	for path, pv := range v.paths {
		if pv.probe.Status != 200 {
			continue
		}
		lp := strings.ToLower(path)
		if strings.Contains(lp, "swagger") || strings.Contains(lp, "openapi") || strings.Contains(lp, "api-docs") || strings.Contains(lp, "graphql") {
			if swaggerRe.MatchString(pv.probe.Excerpt) {
				out[model.ClassAPI] = true
			}
		}
	}

	if h.Status >= 500 || (h.Status >= 400 && h.Status != 401 && errorTitleRe.MatchString(title)) ||
		(h.Status >= 400 && h.Status != 401 && title == "" && len(trimmed) < 600) {
		out[model.ClassErrorPage] = true
	}
	return sortedKeys(out)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// firstLabels returns the host part that names the machine: everything but
// the last two labels (the registered domain), or the whole name when short.
func firstLabels(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return labels[0]
	}
	return strings.Join(labels[:len(labels)-2], ".")
}

func pathOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return rawURL
}
