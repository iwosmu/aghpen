package analyze

import (
	"regexp"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// databaseNames and remoteAccessNames are nmap service names. They classify
// services that have no HTTP fingerprint (and imported nmap data).
var databaseNames = map[string]bool{
	"mysql": true, "postgresql": true, "postgres": true, "ms-sql-s": true, "ms-sql-m": true, "mongodb": true, "mongod": true,
	"redis": true, "elasticsearch": true, "memcached": true, "memcache": true, "oracle-tns": true, "oracle": true,
	"cassandra": true, "couchdb": true, "influxdb": true, "db2": true, "mariadb": true, "neo4j": true, "rethinkdb": true,
	"clickhouse": true, "etcd": true,
}

var remoteAccessNames = map[string]bool{
	"ssh": true, "telnet": true, "ms-wbt-server": true, "rdp": true, "vnc": true, "vnc-http": true, "rlogin": true,
	"login": true, "shell": true, "exec": true, "x11": true, "winrm": true, "wsman": true, "teamviewer": true,
}

var (
	reDirListing  = regexp.MustCompile(`(?i)^\s*(index of /|directory listing for )`)
	reDefaultPage = regexp.MustCompile(`(?i)(welcome to nginx|apache2 (ubuntu|debian) default page|test page for the (apache|nginx) http server|iis windows server|^iis\d*$|apache tomcat/|welcome to openresty|welcome to caddy|default web site page|it works!?$)`)
	reAdminTitle  = regexp.MustCompile(`(?i)(phpmyadmin|adminer|webmin|cpanel|plesk|pgadmin|panel administracyjny|\badmin(istration|istrator|istracja)?\b)`)
	reDevTitle    = regexp.MustCompile(`(?i)(jenkins|gitlab|gitea|gogs|grafana|kibana|sonarqube|portainer|prometheus|swagger ui|traefik|nexus repository|argo ?cd|rabbitmq management)`)
	reStagingName = regexp.MustCompile(`(?i)(^|[.\-_])(staging|stage|stg|test|testing|dev|devel|uat|preprod|pre-prod|qa|sandbox|demo)\d*([.\-_]|$)`)
	reStagingText = regexp.MustCompile(`(?i)\b(staging|środowisko testowe|test environment|preprod|pre-production|uat environment)\b`)
	reDebugText   = regexp.MustCompile(`(?i)(phpinfo\(\)|werkzeug debugger|django.{0,40}debug\s*=\s*true|whoops! there was an error|symfony profiler|laravel.{0,20}ignition|xdebug|traceback \(most recent call last\)|rails\.env|stack trace:|debug mode)`)
)

// EffectiveClasses returns the classes of a service: the ones the classifier
// set, the ones its signature matches carry, and a small set of safe
// fall-back rules for data without signature matches (for example imported
// nmap results). The result is sorted and has no duplicates.
func EffectiveClasses(s *model.ServiceResult, hostnames []string) []string {
	set := map[string]bool{}
	for _, c := range s.Classes {
		set[c] = true
	}
	for _, m := range s.Matches {
		for _, c := range m.Classes {
			set[c] = true
		}
	}
	name := strings.ToLower(s.Name)
	if databaseNames[name] {
		set[model.ClassDatabase] = true
	}
	if remoteAccessNames[name] {
		set[model.ClassRemoteAccess] = true
	}
	if s.HTTP != nil {
		title := s.HTTP.Title
		if reDirListing.MatchString(title) {
			set[model.ClassDirListing] = true
		}
		if reDefaultPage.MatchString(strings.TrimSpace(title)) {
			set[model.ClassDefaultPage] = true
		}
		if reAdminTitle.MatchString(title) {
			set[model.ClassAdminPanel] = true
		}
		if reDevTitle.MatchString(title) {
			set[model.ClassDevTool] = true
		}
		if reStagingText.MatchString(title) || headerValue(s.HTTP.Headers, "X-Environment") != "" && reStagingName.MatchString(headerValue(s.HTTP.Headers, "X-Environment")) {
			set[model.ClassStaging] = true
		}
		if s.HTTP.Host != "" && reStagingName.MatchString(s.HTTP.Host) {
			set[model.ClassStaging] = true
		}
		for _, h := range hostnames {
			if reStagingName.MatchString(h) {
				set[model.ClassStaging] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// isDebugPage reports if the service shows a debug or diagnostic page, and
// the evidence for it.
func isDebugPage(s *model.ServiceResult) (bool, []model.Evidence) {
	var ev []model.Evidence
	for _, m := range s.Matches {
		for _, t := range m.Tags {
			if strings.EqualFold(t, "debug") {
				ev = append(ev, m.Evidence...)
				if len(m.Evidence) == 0 {
					ev = append(ev, model.Evidence{Matcher: "signature", Where: "signature:" + m.Signature, Snippet: m.Name})
				}
			}
		}
	}
	if s.HTTP != nil {
		for _, h := range []string{"X-Debug-Token", "X-Debug-Token-Link"} {
			if v := headerValue(s.HTTP.Headers, h); v != "" {
				ev = append(ev, model.Evidence{Matcher: "header", Where: "header:" + h, Snippet: clip(v, 120)})
			}
		}
		if m := reDebugText.FindString(s.HTTP.Title); m != "" {
			ev = append(ev, model.Evidence{Matcher: "title", Where: "title", Snippet: clip(s.HTTP.Title, 120)})
		} else if m := reDebugText.FindString(s.HTTP.BodyExcerpt); m != "" {
			ev = append(ev, model.Evidence{Matcher: "body", Where: "body", Snippet: clip(m, 120)})
		}
	}
	return len(ev) > 0, ev
}

func hasClass(classes []string, c string) bool {
	for _, x := range classes {
		if x == c {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// isTLS reports if the service speaks TLS.
func isTLS(s *model.ServiceResult) bool {
	return s.TLS != nil || s.Tunnel == "ssl" || (s.HTTP != nil && s.HTTP.Scheme == "https")
}

// isPlainHTTP reports if the service is a web service without TLS.
func isPlainHTTP(s *model.ServiceResult) bool {
	return s.HTTP != nil && s.HTTP.Error == "" && !isTLS(s)
}
