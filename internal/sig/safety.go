package sig

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// The safe-mode rules for extra request paths. A signature may only ask for
// a passive GET of a path on the scanned service. Everything that could change
// state on the target or fetch a secret is refused.

// denySubstrings are refused anywhere in the path or query.
var denySubstrings = []string{
	"logout", "logoff", "signout", "sign-out", "sign_out", "log-out", "log_out",
	"shutdown", "poweroff", "reboot", "restart", "delete", "destroy", "uninstall",
	"backup", "passwd", "shadow", "heapdump", "threaddump", "hprof",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
	"wp-config", "web.config", "credentials", "secret", "private",
	"configuration.php", "config.php", "config.inc", "settings.php", "settings.py", "local.xml",
	"database.yml", "parameters.yml", "appsettings", "docker-compose", "dockerfile",
	"etc/", "proc/", "cgi-bin/luci/;", "jolokia", "actuator/env", "actuator/gateway", "actuator/loggers",
	"xmlrpc", "phpunit", "eval-stdin", "flushall", "flushdb", "resetpassword",
}

// denyTokens are refused as a whole word of the path or query (words are
// split on every character that is not a letter or a digit).
var denyTokens = map[string]bool{
	"exec": true, "execute": true, "eval": true, "cmd": true, "command": true, "shell": true, "sh": true,
	"kill": true, "stop": true, "halt": true, "reset": true, "remove": true, "rm": true, "del": true,
	"drop": true, "dump": true, "truncate": true, "wipe": true, "erase": true, "purge": true, "flush": true,
	"clear": true, "format": true, "factory": true, "update": true, "upgrade": true, "save": true,
	"write": true, "upload": true, "import": true, "export": true, "restore": true, "disable": true,
	"enable": true, "revoke": true, "approve": true, "grant": true, "env": true, "token": true,
	"tokens": true, "apikey": true, "keys": true, "secrets": true, "create": true, "add": true,
	"edit": true, "modify": true, "set": true, "run": true, "start": true, "send": true, "trigger": true,
	"apply": true, "commit": true, "submit": true, "confirm": true, "activate": true, "deactivate": true,
	"unlock": true, "lock": true, "sql": true, "sqli": true, "xss": true, "rce": true, "lfi": true,
	"exploit": true, "payload": true, "inject": true, "bypass": true,
}

// denyExtensions are file types that are backups, archives, keys, databases
// or configuration: fetching them is not presence detection.
var denyExtensions = []string{
	".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".sql", ".dump", ".tar", ".gz",
	".tgz", ".bz2", ".xz", ".zip", ".rar", ".7z", ".sqlite", ".sqlite3", ".db", ".mdb", ".pem", ".key",
	".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx", ".env", ".ini", ".conf", ".cfg", ".config",
	".log", ".inc", ".csv", ".xls", ".xlsx", ".dat", ".cer", ".der", ".asc", ".gpg", ".pgp",
}

// landingWords are the common landing paths of web applications (start,
// home, index, main, welcome, portal, app, web, ui, login, dashboard) that
// are also deny tokens. A same-origin redirect path may contain them: the
// server itself sends every browser there with a GET (/ -> /start -> /pl/).
// Today only "start" is both; the other landing words are not deny tokens.
// A signature path and every query keep the full deny words.
var landingWords = map[string]bool{"start": true}

// CheckPath validates one extra request path against the safe-mode rules.
// It returns "" when the path is allowed, or the reason in Polish.
func CheckPath(path string) string { return checkPath(path, nil) }

// checkPath is CheckPath with deny tokens that the caller allows (allow).
func checkPath(path string, allow map[string]bool) string {
	switch {
	case path == "":
		return "pusta ścieżka"
	case strings.Contains(path, "://") || strings.HasPrefix(path, "//"):
		return "pełne adresy URL i inne hosty są zabronione: sygnatura może pytać tylko skanowaną usługę"
	case path[0] != '/':
		return "ścieżka musi zaczynać się od „/”"
	case len(path) > MaxPathLen:
		return fmt.Sprintf("ścieżka jest za długa (limit %d znaków)", MaxPathLen)
	case strings.Contains(path, "%"):
		return "kodowanie procentowe jest zabronione (ukryte przejście katalogów, np. %2e%2e%2f, albo bajt zerowy)"
	case strings.Contains(path, ".."):
		return "przejście katalogów („..”) jest zabronione"
	case strings.Contains(path, "@"):
		return "znak „@” (dane logowania w adresie) jest zabroniony"
	}
	p, query, hasQuery := strings.Cut(path, "?")
	if strings.Contains(p, "//") {
		return "podwójny ukośnik w ścieżce jest zabroniony"
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '/' || c == '_' || c == '-' || c == '.' || c == '~'
		if !ok {
			return fmt.Sprintf("znak %q jest niedozwolony w ścieżce (dozwolone: litery, cyfry oraz / _ - . ~)", rune(c))
		}
	}
	if hasQuery {
		if len(query) > 80 {
			return "parametry zapytania są za długie (limit 80 znaków)"
		}
		for i := 0; i < len(query); i++ {
			c := query[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
				c == '_' || c == '-' || c == '.' || c == '=' || c == '&'
			if !ok {
				return fmt.Sprintf("znak %q jest niedozwolony w parametrach zapytania (dozwolone: litery, cyfry oraz _ - . = &)", rune(c))
			}
		}
	}
	lowPath := strings.ToLower(p)
	if strings.HasSuffix(lowPath, "~") {
		return "kopie zapasowe edytora (końcówka „~”) są zabronione"
	}
	for _, seg := range strings.Split(lowPath, "/") {
		if strings.HasPrefix(seg, ".") && seg != ".well-known" {
			return fmt.Sprintf("ukryte pliki i katalogi („%s”) są zabronione: mogą zawierać sekrety (.env, .git, .htpasswd)", seg)
		}
	}
	if reason := deniedWords(path, allow); reason != "" {
		return reason
	}
	last := lowPath[strings.LastIndexByte(lowPath, '/')+1:]
	for _, ext := range denyExtensions {
		if strings.HasSuffix(last, ext) || strings.Contains(last, ext+".") {
			return fmt.Sprintf("pliki „%s” (kopie zapasowe, archiwa, klucze, bazy, konfiguracja) są zabronione", ext)
		}
	}
	if (strings.HasSuffix(last, ".yml") || strings.HasSuffix(last, ".yaml")) &&
		!strings.Contains(last, "openapi") && !strings.Contains(last, "swagger") && !strings.Contains(last, "api-docs") {
		return "pliki YAML są zabronione (konfiguracja), z wyjątkiem opisów OpenAPI/Swagger"
	}
	return ""
}

// deniedWords applies the deny substrings and the deny words to s. Words are
// split on every character that is not a letter or a digit and also at the
// parts of camelCase words (security review L3): /api/resetPassword has the
// word "reset", /cache/flushAll the word "flush".
func deniedWords(s string, allow map[string]bool) string {
	low := strings.ToLower(s)
	for _, d := range denySubstrings {
		if strings.Contains(low, d) {
			return fmt.Sprintf("ścieżka zawiera „%s”: żądania zmieniające stan albo pobierające sekrety są zabronione", d)
		}
	}
	for _, w := range words(s) {
		if denyTokens[w] && !allow[w] {
			return fmt.Sprintf("ścieżka zawiera słowo „%s”: żądania zmieniające stan albo pobierające sekrety są zabronione", w)
		}
	}
	return ""
}

// words splits s into lower-case words: on every character that is not an
// ASCII letter or digit, and inside a word at a lower-to-upper change
// (resetPassword) and before the last capital of a capital run (XMLHttp).
func words(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		out = append(out, strings.ToLower(f)) // the whole word as well: "flushall"
		rs := []rune(f)
		start := 0
		for i := 1; i < len(rs); i++ {
			lowUp := unicode.IsLower(rs[i-1]) && unicode.IsUpper(rs[i])
			capRun := i+1 < len(rs) && unicode.IsUpper(rs[i-1]) && unicode.IsUpper(rs[i]) && unicode.IsLower(rs[i+1])
			if lowUp || capRun {
				out = append(out, strings.ToLower(string(rs[start:i])))
				start = i
			}
		}
		if start > 0 {
			out = append(out, strings.ToLower(string(rs[start:])))
		}
	}
	return out
}

// CheckRedirect validates the target of a same-origin redirect before the
// collector follows it. The path takes the full CheckPath, except that it may
// contain a landing word (landingWords); the query (a redirect often carries
// an encoded return address) takes the full deny words, on its decoded text. It returns "" when the target may be fetched.
func CheckRedirect(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if reason := checkPath(p, landingWords); reason != "" {
		return reason
	}
	if u.RawQuery != "" {
		q, err := url.QueryUnescape(u.RawQuery)
		if err != nil {
			q = u.RawQuery
		}
		if len(q) > 2*MaxPathLen {
			return "parametry zapytania przekierowania są za długie"
		}
		return deniedWords(q, nil)
	}
	return ""
}
