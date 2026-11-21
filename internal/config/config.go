// Package config reads the Czujka configuration from CZUJKA_* environment variables.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full runtime configuration of the binary.
type Config struct {
	Listen        string        // CZUJKA_LISTEN, default ":8080"
	DBURL         string        // CZUJKA_DB_URL
	MasterKey     string        // CZUJKA_MASTER_KEY: 32 bytes as base64 or hex
	MasterKeyFile string        // CZUJKA_MASTER_KEY_FILE: file with the key; created when it does not exist
	OldMasterKeys []string      // CZUJKA_MASTER_KEY_OLD: comma separated keys that can still decrypt (used by rotate-key)
	AdminEmail    string        // CZUJKA_ADMIN_EMAIL
	AdminPassword string        // CZUJKA_ADMIN_PASSWORD
	WebDir        string        // CZUJKA_WEB_DIR: directory with the built UI (web/dist)
	TDE           string        // CZUJKA_TDE: auto | require | off
	Timezone      string        // CZUJKA_TZ: timezone of the hour-of-week histogram, default Europe/Warsaw
	SessionTTL    time.Duration // CZUJKA_SESSION_TTL, default 12h
	CookieSecure  string        // CZUJKA_COOKIE_SECURE: auto | true | false
	LoginMaxFails int           // CZUJKA_LOGIN_MAX_FAILURES, default 5
	LoginLockout  time.Duration // CZUJKA_LOGIN_LOCKOUT, default 15m
	LoginPerMin   int           // CZUJKA_LOGIN_RATE_PER_MIN (per client address), default 20
	LogFormat     string        // CZUJKA_LOG_FORMAT: json | text
	AutoResume    bool          // CZUJKA_AUTO_RESUME: resume runs that a restart interrupted, default true
	TrustProxy    bool          // CZUJKA_TRUST_PROXY: take the client address from X-Forwarded-For
	IngestBatch   int           // CZUJKA_INGEST_BATCH: hosts per database batch, default 250
	SchedInterval time.Duration // CZUJKA_SCHED_INTERVAL: tick of the scheduler loop, default 20s
	NmapPath      string        // CZUJKA_NMAP_PATH: nmap binary; empty means "nmap" from PATH
	ForceNative   bool          // CZUJKA_FORCE_NATIVE: use the native Go prober even when nmap is installed
	// AllowedNetworks: CZUJKA_ALLOWED_NETWORKS, comma-separated CIDRs (or
	// addresses). The operator lock: a hard upper bound on what can be
	// scanned that no user can widen. Empty: no lock.
	AllowedNetworks []string
	// HostGateway: CZUJKA_HOST_GATEWAY. The address the loopback targets
	// (localhost, 127.x, ::1) are scanned as when Czujka runs in a container.
	// Empty: the IPv4 address of host.docker.internal (in a container only);
	// "off": loopback stays loopback; a literal IPv4 address overrides.
	HostGateway string
	// PublishedPort: CZUJKA_PUBLISHED_PORT, the port the docker host publishes
	// the UI on (CZUJKA_PORT of the compose file). The service on that port of
	// the docker host is Czujka itself and gets the tag "czujka". 0: the port
	// of CZUJKA_LISTEN.
	PublishedPort int
}

// Load reads the configuration from the process environment.
func Load() (Config, error) { return FromEnv(os.Getenv) }

// FromEnv reads the configuration through the given lookup function.
func FromEnv(get func(string) string) (Config, error) {
	c := Config{
		Listen:        str(get, "CZUJKA_LISTEN", ":8080"),
		DBURL:         get("CZUJKA_DB_URL"),
		MasterKey:     strings.TrimSpace(get("CZUJKA_MASTER_KEY")),
		MasterKeyFile: get("CZUJKA_MASTER_KEY_FILE"),
		AdminEmail:    strings.ToLower(strings.TrimSpace(get("CZUJKA_ADMIN_EMAIL"))),
		AdminPassword: get("CZUJKA_ADMIN_PASSWORD"),
		WebDir:        get("CZUJKA_WEB_DIR"),
		TDE:           strings.ToLower(str(get, "CZUJKA_TDE", "auto")),
		Timezone:      str(get, "CZUJKA_TZ", "Europe/Warsaw"),
		CookieSecure:  strings.ToLower(str(get, "CZUJKA_COOKIE_SECURE", "auto")),
		LogFormat:     strings.ToLower(str(get, "CZUJKA_LOG_FORMAT", "json")),
		HostGateway:   strings.TrimSpace(get("CZUJKA_HOST_GATEWAY")),
	}
	if f := strings.TrimSpace(get("CZUJKA_DB_PASSWORD_FILE")); f != "" && c.DBURL != "" {
		u, err := withPasswordFile(c.DBURL, f)
		if err != nil {
			return c, err
		}
		c.DBURL = u
	}
	for _, k := range strings.Split(get("CZUJKA_MASTER_KEY_OLD"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.OldMasterKeys = append(c.OldMasterKeys, k)
		}
	}
	var err error
	if c.SessionTTL, err = dur(get, "CZUJKA_SESSION_TTL", 12*time.Hour); err != nil {
		return c, err
	}
	if c.LoginLockout, err = dur(get, "CZUJKA_LOGIN_LOCKOUT", 15*time.Minute); err != nil {
		return c, err
	}
	if c.LoginMaxFails, err = num(get, "CZUJKA_LOGIN_MAX_FAILURES", 5); err != nil {
		return c, err
	}
	if c.LoginPerMin, err = num(get, "CZUJKA_LOGIN_RATE_PER_MIN", 20); err != nil {
		return c, err
	}
	if c.IngestBatch, err = num(get, "CZUJKA_INGEST_BATCH", 250); err != nil {
		return c, err
	}
	if c.SchedInterval, err = dur(get, "CZUJKA_SCHED_INTERVAL", 20*time.Second); err != nil {
		return c, err
	}
	if c.PublishedPort, err = num(get, "CZUJKA_PUBLISHED_PORT", 0); err != nil {
		return c, err
	}
	if c.PublishedPort == 0 {
		if _, p, err := net.SplitHostPort(c.Listen); err == nil {
			c.PublishedPort, _ = strconv.Atoi(p)
		}
	}
	for _, n := range strings.Split(get("CZUJKA_ALLOWED_NETWORKS"), ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		p, err := netip.ParsePrefix(n)
		if err != nil {
			a, aerr := netip.ParseAddr(n)
			if aerr != nil {
				return c, fmt.Errorf("CZUJKA_ALLOWED_NETWORKS: %q is not a CIDR or an address", n)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		c.AllowedNetworks = append(c.AllowedNetworks, p.Masked().String())
	}
	c.NmapPath = get("CZUJKA_NMAP_PATH")
	if c.ForceNative, err = boolean(get, "CZUJKA_FORCE_NATIVE", false); err != nil {
		return c, err
	}
	if c.AutoResume, err = boolean(get, "CZUJKA_AUTO_RESUME", true); err != nil {
		return c, err
	}
	if c.TrustProxy, err = boolean(get, "CZUJKA_TRUST_PROXY", false); err != nil {
		return c, err
	}
	switch c.TDE {
	case "auto", "require", "off":
	default:
		return c, fmt.Errorf("CZUJKA_TDE must be auto, require or off, got %q", c.TDE)
	}
	switch c.CookieSecure {
	case "auto", "true", "false":
	default:
		return c, fmt.Errorf("CZUJKA_COOKIE_SECURE must be auto, true or false, got %q", c.CookieSecure)
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return c, fmt.Errorf("CZUJKA_TZ: %w", err)
	}
	return c, nil
}

// RequireDB checks the settings that every database command needs.
func (c Config) RequireDB() error {
	if c.DBURL == "" {
		return fmt.Errorf("CZUJKA_DB_URL is not set")
	}
	return nil
}

func str(get func(string) string, key, def string) string {
	if v := strings.TrimSpace(get(key)); v != "" {
		return v
	}
	return def
}

func num(get func(string) string, key string, def int) (int, error) {
	v := strings.TrimSpace(get(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", key, v)
	}
	return n, nil
}

func dur(get func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(get(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 12h, got %q", key, v)
	}
	return d, nil
}

func boolean(get func(string) string, key string, def bool) (bool, error) {
	v := strings.TrimSpace(get(key))
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false, got %q", key, v)
	}
	return b, nil
}

// withPasswordFile puts the password from file into the database URL. The
// compose stack writes that file into a volume on its first start, so the
// repository holds no database password.
func withPasswordFile(dbURL, file string) (string, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("CZUJKA_DB_PASSWORD_FILE: %w", err)
	}
	pw := strings.TrimSpace(string(raw))
	if pw == "" {
		return "", fmt.Errorf("CZUJKA_DB_PASSWORD_FILE: %s is empty", file)
	}
	u, err := url.Parse(dbURL)
	if err != nil || u.User == nil {
		return "", fmt.Errorf("CZUJKA_DB_PASSWORD_FILE: CZUJKA_DB_URL needs the form postgres://user@host/db")
	}
	u.User = url.UserPassword(u.User.Username(), pw)
	return u.String(), nil
}
