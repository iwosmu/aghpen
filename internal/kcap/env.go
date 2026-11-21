package kcap

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// InContainer reports whether the process runs in a container (docker or podman).
func InContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// SystemUnsafe is Options.Unsafe for the running process: HostNetwork with
// the container markers and the interfaces of the current namespace.
func SystemUnsafe(networkMode string) func() string {
	return func() string {
		var names []string
		if ifs, err := net.Interfaces(); err == nil {
			for _, i := range ifs {
				names = append(names, i.Name)
			}
		}
		_, reason := HostNetwork(InContainer(), networkMode, names)
		return reason
	}
}

// ParseResolvConf returns the nameserver addresses of a resolv.conf.
func ParseResolvConf(data []byte) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.Unmap().WithZone(""))
			}
		}
	}
	return out
}

// SystemExempt is Options.Exempt for the running process: the addresses of
// the database host of dbURL and the resolvers of /etc/resolv.conf. The
// database name is resolved at each install, so a new database address after
// a restart is exempt too.
func SystemExempt(dbURL string) func(ctx context.Context) []netip.Addr {
	return func(ctx context.Context) []netip.Addr {
		var out []netip.Addr
		if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			out = append(out, ParseResolvConf(b)...)
		}
		host := ""
		if u, err := url.Parse(dbURL); err == nil {
			host = u.Hostname()
		}
		if host == "" {
			return out
		}
		if a, err := netip.ParseAddr(host); err == nil {
			return append(out, a)
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if as, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host); err == nil {
			out = append(out, as...)
		}
		return out
	}
}
