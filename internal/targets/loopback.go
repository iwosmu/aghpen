package targets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Loopback mapping. When Czujka runs in a container, "localhost" and
// 127.0.0.1 are the container itself, not the machine the operator means: the
// services that the docker host publishes on its ports are on the host
// gateway (host.docker.internal). With a host gateway set, the targets
// "localhost", any single 127.x address and ::1 are scanned as that address.
// The target keeps its value; MapsTo tells the address it is scanned as.
// Exclusions and the operator lock apply to the mapped address.

// LocalhostName is the hostname stored for the docker host when a loopback
// target is scanned through the host gateway.
const LocalhostName = "localhost"

var hostGateway atomic.Pointer[netip.Addr]

// SetHostGateway sets the address loopback targets are scanned as. An
// invalid address (the zero value) turns the mapping off. Only an IPv4
// address is accepted: the scan engine scans IPv4 scopes, and Docker Desktop
// answers host.docker.internal with an IPv6 address first.
func SetHostGateway(a netip.Addr) {
	a = a.Unmap()
	if !a.IsValid() || !a.Is4() {
		hostGateway.Store(nil)
		return
	}
	hostGateway.Store(&a)
}

// HostGateway returns the address loopback targets are scanned as, or the
// zero value when the mapping is off.
func HostGateway() netip.Addr {
	if p := hostGateway.Load(); p != nil {
		return *p
	}
	return netip.Addr{}
}

// IsLoopbackValue reports whether a target value means "this machine":
// localhost, a single 127.x address or ::1. A CIDR or a range is not.
func IsLoopbackValue(v string) bool {
	v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
	if v == LocalhostName {
		return true
	}
	a, err := netip.ParseAddr(v)
	return err == nil && a.Unmap().IsLoopback()
}

// MapsTo returns the address a target value is scanned as when it differs
// from the value (a loopback target with the host gateway set), else "".
func MapsTo(value string) string {
	gw := HostGateway()
	if !gw.IsValid() || !IsLoopbackValue(value) {
		return ""
	}
	return gw.String()
}

// mapValues replaces loopback values by the host gateway. mapped is true when
// at least one value was replaced.
func mapValues(vals []string) (out []string, mapped bool) {
	gw := HostGateway()
	if !gw.IsValid() {
		return vals, false
	}
	out = make([]string, len(vals))
	for i, v := range vals {
		if IsLoopbackValue(v) {
			out[i], mapped = gw.String(), true
			continue
		}
		out[i] = v
	}
	return out, mapped
}

// InContainer reports whether the process runs in a container (docker or podman).
func InContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// GatewayName is the name the docker host has inside a container.
const GatewayName = "host.docker.internal"

// ResolveHostGateway turns the setting CZUJKA_HOST_GATEWAY into an address.
//
//	"off"           no mapping
//	a literal IPv4  that address
//	""              in a container: the IPv4 address host.docker.internal
//	                resolves to; outside a container: no mapping
//
// An answer without an IPv4 address is an error: the mapping stays off.
func ResolveHostGateway(ctx context.Context, setting string, inContainer bool, res Resolver) (netip.Addr, error) {
	s := strings.ToLower(strings.TrimSpace(setting))
	switch s {
	case "off", "false", "no", "0", "none":
		return netip.Addr{}, nil
	case "":
		if !inContainer {
			return netip.Addr{}, nil
		}
		s = GatewayName
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return netip.Addr{}, errors.New("CZUJKA_HOST_GATEWAY: only an IPv4 address is supported")
		}
		return a, nil
	}
	if res == nil {
		res = net.DefaultResolver
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := res.LookupIP(c, "ip4", s)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, errors.New(s + ": no IPv4 address")
}

// ShownHostname is the name a service or a run export shows for an address.
// A loopback name ("localhost") on an address that is not loopback is a
// loopback target mapped to the docker host (MapsTo): shown or exported, it
// would name Czujka's own container, so the address is shown instead ("").
func ShownHostname(name, ip string) string {
	if name == "" || !IsLoopbackValue(name) {
		return name
	}
	if a, err := netip.ParseAddr(ip); err != nil || a.Unmap().IsLoopback() {
		return name
	}
	return ""
}

// ShownHostnames applies ShownHostname to a list of names of one address.
func ShownHostnames(names []string, ip string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if ShownHostname(n, ip) != "" {
			out = append(out, n)
		}
	}
	return out
}
