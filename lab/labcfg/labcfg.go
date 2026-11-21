// Package labcfg holds the types shared by the lab generator, the imitation
// server (labsim) and the scorer: the labsim host configuration, the
// availability model of unstable hosts and the lab favicon generator.
// It uses the standard library only, so labsim builds without the main module.
package labcfg

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// States are the named lab states, in order.
var States = []string{"t0", "t1", "t2"}

// Avail describes a host that is not always reachable. The decision is a
// pure function of wall-clock time, so the lab, the ground truth and the
// scorer agree on the expected state at any moment.
type Avail struct {
	// Kind is "flap" (pseudo-random per slot) or "schedule" (periodic window).
	Kind string `json:"kind"`
	// Flap: the host is up in a slot when hash(seed, slot) is even. About 50%.
	Seed    string `json:"seed,omitempty"`
	SlotSec int    `json:"slot_sec,omitempty"`
	// Schedule: with p = unix time mod PeriodSec, the host is up when
	// UpFromSec <= p < UpToSec. This is a compressed "day".
	PeriodSec int `json:"period_sec,omitempty"`
	UpFromSec int `json:"up_from_sec,omitempty"`
	UpToSec   int `json:"up_to_sec,omitempty"`
}

// UpAt tells if a host with this availability is reachable at t.
// A nil Avail means always up.
func (a *Avail) UpAt(t time.Time) bool {
	if a == nil {
		return true
	}
	u := t.Unix()
	switch a.Kind {
	case "flap":
		slot := a.SlotSec
		if slot <= 0 {
			slot = 60
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(u/int64(slot)))
		h := sha256.Sum256(append([]byte(a.Seed+"|"), b[:]...))
		return h[0]&1 == 0
	case "schedule":
		if a.PeriodSec <= 0 {
			return true
		}
		p := int(u % int64(a.PeriodSec))
		return p >= a.UpFromSec && p < a.UpToSec
	}
	return true
}

// NextChange returns the first moment after t at which UpAt flips, looking at
// most limit ahead. ok is false when there is no flip in that span.
func (a *Avail) NextChange(t time.Time, limit time.Duration) (at time.Time, ok bool) {
	if a == nil {
		return time.Time{}, false
	}
	cur := a.UpAt(t)
	end := t.Add(limit)
	for x := t.Truncate(time.Second).Add(time.Second); !x.After(end); x = x.Add(time.Second) {
		if a.UpAt(x) != cur {
			return x, true
		}
	}
	return time.Time{}, false
}

// Header is one response header. A slice keeps the order stable.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is one Set-Cookie the imitation sends.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
	MaxAge   int    `json:"max_age,omitempty"`
}

// Route answers one exact path. Path "*" is the fallback for unknown paths.
type Route struct {
	Path        string   `json:"path"`
	Status      int      `json:"status,omitempty"` // default 200
	Location    string   `json:"location,omitempty"`
	ContentType string   `json:"content_type,omitempty"` // default text/html; charset=utf-8
	Body        string   `json:"body,omitempty"`
	Headers     []Header `json:"headers,omitempty"`
	Cookies     []Cookie `json:"cookies,omitempty"`
	BasicRealm  string   `json:"basic_realm,omitempty"` // answer 401 with this realm
	// Volatile bodies may contain {{RAND}}, {{NOW}} and {{COUNTER}}; they are
	// replaced on every request.
	Volatile bool `json:"volatile,omitempty"`
}

// Site is what one HTTP listener serves.
type Site struct {
	Server      string   `json:"server,omitempty"`  // Server header; empty sends none
	Headers     []Header `json:"headers,omitempty"` // on every response
	Cookies     []Cookie `json:"cookies,omitempty"` // on every HTML response
	Routes      []Route  `json:"routes"`
	DelayMs     int      `json:"delay_ms,omitempty"`     // wait before every response
	FaviconSeed string   `json:"favicon_seed,omitempty"` // serve /favicon.ico made by Favicon(seed)
}

// TLS describes the certificate of one listener. labsim creates it at start
// and again when the spec changes between lab states (a "renewal").
type TLS struct {
	Mode          string   `json:"mode"` // "ca": leaf signed by a lab CA; "selfsigned"
	CN            string   `json:"cn"`
	Org           string   `json:"org,omitempty"`
	SANs          []string `json:"sans,omitempty"`      // DNS names and IP addresses
	IssuerCN      string   `json:"issuer_cn,omitempty"` // "ca" mode only
	NotBeforeDays int      `json:"not_before_days"`     // relative to the start of labsim; negative is the past
	NotAfterDays  int      `json:"not_after_days"`
	Key           string   `json:"key,omitempty"` // "ecdsa" (default) or "rsa2048"
	Gen           int      `json:"gen,omitempty"` // raise to force a new certificate
}

// Listener is one TCP port of an imitation host.
type Listener struct {
	Port int    `json:"port"`
	Kind string `json:"kind"` // "http" or "tarpit"
	TLS  *TLS   `json:"tls,omitempty"`
	Site *Site  `json:"site,omitempty"`
}

// Firewall is applied once at start with iptables inside the container.
type Firewall struct {
	DropICMP bool `json:"drop_icmp,omitempty"`
	// StealthExcept: drop every inbound packet except TCP to these ports.
	// Closed ports then give no RST, so the host looks dead to ping and to
	// probes of common ports.
	StealthExcept []int `json:"stealth_except,omitempty"`
}

// HostState is the behaviour of an imitation host in one lab state.
type HostState struct {
	Listeners []Listener `json:"listeners"`
}

// Host is the whole labsim configuration of one container.
type Host struct {
	Name     string               `json:"name"`
	Avail    *Avail               `json:"avail,omitempty"`
	Firewall *Firewall            `json:"firewall,omitempty"`
	States   map[string]HostState `json:"states"`
}
