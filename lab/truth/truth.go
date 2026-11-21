// Package truth defines the ground-truth files of the lab (lab/ground-truth)
// and the expected changes between two lab states. The files are generated
// from the lab manifest; the scorer in e2e/score reads them.
package truth

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

// File is one ground-truth file: the exact expected picture of one lab state.
type File struct {
	State   string   `json:"state"`
	Network string   `json:"network"`
	Note    string   `json:"note"`
	Ignore  []string `json:"ignore"` // addresses that are not lab hosts (gateway, scanner box)
	Hosts   []Host   `json:"hosts"`
}

type Host struct {
	IP        string   `json:"ip"`
	Name      string   `json:"name"`
	Hostnames []string `json:"hostnames"`
	Group     string   `json:"group"`
	Desc      string   `json:"desc"`
	// Availability is set for unstable hosts. Their presence in a scan depends
	// on the time of the scan, so the scorer keeps them out of the host metrics.
	Availability *labcfg.Avail `json:"availability,omitempty"`
	// Hard names host-level hard cases: no-icmp-echo, stealth-firewall, slow,
	// edge-address, many-ports, volatile-content, tarpit.
	Hard     []string  `json:"hard,omitempty"`
	Services []Service `json:"services"`
}

type Service struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Name    string   `json:"name"`               // nmap service name
	NameAlt []string `json:"name_alt,omitempty"` // other names that are also right
	Tunnel  string   `json:"tunnel,omitempty"`   // "ssl" for TLS services
	Product string   `json:"product,omitempty"`
	Version string   `json:"version,omitempty"`
	// Hard marks a service that a plain default scan is allowed to miss or
	// to name wrongly: udp, tarpit, slow, name-unknown.
	Hard          string        `json:"hard,omitempty"`
	Technologies  []Tech        `json:"technologies,omitempty"`
	TechOptional  []string      `json:"tech_optional,omitempty"` // true but not required; never a false positive
	Classes       []string      `json:"classes,omitempty"`
	ClassOptional []string      `json:"class_optional,omitempty"`
	HTTP          *HTTP         `json:"http,omitempty"`
	TLS           *TLS          `json:"tls,omitempty"`
	Interesting   []Interesting `json:"interesting,omitempty"`
	Signatures    []string      `json:"signatures,omitempty"` // custom signature slugs that must match
}

type Tech struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Version  string   `json:"version,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
}

// HTTP is what GET / returns (no redirect followed), plus the title of the
// page a client lands on when the redirects stay on the same service.
type HTTP struct {
	Status        int               `json:"status"`
	Title         string            `json:"title,omitempty"`
	Location      string            `json:"location,omitempty"`
	Server        string            `json:"server,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"` // headers worth checking, exact value; "" means any value
	Cookies       []Cookie          `json:"cookies,omitempty"`
	FaviconMMH3   *int32            `json:"favicon_mmh3,omitempty"`
	FaviconSHA256 string            `json:"favicon_sha256,omitempty"`
	Volatile      bool              `json:"volatile,omitempty"` // the body differs on every request
	VHosts        []VHost           `json:"vhosts,omitempty"`   // other sites on the same address, by Host header
}

type VHost struct {
	Host  string `json:"host"`
	Title string `json:"title"`
}

type Cookie struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	JWT      bool   `json:"jwt,omitempty"` // the value has the shape of a JSON Web Token
}

type TLS struct {
	SubjectCN    string   `json:"subject_cn"`
	SANs         []string `json:"sans,omitempty"`
	IssuerCN     string   `json:"issuer_cn,omitempty"`
	SelfSigned   bool     `json:"self_signed"`
	Expired      bool     `json:"expired"`
	HostMismatch bool     `json:"host_mismatch"` // the certificate does not cover the lab DNS name of the host
	DaysLeft     int      `json:"days_left"`     // at the moment labsim created it; negative when expired
	Gen          int      `json:"gen"`           // changes when the certificate is renewed
}

// Interesting is one header or cookie an analyst should see.
type Interesting struct {
	Kind string `json:"kind"` // header | cookie
	Name string `json:"name"`
	Why  string `json:"why"`
}

// Change is one expected difference between two lab states. Kind uses the
// values of model.ChangeKind.
type Change struct {
	Kind    string `json:"kind"`
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Field   string `json:"field,omitempty"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
	Summary string `json:"summary"`
}

// ChangeFile is lab/ground-truth/changes-FROM-TO.json.
type ChangeFile struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Note    string   `json:"note"`
	Changes []Change `json:"changes"`
}

// Key identifies a change for comparison with an observed diff.
func (c Change) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s", c.Kind, c.IP, c.Port, c.Field)
}

func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

func LoadChanges(path string) (*ChangeFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f ChangeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

func techNames(ts []Tech) map[string]Tech {
	m := map[string]Tech{}
	for _, t := range ts {
		m[t.Name] = t
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Diff lists the expected changes from state a to state b. Unstable hosts are
// left out: their changes come from time, not from the scenario.
func Diff(a, b *File) []Change {
	var out []Change
	ah, bh := map[string]Host{}, map[string]Host{}
	for _, h := range a.Hosts {
		if h.Availability == nil {
			ah[h.IP] = h
		}
	}
	for _, h := range b.Hosts {
		if h.Availability == nil {
			bh[h.IP] = h
		}
	}
	for _, ip := range sortedKeys(bh) {
		if _, ok := ah[ip]; !ok {
			out = append(out, Change{Kind: "host_new", IP: ip, Summary: "new host " + bh[ip].Name})
		}
	}
	for _, ip := range sortedKeys(ah) {
		hb, ok := bh[ip]
		if !ok {
			out = append(out, Change{Kind: "host_gone", IP: ip, Summary: "host " + ah[ip].Name + " is gone"})
			continue
		}
		out = append(out, diffHost(ah[ip], hb)...)
	}
	return out
}

func svcKey(s Service) string { return fmt.Sprintf("%05d/%s", s.Port, s.Proto) }

func diffHost(a, b Host) []Change {
	var out []Change
	as, bs := map[string]Service{}, map[string]Service{}
	for _, s := range a.Services {
		as[svcKey(s)] = s
	}
	for _, s := range b.Services {
		bs[svcKey(s)] = s
	}
	for _, k := range sortedKeys(bs) {
		if _, ok := as[k]; !ok {
			s := bs[k]
			out = append(out, Change{Kind: "service_new", IP: b.IP, Port: s.Port, Proto: s.Proto, Summary: fmt.Sprintf("port %d/%s opened (%s)", s.Port, s.Proto, s.Name)})
		}
	}
	for _, k := range sortedKeys(as) {
		sa := as[k]
		sb, ok := bs[k]
		if !ok {
			out = append(out, Change{Kind: "service_gone", IP: a.IP, Port: sa.Port, Proto: sa.Proto, Summary: fmt.Sprintf("port %d/%s closed (%s)", sa.Port, sa.Proto, sa.Name)})
			continue
		}
		out = append(out, diffService(a.IP, sa, sb)...)
	}
	return out
}

func diffService(ip string, a, b Service) []Change {
	var out []Change
	add := func(kind, field, before, after, summary string) {
		out = append(out, Change{Kind: kind, IP: ip, Port: a.Port, Proto: a.Proto, Field: field, Before: before, After: after, Summary: summary})
	}
	if a.Product != b.Product {
		add("service_changed", "product", a.Product, b.Product, "product changed")
	}
	if a.Version != b.Version {
		add("service_changed", "version", a.Version, b.Version, "version changed")
	}
	at, bt := techNames(a.Technologies), techNames(b.Technologies)
	for _, n := range sortedKeys(bt) {
		if _, ok := at[n]; !ok {
			add("tech_new", "tech:"+n, "", bt[n].Version, "new technology "+n)
		}
	}
	for _, n := range sortedKeys(at) {
		tb, ok := bt[n]
		if !ok {
			add("tech_gone", "tech:"+n, at[n].Version, "", "technology "+n+" is gone")
		} else if at[n].Version != tb.Version {
			add("tech_version", "tech:"+n, at[n].Version, tb.Version, n+" version changed")
		}
	}
	ac, bc := strings.Join(sortedCopy(a.Classes), ","), strings.Join(sortedCopy(b.Classes), ",")
	if ac != bc {
		add("class_changed", "classes", ac, bc, "service classes changed")
	}
	if a.HTTP != nil && b.HTTP != nil {
		if a.HTTP.Title != b.HTTP.Title {
			add("title_changed", "title", a.HTTP.Title, b.HTTP.Title, "page title changed")
		}
		if a.HTTP.Status != b.HTTP.Status {
			add("status_changed", "status", fmt.Sprint(a.HTTP.Status), fmt.Sprint(b.HTTP.Status), "HTTP status changed")
		}
		if a.HTTP.Location != b.HTTP.Location {
			add("redirect_changed", "location", a.HTTP.Location, b.HTTP.Location, "redirect target changed")
		}
		ahd, bhd := map[string]string{}, map[string]string{}
		for k, v := range a.HTTP.Headers {
			ahd[k] = v
		}
		for k, v := range b.HTTP.Headers {
			bhd[k] = v
		}
		if a.HTTP.Server != "" {
			ahd["Server"] = a.HTTP.Server
		}
		if b.HTTP.Server != "" {
			bhd["Server"] = b.HTTP.Server
		}
		names := map[string]bool{}
		for k := range ahd {
			names[k] = true
		}
		for k := range bhd {
			names[k] = true
		}
		for _, n := range sortedKeys(names) {
			va, oka := ahd[n]
			vb, okb := bhd[n]
			if oka != okb || va != vb {
				add("headers_changed", "header:"+n, va, vb, "header "+n+" changed")
			}
		}
		aco, bco := map[string]Cookie{}, map[string]Cookie{}
		for _, c := range a.HTTP.Cookies {
			aco[c.Name] = c
		}
		for _, c := range b.HTTP.Cookies {
			bco[c.Name] = c
		}
		cn := map[string]bool{}
		for k := range aco {
			cn[k] = true
		}
		for k := range bco {
			cn[k] = true
		}
		for _, n := range sortedKeys(cn) {
			ca, oka := aco[n]
			cb, okb := bco[n]
			if oka != okb || ca != cb {
				add("cookies_changed", "cookie:"+n, CookieFlags(oka, ca.Secure, ca.HTTPOnly), CookieFlags(okb, cb.Secure, cb.HTTPOnly), "cookie "+n+" changed")
			}
		}
	}
	if (a.TLS == nil) != (b.TLS == nil) {
		add("cert_changed", "tls", fmt.Sprint(a.TLS != nil), fmt.Sprint(b.TLS != nil), "TLS turned on or off")
	} else if a.TLS != nil && !tlsEqual(*a.TLS, *b.TLS) {
		add("cert_changed", "certificate", a.TLS.SubjectCN, b.TLS.SubjectCN, "certificate replaced")
	}
	return out
}

func tlsEqual(a, b TLS) bool {
	return a.SubjectCN == b.SubjectCN && a.IssuerCN == b.IssuerCN && a.SelfSigned == b.SelfSigned &&
		a.Expired == b.Expired && a.HostMismatch == b.HostMismatch && a.DaysLeft == b.DaysLeft && a.Gen == b.Gen &&
		strings.Join(a.SANs, ",") == strings.Join(b.SANs, ",")
}

// CookieFlags renders the flags of a cookie for a change record.
func CookieFlags(present, secure, httpOnly bool) string {
	if !present {
		return ""
	}
	s := "set"
	if secure {
		s += " Secure"
	}
	if httpOnly {
		s += " HttpOnly"
	}
	return s
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
