// Package passive collects facts about a scope without sending any packet
// to a scan target: files handed over by the network owner (DNS zone exports,
// passive DNS, certificate lists), reverse DNS through the system resolver,
// and, only when an administrator turns it on, Certificate Transparency.
//
// The output is a list of facts (hostname, IP, source) and of candidate
// targets. Nothing here adds a target or starts a scan: the store shows the
// candidates and an analyst confirms them.
package passive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Kinds of facts.
const (
	KindDNS         = "dns"         // forward record or a plain hostname-IP pair
	KindPTR         = "ptr"         // reverse record: IP -> hostname
	KindCNAME       = "cname"       // alias: hostname -> Target
	KindCertificate = "certificate" // hostname seen in a certificate
	KindObservation = "observation" // an address (and maybe a port) seen by a passive sensor
)

// Cert is what a certificate list says about one certificate.
type Cert struct {
	SubjectCN string    `json:"subject_cn,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
}

// Fact is one statement of a passive source.
type Fact struct {
	Hostname  string    `json:"hostname,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Port      int       `json:"port,omitempty"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target,omitempty"` // CNAME target
	Source    string    `json:"source"`           // "file:strefa.csv", "ptr", "crt.sh"
	Sensor    string    `json:"sensor,omitempty"` // the "source" column of a file, when it has one
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
	Count     int       `json:"count,omitempty"`
	Wildcard  bool      `json:"wildcard,omitempty"` // the name came from "*.name"
	Cert      *Cert     `json:"cert,omitempty"`
}

// AddrRange is an inclusive address range.
type AddrRange struct{ From, To netip.Addr }

// Scope says what belongs to the organisation. A passive file can name
// addresses of other networks; only facts inside the scope make candidates.
type Scope struct {
	Prefixes []netip.Prefix
	Ranges   []AddrRange
	Domains  []string     // "kampus.example": the domain and all its subdomains
	KnownIPs []netip.Addr // addresses the inventory already has; PTR looks these up
}

// ContainsIP reports if the address is inside a prefix or a range of the scope.
func (s Scope) ContainsIP(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	for _, r := range s.Ranges {
		if r.From.Is4() == a.Is4() && !a.Less(r.From) && !r.To.Less(a) {
			return true
		}
	}
	return false
}

// ContainsHost reports if the name is a scope domain or below one.
func (s Scope) ContainsHost(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, d := range s.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && (name == d || strings.HasSuffix(name, "."+d)) {
			return true
		}
	}
	return false
}

func (s Scope) knows(a netip.Addr) bool {
	for _, k := range s.KnownIPs {
		if k.Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}

// ScopeFromTargets builds a Scope from the enabled targets of the inventory
// and the addresses of its known hosts. Targets it cannot read are skipped.
func ScopeFromTargets(targets []model.Target, knownIPs []string) Scope {
	var s Scope
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		v := strings.TrimSpace(t.Value)
		switch t.Kind {
		case model.TargetIP:
			if a, err := netip.ParseAddr(v); err == nil {
				s.Prefixes = append(s.Prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			}
		case model.TargetCIDR:
			if p, err := netip.ParsePrefix(v); err == nil {
				s.Prefixes = append(s.Prefixes, p.Masked())
			}
		case model.TargetRange:
			from, to, ok := strings.Cut(v, "-")
			a, err := netip.ParseAddr(strings.TrimSpace(from))
			if !ok || err != nil {
				continue
			}
			to = strings.TrimSpace(to)
			b, err := netip.ParseAddr(to)
			if err != nil && a.Is4() && !strings.Contains(to, ".") {
				// Short form "10.0.0.5-90": the last octet only.
				head := a.String()[:strings.LastIndex(a.String(), ".")+1]
				b, err = netip.ParseAddr(head + to)
			}
			if err == nil && !b.Less(a) {
				s.Ranges = append(s.Ranges, AddrRange{a.Unmap(), b.Unmap()})
			}
		case model.TargetDomain:
			if h, _, ok := cleanHost(v); ok {
				s.Domains = append(s.Domains, h)
			}
		}
	}
	for _, k := range knownIPs {
		if a, err := netip.ParseAddr(strings.TrimSpace(k)); err == nil {
			s.KnownIPs = append(s.KnownIPs, a.Unmap())
		}
	}
	return s
}

// Source is one passive data source.
type Source interface {
	// Name identifies the source in facts and reports.
	Name() string
	// External reports if the source sends data about the scope (a domain
	// name, an address) to a service outside the organisation.
	External() bool
	// Collect returns the hostnames and addresses the source knows for the
	// scope. It must not send any packet to an address of the scope.
	Collect(ctx context.Context, scope Scope) ([]Fact, error)
}

// ErrExternalDisabled is returned for an external source that is not allowed.
var ErrExternalDisabled = errors.New("passive: external source is turned off")

// Options tunes Collect.
type Options struct {
	// AllowExternal lets sources with External() == true run. Off by default.
	AllowExternal bool
}

// Candidate is a possible new target. The store shows it; it becomes a
// target only after an analyst confirms it.
type Candidate struct {
	Kind      model.TargetKind `json:"kind"` // ip | domain
	Value     string           `json:"value"`
	Hostnames []string         `json:"hostnames,omitempty"` // names of an address candidate
	Ports     []int            `json:"ports,omitempty"`     // ports a passive sensor saw
	Sources   []string         `json:"sources"`
	LastSeen  time.Time        `json:"last_seen,omitzero"`
	Reason    string           `json:"reason"` // Polish, one sentence
}

// Hint is a hostname-to-IP fact for an address inside the scope. The store
// adds the names to the host; the HTTP collector can then ask for the right
// virtual host.
type Hint struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports,omitempty"`
	Sources   []string `json:"sources"`
	Known     bool     `json:"known"` // the inventory already has this address
}

// SourceReport says what one source did.
type SourceReport struct {
	Name     string `json:"name"`
	External bool   `json:"external"`
	Facts    int    `json:"facts"`
	Skipped  bool   `json:"skipped"` // external source that was not allowed
	Error    string `json:"error,omitempty"`
}

// Result is the merged output of all sources.
type Result struct {
	Facts      []Fact         `json:"facts"`        // inside the scope, duplicates merged
	OutOfScope []Fact         `json:"out_of_scope"` // outside the scope: shown, never a candidate
	Candidates []Candidate    `json:"candidates"`
	Hints      []Hint         `json:"hints"`
	Sources    []SourceReport `json:"sources"`
}

// Collect runs the sources one after another and merges what they return.
// A failing source does not stop the others; its error is in Result.Sources.
func Collect(ctx context.Context, scope Scope, opts Options, sources ...Source) Result {
	var all []Fact
	var res Result
	for _, src := range sources {
		rep := SourceReport{Name: src.Name(), External: src.External()}
		if src.External() && !opts.AllowExternal {
			rep.Skipped = true
			rep.Error = "źródło zewnętrzne jest wyłączone"
			res.Sources = append(res.Sources, rep)
			continue
		}
		facts, err := src.Collect(ctx, scope)
		if err != nil {
			rep.Error = err.Error()
		}
		rep.Facts = len(facts)
		all = append(all, facts...)
		res.Sources = append(res.Sources, rep)
	}
	res.merge(scope, all)
	return res
}

// Merge builds a Result from facts that are already at hand (for example
// from Parse), with the same scope rules as Collect.
func Merge(scope Scope, facts []Fact) Result {
	var res Result
	res.merge(scope, facts)
	return res
}

func factKey(f Fact) string {
	return strings.Join([]string{f.Kind, f.Hostname, f.IP, fmt.Sprint(f.Port), f.Target, f.Source}, "|")
}

func (res *Result) merge(scope Scope, all []Fact) {
	res.Facts, res.OutOfScope, res.Candidates, res.Hints = []Fact{}, []Fact{}, []Candidate{}, []Hint{}

	// 1. Merge duplicates: same statement from the same source.
	index := map[string]int{}
	var facts []Fact
	for _, f := range all {
		k := factKey(f)
		if i, ok := index[k]; ok {
			g := &facts[i]
			if !f.FirstSeen.IsZero() && (g.FirstSeen.IsZero() || f.FirstSeen.Before(g.FirstSeen)) {
				g.FirstSeen = f.FirstSeen
			}
			if f.LastSeen.After(g.LastSeen) {
				g.LastSeen = f.LastSeen
				if f.Cert != nil {
					g.Cert = f.Cert
				}
			}
			g.Count += f.Count
			g.Wildcard = g.Wildcard && f.Wildcard
			continue
		}
		index[k] = len(facts)
		facts = append(facts, f)
	}

	// 2. Scope. An address decides when the fact has one: a name of the
	// organisation that points to a foreign address (a cloud service) must
	// never make that address a target.
	type agg struct {
		names, sources map[string]bool
		ports          map[int]bool
		last           time.Time
	}
	newAgg := func() *agg { return &agg{names: map[string]bool{}, sources: map[string]bool{}, ports: map[int]bool{}} }
	byIP := map[netip.Addr]*agg{}
	byName := map[string]*agg{}
	resolved := map[string]bool{} // names that some fact ties to an address
	for _, f := range facts {
		if f.IP != "" && f.Hostname != "" {
			resolved[f.Hostname] = true
		}
	}
	for _, f := range facts {
		if f.IP != "" {
			a, err := netip.ParseAddr(f.IP)
			if err != nil || !scope.ContainsIP(a) {
				res.OutOfScope = append(res.OutOfScope, f)
				continue
			}
			res.Facts = append(res.Facts, f)
			g := byIP[a.Unmap()]
			if g == nil {
				g = newAgg()
				byIP[a.Unmap()] = g
			}
			if f.Hostname != "" {
				g.names[f.Hostname] = true
			}
			if f.Port > 0 {
				g.ports[f.Port] = true
			}
			g.sources[f.Source] = true
			if f.LastSeen.After(g.last) {
				g.last = f.LastSeen
			}
			continue
		}
		if !scope.ContainsHost(f.Hostname) {
			res.OutOfScope = append(res.OutOfScope, f)
			continue
		}
		res.Facts = append(res.Facts, f)
		if resolved[f.Hostname] {
			continue // another fact already says where the name points
		}
		g := byName[f.Hostname]
		if g == nil {
			g = newAgg()
			byName[f.Hostname] = g
		}
		g.sources[f.Source] = true
		if f.LastSeen.After(g.last) {
			g.last = f.LastSeen
		}
	}

	// 3. Hints and candidates.
	ips := make([]netip.Addr, 0, len(byIP))
	for a := range byIP {
		ips = append(ips, a)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	for _, a := range ips {
		g := byIP[a]
		names, srcs, ports := sortedKeys(g.names), sortedKeys(g.sources), sortedInts(g.ports)
		known := scope.knows(a)
		if len(names) > 0 || len(ports) > 0 {
			res.Hints = append(res.Hints, Hint{IP: a.String(), Hostnames: names, Ports: ports, Sources: srcs, Known: known})
		}
		if !known {
			res.Candidates = append(res.Candidates, Candidate{Kind: model.TargetIP, Value: a.String(), Hostnames: names, Ports: ports,
				Sources: srcs, LastSeen: g.last, Reason: "Adres z pasywnego źródła leży w zakresie, a nie ma go w inwentarzu."})
		}
	}
	for _, name := range sortedKeys2(byName) {
		g := byName[name]
		res.Candidates = append(res.Candidates, Candidate{Kind: model.TargetDomain, Value: name, Sources: sortedKeys(g.sources), LastSeen: g.last,
			Reason: "Nazwa w domenie zakresu bez znanego adresu. Sprawdź, czy wskazuje na sieć w zakresie, zanim dodasz ją do celów."})
	}
	sortFacts(res.Facts)
	sortFacts(res.OutOfScope)
}

func sortFacts(fs []Fact) {
	sort.SliceStable(fs, func(i, j int) bool { return factKey(fs[i]) < factKey(fs[j]) })
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys2[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
