package probe

import (
	"fmt"
	"strconv"
	"strings"
)

// PortSet is a set of TCP ports (1..65535).
type PortSet struct {
	bits [1024]uint64
}

// Add puts one port into the set. Ports outside 1..65535 are ignored.
func (p *PortSet) Add(port int) {
	if port >= 1 && port <= 65535 {
		p.bits[port>>6] |= 1 << uint(port&63)
	}
}

// Has reports whether the port is in the set.
func (p *PortSet) Has(port int) bool {
	return port >= 1 && port <= 65535 && p.bits[port>>6]&(1<<uint(port&63)) != 0
}

// Count returns the number of ports.
func (p *PortSet) Count() int {
	n := 0
	for port := 1; port <= 65535; port++ {
		if p.Has(port) {
			n++
		}
	}
	return n
}

// List returns the ports in ascending order.
func (p *PortSet) List() []int {
	var out []int
	for port := 1; port <= 65535; port++ {
		if p.Has(port) {
			out = append(out, port)
		}
	}
	return out
}

// String formats the set as an nmap port specification ("22,80,8000-8100").
func (p *PortSet) String() string {
	var b strings.Builder
	for port := 1; port <= 65535; port++ {
		if !p.Has(port) {
			continue
		}
		end := port
		for end < 65535 && p.Has(end+1) {
			end++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(port))
		if end > port {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(end))
		}
		port = end
	}
	return b.String()
}

// Intersect keeps only the ports that are also in o.
func (p *PortSet) Intersect(o *PortSet) {
	for i := range p.bits {
		p.bits[i] &= o.bits[i]
	}
}

// Remove deletes the ports of o from the set.
func (p *PortSet) Remove(o *PortSet) {
	for i := range p.bits {
		p.bits[i] &^= o.bits[i]
	}
}

// PortsOf builds a set from a list.
func PortsOf(ports ...int) *PortSet {
	p := &PortSet{}
	for _, x := range ports {
		p.Add(x)
	}
	return p
}

// ParsePorts parses a port specification: "top-100", "top-1000", single
// ports, ranges "8000-8100", "all" or "-" for every port, and any
// comma-separated mix of these ("top-100,6379,9000-9010"). Only TCP is
// supported. Error texts are Polish: the operator sees them.
func ParsePorts(spec string) (*PortSet, error) {
	p := &PortSet{}
	tokens := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\t' || r == '\n' })
	if len(tokens) == 0 {
		return nil, fmt.Errorf("pusta lista portów")
	}
	for _, tok := range tokens {
		t := strings.ToLower(strings.TrimSpace(tok))
		if strings.HasPrefix(t, "u:") || strings.HasPrefix(t, "s:") {
			return nil, fmt.Errorf("porty %q: obsługiwany jest tylko protokół TCP", tok)
		}
		t = strings.TrimPrefix(t, "t:")
		switch t {
		case "top-100", "top100":
			if err := p.addSpec(top100TCP); err != nil {
				return nil, err
			}
			continue
		case "top-1000", "top1000":
			if err := p.addSpec(top1000TCP); err != nil {
				return nil, err
			}
			continue
		case "all", "-", "*":
			for port := 1; port <= 65535; port++ {
				p.Add(port)
			}
			continue
		}
		if strings.HasPrefix(t, "top") {
			return nil, fmt.Errorf("nieznana lista portów %q (dostępne: top-100, top-1000)", tok)
		}
		if err := p.addSpec(t); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *PortSet) addSpec(spec string) error {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, ok := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return fmt.Errorf("niepoprawny port %q (dozwolone 1–65535)", part)
		}
		b := a
		if ok {
			b, err = strconv.Atoi(hi)
			if err != nil || b < a || b > 65535 {
				return fmt.Errorf("niepoprawny zakres portów %q", part)
			}
		}
		for port := a; port <= b; port++ {
			p.Add(port)
		}
	}
	return nil
}

// EffectivePorts returns the ports a run may touch: the profile ports,
// intersected with the policy allow-list (empty = all allowed), minus the
// policy deny-list. An empty profile spec means top-100.
func EffectivePorts(profile, allowed, denied string) (*PortSet, error) {
	if strings.TrimSpace(profile) == "" {
		profile = "top-100"
	}
	p, err := ParsePorts(profile)
	if err != nil {
		return nil, err
	}
	if err := applyPolicy(p, allowed, denied); err != nil {
		return nil, err
	}
	return p, nil
}

// FilterPorts applies the policy allow and deny lists to a plain port list
// (used for the host-discovery probe ports).
func FilterPorts(ports []int, allowed, denied string) ([]int, error) {
	p := PortsOf(ports...)
	if err := applyPolicy(p, allowed, denied); err != nil {
		return nil, err
	}
	var out []int
	for _, x := range ports { // keep the caller's order
		if p.Has(x) {
			out = append(out, x)
			p.bits[x>>6] &^= 1 << uint(x&63)
		}
	}
	return out, nil
}

func applyPolicy(p *PortSet, allowed, denied string) error {
	if strings.TrimSpace(allowed) != "" {
		a, err := ParsePorts(allowed)
		if err != nil {
			return fmt.Errorf("polityka bezpieczeństwa, dozwolone porty: %w", err)
		}
		p.Intersect(a)
	}
	if strings.TrimSpace(denied) != "" {
		d, err := ParsePorts(denied)
		if err != nil {
			return fmt.Errorf("polityka bezpieczeństwa, zabronione porty: %w", err)
		}
		p.Remove(d)
	}
	return nil
}
