package targets

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// ParseResult is the outcome of parsing a list of targets.
type ParseResult struct {
	Targets    []model.Target
	Invalid    []model.InvalidLine
	Duplicates int
}

// Parsed is one target value in machine form.
type Parsed struct {
	Kind   model.TargetKind
	Value  string     // normalised text
	Range  Range      // IPv4 address range (ip, cidr, range kinds with an IPv4 value)
	V6     netip.Addr // set for a single IPv6 address
	Domain string     // set for the domain kind
	Count  int64      // number of addresses (a domain counts as 1 until it is resolved)
}

var (
	reIPv4ish   = regexp.MustCompile(`^[0-9.]+$`)
	reTLD       = regexp.MustCompile(`^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)
	reLabel     = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	reRangeGlue = regexp.MustCompile(`([0-9])[ \t]+-[ \t]+([0-9])`)
)

// ParseValue parses one target: IPv4, IPv4 CIDR, range "a.b.c.d-e.f.g.h" or
// "a.b.c.d-N", a single IPv6 address, or a domain name. The error text is
// Polish because it is shown to the operator.
func ParseValue(raw string) (Parsed, error) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	if s == "" {
		return Parsed{}, errors.New("pusta wartość")
	}
	if len(s) > 255 {
		return Parsed{}, errors.New("wartość jest za długa (ponad 255 znaków)")
	}
	// URL form: keep the host only.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Parsed{}, errors.New("niepoprawny adres URL; podaj adres IP, zakres CIDR lub nazwę domeny")
		}
		s = u.Hostname()
	}

	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Parsed{}, fmt.Errorf("niepoprawny zakres CIDR %q (oczekiwano np. 10.0.0.0/24)", s)
		}
		if !p.Addr().Unmap().Is4() {
			return Parsed{}, errors.New("zakresy CIDR IPv6 nie są obsługiwane; podaj pojedyncze adresy IPv6")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		r := PrefixRange(p)
		if p.Bits() == 32 {
			return Parsed{Kind: model.TargetIP, Value: p.Addr().String(), Range: r, Count: 1}, nil
		}
		return Parsed{Kind: model.TargetCIDR, Value: p.String(), Range: r, Count: r.Size()}, nil
	}

	if i := strings.IndexByte(s, '-'); i > 0 {
		left, right := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
		if lo, err := netip.ParseAddr(left); err == nil && lo.Is4() {
			var hi netip.Addr
			if n, err := strconv.Atoi(right); err == nil && !strings.Contains(right, ".") {
				if n < 0 || n > 255 {
					return Parsed{}, fmt.Errorf("niepoprawny koniec zakresu %q (ostatni oktet musi być w 0–255)", right)
				}
				b := lo.As4()
				b[3] = byte(n)
				hi = netip.AddrFrom4(b)
			} else {
				hi, err = netip.ParseAddr(right)
				if err != nil || !hi.Is4() {
					return Parsed{}, fmt.Errorf("niepoprawny koniec zakresu %q (oczekiwano adresu IPv4 lub ostatniego oktetu)", right)
				}
			}
			if U32(hi) < U32(lo) {
				return Parsed{}, fmt.Errorf("koniec zakresu %s jest mniejszy niż początek %s", hi, lo)
			}
			r := Range{U32(lo), U32(hi)}
			if r.Lo == r.Hi {
				return Parsed{Kind: model.TargetIP, Value: lo.String(), Range: r, Count: 1}, nil
			}
			return Parsed{Kind: model.TargetRange, Value: lo.String() + "-" + hi.String(), Range: r, Count: r.Size()}, nil
		}
		if reIPv4ish.MatchString(left) {
			return Parsed{}, fmt.Errorf("niepoprawny początek zakresu %q (oczekiwano adresu IPv4)", left)
		}
	}

	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		if a.Is4() {
			u := U32(a)
			return Parsed{Kind: model.TargetIP, Value: a.String(), Range: Range{u, u}, Count: 1}, nil
		}
		return Parsed{Kind: model.TargetIP, Value: a.String(), V6: a, Count: 1}, nil
	}
	if reIPv4ish.MatchString(s) {
		return Parsed{}, fmt.Errorf("niepoprawny adres IPv4 %q (cztery oktety 0–255)", s)
	}
	if strings.Contains(s, ":") {
		return Parsed{}, fmt.Errorf("niepoprawny adres IPv6 %q", s)
	}

	d := strings.ToLower(strings.TrimSuffix(s, "."))
	if err := validDomain(d); err != nil {
		return Parsed{}, err
	}
	return Parsed{Kind: model.TargetDomain, Value: d, Domain: d, Count: 1}, nil
}

func validDomain(d string) error {
	if len(d) > 253 {
		return errors.New("nazwa domeny jest za długa (ponad 253 znaki)")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 && d != "localhost" {
		return fmt.Errorf("nie rozpoznano %q: to nie jest adres IP, zakres CIDR, zakres adresów ani nazwa domeny", d)
	}
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return fmt.Errorf("niepoprawna nazwa domeny %q (dozwolone litery, cyfry i myślnik)", d)
		}
	}
	last := labels[len(labels)-1]
	if d != "localhost" && !reTLD.MatchString(last) {
		return fmt.Errorf("niepoprawna nazwa domeny %q (końcówka musi składać się z liter)", d)
	}
	return nil
}

func (p Parsed) target(source string) model.Target {
	return model.Target{Kind: p.Kind, Value: p.Value, Enabled: true, Source: source, Addresses: p.Count, Tags: []string{}}
}

// collector gathers targets, invalid lines and duplicates.
type collector struct {
	res    ParseResult
	seen   map[string]bool
	source string
}

func newCollector(source string) *collector {
	return &collector{seen: map[string]bool{}, source: source, res: ParseResult{Targets: []model.Target{}, Invalid: []model.InvalidLine{}}}
}

func (c *collector) add(line int, raw, note string, tags []string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	p, err := ParseValue(raw)
	if err != nil {
		c.res.Invalid = append(c.res.Invalid, model.InvalidLine{Line: line, Value: raw, Reason: err.Error()})
		return
	}
	if c.seen[p.Value] {
		c.res.Duplicates++
		return
	}
	c.seen[p.Value] = true
	t := p.target(c.source)
	t.Note = strings.TrimSpace(note)
	if len(tags) > 0 {
		t.Tags = tags
	}
	c.res.Targets = append(c.res.Targets, t)
}

// ParseText parses free text: one target per line, or several separated by
// commas, semicolons or whitespace. Text after '#' is a comment.
func ParseText(text string) ParseResult {
	c := newCollector("manual")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for i, line := range strings.Split(text, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		// "10.0.0.1 - 10.0.0.9" is one range, not three tokens
		line = reRangeGlue.ReplaceAllString(line, "$1-$2")
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			c.add(i+1, tok, "", nil)
		}
	}
	return c.res
}

// splitTags splits a tag cell: "web;prod", "web|prod", "web, prod" or "web prod".
func splitTags(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' || r == ',' || r == ' ' }) {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// valueKeys are the accepted names of the value column or JSON key.
var valueKeys = []string{"value", "target", "ip", "address", "cidr", "host", "domain"}

func isValueKey(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	for _, v := range valueKeys {
		if k == v {
			return true
		}
	}
	return false
}
