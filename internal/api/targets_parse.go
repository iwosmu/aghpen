package api

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// BasicTargetParser is the built-in minimal target parser: IP, CIDR, range and
// domain, with address counting. internal/targets replaces it at integration.
type BasicTargetParser struct{}

var domainRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)

// ParseTarget parses one target value.
func ParseTarget(value string) (model.Target, error) {
	v := strings.TrimSpace(value)
	t := model.Target{Value: v, Enabled: true, Tags: []string{}}
	switch {
	case v == "":
		return t, fmt.Errorf("empty value")
	case strings.Contains(v, "/"):
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return t, fmt.Errorf("not a valid CIDR")
		}
		p = p.Masked()
		t.Kind, t.Value = model.TargetCIDR, p.String()
		host := p.Addr().BitLen() - p.Bits()
		if host >= 62 {
			t.Addresses = math.MaxInt64
		} else {
			t.Addresses = int64(1) << host
		}
		return t, nil
	case strings.Contains(v, "-") && !domainRe.MatchString(v):
		a, b, _ := strings.Cut(v, "-")
		from, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil || !from.Is4() {
			return t, fmt.Errorf("a range must be IPv4: start-end")
		}
		b = strings.TrimSpace(b)
		to, err := netip.ParseAddr(b)
		if err != nil {
			// short form: 10.0.0.5-90
			n, nerr := strconv.Atoi(b)
			if nerr != nil || n < 0 || n > 255 {
				return t, fmt.Errorf("the end of the range is not an address")
			}
			o := from.As4()
			o[3] = byte(n)
			to = netip.AddrFrom4(o)
		}
		if !to.Is4() || to.Less(from) {
			return t, fmt.Errorf("the end of the range is before its start")
		}
		t.Kind, t.Value = model.TargetRange, from.String()+"-"+to.String()
		t.Addresses = int64(u32(to)) - int64(u32(from)) + 1
		return t, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		t.Kind, t.Value, t.Addresses = model.TargetIP, a.Unmap().String(), 1
		return t, nil
	}
	if domainRe.MatchString(v) && len(v) <= 253 {
		t.Kind, t.Value, t.Addresses = model.TargetDomain, strings.ToLower(strings.TrimSuffix(v, ".")), 1
		return t, nil
	}
	return t, fmt.Errorf("not an IP address, CIDR, range or domain")
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// ParseText parses one target per line. Empty lines and lines that start with # are skipped.
func (BasicTargetParser) ParseText(text string) ([]model.Target, []model.InvalidLine) {
	valid, invalid := []model.Target{}, []model.InvalidLine{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if c := strings.Index(line, "#"); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		for _, v := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
			t, err := ParseTarget(v)
			if err != nil {
				invalid = append(invalid, model.InvalidLine{Line: i + 1, Value: v, Reason: err.Error()})
				continue
			}
			t.Source = "manual"
			valid = append(valid, t)
		}
	}
	return valid, invalid
}

// ParseFile parses a target file. JSON: an array of strings or of Target
// objects (or {"targets": [...]}). CSV: the value in the first column, an
// optional note in the second, optional tags (separated by |) in the third; a
// header row is skipped.
func (p BasicTargetParser) ParseFile(filename string, data []byte) ([]model.Target, []model.InvalidLine, error) {
	valid, invalid := []model.Target{}, []model.InvalidLine{}
	trim := bytes.TrimSpace(data)
	add := func(line int, value, note string, tags []string, source string) {
		t, err := ParseTarget(value)
		if err != nil {
			invalid = append(invalid, model.InvalidLine{Line: line, Value: value, Reason: err.Error()})
			return
		}
		t.Note, t.Source = note, source
		if tags != nil {
			t.Tags = tags
		}
		valid = append(valid, t)
	}
	if strings.HasSuffix(strings.ToLower(filename), ".json") || (len(trim) > 0 && (trim[0] == '[' || trim[0] == '{')) {
		var items []json.RawMessage
		if len(trim) > 0 && trim[0] == '{' {
			var wrap struct {
				Targets []json.RawMessage `json:"targets"`
			}
			if err := json.Unmarshal(trim, &wrap); err != nil {
				return nil, nil, fmt.Errorf("the file is not valid JSON: %v", err)
			}
			items = wrap.Targets
		} else if err := json.Unmarshal(trim, &items); err != nil {
			return nil, nil, fmt.Errorf("the file is not valid JSON: %v", err)
		}
		for i, raw := range items {
			var sv string
			if json.Unmarshal(raw, &sv) == nil {
				add(i+1, sv, "", nil, "json")
				continue
			}
			var t model.Target
			if err := json.Unmarshal(raw, &t); err != nil {
				invalid = append(invalid, model.InvalidLine{Line: i + 1, Value: string(raw), Reason: "not a string and not a target object"})
				continue
			}
			add(i+1, t.Value, t.Note, t.Tags, "json")
		}
		return valid, invalid, nil
	}
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	if first, _, _ := strings.Cut(string(trim), "\n"); strings.Count(first, ";") > strings.Count(first, ",") {
		rd.Comma = ';'
	}
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("the file is not valid CSV: %v", err)
	}
	for i, row := range rows {
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" || strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		if i == 0 {
			if _, err := ParseTarget(row[0]); err != nil {
				continue // header row
			}
		}
		note, tags := "", []string(nil)
		if len(row) > 1 {
			note = strings.TrimSpace(row[1])
		}
		if len(row) > 2 && strings.TrimSpace(row[2]) != "" {
			for _, tg := range strings.Split(row[2], "|") {
				if tg = strings.TrimSpace(tg); tg != "" {
					tags = append(tags, tg)
				}
			}
		}
		add(i+1, row[0], note, tags, "csv")
	}
	return valid, invalid, nil
}

type span struct{ from, to uint32 }

func targetSpan(kind model.TargetKind, value string) (span, bool) {
	switch kind {
	case model.TargetIP:
		if a, err := netip.ParseAddr(value); err == nil && a.Is4() {
			return span{u32(a), u32(a)}, true
		}
	case model.TargetCIDR:
		if p, err := netip.ParsePrefix(value); err == nil && p.Addr().Is4() {
			from := u32(p.Masked().Addr())
			return span{from, from + uint32((uint64(1)<<(32-p.Bits()))-1)}, true
		}
	case model.TargetRange:
		a, b, _ := strings.Cut(value, "-")
		from, err1 := netip.ParseAddr(a)
		to, err2 := netip.ParseAddr(b)
		if err1 == nil && err2 == nil && from.Is4() && to.Is4() {
			return span{u32(from), u32(to)}, true
		}
	}
	return span{}, false
}

// Excluded counts the IPv4 addresses of the targets that the exclusions cover.
// Excluded domains count one address each.
func (BasicTargetParser) Excluded(targets []model.Target, exclusions []string) int64 {
	var ex []span
	domains := map[string]bool{}
	for _, e := range exclusions {
		t, err := ParseTarget(e)
		if err != nil {
			continue
		}
		if t.Kind == model.TargetDomain {
			domains[t.Value] = true
			continue
		}
		if sp, ok := targetSpan(t.Kind, t.Value); ok {
			ex = append(ex, sp)
		}
	}
	// merge the exclusion spans so overlapping exclusions are not counted twice
	sort.Slice(ex, func(i, j int) bool { return ex[i].from < ex[j].from })
	var merged []span
	for _, e := range ex {
		if n := len(merged); n > 0 && uint64(e.from) <= uint64(merged[n-1].to)+1 {
			if e.to > merged[n-1].to {
				merged[n-1].to = e.to
			}
			continue
		}
		merged = append(merged, e)
	}
	var total int64
	for _, t := range targets {
		if t.Kind == model.TargetDomain {
			if domains[t.Value] {
				total++
			}
			continue
		}
		sp, ok := targetSpan(t.Kind, t.Value)
		if !ok {
			continue
		}
		for _, e := range merged {
			lo, hi := max(sp.from, e.from), min(sp.to, e.to)
			if lo <= hi {
				total += int64(hi-lo) + 1
			}
		}
	}
	return total
}

// blocks24 lists the /24 blocks that a chunk spec entry (IP, CIDR or range) covers, up to limit.
func blocks24(spec string, limit int) []string {
	t, err := ParseTarget(spec)
	if err != nil {
		return nil
	}
	sp, ok := targetSpan(t.Kind, t.Value)
	if !ok {
		return nil
	}
	var out []string
	for b := uint64(sp.from) &^ 0xff; b <= uint64(sp.to) && len(out) < limit; b += 256 {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], uint32(b))
		out = append(out, netip.AddrFrom4(a).String()+"/24")
	}
	return out
}
