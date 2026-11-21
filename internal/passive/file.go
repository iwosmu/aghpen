package passive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// File formats that Parse reads.
const (
	FormatJSON  = "passive-json"
	FormatJSONL = "passive-jsonl"
	FormatCSV   = "passive-csv"
	FormatZone  = "dns-zone" // zone file or "dig AXFR" output
)

// MaxInvalidReported caps the invalid rows listed in a FileReport.
const MaxInvalidReported = 200

// MaxFileBytes caps the size of one passive data file.
const MaxFileBytes = 256 << 20

// FileReport says what Parse found in a file.
type FileReport struct {
	Format       string              `json:"format"`
	Records      int                 `json:"records"`
	Facts        int                 `json:"facts"`
	Skipped      int                 `json:"skipped"` // records with nothing to learn from (NS, MX, TXT ...)
	InvalidTotal int                 `json:"invalid_total"`
	Invalid      []model.InvalidLine `json:"invalid"`
}

type parser struct {
	source string
	facts  []Fact
	rep    FileReport
}

func (p *parser) invalid(line int, value, reason string) {
	p.rep.InvalidTotal++
	if len(p.rep.Invalid) < MaxInvalidReported {
		if r := []rune(value); len(r) > 120 {
			value = string(r[:120])
		}
		p.rep.Invalid = append(p.rep.Invalid, model.InvalidLine{Line: line, Value: value, Reason: reason})
	}
}

// Parse reads one passive data file: tolerant JSON, JSON Lines, CSV (comma,
// semicolon, tab or pipe) or a DNS zone file. The format is detected from the
// content. name labels the facts ("file:" + name). A row that cannot be read
// goes to the report; it never stops the import.
func Parse(r io.Reader, name string) ([]Fact, FileReport, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, FileReport{}, fmt.Errorf("nie można odczytać pliku: %w", err)
	}
	if len(data) > MaxFileBytes {
		return nil, FileReport{}, fmt.Errorf("plik jest większy niż %d MB", MaxFileBytes>>20)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, FileReport{}, errors.New("plik jest pusty")
	}
	p := &parser{source: "file:" + name}
	p.rep.Invalid = []model.InvalidLine{}
	switch detect(data) {
	case FormatJSON:
		err = p.json(data)
	case FormatZone:
		p.zone(data)
	default:
		err = p.csv(data)
	}
	if err != nil {
		return nil, p.rep, err
	}
	p.rep.Facts = len(p.facts)
	return p.facts, p.rep, nil
}

var reZoneLine = regexp.MustCompile(`(?i)^\S*\s+(\d+[smhdw]?\s+)?IN\s+(A|AAAA|CNAME|PTR|NS|MX|SOA|TXT|SRV)\s+\S`)

func detect(data []byte) string {
	t := bytes.TrimSpace(data)
	if t[0] == '[' || t[0] == '{' {
		return FormatJSON
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; i < 40 && sc.Scan(); i++ {
		line := sc.Text()
		if strings.HasPrefix(line, "$ORIGIN") || strings.HasPrefix(line, "$TTL") || reZoneLine.MatchString(line) {
			return FormatZone
		}
	}
	return FormatCSV
}

// ---------- one record ----------

var listSplit = regexp.MustCompile(`[\s;,|]+`)

func splitList(s string) []string {
	var out []string
	for _, v := range listSplit.Split(strings.TrimSpace(s), -1) {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil
}

// commonName takes the CN out of a subject like "C=PL, O=Uczelnia, CN=www.x".
func commonName(s string) string {
	if i := strings.Index(strings.ToUpper(s), "CN="); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexAny(s, ",/"); j >= 0 {
			s = s[:j]
		}
	}
	return strings.TrimSpace(s)
}

func (p *parser) record(rec map[Field]string, line int) {
	p.rep.Records++
	raw := rec[FHostname] + " " + rec[FIP] + " " + rec[FValue]
	base := Fact{Source: p.source, Sensor: strings.TrimSpace(rec[FSource])}
	if t, ok := parseTime(rec[FFirstSeen]); ok {
		base.FirstSeen = t
	}
	if t, ok := parseTime(rec[FLastSeen]); ok {
		base.LastSeen = t
	}
	if n, err := strconv.Atoi(strings.TrimSpace(rec[FCount])); err == nil && n > 0 {
		base.Count = n
	}
	if v := strings.TrimSpace(rec[FPort]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			p.invalid(line, v, "niepoprawny numer portu")
			return
		}
		base.Port = n
	}
	name, ipText, value := strings.TrimSpace(rec[FHostname]), strings.TrimSpace(rec[FIP]), strings.TrimSpace(rec[FValue])
	// A "host" or "address" column can hold an address or a name.
	if ipText == "" && isIP(name) {
		ipText, name = name, ""
	}
	if name == "" && ipText != "" && !isIP(ipText) && len(splitList(ipText)) == 1 {
		if _, _, ok := cleanHost(ipText); ok {
			name, ipText = ipText, ""
		}
	}
	add := func(f Fact) { p.facts = append(p.facts, f) }
	addr := func(s string) (string, bool) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			p.invalid(line, s, "niepoprawny adres IP")
			return "", false
		}
		return a.Unmap().String(), true
	}
	host := func(s string) (string, bool, bool) {
		h, wc, ok := cleanHost(s)
		if !ok {
			p.invalid(line, s, "niepoprawna nazwa hosta")
		}
		return h, wc, ok
	}

	switch typ := strings.ToUpper(strings.TrimSpace(rec[FType])); typ {
	case "A", "AAAA":
		h, wc, ok := host(name)
		if !ok {
			return
		}
		ips := splitList(value)
		if len(ips) == 0 {
			ips = splitList(ipText)
		}
		if len(ips) == 0 {
			p.invalid(line, raw, "rekord "+typ+" bez adresu")
			return
		}
		for _, s := range ips {
			if a, ok := addr(s); ok {
				f := base
				f.Kind, f.Hostname, f.IP, f.Wildcard = KindDNS, h, a, wc
				add(f)
			}
		}
	case "CNAME":
		h, wc, ok := host(name)
		if !ok {
			return
		}
		tgt, _, ok := host(value)
		if !ok {
			return
		}
		f := base
		f.Kind, f.Hostname, f.Target, f.Wildcard = KindCNAME, h, tgt, wc
		add(f)
	case "PTR":
		a, ok := arpaToAddr(name)
		if !ok {
			text := name
			if text == "" {
				text = ipText
			}
			parsed, err := netip.ParseAddr(text)
			if err != nil {
				p.invalid(line, name, "rekord PTR bez adresu")
				return
			}
			a = parsed
		}
		for _, s := range splitList(value) {
			if h, _, ok := host(s); ok {
				f := base
				f.Kind, f.Hostname, f.IP = KindPTR, h, a.Unmap().String()
				add(f)
			}
		}
	case "":
		p.generic(rec, base, name, ipText, value, line, raw, addr, host)
	default:
		p.rep.Skipped++ // NS, MX, TXT, SOA ...: nothing about hosts of the scope
	}
}

func (p *parser) generic(rec map[Field]string, base Fact, name, ipText, value string, line int, raw string,
	addr func(string) (string, bool), host func(string) (string, bool, bool)) {
	var cert *Cert
	if rec[FCertSANs] != "" || rec[FCertCN] != "" || rec[FNotAfter] != "" || rec[FCertSHA256] != "" || rec[FCertSerial] != "" {
		cert = &Cert{SubjectCN: commonName(rec[FCertCN]), Issuer: strings.TrimSpace(rec[FCertIssuer]),
			Serial: strings.TrimSpace(rec[FCertSerial]), SHA256: strings.ToLower(strings.TrimSpace(rec[FCertSHA256]))}
		cert.NotBefore, _ = parseTime(rec[FNotBefore])
		cert.NotAfter, _ = parseTime(rec[FNotAfter])
	}
	if cert != nil && base.FirstSeen.IsZero() {
		base.FirstSeen = cert.NotBefore // crt.sh often has no entry time
	}
	rawNames := splitList(name)
	if cert != nil {
		rawNames = append(rawNames, splitList(rec[FCertSANs])...)
		if cert.SubjectCN != "" && !strings.Contains(cert.SubjectCN, " ") {
			rawNames = append(rawNames, cert.SubjectCN)
		}
	}
	var ips []string
	for _, s := range splitList(ipText) {
		if a, ok := addr(s); ok {
			ips = append(ips, a)
		}
	}
	// "value" without a record type: addresses, or names when there is no name yet.
	for _, s := range splitList(value) {
		switch {
		case isIP(s):
			if a, ok := addr(s); ok {
				ips = append(ips, a)
			}
		case len(rawNames) == 0:
			rawNames = append(rawNames, s)
		}
	}
	type hn struct {
		name string
		wc   bool
	}
	var names []hn
	seen := map[string]bool{}
	for _, s := range rawNames {
		if isIP(s) {
			continue // certificates can list addresses among the names
		}
		if h, wc, ok := host(s); ok && !seen[h] {
			seen[h] = true
			names = append(names, hn{h, wc})
		}
	}
	kind := KindDNS
	if cert != nil {
		kind = KindCertificate
	}
	switch {
	case len(names) == 0 && len(ips) == 0:
		if len(rawNames) == 0 && ipText == "" {
			p.invalid(line, strings.TrimSpace(raw), "brak adresu IP i nazwy hosta")
		}
	case len(names) == 0:
		for _, a := range ips {
			f := base
			f.Kind, f.IP, f.Cert = KindObservation, a, cert
			if cert != nil {
				f.Kind = kind
			}
			p.facts = append(p.facts, f)
		}
	case len(ips) == 0:
		for _, n := range names {
			f := base
			f.Kind, f.Hostname, f.Wildcard, f.Cert = kind, n.name, n.wc, cert
			p.facts = append(p.facts, f)
		}
	default:
		for _, n := range names {
			for _, a := range ips {
				f := base
				f.Kind, f.Hostname, f.IP, f.Wildcard, f.Cert = kind, n.name, a, n.wc, cert
				p.facts = append(p.facts, f)
			}
		}
	}
}

// ---------- JSON and JSON Lines ----------

var arrayKeys = map[string]bool{"data": true, "results": true, "records": true, "items": true, "hosts": true, "rows": true, "entries": true, "certificates": true, "answers": true}

func (p *parser) json(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	top := 0
	index := 0
	for {
		var raw json.RawMessage
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if top == 0 {
				return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
			}
			p.invalid(top+1, "", "uszkodzony JSON: "+err.Error())
			break
		}
		top++
		p.jsonValue(raw, &index, 0)
	}
	p.rep.Format = FormatJSON
	if top > 1 {
		p.rep.Format = FormatJSONL
	}
	return nil
}

func (p *parser) jsonValue(raw json.RawMessage, index *int, depth int) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return
	}
	if t[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(t, &arr) == nil {
			for _, e := range arr {
				p.jsonValue(e, index, depth+1)
			}
		}
		return
	}
	*index++
	var obj map[string]json.RawMessage
	if t[0] != '{' || json.Unmarshal(t, &obj) != nil {
		p.invalid(*index, string(t), "rekord nie jest obiektem JSON")
		return
	}
	if depth == 0 {
		// An envelope: {"results": [...]} or {"data": {"records": [...]}}.
		for k, v := range obj {
			vt := bytes.TrimSpace(v)
			if arrayKeys[normName(k)] && len(vt) > 0 && (vt[0] == '[' || vt[0] == '{') {
				var arr []json.RawMessage
				if json.Unmarshal(vt, &arr) == nil && (len(arr) == 0 || bytes.HasPrefix(bytes.TrimSpace(arr[0]), []byte("{"))) {
					*index--
					for _, e := range arr {
						p.jsonValue(e, index, 1)
					}
					return
				}
				if vt[0] == '{' {
					*index--
					p.jsonValue(vt, index, 0)
					return
				}
			}
		}
	}
	rec := map[Field]string{}
	fill := func(m map[string]json.RawMessage) {
		for k, v := range m {
			f, ok := LookupField(k)
			if !ok {
				continue
			}
			if s, ok := scalarText(v); ok && rec[f] == "" {
				rec[f] = s
			}
		}
	}
	fill(obj)
	// One level of nesting: {"certificate": {"issuer": ...}}.
	for _, v := range obj {
		if vt := bytes.TrimSpace(v); len(vt) > 0 && vt[0] == '{' {
			var inner map[string]json.RawMessage
			if json.Unmarshal(vt, &inner) == nil {
				fill(inner)
			}
		}
	}
	p.record(rec, *index)
}

// scalarText turns a JSON scalar or an array of scalars into text.
func scalarText(raw json.RawMessage) (string, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return "", false
	}
	switch t[0] {
	case '"':
		var s string
		if json.Unmarshal(t, &s) != nil {
			return "", false
		}
		return s, true
	case '{':
		return "", false
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(t, &arr) != nil {
			return "", false
		}
		var parts []string
		for _, a := range arr {
			if at := bytes.TrimSpace(a); len(at) > 0 && at[0] != '[' && at[0] != '{' {
				if s, ok := scalarText(a); ok {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, ";"), len(parts) > 0
	}
	return string(t), true
}

// ---------- CSV ----------

func (p *parser) csv(data []byte) error {
	p.rep.Format = FormatCSV
	first := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		first = data[:i]
	}
	delim, best := ',', 0
	for _, d := range []rune{',', ';', '\t', '|'} {
		if n := bytes.Count(first, []byte(string(d))); n > best {
			delim, best = d, n
		}
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = delim
	r.Comment = '#'
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	var header []Field
	haveHeader := false
	for n := 0; ; n++ {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := r.FieldPos(0)
		if err != nil {
			p.invalid(line, "", "uszkodzony wiersz CSV: "+err.Error())
			continue
		}
		if n == 0 {
			known, addrs := 0, 0
			header = make([]Field, len(row))
			for i, c := range row {
				if f, ok := LookupField(c); ok {
					header[i] = f
					known++
				}
				if isIP(c) {
					addrs++
				}
			}
			if known > 0 && addrs == 0 {
				haveHeader = true
				continue
			}
		}
		rec := map[Field]string{}
		if haveHeader {
			for i, c := range row {
				if i < len(header) && header[i] != "" && rec[header[i]] == "" {
					rec[header[i]] = strings.TrimSpace(c)
				}
			}
		} else {
			// No header: take the first address and the first name of the row.
			for _, c := range row {
				c = strings.TrimSpace(c)
				switch {
				case isIP(c) && rec[FIP] == "":
					rec[FIP] = c
				case rec[FHostname] == "" && strings.Contains(c, "."):
					if _, _, ok := cleanHost(c); ok {
						rec[FHostname] = c
					}
				}
			}
		}
		empty := true
		for _, v := range rec {
			if v != "" {
				empty = false
			}
		}
		if empty {
			if strings.TrimSpace(strings.Join(row, "")) != "" {
				p.rep.Records++
				p.invalid(line, strings.Join(row, string(delim)), "brak adresu IP i nazwy hosta")
			}
			continue
		}
		p.record(rec, line)
	}
	if len(p.facts) == 0 && !haveHeader {
		return errors.New("nie rozpoznano formatu pliku: oczekiwano JSON, JSON Lines, CSV lub pliku strefy DNS")
	}
	return nil
}

// ---------- DNS zone file ----------

var reTTL = regexp.MustCompile(`^\d+[smhdwSMHDW]?$`)

// zone reads the common subset of a zone file (RFC 1035 master format) and
// the output of "dig AXFR": one record per line, $ORIGIN, "@", relative names.
func (p *parser) zone(data []byte) {
	p.rep.Format = FormatZone
	origin, last := "", ""
	depth := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	fqdn := func(n string) string {
		switch {
		case n == "@":
			return origin
		case strings.HasSuffix(n, "."):
			return strings.TrimSuffix(n, ".")
		case origin != "":
			return n + "." + origin
		}
		return n
	}
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.IndexByte(text, ';'); i >= 0 {
			text = text[:i]
		}
		inside := depth > 0
		depth += strings.Count(text, "(") - strings.Count(text, ")")
		if inside || strings.TrimSpace(text) == "" {
			continue // continuation of a multi-line record (SOA)
		}
		f := strings.Fields(text)
		if strings.HasPrefix(f[0], "$") {
			if strings.EqualFold(f[0], "$ORIGIN") && len(f) > 1 {
				origin = strings.TrimSuffix(strings.ToLower(f[1]), ".")
			}
			continue
		}
		name := last
		if text[0] != ' ' && text[0] != '\t' {
			name, f = fqdn(f[0]), f[1:]
			last = name
		}
		for len(f) > 0 && (reTTL.MatchString(f[0]) || strings.EqualFold(f[0], "IN") || strings.EqualFold(f[0], "CH") || strings.EqualFold(f[0], "HS")) {
			f = f[1:]
		}
		if len(f) < 2 {
			p.rep.Records++
			p.invalid(line, strings.TrimSpace(text), "niepełny rekord strefy")
			continue
		}
		typ := strings.ToUpper(f[0])
		value := f[1]
		if typ == "CNAME" || typ == "PTR" {
			value = fqdn(value)
		}
		p.record(map[Field]string{FHostname: name, FType: typ, FValue: value}, line)
	}
}

// ---------- file source ----------

// FileSource is a passive data file as a Source.
type FileSource struct {
	// Label names the file in facts: "file:" + Label.
	Label string
	// Open returns the content. It is called once per Collect.
	Open func() (io.ReadCloser, error)
	// Report is filled by Collect.
	Report FileReport
}

// NewFileSource reads a file from disk.
func NewFileSource(path string) *FileSource {
	return &FileSource{Label: filepath.Base(path), Open: func() (io.ReadCloser, error) { return os.Open(path) }}
}

func (f *FileSource) Name() string   { return "file:" + f.Label }
func (f *FileSource) External() bool { return false }

// Collect parses the file. It returns all facts of the file; the scope
// filter runs in Collect/Merge, so the caller also sees what was left out.
func (f *FileSource) Collect(ctx context.Context, _ Scope) ([]Fact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("nie można otworzyć pliku %s: %w", f.Label, err)
	}
	defer rc.Close()
	facts, rep, err := Parse(rc, f.Label)
	f.Report = rep
	return facts, err
}
