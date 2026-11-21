package interchange

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// importCSV reads one row per service. Column names are matched through
// FieldMapping; unknown columns are ignored. The delimiter (comma, semicolon,
// tab or pipe) is detected from the header line.
func importCSV(r *bufio.Reader, opts Options, rep *report, emit func(model.HostResult) error) error {
	// Skip a UTF-8 byte order mark and leading blank lines.
	if b, _ := r.Peek(3); string(b) == "\xef\xbb\xbf" {
		r.Discard(3)
	}
	head, _ := r.Peek(8192)
	firstLine := string(head)
	if i := strings.IndexAny(firstLine, "\r\n"); i >= 0 {
		firstLine = firstLine[:i]
	}
	delim, best := ',', 0
	for _, d := range []rune{',', ';', '\t', '|'} {
		if n := strings.Count(firstLine, string(d)); n > best {
			delim, best = d, n
		}
	}
	cr := csv.NewReader(r)
	cr.Comma = delim
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("nie można odczytać nagłówka CSV: %w", err)
	}
	cols := make([]Field, len(header))
	known, hasAddr := 0, false
	for i, name := range header {
		if f, ok := LookupField(name); ok {
			cols[i] = f
			known++
			if f == FIP || f == FHost {
				hasAddr = true
			}
		}
	}
	if !hasAddr {
		return errors.New("CSV nie ma kolumny z adresem (ip, host, address); pierwsza linia musi być nagłówkiem")
	}

	col := newCollector(opts.now(), opts.RunID)
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				rep.invalid(pe.Line, "", "niepoprawna linia CSV: "+pe.Err.Error())
				continue
			}
			return fmt.Errorf("błąd odczytu CSV: %w", err)
		}
		empty := true
		row := make(map[Field]string, known)
		for i, v := range rec {
			if i >= len(cols) {
				break
			}
			v = strings.TrimSpace(v)
			if v != "" {
				empty = false
			}
			if cols[i] != "" && v != "" {
				// A later column with the same meaning does not overwrite an earlier value.
				if _, dup := row[cols[i]]; !dup {
					row[cols[i]] = unguard(v)
				}
			}
		}
		if empty {
			continue
		}
		if err := col.add(row); err != nil {
			var re *rowError
			errors.As(err, &re)
			rep.invalid(line, re.value, re.reason)
		}
	}
	for _, h := range col.results() {
		if !h.Up && !opts.IncludeDown {
			rep.Skipped++
			continue
		}
		if err := emit(h); err != nil {
			return err
		}
	}
	return nil
}

// guard protects spreadsheet users: a cell that starts with a formula
// character gets a leading apostrophe (CSV injection). unguard removes it.
func guard(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func unguard(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

// ---------- export ----------

type csvWriter struct {
	w      *csv.Writer
	closed bool
}

func newCSVWriter(w io.Writer) (*csvWriter, error) {
	c := &csvWriter{w: csv.NewWriter(w)}
	head := make([]string, len(CSVColumns))
	for i, f := range CSVColumns {
		head[i] = string(f)
	}
	if err := c.w.Write(head); err != nil {
		return nil, err
	}
	c.w.Flush()
	return c, c.w.Error()
}

func (c *csvWriter) WriteHost(h model.HostResult) error {
	if c.closed {
		return errors.New("interchange: writer is closed")
	}
	hostVals := map[Field]string{
		FIP: h.IP, FHostname: strings.Join(h.Hostnames, ";"), FUp: strconv.FormatBool(h.Up),
		FOS: h.OSGuess, FMAC: h.MAC, FVendor: h.Vendor, FReason: h.Reason,
	}
	if h.RTTMs > 0 {
		hostVals[FRTT] = strconv.FormatFloat(h.RTTMs, 'f', -1, 64)
	}
	if !h.ObservedAt.IsZero() {
		hostVals[FObservedAt] = h.ObservedAt.UTC().Format(time.RFC3339)
	}
	write := func(vals map[Field]string) error {
		rec := make([]string, len(CSVColumns))
		for i, f := range CSVColumns {
			v, ok := vals[f]
			if !ok {
				v = hostVals[f]
			}
			rec[i] = guard(strings.ToValidUTF8(v, "?"))
		}
		return c.w.Write(rec)
	}
	if len(h.Services) == 0 {
		if err := write(map[Field]string{}); err != nil {
			return err
		}
	}
	for i := range h.Services {
		s := &h.Services[i]
		v := map[Field]string{
			FPort: strconv.Itoa(s.Port), FProto: firstNonEmpty(s.Proto, "tcp"), FState: firstNonEmpty(s.State, "open"),
			FService: s.Name, FProduct: s.Product, FVersion: s.Version, FExtraInfo: s.ExtraInfo, FBanner: s.Banner,
			FCPE: strings.Join(s.CPE, ";"), FClasses: strings.Join(s.Classes, ";"),
		}
		if s.Tunnel == "ssl" || s.TLS != nil {
			v[FTLS] = "true"
		}
		if s.Confidence > 0 {
			v[FConfidence] = strconv.FormatFloat(s.Confidence, 'f', -1, 64)
		}
		techs := make([]string, 0, len(s.Technologies))
		for _, t := range s.Technologies {
			if t.Name != "" {
				techs = append(techs, techText(t))
			}
		}
		v[FTech] = strings.Join(techs, ";")
		if fp := s.HTTP; fp != nil {
			v[FURL], v[FTitle], v[FServer] = fp.URL, fp.Title, fp.Server
			if fp.Status != 0 {
				v[FStatus] = strconv.Itoa(fp.Status)
			}
			if fp.FinalURL != "" && fp.FinalURL != fp.URL {
				v[FRedirect] = fp.FinalURL
			}
			names := make([]string, 0, len(fp.Cookies))
			for _, ck := range fp.Cookies {
				names = append(names, ck.Name)
			}
			v[FCookies] = strings.Join(names, ";")
		}
		if t := s.TLS; t != nil {
			v[FCertCN], v[FCertIssuer], v[FCertSHA256] = t.SubjectCN, t.Issuer, t.SHA256
			if !t.NotAfter.IsZero() {
				v[FCertExpires] = t.NotAfter.UTC().Format(time.RFC3339)
			}
		}
		if err := write(v); err != nil {
			return err
		}
	}
	c.w.Flush()
	return c.w.Error()
}

func (c *csvWriter) Close() error {
	c.closed = true
	c.w.Flush()
	return c.w.Error()
}
