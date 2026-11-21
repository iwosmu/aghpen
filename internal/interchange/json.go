package interchange

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// JSONVersion is the version of the Czujka JSON envelope.
const JSONVersion = 1

// arrayKeys are the keys of a top-level object that hold the records.
var arrayKeys = map[string]bool{"hosts": true, "results": true, "data": true, "items": true, "records": true, "rows": true}

// nestedKeys are the keys of a host object that hold its services in
// formats other than Czujka's own.
var nestedKeys = []string{"ports", "open_ports", "services"}

// importJSON reads Czujka JSON and tolerant variants:
//
//   - the Czujka envelope {"format":"czujka-json","hosts":[HostResult...]};
//   - a bare array of HostResult;
//   - an array (or an object with a "results"/"data"/... array) of flat
//     records, one per service, with keys from FieldMapping;
//   - host objects with a nested "ports" array of port objects or numbers;
//   - JSON Lines: one such object per line.
//
// The decoder streams: one element is in memory at a time.
func importJSON(r io.Reader, opts Options, rep *report, emit func(model.HostResult) error) error {
	dec := json.NewDecoder(r)
	col := newCollector(opts.now(), opts.RunID)
	index := 0
	element := func(raw json.RawMessage) error {
		index++
		return jsonElement(raw, index, opts, rep, col, emit)
	}
	top := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if top == 0 {
				return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
			}
			rep.invalid(index+1, "", "uszkodzony JSON: "+err.Error())
			break
		}
		top++
		d, ok := tok.(json.Delim)
		if !ok {
			return errors.New("nieobsługiwany JSON: oczekiwano tablicy lub obiektu")
		}
		switch d {
		case '[':
			if err := jsonArray(dec, rep, &index, element); err != nil {
				return err
			}
		case '{':
			// Envelope or one record. Keep the scalar keys in case it is a record.
			rest := map[string]json.RawMessage{}
			sawArray := false
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
				}
				key, _ := kt.(string)
				if arrayKeys[normName(key)] {
					t, err := dec.Token()
					if err != nil {
						return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
					}
					if dd, ok := t.(json.Delim); ok && dd == '[' {
						sawArray = true
						if err := jsonArray(dec, rep, &index, element); err != nil {
							return err
						}
						continue
					} else if ok {
						return fmt.Errorf("nieobsługiwany JSON: klucz %q nie jest tablicą", key)
					}
					continue // scalar under an array key: ignore
				}
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
				}
				rest[key] = raw
			}
			if _, err := dec.Token(); err != nil { // closing brace
				return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
			}
			if !sawArray {
				raw, _ := json.Marshal(rest)
				if err := element(raw); err != nil {
					return err
				}
			}
		default:
			return errors.New("nieobsługiwany JSON: oczekiwano tablicy lub obiektu")
		}
	}
	if top == 0 {
		return errors.New("plik jest pusty")
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

func jsonArray(dec *json.Decoder, rep *report, index *int, element func(json.RawMessage) error) error {
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			rep.invalid(*index+1, "", "uszkodzony JSON: "+err.Error())
			return nil
		}
		if err := element(raw); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing bracket
	if err != nil {
		rep.invalid(*index+1, "", "uszkodzony JSON: "+err.Error())
	}
	return nil
}

// jsonElement handles one record: a native HostResult, a flat record, or a
// host with nested ports.
func jsonElement(raw json.RawMessage, index int, opts Options, rep *report, col *collector, emit func(model.HostResult) error) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		rep.invalid(index, snippet(raw), "rekord nie jest obiektem JSON")
		return nil
	}
	_, hasIP := obj["ip"]
	_, hasServices := obj["services"]
	_, hasUp := obj["up"]
	if hasIP && (hasServices || hasUp) && isNativeServices(obj["services"]) {
		var h model.HostResult
		if err := json.Unmarshal(raw, &h); err != nil {
			rep.invalid(index, snippet(raw), "niepoprawny rekord hosta: "+err.Error())
			return nil
		}
		if err := validateHost(&h); err != nil {
			var re *rowError
			errors.As(err, &re)
			rep.invalid(index, re.value, re.reason)
			return nil
		}
		if h.ObservedAt.IsZero() {
			h.ObservedAt = opts.now()
		}
		if h.Hostnames == nil {
			h.Hostnames = []string{}
		}
		if h.Services == nil {
			h.Services = []model.ServiceResult{}
		}
		if !h.Up && !opts.IncludeDown {
			rep.Skipped++
			return nil
		}
		return emit(h)
	}

	// Generic record: map the scalar keys through FieldMapping.
	base := map[Field]string{}
	for k, v := range obj {
		if f, ok := LookupField(k); ok {
			if s, ok := scalarText(v); ok {
				base[f] = s
			}
		}
	}
	var nested []json.RawMessage
	for _, k := range nestedKeys {
		if v, ok := obj[k]; ok && json.Unmarshal(v, &nested) == nil && len(nested) > 0 {
			break
		}
	}
	if len(nested) == 0 {
		if err := col.add(base); err != nil {
			var re *rowError
			errors.As(err, &re)
			rep.invalid(index, re.value, re.reason)
		}
		return nil
	}
	for _, n := range nested {
		row := map[Field]string{}
		for k, v := range base {
			row[k] = v
		}
		var port map[string]json.RawMessage
		if err := json.Unmarshal(n, &port); err == nil {
			for k, v := range port {
				if f, ok := LookupField(k); ok {
					if s, ok := scalarText(v); ok {
						row[f] = s
					}
				}
			}
		} else if s, ok := scalarText(n); ok {
			row[FPort] = s // "ports": [22, 80]
		}
		if err := col.add(row); err != nil {
			var re *rowError
			errors.As(err, &re)
			rep.invalid(index, re.value, re.reason)
		}
	}
	return nil
}

// isNativeServices reports if a "services" value is absent, null or an array
// of objects (Czujka's own shape).
func isNativeServices(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return true
	}
	var arr []map[string]json.RawMessage
	return json.Unmarshal(t, &arr) == nil
}

// scalarText turns a JSON scalar (or an array of scalars) into text.
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
		parts := make([]string, 0, len(arr))
		for _, a := range arr {
			if s, ok := scalarText(a); ok && !strings.HasPrefix(strings.TrimSpace(string(a)), "[") {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ";"), len(parts) > 0
	}
	return string(t), true // number, true, false
}

func snippet(raw json.RawMessage) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// ---------- export ----------

type jsonWriter struct {
	w      *bufio.Writer
	n      int
	closed bool
}

func newJSONWriter(w io.Writer, meta Meta) (*jsonWriter, error) {
	j := &jsonWriter{w: bufio.NewWriter(w)}
	head := struct {
		Format      string    `json:"format"`
		Version     int       `json:"version"`
		GeneratedAt time.Time `json:"generated_at"`
		RunID       int64     `json:"run_id"`
	}{FormatJSON, JSONVersion, meta.generatedAt(), meta.RunID}
	b, err := json.Marshal(head)
	if err != nil {
		return nil, err
	}
	// Reopen the header object and start the hosts array.
	j.w.Write(b[:len(b)-1])
	j.w.WriteString(",\"hosts\":[")
	return j, j.w.Flush()
}

func (j *jsonWriter) WriteHost(h model.HostResult) error {
	if j.closed {
		return errors.New("interchange: writer is closed")
	}
	if h.Hostnames == nil {
		h.Hostnames = []string{}
	}
	if h.Services == nil {
		h.Services = []model.ServiceResult{}
	}
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if j.n > 0 {
		j.w.WriteByte(',')
	}
	j.w.WriteByte('\n')
	j.w.Write(b)
	j.n++
	return j.w.Flush()
}

func (j *jsonWriter) Close() error {
	if j.closed {
		return nil
	}
	j.closed = true
	j.w.WriteString("\n]}\n")
	return j.w.Flush()
}
