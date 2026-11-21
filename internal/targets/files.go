package targets

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// ParseCSV parses a CSV target file. The header row names the value column
// with one of: value, target, ip, address, cidr, host, domain. Optional
// columns: note, tags. A file without a known header is read as one target
// per row in the first column. Comma, semicolon and tab delimiters work.
func ParseCSV(data []byte) (ParseResult, error) {
	c := newCollector("csv")
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(data)) == 0 {
		return c.res, errors.New("plik CSV jest pusty")
	}
	firstLine := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		firstLine = data[:i]
	}
	delim := ','
	if n := bytes.Count(firstLine, []byte{';'}); n > bytes.Count(firstLine, []byte{','}) {
		delim = ';'
	}
	if n := bytes.Count(firstLine, []byte{'\t'}); n > bytes.Count(firstLine, []byte{byte(delim)}) {
		delim = '\t'
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = delim
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true

	valueCol, noteCol, tagsCol := -1, -1, -1
	line := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			return c.res, fmt.Errorf("błąd odczytu CSV w wierszu %d: %v", line, err)
		}
		if line == 1 {
			for i, h := range rec {
				h = strings.ToLower(strings.TrimSpace(h))
				switch {
				case valueCol < 0 && isValueKey(h):
					valueCol = i
				case h == "note" || h == "notes" || h == "notatka" || h == "opis":
					noteCol = i
				case h == "tags" || h == "tag" || h == "tagi":
					tagsCol = i
				}
			}
			if valueCol >= 0 {
				continue // header row consumed
			}
			valueCol = 0 // no header: first column holds the value
		}
		if valueCol >= len(rec) {
			continue
		}
		note := ""
		if noteCol >= 0 && noteCol < len(rec) {
			note = rec[noteCol]
		}
		var tags []string
		if tagsCol >= 0 && tagsCol < len(rec) {
			tags = splitTags(rec[tagsCol])
		}
		c.add(line, rec[valueCol], note, tags)
	}
	return c.res, nil
}

// ParseJSON parses a JSON target file: an array of strings, an array of
// objects with the same keys as the CSV columns, or an object with a
// "targets" array.
func ParseJSON(data []byte) (ParseResult, error) {
	c := newCollector("json")
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var top any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return c.res, fmt.Errorf("niepoprawny JSON: %v", err)
	}
	if obj, ok := top.(map[string]any); ok {
		found := false
		for _, k := range []string{"targets", "items", "hosts", "addresses"} {
			if v, ok := obj[k]; ok {
				top, found = v, true
				break
			}
		}
		if !found {
			return c.res, errors.New("oczekiwano tablicy JSON albo obiektu z kluczem \"targets\"")
		}
	}
	arr, ok := top.([]any)
	if !ok {
		return c.res, errors.New("oczekiwano tablicy JSON z celami")
	}
	for i, item := range arr {
		n := i + 1
		switch v := item.(type) {
		case string:
			c.add(n, v, "", nil)
		case map[string]any:
			value, note := "", ""
			var tags []string
			for k, raw := range v {
				lk := strings.ToLower(k)
				switch {
				case isValueKey(lk):
					if s, ok := raw.(string); ok && value == "" {
						value = s
					}
				case lk == "note" || lk == "notes":
					if s, ok := raw.(string); ok {
						note = s
					}
				case lk == "tags" || lk == "tag":
					switch tv := raw.(type) {
					case string:
						tags = splitTags(tv)
					case []any:
						for _, t := range tv {
							if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
								tags = append(tags, strings.TrimSpace(s))
							}
						}
					}
				}
			}
			if value == "" {
				c.res.Invalid = append(c.res.Invalid, invalid(n, compact(item), "brak pola z wartością (value, target, ip, address, cidr, host lub domain)"))
				continue
			}
			c.add(n, value, note, tags)
		default:
			c.res.Invalid = append(c.res.Invalid, invalid(n, compact(item), "element musi być napisem albo obiektem"))
		}
	}
	return c.res, nil
}

// ParseFile picks the parser from the file name, or from the content when
// the extension is unknown.
func ParseFile(name string, data []byte) (ParseResult, error) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		return ParseJSON(data)
	case ".csv", ".tsv":
		return ParseCSV(data)
	}
	t := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	if len(t) > 0 && (t[0] == '[' || t[0] == '{') {
		return ParseJSON(data)
	}
	first := t
	if i := bytes.IndexByte(t, '\n'); i >= 0 {
		first = t[:i]
	}
	for _, cell := range strings.FieldsFunc(string(first), func(r rune) bool { return r == ',' || r == ';' || r == '\t' }) {
		if isValueKey(strings.Trim(cell, "\" ")) {
			return ParseCSV(data)
		}
	}
	res := ParseText(string(data))
	return res, nil
}
