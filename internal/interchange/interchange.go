package interchange

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Options tunes an import. The zero value auto-detects the format.
type Options struct {
	// Format forces a format (FormatNmapXML, FormatJSON, FormatCSV). Empty means auto-detect.
	Format string
	// RunID is written to every imported HostResult when it is not zero.
	RunID int64
	// Now is the observation time of records that carry none. Zero means time.Now().
	Now time.Time
	// IncludeDown keeps hosts that the file reports as down. By default they
	// are skipped and counted in ImportReport.Skipped: a down host in a file
	// is only useful for an address the inventory already knows.
	IncludeDown bool
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now().UTC()
	}
	return o.Now.UTC()
}

// report wraps model.ImportReport with the cap on listed invalid rows.
type report struct {
	model.ImportReport
}

func (r *report) invalid(line int, value, reason string) {
	if len(r.Invalid) < MaxInvalidReported {
		if len(value) > 120 {
			value = value[:120]
		}
		r.Invalid = append(r.Invalid, model.InvalidLine{Line: line, Value: value, Reason: reason})
	}
	r.Skipped++
}

// ImportEach reads results in any supported format and calls fn once per
// host. The report lists the invalid rows with their reasons; one bad row
// never stops the import. An error is returned only when the file as a whole
// cannot be read (unknown format, broken header) or fn fails.
func ImportEach(r io.Reader, opts Options, fn func(model.HostResult) error) (model.ImportReport, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	rep := &report{ImportReport: model.ImportReport{Invalid: []model.InvalidLine{}}}
	format := opts.Format
	if format == "" {
		head, _ := br.Peek(4096)
		format = Detect(head)
		if format == "" {
			return rep.ImportReport, errors.New("plik jest pusty")
		}
	}
	rep.Format = format
	if opts.RunID != 0 {
		id := opts.RunID
		rep.RunID = &id
	}
	emit := func(h model.HostResult) error {
		if opts.RunID != 0 {
			h.RunID = opts.RunID
		}
		rep.Hosts++
		rep.Services += len(h.Services)
		return fn(h)
	}
	var err error
	switch format {
	case FormatNmapXML:
		err = importNmapXML(br, opts, rep, emit)
	case FormatJSON:
		err = importJSON(br, opts, rep, emit)
	case FormatCSV:
		err = importCSV(br, opts, rep, emit)
	default:
		err = fmt.Errorf("nieznany format importu: %q", format)
	}
	return rep.ImportReport, err
}

// Import reads results in any supported format into memory.
func Import(r io.Reader, opts Options) ([]model.HostResult, model.ImportReport, error) {
	hosts := []model.HostResult{}
	rep, err := ImportEach(r, opts, func(h model.HostResult) error {
		hosts = append(hosts, h)
		return nil
	})
	return hosts, rep, err
}

// Meta describes an export.
type Meta struct {
	GeneratedAt    time.Time // zero means time.Now()
	RunID          int64
	Args           string // written as the nmap "args" attribute
	ScannerVersion string // nmap version written to the XML; default 7.95
}

func (m Meta) generatedAt() time.Time {
	if m.GeneratedAt.IsZero() {
		return time.Now().UTC()
	}
	return m.GeneratedAt.UTC()
}

// Writer is a streaming exporter: hosts are written one by one, so an export
// of a large run does not build the whole file in memory. Close ends the file.
type Writer interface {
	WriteHost(h model.HostResult) error
	Close() error
}

// NewWriter returns a streaming writer for a format.
func NewWriter(w io.Writer, format string, meta Meta) (Writer, error) {
	switch format {
	case FormatNmapXML, "xml":
		return newXMLWriter(w, meta)
	case FormatJSON, "json":
		return newJSONWriter(w, meta)
	case FormatCSV:
		return newCSVWriter(w)
	}
	return nil, fmt.Errorf("interchange: unknown export format %q", format)
}

// Export writes all hosts in one call.
func Export(w io.Writer, format string, hosts []model.HostResult, meta Meta) error {
	wr, err := NewWriter(w, format, meta)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := wr.WriteHost(h); err != nil {
			return err
		}
	}
	return wr.Close()
}
