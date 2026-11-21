package wire

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// Interchange adapts internal/interchange to the import and export seams of the API.
type Interchange struct {
	st *store.Store
}

// ParseResults reads a result file in any supported format (auto-detected).
// A host that the file reports as down is kept only when the inventory already
// knows its address: for a known host it is a miss, for an unknown one it is nothing.
func (x Interchange) ParseResults(ctx context.Context, filename string, data []byte) ([]model.HostResult, model.ImportReport, error) {
	hosts, rep, err := interchange.Import(bytes.NewReader(data), interchange.Options{IncludeDown: true})
	if err != nil {
		return nil, rep, err
	}
	var down []string
	for i := range hosts {
		if !hosts[i].Up {
			down = append(down, strings.TrimSpace(hosts[i].IP))
		}
	}
	// Every host that the file reports as down counts as a down host of the
	// report, kept or not; it is not a skipped (bad) row.
	rep.HostsDown = len(down)
	if len(down) > 0 && x.st != nil {
		known, err := x.st.KnownIPs(ctx, down)
		if err != nil {
			return nil, rep, err
		}
		kept := hosts[:0]
		for i := range hosts {
			if hosts[i].Up || known[strings.TrimSpace(hosts[i].IP)] {
				kept = append(kept, hosts[i])
			}
		}
		hosts = kept
	}
	return hosts, rep, nil
}

// RunWriter returns a streaming writer of one run in the format "xml" (nmap
// XML), "json" (Czujka JSON) or "csv".
func (x Interchange) RunWriter(w io.Writer, format string, run model.ScanRun) (api.ResultWriter, error) {
	f := map[string]string{"xml": interchange.FormatNmapXML, "json": interchange.FormatJSON, "csv": interchange.FormatCSV}[format]
	if f == "" {
		return nil, fmt.Errorf("unknown export format %q", format)
	}
	meta := interchange.Meta{RunID: run.ID, Args: fmt.Sprintf("czujka run %d (%s)", run.ID, run.ProfileName)}
	if run.FinishedAt != nil {
		meta.GeneratedAt = *run.FinishedAt
	} else {
		meta.GeneratedAt = time.Now().UTC()
	}
	return interchange.NewWriter(w, f, meta)
}
