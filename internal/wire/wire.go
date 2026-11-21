package wire

import (
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

// Wiring holds every implementation that the server gets from another package.
type Wiring struct {
	Engine      model.Engine      // internal/scan
	RunAnalyzer runner.Analyzer   // post-run analysis
	Window      runner.WindowFunc // internal/sched: end of the current scan window, start of the next
	API         api.Deps          // seams of the REST API
}

// Build is the single place where the packages are connected. What is nil
// here answers 501 "not_wired" in the API; nothing is faked.
//
// Wired: analysis (stability, diff, interest, grouping, findings), result
// import and export (nmap XML, Czujka JSON, CSV), DefectDojo.
//
// Not merged yet; connect here when they arrive:
//
//	w.Engine          = scan.New(...)                      // model.Engine
//	w.Window          = sched.Window                       // runner.WindowFunc
//	w.API.TargetParser = targets.Parser{}                  // api.TargetParser (a basic parser is built in)
//	w.API.Signatures  = sig.Validator{}                    // api.SignatureValidator
//	w.API.RetroHunter = RetroHunter{st, sig.Engine}        // api.RetroHunter, reads store.EachObservation
//	w.API.Hooks       = api.Hooks{SignaturesChanged: ..., ProfileChanged: scheduler.Reschedule}
//	w.API.WebFS       = web.Dist                           // embedded UI (CZUJKA_WEB_DIR works without it)
//
// The scheduler loop (internal/sched) gets its backend from SchedBackend in sched.go.
func Build(cfg config.Config, st *store.Store, log *slog.Logger) Wiring {
	if log == nil {
		log = slog.Default()
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil || cfg.Timezone == "" {
		loc = time.UTC
	}
	an := NewAnalysis(st, loc, log)
	dojo := Dojo{st: st, log: log}
	an.Auto = dojo
	ic := Interchange{st: st}
	return Wiring{
		RunAnalyzer: an,
		API:         api.Deps{Analyzer: an, Importer: ic, Exporter: ic, Dojo: dojo},
	}
}
