package main

import (
	"log/slog"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

// wiring holds the implementations that other packages supply.
type wiring struct {
	Engine      model.Engine      // internal/scan
	RunAnalyzer runner.Analyzer   // adapter around internal/analyze: runs after a completed run or import
	Window      runner.WindowFunc // internal/sched: end of the current scan window, start of the next
	API         api.Deps          // TargetParser, Importer, Exporter, Dojo, Signatures, RetroHunter, Analyzer, Hooks, WebFS
}

// wire is the single place where the integration step connects the packages
// that other workers build. Everything left nil here answers 501 "not_wired"
// in the API; nothing is faked.
//
//	w.Engine          = scan.New(...)                      // model.Engine
//	w.RunAnalyzer     = analyzeadapter.New(st)             // runner.Analyzer
//	w.Window          = sched.Window                       // runner.WindowFunc
//	w.API.TargetParser = targets.Parser{}                  // api.TargetParser (a basic parser is built in)
//	w.API.Importer    = interchange.Importer{}             // api.Importer
//	w.API.Exporter    = interchange.Exporter{}             // api.Exporter
//	w.API.Dojo        = defectdojo.New()                   // api.DojoClient
//	w.API.Signatures  = sig.Validator{}                    // api.SignatureValidator
//	w.API.RetroHunter = sigadapter.RetroHunter{Store: st}  // api.RetroHunter, reads store.EachObservation
//	w.API.Analyzer    = analyzeadapter.New(st)             // api.Analyzer (diff of two runs, down-after-misses)
//	w.API.Hooks       = api.Hooks{SignaturesChanged: ..., ProfileChanged: ...}
//	w.API.WebFS       = web.Dist                           // embedded UI (CZUJKA_WEB_DIR works without it)
func wire(_ config.Config, _ *store.Store, _ *slog.Logger) wiring {
	return wiring{}
}
