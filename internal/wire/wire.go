package wire

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/enginewire"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/scan"
	"github.com/iwosmu/aghpen/internal/sched"
	"github.com/iwosmu/aghpen/internal/sigsuggest"
	"github.com/iwosmu/aghpen/internal/sigwire"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/web"
)

// Wiring holds every implementation that the server gets from another package.
type Wiring struct {
	Engine      model.Engine              // internal/scan
	Scan        *scan.Engine              // the same engine, for the prober report
	Signatures  *sigwire.Wire             // the shared signature engine of the process
	RunAnalyzer runner.Analyzer           // post-run analysis, then the signature match counts
	Window      runner.WindowFunc         // internal/sched: end of the current scan window, start of the next
	PauseCause  func(reason string) error // scan.PauseCause: pause reasons reach the engine as cancel causes
	API         api.Deps                  // seams of the REST API
	Rules       *rules.Service            // exposure rules (policy-violation findings)

	cfg config.Config
	st  *store.Store
	log *slog.Logger
}

// Build is the single place where the packages are connected. It does no
// I/O; Start seeds the signatures and starts the scheduler.
//
// Wired: scan engine (nmap or native prober, HTTP/TLS collector, signature
// engine), full target parser, scan windows and pause causes, signatures
// (validation, retro-hunt, import, match counts), analysis (stability, diff,
// interest, grouping, findings), result import and export, DefectDojo, run
// reports, passive sources, embedded UI (build tag embedui).
func Build(cfg config.Config, st *store.Store, log *slog.Logger) *Wiring {
	if log == nil {
		log = slog.Default()
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil || cfg.Timezone == "" {
		loc = time.UTC
	}
	sw := sigwire.New(st, log)
	// enginewire builds the engine with the real HTTP/TLS collector, whose
	// requests wait for the engine's per-host and global limiters (scan.HTTPWait).
	eng, _ := enginewire.New(enginewire.Deps{
		Signatures:  sw.Engine(), // the same pointer for the whole process; Reload swaps its set in place
		Logger:      log,
		NmapPath:    cfg.NmapPath,
		ForceNative: cfg.ForceNative,
	}).(*scan.Engine)
	an := NewAnalysis(st, loc, log)
	dojo := Dojo{st: st, log: log}
	an.Auto = dojo
	pol := rules.New(st, log)
	an.Policy = pol
	sugg := sigsuggest.New(st, log)
	ic := Interchange{st: st}
	w := &Wiring{
		Engine:      eng,
		Scan:        eng,
		Signatures:  sw,
		RunAnalyzer: matchCounts{an: an, sw: sw, log: log},
		Window:      enginewire.Window,
		PauseCause:  enginewire.PauseCause,
		cfg:         cfg, st: st, log: log,
		Rules: pol,
	}
	w.API = api.Deps{
		Analyzer:     an,
		Importer:     ic,
		Exporter:     ic,
		Dojo:         dojo,
		TargetParser: enginewire.TargetParser{},
		Signatures:   sw,
		RetroHunter:  sw,
		SigImporter:  SigImporter{sw: sw},
		Reporter:     Reporter{st: st, loc: loc},
		Passive:      Passive{st: st, log: log},
		EngineInfo:   func() map[string]any { return EngineInfo(eng) },
		Routes: []func(r chi.Router, can api.Guard){
			func(r chi.Router, can api.Guard) {
				r.Mount("/rules", pol.Router(rules.Middleware(can)))
				r.With(can(model.PermSignaturesRead)).Post("/signatures/suggest", sugg.Handler)
			},
		},
		Hooks: api.Hooks{
			SignaturesChanged: sw.Changed,
			ProfileChanged:    enginewire.ProfileChanged(st, log),
		},
	}
	if web.Embedded {
		w.API.WebFS = web.FS()
	}
	return w
}

// Start seeds the built-in signatures, loads the signature engine, picks the
// prober, refreshes the next planned starts and starts the scheduler loop. The
// loop ends with ctx.
func (w *Wiring) Start(ctx context.Context, mgr *runner.Manager) error {
	if err := w.Signatures.Start(ctx); err != nil {
		return fmt.Errorf("signatures: %w", err)
	}
	if err := w.Rules.Start(ctx); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	info := EngineInfo(w.Scan) // runs "nmap --version" once and logs the mode
	w.log.Info("scan engine wired", "prober", info["prober"], "mode", info["mode"])
	b := enginewire.NewBackend(w.st, mgr, w.log)
	s := &enginewire.Scheduler{Scheduler: sched.New(b, sched.Options{Interval: w.cfg.SchedInterval, Logger: w.log}), Backend: b}
	go s.Run(ctx) // refreshes the next planned starts once, then ticks
	return nil
}

// EngineInfo describes the prober that runs: nmap with raw sockets (SYN
// scan, ICMP and ARP discovery), nmap in connect mode, or the native Go prober.
func EngineInfo(e *scan.Engine) map[string]any {
	if e == nil {
		return map[string]any{"prober": "none"}
	}
	p := e.Prober()
	out := map[string]any{"prober": p.Name(), "raw_sockets": p.Privileged()}
	switch {
	case p.Name() == "nmap" && p.Privileged():
		out["mode"] = "nmap-raw"
	case p.Name() == "nmap":
		out["mode"] = "nmap-connect"
	default:
		out["mode"] = "native"
	}
	return out
}

// matchCounts runs the analysis and then refreshes the match count of every
// signature, after each finished run, window-paused run and import.
type matchCounts struct {
	an  runner.Analyzer
	sw  *sigwire.Wire
	log *slog.Logger
}

func (m matchCounts) AnalyzeRun(ctx context.Context, runID int64) (*model.RunDiffSummary, error) {
	sum, err := m.an.AnalyzeRun(ctx, runID)
	if _, cerr := m.sw.UpdateMatchCounts(ctx); cerr != nil {
		m.log.Error("signature match counts", "run", runID, "err", cerr)
	}
	return sum, err
}
