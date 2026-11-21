// Package enginewire connects the scan engine packages (scan, probe, targets,
// sched) to the core (store, runner, api). The integration step in
// cmd/czujka/wire.go needs only a few lines:
//
//	sigs, _ := sig.NewBuiltinEngine()                       // the shared signature engine
//	w.Engine = enginewire.New(enginewire.Deps{Signatures: sigs, Logger: log})
//	w.Window = enginewire.Window
//	w.API.TargetParser = enginewire.TargetParser{}
//	w.API.Hooks.ProfileChanged = enginewire.ProfileChanged(st, log)
//
// and after the run manager exists (cmd/czujka/main.go, next to mgr.Recover):
//
//	go enginewire.NewScheduler(st, mgr, log).Run(ctx)
package enginewire

import (
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/scan"
	"github.com/iwosmu/aghpen/internal/sched"
	"github.com/iwosmu/aghpen/internal/targets"
)

// Deps are the inputs of the engine factory.
type Deps struct {
	// Signatures is the shared signature engine (internal/sig). The engine
	// uses PathsFor and MatchHost when it has them. Nil skips the stage.
	Signatures model.SignatureEngine
	// Fingerprinter is the HTTP/TLS collector. Nil makes a default
	// httpfp.Collector. A *httpfp.Collector gets the per-request rate limit
	// hook of the engine when its Wait field is empty.
	Fingerprinter model.Fingerprinter
	Logger        *slog.Logger
	NmapPath      string // empty: "nmap" from PATH; the native Go prober runs when nmap is missing
	ForceNative   bool   // never use nmap

	Prober probe.Prober // tests only: replaces nmap and the native prober
}

// New builds the scan engine with the real collector and the given signature engine.
func New(d Deps) model.Engine {
	fp := d.Fingerprinter
	if fp == nil {
		fp = httpfp.New()
	}
	if c, ok := fp.(*httpfp.Collector); ok && c.Wait == nil {
		// every HTTP request waits for the per-host and the global limit of its run
		c.Wait = scan.HTTPWait
	}
	return scan.New(scan.Deps{
		Fingerprinter: fp, Signatures: d.Signatures, Logger: d.Logger,
		NmapPath: d.NmapPath, ForceNative: d.ForceNative, Prober: d.Prober,
	})
}

// Window is the runner.WindowFunc: the scan windows of the profile schedule.
//
//   - No windows: (nil, nil), the run has no time limit.
//   - now inside a window: windowEnd is when that window closes (windows that
//     touch count as one) and nextStart is the first window start after it.
//   - now outside every window: windowEnd is now, so the engine starts no
//     chunk and the run pauses with reason "window_closed"; nextStart is when
//     the next window opens. A run started by hand outside its windows
//     therefore waits for the next window instead of scanning at a
//     forbidden time.
func Window(p model.ScanProfile, now time.Time) (windowEnd, nextStart *time.Time) {
	ws := p.Schedule.Windows
	if len(ws) == 0 {
		return nil, nil
	}
	loc, err := sched.Location(p.Schedule.Timezone)
	if err != nil {
		loc, _ = sched.Location("")
	}
	from := now
	if end, ok := sched.WindowEnd(now, ws, loc); ok {
		windowEnd = &end
		from = end
	} else {
		t := now
		windowEnd = &t
	}
	if next, ok := sched.NextWindowStart(from, ws, loc); ok {
		nextStart = &next
	}
	return windowEnd, nextStart
}

// PauseCause is the cancel cause that makes the engine itself report
// RunPaused with the given reason (model.PauseManual, model.PauseEmergency,
// model.PauseWindowClosed). See the package documentation of the runner
// integration: a plain cancel also works, the engine then answers
// RunCancelled and still marks the unfinished chunks as deferred.
func PauseCause(reason string) error { return scan.PauseCause(reason) }

// TargetParser implements api.TargetParser with internal/targets.
type TargetParser struct{}

// ParseText parses one target per line: IPv4, CIDR, ranges, domains, single IPv6.
func (TargetParser) ParseText(text string) ([]model.Target, []model.InvalidLine) {
	res := targets.ParseText(text)
	return nonNil(res.Targets), nonNilInv(res.Invalid)
}

// ParseFile parses a CSV, JSON or text target file.
func (TargetParser) ParseFile(filename string, data []byte) ([]model.Target, []model.InvalidLine, error) {
	res, err := targets.ParseFile(filename, data)
	if err != nil {
		return nil, nil, err
	}
	return nonNil(res.Targets), nonNilInv(res.Invalid), nil
}

// Excluded counts the addresses that the exclusions remove. It is exact for
// overlapping targets and does not expand ranges.
func (TargetParser) Excluded(ts []model.Target, exclusions []string) int64 {
	_, excluded := targets.Count(ts, exclusions)
	return excluded
}

func nonNil(ts []model.Target) []model.Target {
	if ts == nil {
		return []model.Target{}
	}
	return ts
}

func nonNilInv(xs []model.InvalidLine) []model.InvalidLine {
	if xs == nil {
		return []model.InvalidLine{}
	}
	return xs
}
