package scan

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ppsWindow is the look-back of RunStats.CurrentPPS.
const ppsWindow = 5 * time.Second

type stageRec struct {
	start, end time.Time
	packets    int64
	exact      bool
}

// statsKeeper holds the run counters. Packets are counted when a probe
// stage ends: nmap reports its raw packet count then. CurrentPPS covers the
// last seconds: the exact packets of the stages that ended, spread over the
// time they ran, plus the rate share of the paced stages that still run.
type statsKeeper struct {
	mu        sync.Mutex
	s         model.RunStats // cumulative, earlier sessions of a resumed run included
	started   time.Time
	prevSec   int64
	prevDone  int64 // addresses done before this session
	stages    []stageRec
	fallback  float64 // seconds per address before anything is measured
	parallel  int
	now       func() time.Time
	peakPPS   float64
	sessionPk int64
	flights   map[int]flight // paced probe stages that run now
	flightSeq int
	passes    []*passRec // port passes in execution order (RunStats.Passes)
}

// passRec is one port pass. Its running port scans count in PortsDone at
// their pinned rate until they end.
type passRec struct {
	st      model.PassStat
	running map[int]passFlight
}

type passFlight struct {
	start time.Time
	rate  int
	pairs int64
}

func (k *statsKeeper) passLocked(name string) *passRec {
	for _, p := range k.passes {
		if p.st.Name == name {
			return p
		}
	}
	p := &passRec{st: model.PassStat{Name: name, State: model.PassPending}, running: map[int]passFlight{}}
	k.passes = append(k.passes, p)
	return p
}

// addPass lists a pass that will run (pending) so the run page shows it
// from the start.
func (k *statsKeeper) addPass(name string) {
	k.mu.Lock()
	k.passLocked(name)
	k.mu.Unlock()
}

// passBegin marks a port scan of a pass as started; call end when it ends.
func (k *statsKeeper) passBegin(name string, hosts int, pairs int64, rate int) (end func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p := k.passLocked(name)
	p.st.State = model.PassRunning
	p.st.Hosts += hosts
	p.st.PortsTotal += pairs
	k.flightSeq++
	id := k.flightSeq
	p.running[id] = passFlight{start: k.now(), rate: max(1, rate), pairs: pairs}
	return func() {
		k.mu.Lock()
		defer k.mu.Unlock()
		if f, ok := p.running[id]; ok {
			p.st.PortsDone += f.pairs
			delete(p.running, id)
		}
	}
}

// passState sets the state of a pass (done when the engine knows no more
// scan of it will come, skipped when it will not run).
func (k *statsKeeper) passState(name, state string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p := k.passLocked(name)
	if len(p.running) == 0 {
		p.st.State = state
	}
}

// passSkipHosts counts live hosts that a pass did not cover.
func (k *statsKeeper) passSkipHosts(name string, n int) {
	k.mu.Lock()
	k.passLocked(name).st.HostsSkipped += n
	k.mu.Unlock()
}

// finishPasses closes the passes when the run ends: a completed run has
// every pass done or skipped. A full-range pass that left live hosts out
// adds a note, so that the difference in coverage is visible.
func (k *statsKeeper) finishPasses(completed bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range k.passes {
		if p.st.Name == model.PassDeep && p.st.Hosts > 0 {
			if note := deepNote(p.st.Hosts, p.st.HostsSkipped); !slices.Contains(k.s.Notes, note) {
				k.s.Notes = append(k.s.Notes, note)
			}
		}
		if p.st.Name == model.PassFullRange && p.st.HostsSkipped > 0 {
			note := fmt.Sprintf("pełny zakres portów (1-65535) objął %d z %d aktywnych hostów; pozostałe: porty z profilu",
				p.st.Hosts, p.st.Hosts+p.st.HostsSkipped)
			if !slices.Contains(k.s.Notes, note) {
				k.s.Notes = append(k.s.Notes, note)
			}
		}
	}
	if !completed {
		return
	}
	for _, p := range k.passes {
		switch {
		case p.st.State == model.PassPending:
			p.st.State = model.PassSkipped
		case len(p.running) == 0:
			p.st.State = model.PassDone
		}
	}
}

// passesLocked is the Passes value of a snapshot: present only with more
// than one pass.
func (k *statsKeeper) passesLocked(now time.Time) []model.PassStat {
	if len(k.passes) < 2 {
		return nil
	}
	out := make([]model.PassStat, len(k.passes))
	for i, p := range k.passes {
		out[i] = p.st
		for _, f := range p.running {
			out[i].PortsDone += min(f.pairs, int64(now.Sub(f.start).Seconds()*float64(f.rate)))
		}
	}
	return out
}

// flight is a probe stage that is still running. Its packet count is known
// only when it ends. Until then CurrentPPS counts it at its rate share: the
// nmap runner pins the send rate to that share (--min-rate = --max-rate),
// and the lab measurements show 247 of 250 packets per second.
type flight struct {
	start time.Time
	rate  int
}

func newStatsKeeper(prev *model.RunStats, now func() time.Time) *statsKeeper {
	k := &statsKeeper{now: now, started: now(), flights: map[int]flight{}}
	if prev != nil {
		k.s = *prev
		k.prevSec = prev.ElapsedSec
		k.prevDone = prev.AddressesDone
	}
	return k
}

func (k *statsKeeper) update(fn func(s *model.RunStats)) {
	k.mu.Lock()
	fn(&k.s)
	k.mu.Unlock()
}

// warn adds a warning to the run once. The text is what the user reads
// (Polish, like the rest of the UI); the caller logs in English.
func (k *statsKeeper) warn(text string) {
	k.update(func(s *model.RunStats) {
		for _, w := range s.Warnings {
			if w == text {
				return
			}
		}
		s.Warnings = append(s.Warnings, text)
	})
}

// begin marks the start of a rate-paced probe stage. Call the returned
// function when the stage ends, just before addStage.

func (k *statsKeeper) begin(rate int) (end func()) {
	k.mu.Lock()
	k.flightSeq++
	id := k.flightSeq
	k.flights[id] = flight{start: k.now(), rate: rate}
	k.mu.Unlock()
	return func() {
		k.mu.Lock()
		delete(k.flights, id)
		k.mu.Unlock()
	}
}

// addStage records the packets of one finished probe stage.
func (k *statsKeeper) addStage(packets int64, exact bool, start, end time.Time) {
	if packets <= 0 {
		return
	}
	k.mu.Lock()
	k.s.PacketsSent += packets
	if !exact {
		k.s.PacketsEstimated += packets
	}
	k.sessionPk += packets
	k.stages = append(k.stages, stageRec{start, end, packets, exact})
	k.mu.Unlock()
}

// snapshot returns the stats with the derived fields filled in.
func (k *statsKeeper) snapshot() model.RunStats {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	active := now.Sub(k.started)
	s := k.s
	s.ElapsedSec = k.prevSec + int64(active.Seconds())
	s.Passes = k.passesLocked(now)

	// current speed: packets of recent stages that fall into the window
	from := now.Add(-ppsWindow)
	var recent float64
	basis := "measured"
	keep := k.stages[:0]
	for _, st := range k.stages {
		if st.end.Before(from) {
			continue
		}
		keep = append(keep, st)
		d := st.end.Sub(st.start)
		if d < 50*time.Millisecond {
			d = 50 * time.Millisecond
		}
		lo := st.start
		if lo.Before(from) {
			lo = from
		}
		if ov := st.end.Sub(lo); ov > 0 {
			recent += float64(st.packets) * float64(ov) / float64(d)
			if !st.exact {
				basis = "pace"
			}
		}
	}
	k.stages = keep
	for _, f := range k.flights {
		lo := f.start
		if lo.Before(from) {
			lo = from
		}
		if d := now.Sub(lo); d > 0 {
			recent += float64(f.rate) * d.Seconds()
			basis = "pace"
		}
	}
	win := ppsWindow
	if active < win {
		win = active
	}
	if win > 0 {
		s.CurrentPPS = round1(recent / win.Seconds())
		s.CurrentPPSBasis = basis
	}
	if s.CurrentPPS > k.peakPPS {
		k.peakPPS = s.CurrentPPS
	}
	total := float64(k.prevSec) + active.Seconds()
	if total > 0 {
		s.AvgPPS = round1(float64(s.PacketsSent) / total)
	}

	// ETA from the measured address rate of this session
	remaining := s.AddressesTotal - s.AddressesDone
	if remaining <= 0 {
		s.ETASec = 0
	} else if done := s.AddressesDone - k.prevDone; done > 0 && active > 0 {
		s.ETASec = int64(float64(remaining) * active.Seconds() / float64(done))
	} else {
		s.ETASec = int64(float64(remaining) * k.fallback / float64(max(1, k.parallel)))
	}
	return s
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
