package scan

import (
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ppsWindow is the look-back of RunStats.CurrentPPS.
const ppsWindow = 5 * time.Second

type stageRec struct {
	start, end time.Time
	packets    int64
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
func (k *statsKeeper) addStage(packets int64, start, end time.Time) {
	if packets <= 0 {
		return
	}
	k.mu.Lock()
	k.s.PacketsSent += packets
	k.sessionPk += packets
	k.stages = append(k.stages, stageRec{start, end, packets})
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

	// current speed: packets of recent stages that fall into the window
	from := now.Add(-ppsWindow)
	var recent float64
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
		}
	}
	win := ppsWindow
	if active < win {
		win = active
	}
	if win > 0 {
		s.CurrentPPS = round1(recent / win.Seconds())
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
