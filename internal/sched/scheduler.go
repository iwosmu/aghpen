package sched

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Backend is what the scheduler needs from the rest of the system. The API
// layer implements it with the store and the run manager.
type Backend interface {
	// ScheduledProfiles lists the enabled profiles whose schedule is enabled.
	ScheduledProfiles(ctx context.Context) ([]model.ScanProfile, error)
	// LastRun returns the start time of the newest run of a profile (zero
	// when it never ran) and whether a run of it is queued, running or paused.
	LastRun(ctx context.Context, profileID int64) (startedAt time.Time, active bool, err error)
	// StartRun starts a scheduled run. windowEnd is nil when the schedule has no windows.
	StartRun(ctx context.Context, profileID int64, windowEnd *time.Time) error
	// WindowPausedRuns lists the runs paused with reason "window_closed".
	WindowPausedRuns(ctx context.Context) ([]model.ScanRun, error)
	// ResumeRun continues a paused run with its remaining chunks.
	ResumeRun(ctx context.Context, runID int64, windowEnd *time.Time) error
}

// ErrBusy may be returned by StartRun or ResumeRun when the run cannot
// start now (for example another run of the profile is active). The
// scheduler tries again on the next tick and does not log an error.
var ErrBusy = errors.New("sched: busy")

// Scheduler starts due runs inside their windows and resumes runs that a
// closing window paused, at the next window start.
type Scheduler struct {
	backend  Backend
	log      *slog.Logger
	interval time.Duration
	now      func() time.Time
	started  time.Time
}

// Options configure a Scheduler. Zero values mean a 20 s tick and the real clock.
type Options struct {
	Interval time.Duration
	Now      func() time.Time
	Logger   *slog.Logger
}

// New builds a scheduler.
func New(b Backend, o Options) *Scheduler {
	s := &Scheduler{backend: b, log: o.Logger, interval: o.Interval, now: o.Now}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.interval <= 0 {
		s.interval = 20 * time.Second
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.started = s.now()
	return s
}

// Run ticks until the context ends.
func (s *Scheduler) Run(ctx context.Context) {
	s.log.Info("scheduler started", "interval", s.interval.String())
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		s.Tick(ctx, s.now())
		select {
		case <-ctx.Done():
			s.log.Info("scheduler stopped")
			return
		case <-t.C:
		}
	}
}

// Decision is what one tick did, for logs and tests.
type Decision struct {
	Started []int64 // profile IDs
	Resumed []int64 // run IDs
	Waiting []int64 // profile IDs that are due but outside their windows
}

// Tick makes the decisions for the moment now.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) Decision {
	var d Decision
	profiles, err := s.backend.ScheduledProfiles(ctx)
	if err != nil {
		s.log.Error("scheduler: cannot list profiles", "error", err.Error())
		return d
	}
	byID := map[int64]model.ScanProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	busy := map[int64]bool{}

	// 1. Runs that a window paused: resume when a window is open again.
	paused, err := s.backend.WindowPausedRuns(ctx)
	if err != nil {
		s.log.Error("scheduler: cannot list paused runs", "error", err.Error())
	}
	for _, run := range paused {
		if run.ProfileID == nil {
			continue
		}
		busy[*run.ProfileID] = true
		p, ok := byID[*run.ProfileID]
		if !ok {
			continue // schedule switched off: the run waits for a manual resume
		}
		loc, err := Location(p.Schedule.Timezone)
		if err != nil {
			s.log.Error("scheduler: bad timezone", "profile", p.ID, "error", err.Error())
			continue
		}
		if !InWindow(now, p.Schedule.Windows, loc) {
			continue
		}
		if run.ResumeAt != nil && now.Before(*run.ResumeAt) {
			continue
		}
		if err := s.backend.ResumeRun(ctx, run.ID, windowEndPtr(now, p.Schedule.Windows, loc)); err != nil {
			if !errors.Is(err, ErrBusy) {
				s.log.Error("scheduler: resume failed", "run", run.ID, "error", err.Error())
			}
			continue
		}
		s.log.Info("scheduler: resumed a window-paused run", "run", run.ID, "profile", p.ID)
		d.Resumed = append(d.Resumed, run.ID)
	}

	// 2. Profiles that are due.
	for _, p := range profiles {
		if !p.Enabled || !p.Schedule.Enabled || busy[p.ID] {
			continue
		}
		loc, err := Location(p.Schedule.Timezone)
		if err != nil {
			s.log.Error("scheduler: bad timezone", "profile", p.ID, "error", err.Error())
			continue
		}
		last, active, err := s.backend.LastRun(ctx, p.ID)
		if err != nil {
			s.log.Error("scheduler: cannot read the last run", "profile", p.ID, "error", err.Error())
			continue
		}
		if active {
			continue
		}
		due, err := NextRun(p.Schedule, last, s.started)
		if err != nil {
			if !errors.Is(err, ErrNoSchedule) {
				s.log.Error("scheduler: bad schedule", "profile", p.ID, "error", err.Error())
			}
			continue
		}
		if due.After(now) {
			continue
		}
		if !InWindow(now, p.Schedule.Windows, loc) {
			d.Waiting = append(d.Waiting, p.ID) // starts when the next window opens
			continue
		}
		if err := s.backend.StartRun(ctx, p.ID, windowEndPtr(now, p.Schedule.Windows, loc)); err != nil {
			if !errors.Is(err, ErrBusy) {
				s.log.Error("scheduler: start failed", "profile", p.ID, "error", err.Error())
			}
			continue
		}
		s.log.Info("scheduler: started a scheduled run", "profile", p.ID, "due", due.Format(time.RFC3339))
		d.Started = append(d.Started, p.ID)
	}
	return d
}

func windowEndPtr(now time.Time, ws []model.Window, loc *time.Location) *time.Time {
	if end, ok := WindowEnd(now, ws, loc); ok {
		return &end
	}
	return nil
}
