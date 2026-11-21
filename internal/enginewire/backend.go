package enginewire

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/sched"
	"github.com/iwosmu/aghpen/internal/store"
)

// Runs is the part of *runner.Manager that the scheduler needs.
type Runs interface {
	Start(ctx context.Context, profileID int64, userID *int64, trigger string) (model.ScanRun, error)
	Resume(ctx context.Context, runID int64) (model.ScanRun, error)
}

// Backend implements sched.Backend over the store and the run manager.
type Backend struct {
	st   *store.Store
	runs Runs
	log  *slog.Logger
	now  func() time.Time
}

var _ sched.Backend = (*Backend)(nil)

// NewBackend builds the scheduler backend.
func NewBackend(st *store.Store, runs Runs, log *slog.Logger) *Backend {
	if log == nil {
		log = slog.Default()
	}
	return &Backend{st: st, runs: runs, log: log, now: time.Now}
}

// NewScheduler builds the scheduler of the product: it starts due profiles
// inside their windows with trigger "schedule" and resumes runs that a
// closed window paused. Call Run in a goroutine.
func NewScheduler(st *store.Store, runs Runs, log *slog.Logger) *Scheduler {
	b := NewBackend(st, runs, log)
	return &Scheduler{Scheduler: sched.New(b, sched.Options{Logger: log}), Backend: b}
}

// Scheduler is sched.Scheduler plus the upkeep of ScanProfile.NextRunAt.
type Scheduler struct {
	*sched.Scheduler
	Backend *Backend
}

// Run refreshes the next-run times once, then ticks until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	s.Backend.RefreshNextRuns(ctx)
	s.Scheduler.Run(ctx)
}

// allProfiles reads every scan profile.
func (b *Backend) allProfiles(ctx context.Context) ([]model.ScanProfile, error) {
	var out []model.ScanProfile
	for off := 0; ; off += 500 {
		page, err := b.st.ListProfiles(ctx, store.ListOpts{Limit: 500, Offset: off, Sort: "id"})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if len(page.Items) < 500 {
			return out, nil
		}
	}
}

// ScheduledProfiles lists the enabled profiles whose schedule is enabled.
func (b *Backend) ScheduledProfiles(ctx context.Context) ([]model.ScanProfile, error) {
	all, err := b.allProfiles(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.ScanProfile
	for _, p := range all {
		if p.Enabled && p.Schedule.Enabled {
			out = append(out, p)
		}
	}
	return out, nil
}

// LastRun returns the start of the newest run of the profile and whether one
// of its runs is queued, running, analyzing or paused.
func (b *Backend) LastRun(ctx context.Context, profileID int64) (time.Time, bool, error) {
	page, err := b.st.ListRuns(ctx, store.RunFilter{ProfileID: profileID, ListOpts: store.ListOpts{Limit: 1, Sort: "-id"}})
	if err != nil {
		return time.Time{}, false, err
	}
	var last time.Time
	if len(page.Items) > 0 {
		last = page.Items[0].CreatedAt
		if s := page.Items[0].StartedAt; s != nil {
			last = *s
		}
	}
	act, err := b.st.ListRuns(ctx, store.RunFilter{ProfileID: profileID, Status: store.ActiveStatuses, ListOpts: store.ListOpts{Limit: 1}})
	if err != nil {
		return last, false, err
	}
	return last, act.Total > 0, nil
}

// StartRun starts a scheduled run. The run manager computes the window end
// itself with Window, from the same schedule, so windowEnd is not passed on.
func (b *Backend) StartRun(ctx context.Context, profileID int64, _ *time.Time) error {
	if _, err := b.runs.Start(ctx, profileID, nil, "schedule"); err != nil {
		return busy(err)
	}
	if p, err := b.st.GetProfile(ctx, profileID); err == nil {
		b.setNextRun(ctx, p, b.now())
	}
	return nil
}

// WindowPausedRuns lists the runs paused with reason "window_closed".
func (b *Backend) WindowPausedRuns(ctx context.Context) ([]model.ScanRun, error) {
	runs, err := b.st.RunsByStatus(ctx, model.RunPaused)
	if err != nil {
		return nil, err
	}
	var out []model.ScanRun
	for _, r := range runs {
		if r.PauseReason == model.PauseWindowClosed {
			out = append(out, r)
		}
	}
	return out, nil
}

// ResumeRun continues a paused run with its remaining chunks.
func (b *Backend) ResumeRun(ctx context.Context, runID int64, _ *time.Time) error {
	_, err := b.runs.Resume(ctx, runID)
	return busy(err)
}

// busy maps the "not now" answers of the run manager to sched.ErrBusy, so
// the scheduler tries again on its next tick without an error in the log.
func busy(err error) error {
	if errors.Is(err, runner.ErrActiveRun) || errors.Is(err, runner.ErrEmergencyStop) || errors.Is(err, runner.ErrBadState) {
		return errors.Join(sched.ErrBusy, err)
	}
	return err
}

// setNextRun stores when the profile starts next (nil when it has no schedule).
func (b *Backend) setNextRun(ctx context.Context, p model.ScanProfile, last time.Time) {
	var at *time.Time
	if p.Enabled && p.Schedule.Enabled {
		if t, err := sched.NextStart(p.Schedule, last, b.now()); err == nil {
			at = &t
		} else if !errors.Is(err, sched.ErrNoSchedule) {
			b.log.Warn("scheduler: cannot compute the next run", "profile", p.ID, "error", err.Error())
		}
	}
	if err := b.st.SetProfileNextRun(ctx, p.ID, at); err != nil && !errors.Is(err, context.Canceled) {
		b.log.Warn("scheduler: cannot store the next run", "profile", p.ID, "error", err.Error())
	}
}

// RefreshNextRuns recomputes ScanProfile.NextRunAt of every profile.
func (b *Backend) RefreshNextRuns(ctx context.Context) {
	all, err := b.allProfiles(ctx)
	if err != nil {
		b.log.Warn("scheduler: cannot list profiles", "error", err.Error())
		return
	}
	for _, p := range all {
		last, _, err := b.LastRun(ctx, p.ID)
		if err != nil {
			continue
		}
		b.setNextRun(ctx, p, last)
	}
}

// ProfileChanged returns the api.Hooks.ProfileChanged callback: it recomputes
// the next run of a profile after a create or an update.
func ProfileChanged(st *store.Store, log *slog.Logger) func(ctx context.Context, p model.ScanProfile, deleted bool) {
	b := NewBackend(st, nil, log)
	return func(ctx context.Context, p model.ScanProfile, deleted bool) {
		if deleted {
			return
		}
		last, _, err := b.LastRun(ctx, p.ID)
		if err != nil {
			return
		}
		b.setNextRun(ctx, p, last)
	}
}
