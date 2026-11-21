package wire

import (
	"context"
	"errors"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/sched"
	"github.com/iwosmu/aghpen/internal/store"
)

// SchedBackend is the sched.Backend of the scheduler loop: the profiles with
// a schedule, when each ran last, starting a run, and the runs that a closed
// window paused. The run manager computes the window end itself (Window), so
// the windowEnd arguments are not needed here.
type SchedBackend struct {
	Store  *store.Store
	Runner *runner.Manager
	Now    func() time.Time // clock of the next-run hint; nil means time.Now
}

var _ sched.Backend = SchedBackend{}

// ScheduledProfiles returns the enabled profiles whose schedule is enabled.
func (b SchedBackend) ScheduledProfiles(ctx context.Context) ([]model.ScanProfile, error) {
	return b.Store.ScheduledProfiles(ctx)
}

// LastRun returns the start of the newest run of the profile (zero when it
// never ran) and whether a run of it is still active.
func (b SchedBackend) LastRun(ctx context.Context, profileID int64) (time.Time, bool, error) {
	t, err := b.Store.LastRunStart(ctx, profileID)
	if err != nil {
		return time.Time{}, false, err
	}
	active, err := b.Store.ProfileHasActiveRun(ctx, profileID)
	if err != nil {
		return time.Time{}, false, err
	}
	var last time.Time
	if t != nil {
		last = *t
	}
	return last, active, nil
}

// StartRun starts a scheduled run of a profile and stores the next planned start.
func (b SchedBackend) StartRun(ctx context.Context, profileID int64, _ *time.Time) error {
	_, err := b.Runner.Start(ctx, profileID, nil, "schedule")
	if err != nil {
		return busy(err)
	}
	if p, err := b.Store.GetProfile(ctx, profileID); err == nil {
		_ = b.SetNextRun(ctx, p)
	}
	return nil
}

// WindowPausedRuns returns the runs that a closed scan window paused.
func (b SchedBackend) WindowPausedRuns(ctx context.Context) ([]model.ScanRun, error) {
	return b.Store.WindowPausedRuns(ctx)
}

// ResumeRun continues a paused run with its remaining chunks.
func (b SchedBackend) ResumeRun(ctx context.Context, runID int64, _ *time.Time) error {
	_, err := b.Runner.Resume(ctx, runID)
	return busy(err)
}

// SetNextRun stores the next planned start of a profile, shown in the UI.
// A profile without an enabled schedule gets no next start.
func (b SchedBackend) SetNextRun(ctx context.Context, p model.ScanProfile) error {
	if !p.Enabled || !p.Schedule.Enabled {
		return b.Store.SetProfileNextRun(ctx, p.ID, nil)
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	var last time.Time
	if t, err := b.Store.LastRunStart(ctx, p.ID); err == nil && t != nil {
		last = *t
	}
	next, err := sched.NextStart(p.Schedule, last, now)
	if err != nil {
		return b.Store.SetProfileNextRun(ctx, p.ID, nil)
	}
	return b.Store.SetProfileNextRun(ctx, p.ID, &next)
}

// ProfileChanged is the api.Hooks.ProfileChanged callback: it refreshes the next planned start.
func (b SchedBackend) ProfileChanged(ctx context.Context, p model.ScanProfile, deleted bool) {
	if deleted {
		return
	}
	_ = b.SetNextRun(ctx, p)
}

// busy maps the run manager errors that mean "try again later" to sched.ErrBusy.
func busy(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, runner.ErrActiveRun) || errors.Is(err, runner.ErrEmergencyStop) || errors.Is(err, runner.ErrBadState) {
		return errors.Join(sched.ErrBusy, err)
	}
	return err
}

// Window is the runner.WindowFunc: the end of the scan window that contains
// now and the start of the next one, from the windows of the profile
// schedule. A profile without windows has no limit. A run started by hand
// outside every window gets no end (an operator decided to scan now).
func Window(p model.ScanProfile, now time.Time) (windowEnd, nextStart *time.Time) {
	ws := p.Schedule.Windows
	if len(ws) == 0 {
		return nil, nil
	}
	loc, err := sched.Location(p.Schedule.Timezone)
	if err != nil {
		loc = time.UTC
	}
	if end, ok := sched.WindowEnd(now, ws, loc); ok {
		windowEnd = &end
	}
	from := now
	if windowEnd != nil {
		from = *windowEnd
	}
	if next, ok := sched.NextWindowStart(from, ws, loc); ok {
		nextStart = &next
	}
	return windowEnd, nextStart
}
