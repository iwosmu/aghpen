package wire

import (
	"context"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

// SchedBackend is what a scheduler loop needs from the store and the run
// manager: the profiles with a schedule, when each ran last, starting a run,
// and the runs that a closed window paused. internal/sched defines its own
// small Backend interface; this type is meant to satisfy it with, at most, a
// rename of methods.
type SchedBackend struct {
	Store  *store.Store
	Runner *runner.Manager
}

// Profiles returns the enabled profiles whose schedule is enabled.
func (b SchedBackend) Profiles(ctx context.Context) ([]model.ScanProfile, error) {
	return b.Store.ScheduledProfiles(ctx)
}

// DueProfiles returns the scheduled profiles whose next_run_at has passed and that have no active run.
func (b SchedBackend) DueProfiles(ctx context.Context, now time.Time) ([]model.ScanProfile, error) {
	return b.Store.DueProfiles(ctx, now)
}

// LastRunStart returns when the newest run of the profile started; nil when it never ran.
func (b SchedBackend) LastRunStart(ctx context.Context, profileID int64) (*time.Time, error) {
	return b.Store.LastRunStart(ctx, profileID)
}

// SetNextRun stores the next planned start of a profile (shown in the UI); nil clears it.
func (b SchedBackend) SetNextRun(ctx context.Context, profileID int64, at *time.Time) error {
	return b.Store.SetProfileNextRun(ctx, profileID, at)
}

// StartRun starts a scheduled run of a profile.
func (b SchedBackend) StartRun(ctx context.Context, profileID int64) (model.ScanRun, error) {
	return b.Runner.Start(ctx, profileID, nil, "schedule")
}

// PausedByWindow returns the runs that a closed scan window paused, with their resume_at.
func (b SchedBackend) PausedByWindow(ctx context.Context) ([]model.ScanRun, error) {
	return b.Store.WindowPausedRuns(ctx)
}

// ResumeRun continues a paused run with its remaining chunks.
func (b SchedBackend) ResumeRun(ctx context.Context, runID int64) (model.ScanRun, error) {
	return b.Runner.Resume(ctx, runID)
}
