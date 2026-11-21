package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

var (
	// ErrNotWired means no scan engine is connected to the manager.
	ErrNotWired = errors.New("the scan engine is not wired")
	// ErrEmergencyStop means the emergency stop is active.
	ErrEmergencyStop = errors.New("the emergency stop is active: no run may start")
	// ErrActiveRun means the profile already has an active run.
	ErrActiveRun = errors.New("this profile already has an active run")
	// ErrBadState means the run is not in a state that allows the action.
	ErrBadState = errors.New("the run is not in a state that allows this action")
	// ErrInvalid means the profile cannot be scanned as it is.
	ErrInvalid = errors.New("invalid")
)

// PauseRestart is the pause reason of a run that a restart of Czujka interrupted.
const PauseRestart = "restart"

// Analyzer is the hook that runs after a completed run or import: stability
// model, diff, interest score, grouping and findings. Implemented by an adapter
// around internal/analyze that reads and writes through the store.
type Analyzer interface {
	AnalyzeRun(ctx context.Context, runID int64) (*model.RunDiffSummary, error)
}

// WindowFunc tells the manager when the current scan window of a profile ends
// (nil = no limit) and when the next window starts. Supplied by internal/sched.
type WindowFunc func(p model.ScanProfile, now time.Time) (windowEnd, nextStart *time.Time)

// Options configure the manager. Engine and Analyzer may be nil until the integration step wires them.
type Options struct {
	Engine      model.Engine
	Analyzer    Analyzer
	Bus         *Bus
	Window      WindowFunc
	IngestBatch int
	Logger      *slog.Logger
	StopTimeout time.Duration // how long Pause, Cancel and EmergencyStop wait for the engine; default 30s
}

// Manager runs scans. One Manager exists per process.
type Manager struct {
	st  *store.Store
	opt Options
	log *slog.Logger

	mu     sync.Mutex
	active map[int64]*activeRun
	wg     sync.WaitGroup
}

type activeRun struct {
	mu     sync.Mutex
	run    model.ScanRun
	intent string // "", pause, cancel, emergency, shutdown
	cancel context.CancelFunc
	done   chan struct{}
}

func (a *activeRun) snapshot() model.ScanRun {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.run
}

// New returns a run manager.
func New(st *store.Store, opt Options) *Manager {
	if opt.Bus == nil {
		opt.Bus = NewBus()
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.StopTimeout <= 0 {
		opt.StopTimeout = 30 * time.Second
	}
	return &Manager{st: st, opt: opt, log: opt.Logger, active: map[int64]*activeRun{}}
}

// Bus returns the event bus of the manager.
func (m *Manager) Bus() *Bus { return m.opt.Bus }

// EngineWired reports whether a scan engine is connected.
func (m *Manager) EngineWired() bool { return m.opt.Engine != nil }

// SetEngine connects the scan engine (integration step).
func (m *Manager) SetEngine(e model.Engine) { m.opt.Engine = e }

// SetAnalyzer connects the analysis hook (integration step).
func (m *Manager) SetAnalyzer(a Analyzer) { m.opt.Analyzer = a }

// SetWindow connects the scan-window function of the scheduler (integration step).
func (m *Manager) SetWindow(w WindowFunc) { m.opt.Window = w }

// Wait blocks until every run goroutine has ended.
func (m *Manager) Wait() { m.wg.Wait() }

// ActiveRunIDs returns the ids of the runs that this process is executing.
func (m *Manager) ActiveRunIDs() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int64, 0, len(m.active))
	for id := range m.active {
		out = append(out, id)
	}
	return out
}

// BuildPlan assembles the engine input of a run from the database: targets of
// the profile scopes, the safety policy, hints from known hosts, the speed
// measured in earlier runs, and on resume the remaining chunks and the stats so far.
func (m *Manager) BuildPlan(ctx context.Context, profile model.ScanProfile, run *model.ScanRun, resume bool) (model.ScanPlan, error) {
	plan := model.ScanPlan{Profile: profile}
	var err error
	if plan.Policy, err = m.st.GetSafetyPolicy(ctx); err != nil {
		return plan, err
	}
	if len(profile.ScopeIDs) == 0 {
		return plan, fmt.Errorf("%w: the profile has no scope", ErrInvalid)
	}
	if plan.Targets, err = m.st.EnabledTargets(ctx, profile.ScopeIDs); err != nil {
		return plan, err
	}
	if len(plan.Targets) == 0 {
		return plan, fmt.Errorf("%w: the scopes of the profile have no enabled target", ErrInvalid)
	}
	if plan.Hints, err = m.st.HostHints(ctx, profile.ScopeIDs); err != nil {
		return plan, err
	}
	if plan.MeasuredPPS, err = m.st.ProfileMeasuredPPS(ctx, profile.ID); err != nil {
		return plan, err
	}
	if m.opt.Window != nil {
		plan.WindowEnd, _ = m.opt.Window(profile, time.Now())
	}
	if run != nil {
		plan.RunID = run.ID
		if resume {
			if plan.Chunks, err = m.st.RemainingChunks(ctx, run.ID); err != nil {
				return plan, err
			}
			stats := run.Stats
			plan.PrevStats = &stats
		}
	}
	return plan, nil
}

// Estimate computes the traffic budget of a profile without sending anything.
func (m *Manager) Estimate(ctx context.Context, profileID int64) (model.ScanEstimate, error) {
	if m.opt.Engine == nil {
		return model.ScanEstimate{}, ErrNotWired
	}
	p, err := m.st.GetProfile(ctx, profileID)
	if err != nil {
		return model.ScanEstimate{}, err
	}
	plan, err := m.BuildPlan(ctx, p, nil, false)
	if err != nil {
		return model.ScanEstimate{}, err
	}
	return m.opt.Engine.Estimate(plan), nil
}

// Start creates a run from a profile and starts it in the background.
// trigger is "manual" or "schedule".
func (m *Manager) Start(ctx context.Context, profileID int64, userID *int64, trigger string) (model.ScanRun, error) {
	if m.opt.Engine == nil {
		return model.ScanRun{}, ErrNotWired
	}
	policy, err := m.st.GetSafetyPolicy(ctx)
	if err != nil {
		return model.ScanRun{}, err
	}
	if policy.EmergencyStop {
		return model.ScanRun{}, ErrEmergencyStop
	}
	p, err := m.st.GetProfile(ctx, profileID)
	if err != nil {
		return model.ScanRun{}, err
	}
	if !p.Enabled {
		return model.ScanRun{}, fmt.Errorf("%w: the profile is disabled", ErrInvalid)
	}
	// Fail early on a profile that cannot be planned.
	if _, err := m.BuildPlan(ctx, p, nil, false); err != nil {
		return model.ScanRun{}, err
	}
	if trigger == "" {
		trigger = "manual"
	}
	run, err := m.st.CreateRun(ctx, model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name, Status: model.RunQueued, Trigger: trigger, CreatedBy: userID})
	if errors.Is(err, store.ErrConflict) {
		return model.ScanRun{}, ErrActiveRun // the unique index allows one active run per profile
	}
	if err != nil {
		return model.ScanRun{}, err
	}
	m.launch(run, p, false)
	return run, nil
}

func (m *Manager) launch(run model.ScanRun, p model.ScanProfile, resume bool) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &activeRun{run: run, cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.active[run.ID] = a
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			cancel()
			m.mu.Lock()
			delete(m.active, run.ID)
			m.mu.Unlock()
			close(a.done)
		}()
		m.execute(ctx, a, p, resume)
	}()
}

// save stores the run state of a and publishes it.
func (m *Manager) save(a *activeRun, typ string) model.ScanRun {
	run := a.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.st.SaveRun(ctx, run); err != nil {
		m.log.Error("save run", "run", run.ID, "err", err)
	}
	m.opt.Bus.Publish(Event{RunID: run.ID, Type: EventRun, Data: run})
	if typ != "" {
		m.opt.Bus.Publish(Event{RunID: run.ID, Type: typ, Data: run})
	}
	return run
}

func (m *Manager) execute(ctx context.Context, a *activeRun, p model.ScanProfile, resume bool) {
	bg := context.WithoutCancel(ctx)
	fail := func(err error) {
		now := time.Now().UTC()
		a.mu.Lock()
		a.run.Status, a.run.Error, a.run.FinishedAt = model.RunFailed, err.Error(), &now
		a.mu.Unlock()
		m.save(a, EventDone)
		m.log.Error("run failed", "run", a.run.ID, "err", err)
	}
	run := a.snapshot()
	plan, err := m.BuildPlan(bg, p, &run, resume)
	if err != nil {
		fail(err)
		return
	}
	now := time.Now().UTC()
	a.mu.Lock()
	a.run.Status, a.run.PauseReason, a.run.ResumeAt, a.run.WindowEnd, a.run.Error = model.RunRunning, "", nil, plan.WindowEnd, ""
	if a.run.StartedAt == nil {
		a.run.StartedAt = &now
	}
	stopped := a.intent != ""
	a.mu.Unlock()
	m.save(a, EventProgress)

	sink := &eventSink{inner: m.st.NewSink(store.SinkOptions{BatchSize: m.opt.IngestBatch, Source: "scan", MarkMissing: true}), m: m, a: a}
	var outcome model.RunOutcome
	if stopped { // paused or cancelled before the engine started
		outcome = model.RunOutcome{Status: model.RunPaused, Stats: run.Stats}
	} else {
		outcome = m.runEngine(ctx, plan, sink)
	}
	if err := sink.inner.Flush(bg); err != nil {
		m.log.Error("flush results", "run", run.ID, "err", err)
		if outcome.Err == nil {
			outcome.Err = fmt.Errorf("store results: %w", err)
		}
		if outcome.Status == model.RunCompleted {
			outcome.Status = model.RunFailed
		}
	}

	end := time.Now().UTC()
	a.mu.Lock()
	if outcome.Stats != (model.RunStats{}) {
		a.run.Stats = outcome.Stats
	}
	intent := a.intent
	switch {
	case intent == "cancel":
		a.run.Status, a.run.FinishedAt = model.RunCancelled, &end
	case intent == "pause":
		a.run.Status, a.run.PauseReason = model.RunPaused, model.PauseManual
	case intent == "emergency":
		a.run.Status, a.run.PauseReason = model.RunPaused, model.PauseEmergency
	case intent == "shutdown":
		a.run.Status, a.run.PauseReason = model.RunPaused, PauseRestart
	case outcome.Status == model.RunCompleted:
		a.run.Status = model.RunAnalyzing
	case outcome.Status == model.RunPaused:
		a.run.Status, a.run.PauseReason = model.RunPaused, outcome.PauseReason
		if a.run.PauseReason == "" {
			a.run.PauseReason = model.PauseWindowClosed
		}
		if a.run.PauseReason == model.PauseWindowClosed && m.opt.Window != nil {
			_, a.run.ResumeAt = m.opt.Window(p, end)
		}
	case outcome.Status == model.RunCancelled:
		a.run.Status, a.run.FinishedAt = model.RunCancelled, &end
	default:
		a.run.Status, a.run.FinishedAt = model.RunFailed, &end
		if outcome.Err != nil {
			a.run.Error = outcome.Err.Error()
		} else {
			a.run.Error = fmt.Sprintf("the engine returned status %q", outcome.Status)
		}
	}
	status, reason := a.run.Status, a.run.PauseReason
	a.mu.Unlock()

	if status != model.RunAnalyzing {
		partial := status == model.RunPaused && reason == model.PauseWindowClosed && m.opt.Analyzer != nil
		if partial {
			// A run that its scan window stopped is analysed for what it probed so
			// far. The analysis reads only stored observations, so an address the
			// run did not reach is not a miss. The resumed run is analysed again.
			if summary, err := m.analyze(bg, run.ID); err != nil {
				m.log.Error("analysis of a partial run failed", "run", run.ID, "err", err)
			} else {
				a.mu.Lock()
				a.run.Summary = summary
				a.mu.Unlock()
			}
		}
		m.save(a, EventDone)
		if partial {
			m.publishResults(bg, run.ID)
		}
		return
	}
	m.save(a, EventProgress)
	m.finish(bg, a, &p)
}

// runEngine calls the engine and turns a panic into a failed outcome.
func (m *Manager) runEngine(ctx context.Context, plan model.ScanPlan, sink model.ResultSink) (out model.RunOutcome) {
	defer func() {
		if r := recover(); r != nil {
			out = model.RunOutcome{Status: model.RunFailed, Err: fmt.Errorf("engine panic: %v", r)}
		}
	}()
	return m.opt.Engine.Run(ctx, plan, sink)
}

// analyze calls the analysis hook and turns a panic into an error.
func (m *Manager) analyze(ctx context.Context, runID int64) (summary *model.RunDiffSummary, err error) {
	if m.opt.Analyzer == nil {
		return nil, nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("analysis panic: %v", r)
		}
	}()
	return m.opt.Analyzer.AnalyzeRun(ctx, runID)
}

// finish runs the analysis hook and completes the run.
func (m *Manager) finish(ctx context.Context, a *activeRun, p *model.ScanProfile) {
	run := a.snapshot()
	summary, aerr := m.analyze(ctx, run.ID)
	end := time.Now().UTC()
	a.mu.Lock()
	a.run.Status, a.run.FinishedAt, a.run.Summary = model.RunCompleted, &end, summary
	if aerr != nil {
		// The scan data is stored and valid; only the analysis is missing.
		a.run.Error = "analysis failed: " + aerr.Error()
		m.log.Error("analysis failed", "run", run.ID, "err", aerr)
	}
	a.mu.Unlock()
	run = m.save(a, EventDone)
	if p != nil {
		if err := m.st.SetProfileLastRun(ctx, p.ID, run.ID, run.Stats.AvgPPS); err != nil {
			m.log.Error("set profile last run", "err", err)
		}
	}
	m.publishResults(ctx, run.ID)
}

// publishResults sends the new changes and findings of a run to the global event stream.
func (m *Manager) publishResults(ctx context.Context, runID int64) {
	no := false
	if page, err := m.st.ListChanges(ctx, store.ChangeFilter{RunID: runID, Expected: &no, ListOpts: store.ListOpts{Limit: 100}}); err == nil {
		for _, c := range page.Items {
			m.opt.Bus.Publish(Event{RunID: runID, Type: EventChange, Data: c})
		}
	}
	if page, err := m.st.ListFindings(ctx, store.FindingFilter{FirstRunID: runID, ListOpts: store.ListOpts{Limit: 100}}); err == nil {
		for _, f := range page.Items {
			m.opt.Bus.Publish(Event{RunID: runID, Type: EventFinding, Data: f})
		}
	}
}

// stop asks a running run to stop with the given intent and waits for it.
func (m *Manager) stop(ctx context.Context, runID int64, intent string) bool {
	m.mu.Lock()
	a := m.active[runID]
	m.mu.Unlock()
	if a == nil {
		return false
	}
	a.mu.Lock()
	if a.intent == "" || intent == "cancel" {
		a.intent = intent
	}
	a.mu.Unlock()
	a.cancel()
	select {
	case <-a.done:
	case <-ctx.Done():
	case <-time.After(m.opt.StopTimeout):
		m.log.Warn("engine did not stop in time", "run", runID)
	}
	return true
}

// Pause stops a running run and keeps its remaining chunks for a later resume.
func (m *Manager) Pause(ctx context.Context, runID int64) (model.ScanRun, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return run, err
	}
	if run.Status != model.RunRunning && run.Status != model.RunQueued {
		return run, fmt.Errorf("%w: status is %s", ErrBadState, run.Status)
	}
	if !m.stop(ctx, runID, "pause") {
		// Not executing in this process (left over by a crash): fix the state.
		run.Status, run.PauseReason = model.RunPaused, model.PauseManual
		if err := m.st.SaveRun(ctx, run); err != nil {
			return run, err
		}
		m.opt.Bus.Publish(Event{RunID: run.ID, Type: EventRun, Data: run})
	}
	return m.st.GetRun(ctx, runID)
}

// Resume continues a paused run with its remaining chunks.
func (m *Manager) Resume(ctx context.Context, runID int64) (model.ScanRun, error) {
	if m.opt.Engine == nil {
		return model.ScanRun{}, ErrNotWired
	}
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return run, err
	}
	if run.Status != model.RunPaused {
		return run, fmt.Errorf("%w: status is %s", ErrBadState, run.Status)
	}
	policy, err := m.st.GetSafetyPolicy(ctx)
	if err != nil {
		return run, err
	}
	if policy.EmergencyStop {
		return run, ErrEmergencyStop
	}
	if run.ProfileID == nil {
		return run, fmt.Errorf("%w: the run has no profile", ErrBadState)
	}
	p, err := m.st.GetProfile(ctx, *run.ProfileID)
	if err != nil {
		return run, err
	}
	m.mu.Lock()
	_, busy := m.active[runID]
	m.mu.Unlock()
	if busy {
		return run, fmt.Errorf("%w: the run is still stopping", ErrBadState)
	}
	run.Status, run.PauseReason, run.ResumeAt = model.RunQueued, "", nil
	if err := m.st.SaveRun(ctx, run); err != nil {
		return run, err
	}
	m.launch(run, p, true)
	return run, nil
}

// Cancel ends a run for good. A cancelled run cannot be resumed.
func (m *Manager) Cancel(ctx context.Context, runID int64) (model.ScanRun, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return run, err
	}
	switch run.Status {
	case model.RunQueued, model.RunRunning, model.RunPaused, model.RunAnalyzing:
	default:
		return run, fmt.Errorf("%w: status is %s", ErrBadState, run.Status)
	}
	if !m.stop(ctx, runID, "cancel") {
		now := time.Now().UTC()
		run.Status, run.FinishedAt, run.ResumeAt = model.RunCancelled, &now, nil
		if err := m.st.SaveRun(ctx, run); err != nil {
			return run, err
		}
		m.opt.Bus.Publish(Event{RunID: run.ID, Type: EventRun, Data: run})
		m.opt.Bus.Publish(Event{RunID: run.ID, Type: EventDone, Data: run})
	}
	return m.st.GetRun(ctx, runID)
}

// EmergencyStop sets the emergency stop flag and stops every running run. The
// context of every engine is cancelled at once, before anything else is
// awaited, so traffic stops as fast as the engine honours its context. The
// runs become paused with reason "emergency_stop": no result is lost and an
// operator can resume them after the release. No analysis runs here.
func (m *Manager) EmergencyStop(ctx context.Context) (model.SafetyPolicy, error) {
	// First cancel the engines: this needs no database round trip.
	m.mu.Lock()
	for _, a := range m.active {
		a.mu.Lock()
		if a.intent == "" {
			a.intent = "emergency"
		}
		a.mu.Unlock()
		a.cancel()
	}
	m.mu.Unlock()
	policy, err := m.st.SetEmergencyStop(ctx, true)
	var wg sync.WaitGroup
	for _, id := range m.ActiveRunIDs() {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			m.stop(ctx, id, "emergency")
		}(id)
	}
	wg.Wait()
	return policy, err
}

// ReleaseEmergencyStop clears the emergency stop flag. Paused runs stay paused until someone resumes them.
func (m *Manager) ReleaseEmergencyStop(ctx context.Context) (model.SafetyPolicy, error) {
	return m.st.SetEmergencyStop(ctx, false)
}

// Shutdown stops every running run for a restart. Recover resumes them.
func (m *Manager) Shutdown(ctx context.Context) {
	var wg sync.WaitGroup
	for _, id := range m.ActiveRunIDs() {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			m.stop(ctx, id, "shutdown")
		}(id)
	}
	wg.Wait()
}

// Recover repairs runs that a crash or restart left as queued, running or
// analyzing. Scans become paused with reason "restart" and, with autoResume,
// continue with their remaining chunks. Runs in analysis are analysed again.
func (m *Manager) Recover(ctx context.Context, autoResume bool) (recovered []int64, err error) {
	runs, err := m.st.RunsByStatus(ctx, model.RunQueued, model.RunRunning, model.RunAnalyzing)
	if err != nil {
		return nil, err
	}
	policy, err := m.st.GetSafetyPolicy(ctx)
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		m.mu.Lock()
		_, live := m.active[run.ID]
		m.mu.Unlock()
		if live {
			continue
		}
		recovered = append(recovered, run.ID)
		if run.Status == model.RunAnalyzing {
			a := &activeRun{run: run, cancel: func() {}, done: make(chan struct{})}
			var p *model.ScanProfile
			if run.ProfileID != nil {
				if prof, err := m.st.GetProfile(ctx, *run.ProfileID); err == nil {
					p = &prof
				}
			}
			m.finish(ctx, a, p)
			continue
		}
		if _, err := m.st.RemainingChunks(ctx, run.ID); err != nil { // running chunks become deferred
			return recovered, err
		}
		run.Status, run.PauseReason = model.RunPaused, PauseRestart
		if run.Trigger == "import" || run.ProfileID == nil {
			now := time.Now().UTC()
			run.Status, run.PauseReason, run.FinishedAt, run.Error = model.RunFailed, "", &now, "interrupted by a restart"
		}
		if err := m.st.SaveRun(ctx, run); err != nil {
			return recovered, err
		}
		m.log.Warn("recovered an interrupted run", "run", run.ID, "status", run.Status)
		if autoResume && run.Status == model.RunPaused && m.opt.Engine != nil && !policy.EmergencyStop {
			if _, err := m.Resume(ctx, run.ID); err != nil {
				m.log.Error("resume after restart", "run", run.ID, "err", err)
			}
		}
	}
	return recovered, nil
}

// ResumeDue resumes the runs that a closed scan window paused and whose next
// window has started. The scheduler calls it.
func (m *Manager) ResumeDue(ctx context.Context, now time.Time) ([]int64, error) {
	runs, err := m.st.RunsByStatus(ctx, model.RunPaused)
	if err != nil {
		return nil, err
	}
	var resumed []int64
	for _, run := range runs {
		if run.PauseReason != model.PauseWindowClosed || run.ResumeAt == nil || run.ResumeAt.After(now) {
			continue
		}
		if _, err := m.Resume(ctx, run.ID); err != nil {
			m.log.Error("resume in the next window", "run", run.ID, "err", err)
			continue
		}
		resumed = append(resumed, run.ID)
	}
	return resumed, nil
}

// Import stores host results that came from a file (nmap XML, JSON, CSV) as a
// run with trigger "import". The records take the same path as scanned
// results: the store sink, then the analysis hook.
func (m *Manager) Import(ctx context.Context, filename string, hosts []model.HostResult, userID *int64) (model.ScanRun, error) {
	now := time.Now().UTC()
	run, err := m.st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, Trigger: "import", ProfileName: "import", ImportFile: filename, CreatedBy: userID, StartedAt: &now})
	if err != nil {
		return run, err
	}
	stats := model.RunStats{AddressesTotal: int64(len(hosts)), AddressesDone: int64(len(hosts))}
	for i := range hosts {
		hosts[i].RunID = run.ID
		if hosts[i].Reason == "" {
			hosts[i].Reason = "imported"
		}
		if hosts[i].ObservedAt.IsZero() {
			hosts[i].ObservedAt = now
		}
		if hosts[i].Up {
			stats.HostsUp++
		}
		for _, sv := range hosts[i].Services {
			if sv.State == "open" || sv.State == "" {
				stats.ServicesOpen++
				if sv.HTTP != nil {
					stats.HTTPServices++
				}
			}
		}
	}
	a := &activeRun{run: run, cancel: func() {}, done: make(chan struct{})}
	a.run.Stats = stats
	sink := m.st.NewSink(store.SinkOptions{BatchSize: m.opt.IngestBatch, Source: "import", MarkMissing: false})
	for i := range hosts {
		if err = sink.OnHost(ctx, hosts[i]); err != nil {
			break
		}
	}
	if err == nil {
		err = sink.Flush(ctx)
	}
	if err != nil {
		end := time.Now().UTC()
		a.run.Status, a.run.Error, a.run.FinishedAt = model.RunFailed, err.Error(), &end
		return m.save(a, EventDone), err
	}
	a.run.Status = model.RunAnalyzing
	m.save(a, "")
	m.finish(context.WithoutCancel(ctx), a, nil)
	return m.st.GetRun(ctx, run.ID)
}

// eventSink forwards engine output to the store sink and to the event bus.
type eventSink struct {
	inner *store.Sink
	m     *Manager
	a     *activeRun
}

func (s *eventSink) OnPlan(ctx context.Context, runID int64, chunks []model.Chunk) error {
	return s.inner.OnPlan(ctx, runID, chunks)
}

func (s *eventSink) OnChunk(ctx context.Context, c model.Chunk) error {
	if c.RunID == 0 {
		c.RunID = s.a.run.ID
	}
	// Results must reach the database also when the engine context is already cancelled.
	err := s.inner.OnChunk(context.WithoutCancel(ctx), c)
	s.m.opt.Bus.Publish(Event{RunID: c.RunID, Type: EventChunk, Data: c})
	return err
}

func (s *eventSink) OnHost(ctx context.Context, res model.HostResult) error {
	if res.RunID == 0 {
		res.RunID = s.a.run.ID
	}
	err := s.inner.OnHost(context.WithoutCancel(ctx), res)
	open := 0
	for _, sv := range res.Services {
		if sv.State == "open" || sv.State == "" {
			open++
		}
	}
	s.m.opt.Bus.Publish(Event{RunID: res.RunID, Type: EventHost, Data: HostEvent{IP: res.IP, Up: res.Up, Services: open}})
	return err
}

func (s *eventSink) OnProgress(ctx context.Context, runID int64, stats model.RunStats) error {
	s.a.mu.Lock()
	s.a.run.Stats = stats
	run := s.a.run
	s.a.mu.Unlock()
	err := s.inner.OnProgress(context.WithoutCancel(ctx), run.ID, stats)
	s.m.opt.Bus.Publish(Event{RunID: run.ID, Type: EventProgress, Data: run})
	return err
}
