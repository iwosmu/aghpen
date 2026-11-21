package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func TestBusRouting(t *testing.T) {
	b := NewBus()
	run7, cancel7 := b.Subscribe(7)
	glob, cancelG := b.Subscribe(0)
	b.Publish(Event{RunID: 7, Type: EventProgress})
	b.Publish(Event{RunID: 8, Type: EventProgress})
	b.Publish(Event{RunID: 7, Type: EventRun})
	b.Publish(Event{RunID: 9, Type: EventFinding})
	if len(run7) != 1 || len(glob) != 2 {
		t.Fatalf("routing: run7=%d global=%d", len(run7), len(glob))
	}
	// A slow subscriber never blocks the publisher.
	for i := 0; i < 1000; i++ {
		b.Publish(Event{RunID: 7, Type: EventHost})
	}
	cancel7()
	cancel7()
	cancelG()
	if b.Subscribers() != 0 {
		t.Fatal("subscriptions must be removed")
	}
	(*Bus)(nil).Publish(Event{})
}

// fakeEngine plans three chunks and reports one host per chunk. It blocks
// before chunk "blockAt" until release is closed or the context is cancelled.
type fakeEngine struct {
	mu       sync.Mutex
	plans    []model.ScanPlan
	blockAt  int
	release  chan struct{}
	outcome  *model.RunOutcome
	started  chan struct{}
	blocked  chan struct{} // gets a value when Run waits at blockAt
	runCount atomic.Int32
	// cancelledAt is when the engine saw its context cancelled (unix nanoseconds).
	cancelledAt atomic.Int64
}

func newFake() *fakeEngine {
	return &fakeEngine{blockAt: -1, release: make(chan struct{}), started: make(chan struct{}, 16), blocked: make(chan struct{}, 16)}
}

func (f *fakeEngine) Estimate(plan model.ScanPlan) model.ScanEstimate {
	return model.ScanEstimate{Addresses: int64(len(plan.Targets)) * 256, Chunks: 3, EffectivePPS: min(plan.Profile.Rate.MaxPPS, plan.Policy.MaxPPS)}
}

func (f *fakeEngine) Run(ctx context.Context, plan model.ScanPlan, sink model.ResultSink) model.RunOutcome {
	f.mu.Lock()
	f.plans = append(f.plans, plan)
	blockAt, forced := f.blockAt, f.outcome
	f.mu.Unlock()
	f.runCount.Add(1)
	chunks := plan.Chunks
	stats := model.RunStats{ChunksTotal: 3, AddressesTotal: 768}
	if plan.PrevStats != nil {
		stats = *plan.PrevStats
	}
	if len(chunks) == 0 {
		for i := 0; i < 3; i++ {
			chunks = append(chunks, model.Chunk{RunID: plan.RunID, Seq: i, Spec: []string{fmt.Sprintf("10.50.%d.0/24", i)}, Size: 256, Status: model.ChunkPending})
		}
	}
	_ = sink.OnPlan(ctx, plan.RunID, chunks)
	f.started <- struct{}{}
	for _, c := range chunks {
		if c.Seq == blockAt {
			f.blocked <- struct{}{}
			select {
			case <-f.release:
			case <-ctx.Done():
				f.cancelledAt.Store(time.Now().UnixNano())
				c.Status = model.ChunkDeferred
				_ = sink.OnChunk(ctx, c)
				return model.RunOutcome{Status: model.RunPaused, Stats: stats}
			}
		}
		now := time.Now()
		c.Status, c.StartedAt = model.ChunkRunning, &now
		_ = sink.OnChunk(ctx, c)
		_ = sink.OnHost(ctx, model.HostResult{RunID: plan.RunID, IP: fmt.Sprintf("10.50.%d.10", c.Seq), Up: true,
			Services: []model.ServiceResult{{Port: 80, State: "open", Name: "http"}}})
		c.Status, c.FinishedAt, c.HostsUp = model.ChunkDone, &now, 1
		_ = sink.OnChunk(ctx, c)
		stats.ChunksDone++
		stats.HostsUp++
		stats.ServicesOpen++
		stats.AddressesDone += 256
		stats.AvgPPS = 400
		_ = sink.OnProgress(ctx, plan.RunID, stats)
	}
	if forced != nil {
		forced.Stats = stats
		return *forced
	}
	return model.RunOutcome{Status: model.RunCompleted, Stats: stats}
}

type fakeAnalyzer struct {
	mu   sync.Mutex
	runs []int64
	err  error
}

func (a *fakeAnalyzer) AnalyzeRun(_ context.Context, runID int64) (*model.RunDiffSummary, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.runs = append(a.runs, runID)
	return &model.RunDiffSummary{HostsNew: 3, ServicesNew: 3}, a.err
}

type env struct {
	st  *store.Store
	m   *Manager
	eng *fakeEngine
	an  *fakeAnalyzer
	p   model.ScanProfile
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := storetest.New(t)
	scope, err := st.CreateScope(ctx, model.Scope{Name: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddTargets(ctx, scope.ID, []model.Target{{Kind: model.TargetCIDR, Value: "10.50.0.0/22", Enabled: true, Addresses: 1024}}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, model.ScanProfile{Name: "Lab szybki", ScopeIDs: []int64{scope.ID}, Ports: "top-100", Enabled: true, Rate: model.RateLimits{MaxPPS: 300}})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, eng: newFake(), an: &fakeAnalyzer{}, p: p}
	e.m = New(st, Options{Engine: e.eng, Analyzer: e.an, StopTimeout: 10 * time.Second})
	t.Cleanup(func() { e.m.Shutdown(context.Background()); e.m.Wait() })
	return e
}

func waitStatus(t *testing.T, st *store.Store, id int64, want model.RunStatus) model.ScanRun {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		run, err := st.GetRun(context.Background(), id)
		if err == nil && run.Status == want {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %d: status %s, want %s (err %v)", id, run.Status, want, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunCompletes(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	events, cancel := e.m.Bus().Subscribe(0)
	defer cancel()
	uid := int64(1)
	run, err := e.m.Start(ctx, e.p.ID, &uid, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.RunQueued || run.ProfileName != "Lab szybki" {
		t.Fatalf("new run: %+v", run)
	}
	done := waitStatus(t, e.st, run.ID, model.RunCompleted)
	e.m.Wait()
	if done.Stats.HostsUp != 3 || done.Stats.ChunksDone != 3 || done.StartedAt == nil || done.FinishedAt == nil || done.Summary == nil || done.Summary.HostsNew != 3 {
		t.Fatalf("completed run: %+v", done)
	}
	if len(e.an.runs) != 1 || e.an.runs[0] != run.ID {
		t.Fatalf("the analyzer hook must run once: %v", e.an.runs)
	}
	plan := e.eng.plans[0]
	if plan.RunID != run.ID || len(plan.Targets) != 1 || plan.Policy.MaxPPS == 0 || len(plan.Chunks) != 0 || plan.PrevStats != nil {
		t.Fatalf("plan: %+v", plan)
	}
	hosts, _ := e.st.ListHosts(ctx, store.HostFilter{})
	chunks, _ := e.st.ListChunks(ctx, run.ID)
	if hosts.Total != 3 || len(chunks) != 3 || chunks[2].Status != model.ChunkDone {
		t.Fatalf("stored results: hosts=%d chunks=%+v", hosts.Total, chunks)
	}
	p, _ := e.st.GetProfile(ctx, e.p.ID)
	if p.LastRunID == nil || *p.LastRunID != run.ID {
		t.Fatalf("profile last run: %+v", p.LastRunID)
	}
	if pps, _ := e.st.ProfileMeasuredPPS(ctx, e.p.ID); pps != 400 {
		t.Fatalf("measured speed %v", pps)
	}
	var statuses []model.RunStatus
	for len(events) > 0 {
		if ev := <-events; ev.Type == EventRun {
			statuses = append(statuses, ev.Data.(model.ScanRun).Status)
		}
	}
	if fmt.Sprint(statuses) != "[running analyzing completed]" {
		t.Fatalf("run events: %v", statuses)
	}
	// The next run gets hints and the measured speed from the first.
	run2, err := e.m.Start(ctx, e.p.ID, nil, "schedule")
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, e.st, run2.ID, model.RunCompleted)
	e.m.Wait()
	if plan2 := e.eng.plans[1]; len(plan2.Hints) != 3 || plan2.MeasuredPPS != 400 || len(plan2.Hints[0].OpenPorts) != 1 {
		t.Fatalf("second plan: hints=%d pps=%v", len(plan2.Hints), plan2.MeasuredPPS)
	}
}

func TestOneActiveRunPerProfileAndPauseResume(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.eng.blockAt = 1
	run, err := e.m.Start(ctx, e.p.ID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	<-e.eng.started
	waitStatus(t, e.st, run.ID, model.RunRunning)
	if _, err := e.m.Start(ctx, e.p.ID, nil, "manual"); !errors.Is(err, ErrActiveRun) {
		t.Fatalf("second run of the profile: %v", err)
	}
	if _, err := e.m.Resume(ctx, run.ID); !errors.Is(err, ErrBadState) {
		t.Fatalf("resume of a running run: %v", err)
	}
	paused, err := e.m.Pause(ctx, run.ID)
	if err != nil || paused.Status != model.RunPaused || paused.PauseReason != model.PauseManual || paused.FinishedAt != nil {
		t.Fatalf("pause: %+v %v", paused, err)
	}
	if paused.Stats.ChunksDone != 1 {
		t.Fatalf("stats after pause: %+v", paused.Stats)
	}
	// A paused run still blocks a second run of the profile.
	if _, err := e.m.Start(ctx, e.p.ID, nil, "manual"); !errors.Is(err, ErrActiveRun) {
		t.Fatalf("start while paused: %v", err)
	}
	e.eng.mu.Lock()
	e.eng.blockAt = -1
	e.eng.mu.Unlock()
	if _, err := e.m.Resume(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, e.st, run.ID, model.RunCompleted)
	e.m.Wait()
	plan := e.eng.plans[1]
	if len(plan.Chunks) != 2 || plan.Chunks[0].Seq != 1 || plan.Chunks[0].Status != model.ChunkDeferred || plan.PrevStats == nil || plan.PrevStats.ChunksDone != 1 {
		t.Fatalf("resume plan: chunks=%+v prev=%+v", plan.Chunks, plan.PrevStats)
	}
	if done.Stats.ChunksDone != 3 || done.Stats.HostsUp != 3 {
		t.Fatalf("stats after resume: %+v", done.Stats)
	}
	if hosts, _ := e.st.ListHosts(ctx, store.HostFilter{}); hosts.Total != 3 {
		t.Fatalf("hosts: %d", hosts.Total)
	}
}

func TestCancel(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.eng.blockAt = 2
	run, _ := e.m.Start(ctx, e.p.ID, nil, "manual")
	<-e.eng.started
	waitStatus(t, e.st, run.ID, model.RunRunning)
	c, err := e.m.Cancel(ctx, run.ID)
	if err != nil || c.Status != model.RunCancelled || c.FinishedAt == nil {
		t.Fatalf("cancel: %+v %v", c, err)
	}
	if _, err := e.m.Resume(ctx, run.ID); !errors.Is(err, ErrBadState) {
		t.Fatalf("resume of a cancelled run: %v", err)
	}
	if _, err := e.m.Cancel(ctx, run.ID); !errors.Is(err, ErrBadState) {
		t.Fatalf("second cancel: %v", err)
	}
	if len(e.an.runs) != 0 {
		t.Fatal("a cancelled run must not be analysed")
	}
	// The profile is free again.
	e.eng.mu.Lock()
	e.eng.blockAt = -1
	e.eng.mu.Unlock()
	run2, err := e.m.Start(ctx, e.p.ID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, e.st, run2.ID, model.RunCompleted)
}

func TestEmergencyStop(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.eng.blockAt = 1
	run, _ := e.m.Start(ctx, e.p.ID, nil, "manual")
	<-e.eng.started
	waitStatus(t, e.st, run.ID, model.RunRunning)
	<-e.eng.blocked // the engine waits at its block point: a cancel reaches it at once
	t0 := time.Now()
	policy, err := e.m.EmergencyStop(ctx)
	total := time.Since(t0)
	if err != nil || !policy.EmergencyStop {
		t.Fatalf("emergency stop: %+v %v", policy, err)
	}
	// Traffic must stop at once: the engine context is cancelled before any database work.
	toCancel := time.Unix(0, e.eng.cancelledAt.Load()).Sub(t0)
	t.Logf("emergency stop: engine context cancelled after %s, call returned after %s", toCancel, total)
	if e.eng.cancelledAt.Load() == 0 || toCancel > 100*time.Millisecond || total > time.Second {
		t.Fatalf("emergency stop is too slow: cancel after %s, return after %s", toCancel, total)
	}
	stopped, _ := e.st.GetRun(ctx, run.ID)
	if stopped.Status != model.RunPaused || stopped.PauseReason != model.PauseEmergency {
		t.Fatalf("run after emergency stop: %+v", stopped)
	}
	if len(e.m.ActiveRunIDs()) != 0 {
		t.Fatal("no run may be active after the emergency stop")
	}
	if _, err := e.m.Resume(ctx, run.ID); !errors.Is(err, ErrEmergencyStop) {
		t.Fatalf("resume during emergency stop: %v", err)
	}
	if _, err := e.m.Start(ctx, e.p.ID, nil, "manual"); !errors.Is(err, ErrEmergencyStop) {
		t.Fatalf("start during emergency stop: %v", err)
	}
	if p, err := e.m.ReleaseEmergencyStop(ctx); err != nil || p.EmergencyStop {
		t.Fatalf("release: %+v %v", p, err)
	}
	e.eng.mu.Lock()
	e.eng.blockAt = -1
	e.eng.mu.Unlock()
	if _, err := e.m.Resume(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, e.st, run.ID, model.RunCompleted)
}

func TestRecoverAfterRestart(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	// State that a crash leaves behind: a running run with one done and one running chunk.
	now := time.Now().UTC()
	run, err := e.st.CreateRun(ctx, model.ScanRun{ProfileID: &e.p.ID, ProfileName: e.p.Name, Status: model.RunRunning, StartedAt: &now, Stats: model.RunStats{ChunksTotal: 3, ChunksDone: 1, HostsUp: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.SavePlan(ctx, run.ID, []model.Chunk{
		{Seq: 0, Spec: []string{"10.50.0.0/24"}, Size: 256, Status: model.ChunkDone},
		{Seq: 1, Spec: []string{"10.50.1.0/24"}, Size: 256, Status: model.ChunkRunning},
		{Seq: 2, Spec: []string{"10.50.2.0/24"}, Size: 256, Status: model.ChunkPending}})

	// Without auto-resume the run is paused with reason "restart".
	rec, err := e.m.Recover(ctx, false)
	if err != nil || len(rec) != 1 {
		t.Fatalf("recover: %v %v", rec, err)
	}
	r, _ := e.st.GetRun(ctx, run.ID)
	if r.Status != model.RunPaused || r.PauseReason != PauseRestart {
		t.Fatalf("recovered run: %+v", r)
	}
	// A second process start with auto-resume: put it back to "running" and recover again.
	r.Status = model.RunRunning
	_ = e.st.SaveRun(ctx, r)
	if _, err := e.m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, e.st, run.ID, model.RunCompleted)
	e.m.Wait()
	plan := e.eng.plans[0]
	if len(plan.Chunks) != 2 || plan.Chunks[0].Seq != 1 || plan.PrevStats.ChunksDone != 1 {
		t.Fatalf("resume plan after restart: %+v", plan.Chunks)
	}
	if done.Stats.ChunksDone != 3 {
		t.Fatalf("stats: %+v", done.Stats)
	}
	// A run that stopped in "analyzing" is analysed again and completed.
	run2, _ := e.st.CreateRun(ctx, model.ScanRun{ProfileID: &e.p.ID, ProfileName: e.p.Name, Status: model.RunAnalyzing, StartedAt: &now})
	if _, err := e.m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
	if r2, _ := e.st.GetRun(ctx, run2.ID); r2.Status != model.RunCompleted || r2.Summary == nil {
		t.Fatalf("analyzing run after recover: %+v", r2)
	}
}

func TestWindowClosedFailureAndNotWired(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	next := time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second)
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	e.m.SetWindow(func(model.ScanProfile, time.Time) (*time.Time, *time.Time) { return &end, &next })
	e.eng.outcome = &model.RunOutcome{Status: model.RunPaused, PauseReason: model.PauseWindowClosed}
	run, _ := e.m.Start(ctx, e.p.ID, nil, "schedule")
	p := waitStatus(t, e.st, run.ID, model.RunPaused)
	e.m.Wait()
	if p.PauseReason != model.PauseWindowClosed || p.ResumeAt == nil || !p.ResumeAt.Equal(next) || p.WindowEnd == nil || !e.eng.plans[0].WindowEnd.Equal(end) {
		t.Fatalf("window pause: %+v", p)
	}
	// A run that its window paused is analysed for what it probed so far.
	e.an.mu.Lock()
	analysed := len(e.an.runs) == 1 && e.an.runs[0] == run.ID
	e.an.mu.Unlock()
	if !analysed || p.Summary == nil || p.Summary.HostsNew != 3 {
		t.Fatalf("a window-paused run must be analysed: analysed=%v summary=%+v", analysed, p.Summary)
	}
	if paused, err := e.st.WindowPausedRuns(ctx); err != nil || len(paused) != 1 || paused[0].ID != run.ID || paused[0].ResumeAt == nil {
		t.Fatalf("window paused runs: %+v %v", paused, err)
	}
	if ids, _ := e.m.ResumeDue(ctx, time.Now()); len(ids) != 0 {
		t.Fatalf("not due yet: %v", ids)
	}
	e.eng.mu.Lock()
	e.eng.outcome = &model.RunOutcome{Status: model.RunFailed, Err: errors.New("nmap: permission denied")}
	e.eng.mu.Unlock()
	if ids, err := e.m.ResumeDue(ctx, next.Add(time.Minute)); err != nil || len(ids) != 1 {
		t.Fatalf("due: %v %v", ids, err)
	}
	f := waitStatus(t, e.st, run.ID, model.RunFailed)
	e.m.Wait()
	if f.Error != "nmap: permission denied" || f.FinishedAt == nil {
		t.Fatalf("failed run: %+v", f)
	}

	// Analysis errors do not lose the scan.
	e.eng.mu.Lock()
	e.eng.outcome = nil
	e.eng.mu.Unlock()
	e.an.err = errors.New("boom")
	run2, _ := e.m.Start(ctx, e.p.ID, nil, "manual")
	c := waitStatus(t, e.st, run2.ID, model.RunCompleted)
	if c.Error != "analysis failed: boom" {
		t.Fatalf("analysis error must be recorded: %q", c.Error)
	}

	// No engine: 501 material.
	bare := New(e.st, Options{})
	if _, err := bare.Start(ctx, e.p.ID, nil, "manual"); !errors.Is(err, ErrNotWired) {
		t.Fatalf("start without engine: %v", err)
	}
	if _, err := bare.Estimate(ctx, e.p.ID); !errors.Is(err, ErrNotWired) {
		t.Fatalf("estimate without engine: %v", err)
	}
	if est, err := e.m.Estimate(ctx, e.p.ID); err != nil || est.EffectivePPS != 300 || est.Addresses != 256 {
		t.Fatalf("estimate: %+v %v", est, err)
	}
	// A profile without targets cannot start.
	empty, _ := e.st.CreateProfile(ctx, model.ScanProfile{Name: "Pusty", Enabled: true})
	if _, err := e.m.Start(ctx, empty.ID, nil, "manual"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("profile without scope: %v", err)
	}
	if _, err := e.m.Start(ctx, 99999, nil, "manual"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown profile: %v", err)
	}
}

func TestImport(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.an.err = nil
	run, err := e.m.Import(ctx, "skan.xml", []model.HostResult{
		{IP: "10.60.0.1", Up: true, Services: []model.ServiceResult{{Port: 22, State: "open", Name: "ssh"}, {Port: 443, State: "open", Name: "https", HTTP: &model.HTTPFingerprint{Status: 200}}}},
		{IP: "10.60.0.2", Up: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.RunCompleted || run.Trigger != "import" || run.ImportFile != "skan.xml" || run.Stats.HostsUp != 2 || run.Stats.ServicesOpen != 2 || run.Stats.HTTPServices != 1 || run.Summary == nil {
		t.Fatalf("import run: %+v", run)
	}
	hosts, _ := e.st.ListHosts(ctx, store.HostFilter{})
	if hosts.Total != 2 || hosts.Items[0].Source != "import" {
		t.Fatalf("imported hosts: %+v", hosts.Items)
	}
	if len(e.an.runs) != 1 {
		t.Fatal("imports go through the analysis hook too")
	}
}
