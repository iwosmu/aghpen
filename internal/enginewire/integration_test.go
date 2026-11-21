package enginewire

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// oneHost is a prober that finds one host. Everything above it is real: the
// scan engine, the run manager, the store sink and PostgreSQL.
type oneHost struct{ ip string }

func (oneHost) Name() string     { return "test" }
func (oneHost) Privileged() bool { return false }
func (o oneHost) Discover(context.Context, probe.DiscoverRequest) (*probe.Result, error) {
	return &probe.Result{Packets: 10, Hosts: []probe.Host{{IP: o.ip, Up: true, Reason: "syn-ack", Responded: true}}}, nil
}
func (o oneHost) PortScan(_ context.Context, req probe.PortScanRequest) (*probe.Result, error) {
	res := &probe.Result{Packets: 2}
	for _, ip := range req.Hosts {
		res.Hosts = append(res.Hosts, probe.Host{IP: ip, Up: true, Responded: true, Ports: []probe.Port{{Port: 80, Proto: "tcp", State: "open", Name: "http"}}})
	}
	return res, nil
}
func (oneHost) ServiceScan(context.Context, probe.ServiceRequest) (*probe.Result, error) {
	return &probe.Result{}, nil
}

// The scheduler backend against the real database and the real run manager:
// a due profile starts with trigger "schedule", a run outside its window
// pauses with "window_closed" and the scheduler resumes it, and the
// emergency stop blocks scheduled starts.
func TestSchedulerBackendWithRealStoreAndRunner(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	scope, err := st.CreateScope(ctx, model.Scope{Name: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddTargets(ctx, scope.ID, []model.Target{{Kind: model.TargetCIDR, Value: "10.50.0.0/24", Enabled: true, Addresses: 256}}, nil); err != nil {
		t.Fatal(err)
	}
	base := model.ScanProfile{ScopeIDs: []int64{scope.ID}, Ports: "80", Enabled: true, Rate: model.RateLimits{MaxPPS: 300}}
	hourly := base
	hourly.Name, hourly.Schedule = "co godzinę", model.Schedule{Enabled: true, IntervalMinutes: 60, Timezone: "Europe/Warsaw"}
	hourly, err = st.CreateProfile(ctx, hourly)
	if err != nil {
		t.Fatal(err)
	}

	engine := New(Deps{Prober: oneHost{"10.50.0.7"}, Logger: quiet})
	mgr := runner.New(st, runner.Options{Engine: engine, Window: Window, Logger: quiet})
	s := NewScheduler(st, mgr, quiet)
	b := s.Backend

	profiles, err := b.ScheduledProfiles(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].ID != hourly.ID {
		t.Fatalf("scheduled profiles = %+v, %v", profiles, err)
	}
	if last, active, err := b.LastRun(ctx, hourly.ID); err != nil || active || !last.IsZero() {
		t.Fatalf("last run of a new profile = %v %v %v", last, active, err)
	}

	// 1. A profile that never ran is not due on save; it is due one interval after the save.
	now := time.Now()
	if d := s.Tick(ctx, now); len(d.Started) != 0 {
		t.Fatalf("a schedule must not start on save: %+v", d)
	}
	if d := s.Tick(ctx, now.Add(61*time.Minute)); len(d.Started) != 1 || d.Started[0] != hourly.ID {
		t.Fatalf("first tick = %+v", d)
	}
	mgr.Wait()
	runs, err := st.ListRuns(ctx, store.RunFilter{ProfileID: hourly.ID})
	if err != nil || len(runs.Items) != 1 {
		t.Fatalf("runs = %+v, %v", runs, err)
	}
	run := runs.Items[0]
	if run.Trigger != "schedule" || run.Status != model.RunCompleted || run.Stats.HostsUp != 1 || run.Stats.AddressesDone != 256 {
		t.Fatalf("scheduled run = %+v", run)
	}
	if last, active, err := b.LastRun(ctx, hourly.ID); err != nil || active || time.Since(last) > time.Minute {
		t.Errorf("last run = %v active=%v err=%v", last, active, err)
	}
	p, _ := st.GetProfile(ctx, hourly.ID)
	if p.NextRunAt == nil || p.NextRunAt.Before(now.Add(59*time.Minute)) || p.NextRunAt.After(now.Add(62*time.Minute)) {
		t.Errorf("next run = %v, want about one hour after %v", p.NextRunAt, now)
	}
	// not due again before the interval has passed
	if d := s.Tick(ctx, time.Now()); len(d.Started) != 0 {
		t.Errorf("second tick started %v", d.Started)
	}

	// 2. A run started outside its window does not scan: it pauses and waits.
	loc, _ := time.LoadLocation("Europe/Warsaw")
	closed := time.Now().In(loc).Add(-2 * time.Hour)
	night := base
	night.Name = "okno zamknięte"
	night.Schedule = model.Schedule{Enabled: true, IntervalMinutes: 100000, Timezone: "Europe/Warsaw",
		Windows: []model.Window{{Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: closed.Format("15:04"), End: closed.Add(time.Minute).Format("15:04")}}}
	night, err = st.CreateProfile(ctx, night)
	if err != nil {
		t.Fatal(err)
	}
	started, err := mgr.Start(ctx, night.ID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	mgr.Wait()
	paused, err := st.GetRun(ctx, started.ID)
	if err != nil || paused.Status != model.RunPaused || paused.PauseReason != model.PauseWindowClosed || paused.Stats.PacketsSent != 0 {
		t.Fatalf("run outside the window = %+v, %v", paused, err)
	}
	if paused.ResumeAt == nil || !paused.ResumeAt.After(time.Now()) || paused.ResumeAt.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("resume_at = %v, want the next window start", paused.ResumeAt)
	}
	wp, err := b.WindowPausedRuns(ctx)
	if err != nil || len(wp) != 1 || wp[0].ID != paused.ID {
		t.Fatalf("window-paused runs = %+v, %v", wp, err)
	}
	if _, active, _ := b.LastRun(ctx, night.ID); !active {
		t.Error("a paused run counts as active")
	}
	// still closed: nothing resumes
	if d := s.Tick(ctx, time.Now()); len(d.Resumed) != 0 {
		t.Errorf("resumed outside the window: %+v", d)
	}
	// the operator removes the window; at the stored resume time the scheduler resumes the run
	night.Schedule.Windows = nil
	if _, err := st.UpdateProfile(ctx, night); err != nil {
		t.Fatal(err)
	}
	d := s.Tick(ctx, paused.ResumeAt.Add(time.Second))
	if len(d.Resumed) != 1 || d.Resumed[0] != paused.ID {
		t.Fatalf("resume tick = %+v", d)
	}
	mgr.Wait()
	done, _ := st.GetRun(ctx, paused.ID)
	if done.Status != model.RunCompleted || done.Stats.HostsUp != 1 || done.Stats.ChunksDone != 1 {
		t.Fatalf("resumed run = %+v", done)
	}

	// 3. Emergency stop: a due profile does not start, and no error is raised.
	before, _ := st.ListRuns(ctx, store.RunFilter{})
	if _, err := mgr.EmergencyStop(ctx); err != nil {
		t.Fatal(err)
	}
	if d := s.Tick(ctx, time.Now().Add(300*time.Hour)); len(d.Started) != 0 || len(d.Resumed) != 0 {
		t.Errorf("tick under emergency stop = %+v", d)
	}
	mgr.Wait()
	after, _ := st.ListRuns(ctx, store.RunFilter{})
	if after.Total != before.Total {
		t.Errorf("runs under emergency stop: %d before, %d after", before.Total, after.Total)
	}
}
