package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func TestSeedDefaultsRunsOnce(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	created, err := st.SeedDefaults(ctx)
	if err != nil || !created {
		t.Fatalf("first seed: created=%v err=%v", created, err)
	}
	policy, err := st.GetSafetyPolicy(ctx)
	if err != nil || policy.EmergencyStop || policy.MaxPPS <= 0 || len(policy.AllowedMethods) != 2 {
		t.Fatalf("seeded policy: %+v %v", policy, err)
	}
	profiles, _ := st.ListProfiles(ctx, store.ListOpts{})
	if profiles.Total != 1 || profiles.Items[0].Schedule.Enabled || len(profiles.Items[0].ScopeIDs) != 0 || profiles.Items[0].Rate.MaxPPS > policy.MaxPPS {
		t.Fatalf("seeded profile: %+v", profiles.Items)
	}
	// Nothing else: no scope, no host, no finding.
	scopes, _ := st.ListScopes(ctx, store.ListOpts{})
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	findings, _ := st.ListFindings(ctx, store.FindingFilter{})
	if scopes.Total != 0 || hosts.Total != 0 || findings.Total != 0 {
		t.Fatalf("the seed must add no demo data: scopes=%d hosts=%d findings=%d", scopes.Total, hosts.Total, findings.Total)
	}
	// A later start does not bring a deleted profile back.
	if err := st.DeleteProfile(ctx, profiles.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if again, err := st.SeedDefaults(ctx); err != nil || again {
		t.Fatalf("second seed: created=%v err=%v", again, err)
	}
	if p, _ := st.ListProfiles(ctx, store.ListOpts{}); p.Total != 0 {
		t.Fatalf("the seed ran twice: %+v", p.Items)
	}
}

func TestSchedulerSeam(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(name string, enabled, sched bool) model.ScanProfile {
		t.Helper()
		p, err := st.CreateProfile(ctx, model.ScanProfile{Name: name, Enabled: enabled, Ports: "top-100",
			Schedule: model.Schedule{Enabled: sched, IntervalMinutes: 60}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	due := mk("due", true, true)
	later := mk("later", true, true)
	busy := mk("busy", true, true)
	manual := mk("manual only", true, false)
	off := mk("disabled", false, true)
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	for id, at := range map[int64]*time.Time{due.ID: &past, later.ID: &future, busy.ID: &past, off.ID: &past} {
		if err := st.SetProfileNextRun(ctx, id, at); err != nil {
			t.Fatal(err)
		}
	}
	// "busy" has an active run; "due" ran an hour ago.
	started := now.Add(-time.Hour)
	if _, err := st.CreateRun(ctx, model.ScanRun{ProfileID: &busy.ID, ProfileName: busy.Name, Status: model.RunRunning, Trigger: "schedule", StartedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRun(ctx, model.ScanRun{ProfileID: &due.ID, ProfileName: due.Name, Status: model.RunCompleted, Trigger: "schedule", StartedAt: &started, FinishedAt: &started}); err != nil {
		t.Fatal(err)
	}

	sched, err := st.ScheduledProfiles(ctx)
	if err != nil || len(sched) != 3 {
		t.Fatalf("scheduled profiles: %d %v", len(sched), err)
	}
	got, err := st.DueProfiles(ctx, now)
	if err != nil || len(got) != 1 || got[0].ID != due.ID {
		t.Fatalf("due profiles: %+v %v", got, err)
	}
	if last, err := st.LastRunStart(ctx, due.ID); err != nil || last == nil || !last.Equal(started) {
		t.Fatalf("last run start: %v %v", last, err)
	}
	if last, err := st.LastRunStart(ctx, later.ID); err != nil || last != nil {
		t.Fatalf("a profile that never ran: %v %v", last, err)
	}
	if next, err := st.NextScheduledRun(ctx); err != nil || next == nil {
		t.Fatalf("next scheduled run: %v %v", next, err)
	}

	// Runs paused by a window, soonest resume first; an operator pause is not listed.
	// (A profile has at most one active run, and a paused run is active.)
	r1, r2 := now.Add(2*time.Hour), now.Add(time.Hour)
	for _, r := range []model.ScanRun{
		{ProfileID: &later.ID, Status: model.RunPaused, PauseReason: model.PauseWindowClosed, ResumeAt: &r1},
		{ProfileID: &off.ID, Status: model.RunPaused, PauseReason: model.PauseWindowClosed, ResumeAt: &r2},
		{ProfileID: &manual.ID, Status: model.RunPaused, PauseReason: model.PauseManual},
	} {
		created, err := st.CreateRun(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		// resume_at is set when a run pauses, so it is written by SaveRun.
		created.ResumeAt = r.ResumeAt
		if err := st.SaveRun(ctx, created); err != nil {
			t.Fatal(err)
		}
	}
	paused, err := st.WindowPausedRuns(ctx)
	if err != nil || len(paused) != 2 || paused[0].ResumeAt == nil || !paused[0].ResumeAt.Equal(r2) || !paused[1].ResumeAt.Equal(r1) {
		t.Fatalf("window paused runs: %+v %v", paused, err)
	}
}
