package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/reprobe"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A juror stops a container and scans again. The second scan reports the
// host as "nie odpowiada (niepotwierdzone)" with the services it had; the
// re-probe plan confirms it 1 minute after the miss; for a host seen once a
// single confirmation miss is enough for the model to report it inactive,
// with its services gone.
func TestVanishedHostInTwoScans(t *testing.T) {
	vanishedHostInTwoScans(t, time.Now().UTC().Truncate(time.Second))
}

// The same scenario at fixed clock times: the last answer in the previous
// clock hour and the miss and the confirmation in the new one (every hour
// boundary, midnight in Warsaw, Saturday to Sunday, Sunday to Monday, both
// DST changes, the year boundary), and the same minutes inside one hour.
// analyze.TestYoungHostVerdictAtEveryTime sweeps the model alone over 8 days.
func TestVanishedHostAtClockBoundaries(t *testing.T) {
	for _, at := range []string{
		"2026-11-21T23:05:00Z",                                                 // 00:05 Warsaw: midnight, Saturday to Sunday
		"2026-11-21T22:05:00Z",                                                 // 23:05 Warsaw: an hour boundary
		"2026-11-22T10:05:00Z",                                                 // 11:05 Warsaw
		"2026-11-22T23:05:00Z",                                                 // Sunday to Monday
		"2026-03-29T01:05:00Z",                                                 // 03:05 CEST, right after the spring DST change
		"2026-10-25T01:05:00Z",                                                 // 02:05 CET, right after the autumn DST change
		"2026-12-31T23:05:00Z",                                                 // the year boundary in Warsaw
		"2026-11-21T23:30:00Z", "2026-11-21T20:30:00Z", "2026-11-22T10:30:00Z", // inside one hour
	} {
		now, err := time.Parse(time.RFC3339, at)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(at, func(t *testing.T) { vanishedHostInTwoScans(t, now) })
	}
}

func vanishedHostInTwoScans(t *testing.T, now time.Time) {
	st := storetest.New(t)
	ctx := context.Background()
	waw, _ := time.LoadLocation("Europe/Warsaw") // the zone the store counts the histogram in (CZUJKA_TZ default)
	an := NewAnalysis(st, waw, quiet())
	const ip = "172.30.0.7"
	svcs := []model.ServiceResult{
		{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx", HTTP: &model.HTTPFingerprint{Scheme: "http", URL: "http://x/", Status: 200, Title: "Shop"}},
		{Port: 5432, Proto: "tcp", State: "open", Name: "postgresql"},
	}
	scan := func(trigger string, at time.Time, up bool) (model.ScanRun, []model.Change) {
		t.Helper()
		r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: trigger, ProfileName: "test"})
		if err != nil {
			t.Fatal(err)
		}
		h := model.HostResult{RunID: r.ID, ObservedAt: at, IP: ip, Up: up}
		if up {
			h.Services = svcs
		} else {
			h.Reason = "no-response"
		}
		if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		r, _ = st.GetRun(ctx, r.ID)
		r.Status = model.RunCompleted
		_ = st.SaveRun(ctx, r)
		page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
		return r, page.Items
	}

	scan("manual", now.Add(-10*time.Minute), true)
	r2, ch := scan("manual", now.Add(-time.Minute), false)
	k := kinds(ch)
	if k["host_missing "+ip+":0"] != 1 || k["service_unreachable "+ip+":80"] != 1 || k["service_unreachable "+ip+":5432"] != 1 || len(ch) != 3 {
		t.Fatalf("second scan: %v", k)
	}
	for _, c := range ch {
		if c.Kind == model.ChangeServiceUnreachable && c.ServiceID == nil {
			t.Errorf("service_unreachable without the service id: %+v", c)
		}
	}
	if r2.Summary == nil || r2.Summary.HostsMissing != 1 || r2.Summary.ServicesUnreachable != 2 {
		t.Fatalf("second scan summary %+v", r2.Summary)
	}

	// The re-probe plan: the host has 2 observations, so the first confirmation is 1 minute after the miss.
	rb := reprobe.NewStoreBackend(st, waw, nil, quiet())
	if err := rb.Init(ctx); err != nil {
		t.Fatal(err)
	}
	in, err := rb.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	plan := reprobe.Build(in)
	if !plan.Enabled || len(plan.Probes) != 1 || plan.Probes[0].Kind != reprobe.KindConfirm || plan.Probes[0].IP != ip ||
		!plan.Probes[0].NotBefore.Equal(now) {
		t.Fatalf("plan %+v (skipped %+v, blocked %q)", plan.Probes, plan.Skipped, plan.Blocked)
	}

	// Confirmation 1 (one address, its known ports) finds it silent: inactive, services gone.
	_, ch = scan("reprobe", now, false)
	k = kinds(ch)
	if k["host_gone "+ip+":0"] != 1 || k["service_gone "+ip+":80"] != 1 || k["service_gone "+ip+":5432"] != 1 {
		t.Fatalf("confirmation: %v", k)
	}
}
