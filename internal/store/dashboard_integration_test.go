package store_test

import (
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A partial run (ad hoc, re-probe, import) never drives the "since last scan"
// numbers or the trend: they come from the full runs of the profile, and the
// partial run is named on its own.
func TestDashboardIgnoresPartialRuns(t *testing.T) {
	st := storetest.New(t)
	p, err := st.CreateProfile(ctx, model.ScanProfile{Name: "pełny"})
	if err != nil {
		t.Fatal(err)
	}
	finish := func(r model.ScanRun, hosts int, sum *model.RunDiffSummary) model.ScanRun {
		t.Helper()
		run, err := st.CreateRun(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		run.Status, run.FinishedAt, run.Summary = model.RunCompleted, &now, sum
		run.Stats.HostsUp, run.Stats.AddressesTotal = hosts, 1024
		if r.AdHoc != nil {
			run.Stats.AddressesTotal = 512
		}
		if err := st.SaveRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		return run
	}
	finish(model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name, Trigger: "manual"}, 128, &model.RunDiffSummary{})
	full := finish(model.ScanRun{ProfileID: &p.ID, ProfileName: p.Name, Trigger: "schedule"}, 130, &model.RunDiffSummary{HostsNew: 2, ServicesNew: 1, HostsGone: 1})
	finish(model.ScanRun{ProfileName: p.Name, Trigger: "reprobe", AdHoc: &model.AdHocScope{Addresses: []string{"10.0.0.0/23"}}}, 71,
		&model.RunDiffSummary{HostsNew: 17})
	imp := finish(model.ScanRun{ProfileName: "import", Trigger: "import"}, 3, &model.RunDiffSummary{HostsNew: 3})

	d, err := st.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.LastRun == nil || d.LastRun.ID != full.ID || d.Headline.NewSinceLastRun != 3 || d.Headline.GoneSinceLastRun != 1 {
		t.Fatalf("headline from the last full run: last_run=%v headline=%+v", d.LastRun, d.Headline)
	}
	if len(d.Trend) != 2 || d.Trend[0].Hosts != 128 || d.Trend[1].Hosts != 130 {
		t.Fatalf("trend of full runs only: %+v", d.Trend)
	}
	lp := d.Headline.LastPartial
	if lp == nil || lp.RunID != imp.ID || lp.Trigger != "import" || lp.At.IsZero() {
		t.Fatalf("last partial run: %+v", lp)
	}
}

// Ordered by interest, live hosts and open services come first.
func TestInterestOrderPutsLiveFirst(t *testing.T) {
	st := storetest.New(t)
	sink := st.NewSink(store.SinkOptions{})
	run := mkRun(t, st)
	for _, ip := range []string{"10.40.0.1", "10.40.0.2"} {
		if err := sink.OnHost(ctx, model.HostResult{RunID: run.ID, IP: ip, Up: true, Services: []model.ServiceResult{
			{Port: 80, Proto: "tcp", State: "open", Name: "http"}, {Port: 8080, Proto: "tcp", State: "open", Name: "http"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	pool := st.Pool()
	for _, q := range []string{
		`UPDATE services SET interest = 95, state = 'gone' WHERE port = 8080 AND host(ip) = '10.40.0.1'`,
		`UPDATE services SET interest = 10 WHERE NOT (port = 8080 AND host(ip) = '10.40.0.1')`,
		`UPDATE hosts SET interest = 90, status = 'down' WHERE host(ip) = '10.40.0.1'`,
		`UPDATE hosts SET interest = 20 WHERE host(ip) = '10.40.0.2'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, sort := range []string{"", "-interest"} {
		svcs, err := st.ListServices(ctx, store.ServiceFilter{ListOpts: store.ListOpts{Limit: 10, Sort: sort}})
		if err != nil || len(svcs.Items) != 4 {
			t.Fatalf("services: %v %v", svcs.Items, err)
		}
		if last := svcs.Items[3]; last.State != model.ServiceGone || last.Interest != 95 {
			t.Fatalf("sort %q: the gone service must come last, with its interest unchanged: %+v", sort, last)
		}
		hosts, err := st.ListHosts(ctx, store.HostFilter{ListOpts: store.ListOpts{Limit: 10, Sort: sort}})
		if err != nil || len(hosts.Items) != 2 || hosts.Items[0].IP != "10.40.0.2" {
			t.Fatalf("sort %q: the live host must come first: %+v %v", sort, hosts.Items, err)
		}
	}
}
