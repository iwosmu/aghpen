package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// The engine's quick path sends a partial result of a host (Interim,
// PortsUnknown) while the host is described, and the final result later in
// the same run. A run can also stop after the partial result. The store, the
// ingest and the analysis are real.
func TestPartialResultsDuringARun(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	sink := st.NewSink(store.SinkOptions{Source: "scan", MarkMissing: true})
	const ip = "10.9.0.1"
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Minute)
	web := func(port int, title string, ms int) model.ServiceResult {
		return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", Product: "nginx",
			HTTP: &model.HTTPFingerprint{Scheme: "http", URL: "http://x/", Status: 200, Title: title, ResponseMs: ms}}
	}
	bare := func(port int) model.ServiceResult { // described by the port scan only, no HTTP stage yet
		return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http"}
	}
	newRun := func(status model.RunStatus) model.ScanRun {
		t.Helper()
		r, err := st.CreateRun(ctx, model.ScanRun{Status: status, Trigger: "manual", ProfileName: "test"})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	send := func(h model.HostResult) {
		t.Helper()
		if err := sink.OnHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		if err := sink.Flush(ctx); err != nil { // each result in its own batch: the repeat path
			t.Fatal(err)
		}
	}
	finish := func(r model.ScanRun) []model.Change {
		t.Helper()
		if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		r, _ = st.GetRun(ctx, r.ID)
		r.Status = model.RunCompleted
		_ = st.SaveRun(ctx, r)
		page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
		return page.Items
	}
	svc := func(port int) model.Service {
		t.Helper()
		p, err := st.ListServices(ctx, store.ServiceFilter{Port: port})
		if err != nil || len(p.Items) != 1 {
			t.Fatalf("service %d: %+v %v", port, p.Items, err)
		}
		return p.Items[0]
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := st.Pool().QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Run 1: complete.
	r1 := newRun(model.RunAnalyzing)
	send(model.HostResult{RunID: r1.ID, ObservedAt: start, IP: ip, Up: true, Services: []model.ServiceResult{web(80, "Site", 50), web(8080, "Admin", 60), web(9000, "Old", 10)}})
	if ch := finish(r1); len(ch) != 0 {
		t.Fatalf("run 1: %v", kinds(ch))
	}

	// Run 2: a partial result (80 without HTTP yet, and 7000 that the final
	// result will not list), then the final result without 9000.
	r2 := newRun(model.RunRunning)
	send(model.HostResult{RunID: r2.ID, ObservedAt: start.Add(time.Hour), IP: ip, Up: true, Interim: true, PortsUnknown: true,
		Services: []model.ServiceResult{bare(80), bare(7000)}})
	// Mid-run: nothing is gone, the known fields stay, the run has one host observation saying the scan is not finished.
	if s := svc(9000); s.State != model.ServiceOpen {
		t.Fatalf("mid-run: 9000 is %s", s.State)
	}
	if s := svc(80); s.Title != "Site" || s.HTTPStatus != 200 {
		t.Fatalf("mid-run: the partial result erased the known fields of 80: %+v", s)
	}
	var reason string
	_ = st.Pool().QueryRow(ctx, "SELECT reason FROM host_observations WHERE run_id = $1", r2.ID).Scan(&reason)
	if reason != model.ReasonPortsUnknown {
		t.Fatalf("mid-run host observation reason %q", reason)
	}
	send(model.HostResult{RunID: r2.ID, ObservedAt: start.Add(time.Hour + time.Minute), IP: ip, Up: true,
		Services: []model.ServiceResult{web(80, "Site", 55), web(8080, "Admin", 65)}})
	ch := finish(r2)
	k := kinds(ch)
	if len(ch) != 1 || k["service_gone "+ip+":9000"] != 1 {
		t.Fatalf("run 2 changes: %v", k)
	}
	if n := count("SELECT count(*) FROM host_observations WHERE run_id = $1", r2.ID); n != 1 {
		t.Errorf("run 2 has %d host observations", n)
	}
	_ = st.Pool().QueryRow(ctx, "SELECT reason FROM host_observations WHERE run_id = $1", r2.ID).Scan(&reason)
	if reason != "" {
		t.Errorf("the final result did not replace the reason: %q", reason)
	}
	if n := count("SELECT count(*) FROM service_observations WHERE run_id = $1", r2.ID); n != 2 {
		t.Errorf("run 2 has %d service observations, want 2 (80, 8080)", n)
	}
	if s := svc(7000); s.State != model.ServiceGone {
		t.Errorf("7000, listed only by the partial result, is %s", s.State)
	}
	if s := svc(80); s.LastChanged != nil {
		t.Errorf("80 did not change, last_changed = %v", s.LastChanged)
	}
	if n := count("SELECT obs_total FROM hosts WHERE host(ip) = $1", ip); n != 2 {
		t.Errorf("obs_total = %d after 2 runs", n)
	}
	if n := count("SELECT COALESCE(sum(up + down), 0)::int FROM host_availability a JOIN hosts h ON h.id = a.host_id WHERE host(h.ip) = $1", ip); n != 2 {
		t.Errorf("availability histogram counts %d observations after 2 runs", n)
	}

	// Run 3: stopped after a partial result (emergency stop): no analysis.
	r3 := newRun(model.RunRunning)
	send(model.HostResult{RunID: r3.ID, ObservedAt: start.Add(90 * time.Minute), IP: ip, Up: true, Interim: true, PortsUnknown: true,
		Services: []model.ServiceResult{bare(80)}})
	r3.Status = model.RunCancelled
	_ = st.SaveRun(ctx, r3)
	if s := svc(8080); s.State != model.ServiceOpen {
		t.Fatalf("after the stop: 8080 is %s", s.State)
	}
	var stopped []store.RunHost
	_ = st.EachRunHost(ctx, r3.ID, func(h *store.RunHost) error { stopped = append(stopped, *h); return nil })
	if len(stopped) != 1 || !stopped[0].HasUnknownPorts() {
		t.Fatalf("the stopped run must say its port scan did not finish: %+v", stopped)
	}

	// Run 4: complete again, nothing changed since run 2. The stopped run is
	// not a baseline: 8080 did not "return", and no response time changed.
	r4 := newRun(model.RunAnalyzing)
	send(model.HostResult{RunID: r4.ID, ObservedAt: start.Add(2 * time.Hour), IP: ip, Up: true,
		Services: []model.ServiceResult{web(80, "Site", 52), web(8080, "Admin", 66)}})
	if ch := finish(r4); len(ch) != 0 {
		t.Fatalf("run 4 after a stopped run: %v", kinds(ch))
	}
	pts, err := st.ResponseSeries(ctx, svc(80).ID, 50)
	if err != nil || len(pts) != 3 || pts[0].Ms != 50 || pts[1].Ms != 55 || pts[2].Ms != 52 {
		t.Fatalf("series without the stopped run: %+v %v", pts, err)
	}
}
